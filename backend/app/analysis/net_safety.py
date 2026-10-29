"""Central SSRF guard for every outbound connection to a scanned site (SPEC_V2 section 0).

Every fetch that touches the *target* (HTTP probe and each redirect hop, SSL handshake, favicon, cloaking
variants, download hashing, browser capture route filter / proxy) goes through this module:

* only http/https, only ports 80/443/8080/8443;
* the host is resolved and EVERY resolved address must be globally routable (``ipaddress.is_global``) and not
  multicast / NAT64- / 6to4- / Teredo- / IPv4-mapped wrappers of a non-public address;
* ``guarded_client()`` returns an httpx client whose connection layer resolves, validates and then connects to the
  validated IP itself (TLS SNI still uses the hostname). This pins the connection to the checked address, so a DNS
  rebinding answer between "check" and "connect" cannot reach an internal host, and redirects that slip past a
  caller are still refused at connect time;
* ``fetch()`` follows redirects manually and re-validates every hop.

Third-party services (ip-api, ipwho.is, rdap.org, crt.sh, thum.io, DNSBL queries) do not use this module.
Never raises out of ``fetch()``; policy violations are reported as ``UnsafeTarget``.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
DEFAULT_PORTS = {"http": 80, "https": 443}
BLOCKED_ERROR = "blocked: non-public address"
_NAT64 = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
_LOCAL_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home.arpa", ".corp", ".localdomain")
_RESOLVE_TTL = 30.0


class UnsafeTarget(Exception):
    """The target must not be contacted (non-public address, forbidden port or scheme)."""

    def __init__(self, reason: str, *, kind: str = "address", url: str | None = None, host: str | None = None,
                 ip: str | None = None, port: int | None = None):
        super().__init__(reason)
        self.reason, self.kind, self.url, self.host, self.ip, self.port = reason, kind, url, host, ip, port

    @property
    def error(self) -> str:
        """Short sub-result error string (SPEC_V2: ``blocked: non-public address``)."""
        if self.kind == "address":
            return BLOCKED_ERROR
        return f"blocked: {self.reason}"

    def as_dict(self) -> dict:
        return {"error": self.error, "reason": self.reason, "kind": self.kind, "url": self.url, "host": self.host,
                "ip": self.ip, "port": self.port}


class ResolutionError(OSError):
    """Host name could not be resolved (not a policy block)."""


# ----------------------------------------------------------------------------------------------- address policy
def ip_block_reason(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return why an address is not allowed (None when it is a public, globally routable unicast address)."""
    try:
        a = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else \
            ipaddress.ip_address(str(ip).strip("[]").split("%", 1)[0])
    except ValueError:
        return "not a valid IP address"
    if isinstance(a, ipaddress.IPv6Address):
        mapped = a.ipv4_mapped
        if mapped is not None:
            r = ip_block_reason(mapped)
            return f"IPv4-mapped {r}" if r else None
        if a.sixtofour is not None:
            r = ip_block_reason(a.sixtofour)
            if r:
                return f"6to4-embedded {r}"
        if a.teredo is not None:
            return "Teredo tunnel address"
        for net in _NAT64:
            if a in net:
                # DNS64/NAT64 networks synthesise 64:ff9b::<ipv4> for IPv4-only hosts. The prefix itself sits in
                # ::/8 (is_reserved), so the decision must be made on the embedded IPv4 destination.
                r = ip_block_reason(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
                return f"NAT64-embedded {r}" if r else None
        if a.is_site_local:
            return "site-local address"
    if a.is_loopback:
        return "loopback address"
    if a.is_link_local:
        return "link-local address (e.g. cloud metadata service)"
    if a.is_multicast:
        return "multicast address"
    if a.is_unspecified:
        return "unspecified address"
    if a.is_reserved:
        return "reserved address"
    if a.is_private:
        return "private network address"
    if not a.is_global:
        return "non-global address (shared/CGNAT or special-purpose range)"
    return None


def is_public_ip(ip) -> bool:
    return ip_block_reason(ip) is None


def literal_block_reason(host: str) -> str | None:
    """Policy decision possible without DNS: localhost-style names and literal non-public IPs."""
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    if not h:
        return "empty host"
    if h == "localhost" or h.endswith(_LOCAL_SUFFIXES):
        return f"'{h}' is a local/internal host name"
    ip = _literal_ip(h)
    if ip is not None:
        r = ip_block_reason(ip)
        return f"{ip} is a {r}" if r else None
    return None


_LEGACY_V4 = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)


def _literal_ip(h: str) -> str | None:
    try:
        return str(ipaddress.ip_address(h.split("%", 1)[0]))
    except ValueError:
        pass
    # legacy inet_aton forms (decimal 2130706433, hex 0x7f000001, octal 0177.0.0.1, short 127.1)
    if _LEGACY_V4.match(h):
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except OSError:
            return None
    return None


def port_of(sp) -> int | None:
    try:
        p = sp.port
    except ValueError:
        return None
    return p if p is not None else DEFAULT_PORTS.get((sp.scheme or "").lower())


# ----------------------------------------------------------------------------------------------- resolution
_res_cache: dict[tuple[str, int], tuple[float, list[str]]] = {}
_res_lock = threading.Lock()


def _cache_get(key):
    with _res_lock:
        v = _res_cache.get(key)
        if v and time.time() - v[0] < _RESOLVE_TTL:
            return list(v[1])
        return None


def _cache_set(key, ips):
    with _res_lock:
        _res_cache[key] = (time.time(), list(ips))
        if len(_res_cache) > 4096:
            for k in list(_res_cache)[:1024]:
                _res_cache.pop(k, None)


def _order(infos) -> list[str]:
    v4, v6 = [], []
    for fam, *_rest, sockaddr in infos:
        ip = sockaddr[0]
        (v4 if fam == socket.AF_INET else v6).append(ip)
    out = []
    for ip in v4 + v6:
        if ip not in out:
            out.append(ip)
    return out


async def resolve(host: str, port: int = 443, timeout: float = 4.0) -> list[str]:
    """Resolve host -> IP list (IPv4 first). Literal IPs are returned as-is. Raises ResolutionError."""
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    lit = _literal_ip(h)
    if lit:
        return [lit]
    key = (h, int(port or 0))
    c = _cache_get(key)
    if c:
        return c
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(h, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP),
                                       timeout)
    except asyncio.TimeoutError as e:
        raise ResolutionError(f"DNS resolution of {h} timed out") from e
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise ResolutionError(f"DNS resolution of {h} failed: {getattr(e, 'strerror', None) or e}") from e
    ips = _order(infos)
    if not ips:
        raise ResolutionError(f"DNS resolution of {h} returned no addresses")
    _cache_set(key, ips)
    return ips


def resolve_sync(host: str, port: int = 443, timeout: float = 4.0) -> list[str]:
    h = (host or "").strip().strip("[]").rstrip(".").lower()
    lit = _literal_ip(h)
    if lit:
        return [lit]
    key = (h, int(port or 0))
    c = _cache_get(key)
    if c:
        return c
    try:
        infos = socket.getaddrinfo(h, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise ResolutionError(f"DNS resolution of {h} failed: {getattr(e, 'strerror', None) or e}") from e
    ips = _order(infos)
    if not ips:
        raise ResolutionError(f"DNS resolution of {h} returned no addresses")
    _cache_set(key, ips)
    return ips


def _validate_ips(host: str, port: int, ips: list[str], url: str | None = None) -> list[str]:
    for ip in ips:
        r = ip_block_reason(ip)
        if r:
            raise UnsafeTarget(f"{host} resolves to {ip} ({r})", kind="address", url=url, host=host, ip=ip, port=port)
    return ips


def _check_port(host: str, port: int | None, url: str | None = None) -> int:
    if port is None or port not in ALLOWED_PORTS:
        raise UnsafeTarget(f"port {port} not allowed (only 80, 443, 8080, 8443)", kind="port", url=url, host=host,
                           port=port)
    return port


async def check_host(host: str, port: int, timeout: float = 4.0, url: str | None = None) -> list[str]:
    """Resolve and validate. Returns the validated IPs; raises UnsafeTarget / ResolutionError."""
    _check_port(host, port, url)
    reason = literal_block_reason(host)
    if reason:
        lit = _literal_ip((host or "").strip("[]").lower())
        raise UnsafeTarget(reason, kind="address", url=url, host=host, ip=lit, port=port)
    ips = await resolve(host, port, timeout)
    return _validate_ips(host, port, ips, url)


def check_host_sync(host: str, port: int, timeout: float = 4.0, url: str | None = None) -> list[str]:
    _check_port(host, port, url)
    reason = literal_block_reason(host)
    if reason:
        raise UnsafeTarget(reason, kind="address", url=url, host=host, port=port)
    return _validate_ips(host, port, resolve_sync(host, port, timeout), url)


def _split_url(url: str):
    sp = urlsplit(url)
    scheme = (sp.scheme or "").lower()
    if scheme not in DEFAULT_PORTS:
        raise UnsafeTarget(f"unsupported scheme '{scheme or '?'}'", kind="scheme", url=url)
    host = (sp.hostname or "").lower()
    if not host:
        raise UnsafeTarget("URL has no host", kind="host", url=url)
    return sp, host, port_of(sp)


async def check_url(url: str, timeout: float = 4.0) -> dict:
    """Validate a URL before fetching it. Returns {"url","host","port","ips"}; raises UnsafeTarget/ResolutionError."""
    sp, host, port = _split_url(url)
    ips = await check_host(host, port, timeout, url=url)
    return {"url": url, "host": host, "port": port, "ips": ips}


def check_url_sync(url: str, timeout: float = 4.0) -> dict:
    sp, host, port = _split_url(url)
    return {"url": url, "host": host, "port": port, "ips": check_host_sync(host, port, timeout, url=url)}


# ----------------------------------------------------------------------------------------------- guarded transport
class _GuardedBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that validates the destination and connects to the validated IP."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend):
        self._inner = inner

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ips = await check_host(host, int(port), timeout=min(float(timeout or 4.0), 5.0))
        last: BaseException | None = None
        for ip in ips[:3]:
            try:
                return await self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                                     socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as e:
                last = e
        raise last or httpcore.ConnectError(f"could not connect to {host}")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise UnsafeTarget("unix sockets are not allowed", kind="scheme")

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


def guarded_client(*, timeout: float | httpx.Timeout = 8.0, headers: dict | None = None,
                   verify: bool = False) -> httpx.AsyncClient:
    """httpx.AsyncClient for target fetches: no env proxies, no automatic redirects, connect-time IP validation."""
    transport = httpx.AsyncHTTPTransport(verify=verify, trust_env=False, retries=0)
    pool = getattr(transport, "_pool", None)
    if pool is not None and hasattr(pool, "_network_backend"):
        pool._network_backend = _GuardedBackend(pool._network_backend)
    t = timeout if isinstance(timeout, httpx.Timeout) else httpx.Timeout(max(1.0, float(timeout)),
                                                                          connect=min(5.0, float(timeout)))
    return httpx.AsyncClient(transport=transport, timeout=t, headers=headers or {}, follow_redirects=False,
                             trust_env=False)


# ----------------------------------------------------------------------------------------------- fetch helper
@dataclass
class FetchResult:
    url: str
    final_url: str | None = None
    status: int | None = None
    headers: httpx.Headers | None = None
    body: bytes = b""
    extra: Any = None
    chain: list[dict] = field(default_factory=list)
    error: str | None = None
    blocked: UnsafeTarget | None = None
    elapsed_ms: int = 0
    truncated: bool = False
    encoding: str | None = None
    cross_domain_redirects: int = 0

    @property
    def ok(self) -> bool:
        return self.status is not None


BodyHandler = Callable[[httpx.Response, float], Awaitable[tuple[bytes, Any, bool]]]


async def read_limited(resp: httpx.Response, max_bytes: int, deadline: float) -> tuple[bytes, Any, bool]:
    chunks, size, trunc = [], 0, False
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= max_bytes:
            trunc = True
            break
        if time.perf_counter() > deadline:
            trunc = True
            break
    return b"".join(chunks)[:max_bytes], None, trunc


async def fetch(url: str, *, headers: dict | None = None, timeout: float = 8.0, max_bytes: int = 2 * 1024 * 1024,
                max_redirects: int = 10, body_handler: BodyHandler | None = None,
                same_site: Callable[[str, str], bool] | None = None) -> FetchResult:
    """GET ``url`` following redirects manually; every hop is validated with ``check_url``. Never raises."""
    t0 = time.perf_counter()
    deadline = t0 + timeout
    res = FetchResult(url=url)
    current = url
    try:
        async with guarded_client(timeout=timeout, headers=headers) as client:
            for hop in range(max_redirects + 1):
                remaining = deadline - time.perf_counter()
                if remaining <= 0.2:
                    res.error = "Timed out while following redirects"
                    break
                try:
                    await check_url(current, timeout=min(4.0, remaining))
                except UnsafeTarget as e:
                    e.url = e.url or current
                    res.blocked, res.error = e, e.error
                    break
                except ResolutionError as e:
                    res.error = str(e)
                    break
                try:
                    async with client.stream("GET", current, timeout=remaining) as r:
                        res.chain.append({"url": current, "status": r.status_code})
                        res.status, res.headers, res.final_url = r.status_code, r.headers, current
                        res.encoding = r.charset_encoding
                        loc = r.headers.get("location")
                        if r.is_redirect and loc and hop < max_redirects:
                            nxt = urljoin(current, loc.strip())
                            if same_site and not same_site(urlsplit(current).hostname or "", urlsplit(nxt).hostname or ""):
                                res.cross_domain_redirects += 1
                            current = nxt
                            continue
                        handler = body_handler or (lambda resp, dl: read_limited(resp, max_bytes, dl))
                        res.body, res.extra, res.truncated = await handler(r, deadline)
                        break
                except UnsafeTarget as e:  # connect-time refusal (e.g. DNS changed between check and connect)
                    e.url = e.url or current
                    res.blocked, res.error = e, e.error
                    break
                except Exception as e:
                    res.error = (f"{type(e).__name__}: {e}"[:300]) or type(e).__name__
                    break
    except Exception as e:  # pragma: no cover - client construction failures
        res.error = f"{type(e).__name__}: {e}"[:300]
    res.elapsed_ms = int((time.perf_counter() - t0) * 1000)
    return res
