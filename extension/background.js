/* PhishGuard background service worker (MV3). */
importScripts("shared.js");

const CACHE_TTL_MS = 30 * 60 * 1000;
const CACHE_KEY = "scanCache";
const MENU_ID = "phishguard-scan-link";
const notifiedUrls = new Set();

// ---------- helpers ----------
function isScannable(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    const h = u.hostname;
    if (h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h.endsWith(".localhost")) return false;
    return true;
  } catch {
    return false;
  }
}

async function readCache() {
  const { [CACHE_KEY]: cache = {} } = await chrome.storage.local.get(CACHE_KEY);
  return cache;
}

async function getCached(url) {
  const cache = await readCache();
  const entry = cache[url];
  if (entry && Date.now() - entry.ts < CACHE_TTL_MS) return entry.result;
  return null;
}

async function putCached(url, result) {
  const cache = await readCache();
  const now = Date.now();
  for (const k of Object.keys(cache)) if (now - cache[k].ts >= CACHE_TTL_MS) delete cache[k];
  cache[url] = { ts: now, result };
  await chrome.storage.local.set({ [CACHE_KEY]: cache });
}

async function scanUrl(url, { deep = false, force = false } = {}) {
  if (!force) {
    const cached = await getCached(url);
    if (cached && (!deep || cached._deep)) return cached;
  }
  const settings = await pgGetSettings();
  const res = await fetch(`${pgTrimSlash(settings.backendUrl)}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, deep, source: "extension" }),
  });
  if (!res.ok) {
    let msg = `Backend returned ${res.status}`;
    try {
      const body = await res.json();
      if (body && body.detail) msg += `: ${typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)}`;
    } catch { /* ignore */ }
    throw new Error(msg);
  }
  const result = await res.json();
  result._deep = deep;
  await putCached(url, result);
  return result;
}

async function setBadge(tabId, result) {
  try {
    if (!result) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    const color = PG_COLORS[result.verdict] || PG_COLORS.unknown;
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
    if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
    await chrome.action.setBadgeText({ tabId, text: String(Math.round(result.risk_score ?? 0)) });
    await chrome.action.setTitle({
      tabId,
      title: `PhishGuard: ${result.verdict} (risk ${Math.round(result.risk_score ?? 0)})`,
    });
  } catch {
    /* tab may have closed */
  }
}

async function setBadgeError(tabId) {
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: PG_COLORS.unknown });
    await chrome.action.setBadgeText({ tabId, text: "!" });
    await chrome.action.setTitle({ tabId, title: "PhishGuard: backend unreachable" });
  } catch { /* ignore */ }
}

function notifyPhishing(result, url) {
  if (notifiedUrls.has(url)) return;
  notifiedUrls.add(url);
  const brand = result.brand && result.brand.impersonated_brand;
  chrome.notifications.create(`pg-${result.id}`, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon128.png"),
    title: "PhishGuard: phishing detected",
    message:
      `${result.domain || url} scored ${Math.round(result.risk_score)}/100.` +
      (brand ? ` Possible ${brand} impersonation.` : "") +
      " Click for the full report.",
    priority: 2,
    requireInteraction: true,
  });
}

async function injectBanner(tabId, result) {
  const settings = await pgGetSettings();
  if (!settings.warningBanner) return;
  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content/banner.js"] });
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (data) => window.__phishguardShowBanner && window.__phishguardShowBanner(data),
      args: [{
        risk: Math.round(result.risk_score ?? 0),
        brand: (result.brand && result.brand.impersonated_brand) || null,
        reportUrl: pgReportUrl(settings, result.id),
      }],
    });
  } catch (e) {
    // Missing optional <all_urls> permission or restricted page: silently skip.
    console.debug("PhishGuard banner injection skipped:", e && e.message);
  }
}

async function handleResult(tabId, url, result) {
  await setBadge(tabId, result);
  if (result.verdict === "phishing") {
    notifyPhishing(result, url);
    if (tabId != null) await injectBanner(tabId, result);
  }
}

// ---------- auto-scan on navigation ----------
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url) return;
  if (!isScannable(tab.url)) {
    setBadge(tabId, null);
    return;
  }
  const settings = await pgGetSettings();
  if (!settings.autoScan) return;
  try {
    const result = await scanUrl(tab.url, { deep: false });
    await handleResult(tabId, tab.url, result);
  } catch (e) {
    console.debug("PhishGuard auto-scan failed:", e && e.message);
    await setBadgeError(tabId);
  }
});

// ---------- context menu ----------
function createMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: MENU_ID,
      title: "Scan link with PhishGuard",
      contexts: ["link"],
    });
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  createMenus();
  // Fill in any missing defaults without overwriting user settings.
  const current = await chrome.storage.sync.get(null);
  const missing = {};
  for (const [k, v] of Object.entries(PG_DEFAULTS)) if (!(k in current)) missing[k] = v;
  if (Object.keys(missing).length) await chrome.storage.sync.set(missing);
});
chrome.runtime.onStartup.addListener(createMenus);

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== MENU_ID || !info.linkUrl) return;
  const settings = await pgGetSettings();
  try {
    const result = await scanUrl(info.linkUrl, { deep: true });
    const brand = result.brand && result.brand.impersonated_brand;
    chrome.notifications.create(`pg-${result.id}`, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: `PhishGuard: ${result.verdict} (risk ${Math.round(result.risk_score)})`,
      message: `${info.linkUrl}${brand ? `\nImpersonates: ${brand}` : ""}\nClick for the full report.`,
      priority: result.verdict === "phishing" ? 2 : 0,
    });
  } catch (e) {
    chrome.notifications.create({
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title: "PhishGuard: scan failed",
      message: `${e.message}. Is the backend running at ${settings.backendUrl}?`,
    });
  }
});

chrome.notifications.onClicked.addListener(async (notificationId) => {
  if (!notificationId.startsWith("pg-")) return;
  const settings = await pgGetSettings();
  chrome.tabs.create({ url: pgReportUrl(settings, notificationId.slice(3)) });
  chrome.notifications.clear(notificationId);
});

// ---------- popup messaging ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg !== "object") return false;
  if (msg.type === "getCached") {
    getCached(msg.url).then((result) => sendResponse({ ok: true, result }));
    return true;
  }
  if (msg.type === "scan") {
    scanUrl(msg.url, { deep: !!msg.deep, force: !!msg.force })
      .then(async (result) => {
        if (msg.tabId != null) await handleResult(msg.tabId, msg.url, result);
        sendResponse({ ok: true, result });
      })
      .catch((e) => sendResponse({ ok: false, error: e.message || String(e) }));
    return true;
  }
  return false;
});
