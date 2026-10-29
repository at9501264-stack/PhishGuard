/* PhishGuard options page */
const $ = (id) => document.getElementById(id);
const ALL_URLS = { origins: ["<all_urls>"] };

function setMsg(text, kind = "") {
  $("msg").textContent = text;
  $("msg").className = `msg ${kind}`;
}

async function load() {
  const s = await pgGetSettings();
  $("backendUrl").value = s.backendUrl;
  $("dashboardUrl").value = s.dashboardUrl;
  $("autoScan").checked = !!s.autoScan;
  $("warningBanner").checked = !!s.warningBanner;
}

// Permission requests must happen in the user gesture, so ask as soon as the box is ticked.
$("warningBanner").addEventListener("change", async (e) => {
  if (!e.target.checked) return;
  const granted = await chrome.permissions.request(ALL_URLS);
  if (!granted) {
    e.target.checked = false;
    setMsg("Banner needs access to all sites; permission was not granted.", "err");
  }
});

async function ensureOriginPermission(url) {
  // A non-default backend host needs its own host permission (the default localhost:8000 is in the manifest).
  try {
    const origin = `${new URL(url).origin}/*`;
    // request() resolves immediately when already granted; called first so the user gesture is intact.
    await chrome.permissions.request({ origins: [origin] });
  } catch { /* invalid URL handled by form validation */ }
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const backendUrl = pgTrimSlash($("backendUrl").value.trim()) || PG_DEFAULTS.backendUrl;
  const dashboardUrl = pgTrimSlash($("dashboardUrl").value.trim()) || PG_DEFAULTS.dashboardUrl;
  await ensureOriginPermission(backendUrl);
  await chrome.storage.sync.set({
    backendUrl,
    dashboardUrl,
    autoScan: $("autoScan").checked,
    warningBanner: $("warningBanner").checked,
  });
  setMsg("Saved.", "ok");
});

$("testBtn").addEventListener("click", async () => {
  const base = pgTrimSlash($("backendUrl").value.trim()) || PG_DEFAULTS.backendUrl;
  setMsg("Checking...");
  try {
    const res = await fetch(`${base}/api/health`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const h = await res.json();
    setMsg(`Connected: ${h.status}${h.model_version ? `, model ${h.model_version}` : ""}`, "ok");
  } catch (err) {
    setMsg(`Cannot reach ${base} (${err.message})`, "err");
  }
});

load();
