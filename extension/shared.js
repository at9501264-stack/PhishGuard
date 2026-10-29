// Shared helpers for background, popup and options (loaded via importScripts / <script>).
const PG_DEFAULTS = {
  backendUrl: "http://localhost:8000",
  dashboardUrl: "http://localhost:5173",
  autoScan: true,
  warningBanner: false,
};

const PG_COLORS = {
  legitimate: "#10b981", // emerald-500
  suspicious: "#f59e0b", // amber-500
  phishing: "#f43f5e",   // rose-500
  unknown: "#64748b",    // slate-500
};

function pgGetSettings() {
  return chrome.storage.sync.get(PG_DEFAULTS);
}

function pgTrimSlash(u) {
  return String(u || "").replace(/\/+$/, "");
}

function pgReportUrl(settings, id) {
  return `${pgTrimSlash(settings.dashboardUrl)}/scans/${encodeURIComponent(id)}`;
}
