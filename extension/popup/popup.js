/* PhishGuard popup */
const $ = (id) => document.getElementById(id);
let currentTab = null;

function showStatus(text, isError = false) {
  const el = $("status");
  el.hidden = !text;
  el.textContent = text || "";
  el.classList.toggle("error", isError);
}

function topFailedChecks(checks) {
  const rank = { fail: 0, warn: 1 };
  return (checks || [])
    .filter((c) => c.status === "fail" || c.status === "warn")
    .sort((a, b) => rank[a.status] - rank[b.status] || (b.weight || 0) - (a.weight || 0))
    .slice(0, 3);
}

async function render(result) {
  const settings = await pgGetSettings();
  const color = PG_COLORS[result.verdict] || PG_COLORS.unknown;
  const score = Math.max(0, Math.min(100, Math.round(result.risk_score ?? 0)));

  $("verdict").textContent = result.verdict || "unknown";
  $("verdict").style.background = color;
  $("confidence").textContent =
    result.confidence != null ? `${Math.round(result.confidence * 100)}%` : "-";
  $("score").textContent = score;
  $("score").style.color = color;
  $("barFill").style.width = `${score}%`;
  $("barFill").style.background = color;

  const brand = result.brand && result.brand.impersonated_brand;
  $("brandRow").hidden = !brand;
  $("brand").textContent = brand || "";

  const list = $("checks");
  list.replaceChildren();
  const failed = topFailedChecks(result.checks);
  if (!failed.length) {
    const li = document.createElement("li");
    li.className = "detail";
    li.textContent = "No failed checks.";
    list.appendChild(li);
  }
  for (const c of failed) {
    const li = document.createElement("li");
    const name = document.createElement("div");
    name.className = "name";
    const dot = document.createElement("span");
    dot.className = "dot";
    dot.style.background = c.status === "fail" ? PG_COLORS.phishing : PG_COLORS.suspicious;
    name.append(dot, document.createTextNode(c.name || c.id));
    const detail = document.createElement("div");
    detail.className = "detail";
    detail.textContent = c.detail || "";
    li.append(name, detail);
    list.appendChild(li);
  }

  $("reportLink").href = pgReportUrl(settings, result.id);
  $("result").hidden = false;
}

function isScannable(url) {
  return /^https?:\/\//i.test(url || "");
}

async function scan() {
  if (!currentTab) return;
  $("scanBtn").disabled = true;
  $("scanBtn").textContent = "Scanning...";
  showStatus("Running deep scan, this can take a few seconds...");
  try {
    const resp = await chrome.runtime.sendMessage({
      type: "scan", url: currentTab.url, tabId: currentTab.id, deep: true, force: true,
    });
    if (!resp || !resp.ok) throw new Error((resp && resp.error) || "Unknown error");
    showStatus("");
    await render(resp.result);
  } catch (e) {
    const settings = await pgGetSettings();
    showStatus(`Scan failed: ${e.message}. Is the backend running at ${settings.backendUrl}?`, true);
  } finally {
    $("scanBtn").disabled = false;
    $("scanBtn").textContent = "Scan this page";
  }
}

async function init() {
  $("optionsLink").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
  $("scanBtn").addEventListener("click", scan);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab || null;
  $("url").textContent = (tab && tab.url) || "-";
  $("url").title = (tab && tab.url) || "";

  if (!tab || !isScannable(tab.url)) {
    $("scanBtn").disabled = true;
    showStatus("Only http(s) pages can be scanned.");
    return;
  }
  const resp = await chrome.runtime.sendMessage({ type: "getCached", url: tab.url });
  if (resp && resp.result) await render(resp.result);
}

init();
