/* PhishGuard warning banner. Injected on demand by the background worker. */
(() => {
  if (window.__phishguardShowBanner) return;
  window.__phishguardShowBanner = (data) => {
    if (document.getElementById("phishguard-warning-banner")) return;
    const host = document.createElement("div");
    host.id = "phishguard-warning-banner";
    host.style.cssText = "all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    const brand = data.brand ? ` It may be impersonating <b></b>.` : "";
    root.innerHTML = `
      <style>
        .bar{font:14px/1.4 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
          background:#e11d48;color:#fff;display:flex;align-items:center;gap:12px;
          padding:10px 16px;box-shadow:0 2px 10px rgba(0,0,0,.25)}
        .msg{flex:1}
        a{color:#fff;font-weight:600;text-decoration:underline;white-space:nowrap}
        button{all:unset;cursor:pointer;font-size:18px;line-height:1;padding:2px 6px;border-radius:4px}
        button:hover{background:rgba(255,255,255,.2)}
      </style>
      <div class="bar" role="alert">
        <span>&#9888;</span>
        <span class="msg"><b>PhishGuard warning:</b> this page looks like phishing
          (risk <span class="risk"></span>/100).${brand} Do not enter passwords or payment details.</span>
        <a target="_blank" rel="noopener">View report</a>
        <button aria-label="Dismiss" title="Dismiss">&times;</button>
      </div>`;
    root.querySelector(".risk").textContent = String(data.risk);
    if (data.brand) root.querySelector(".msg b:last-of-type").textContent = data.brand;
    root.querySelector("a").href = data.reportUrl;
    root.querySelector("button").addEventListener("click", () => host.remove());
    (document.body || document.documentElement).appendChild(host);
  };
})();
