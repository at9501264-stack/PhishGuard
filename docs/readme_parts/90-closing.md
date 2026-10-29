## ⚠️ Limitations & ethics

- **Educational prototype.** PhishGuard was built as a B.Tech mini project and the live site runs on demo data. It gives a preliminary assessment, it is **not a replacement for professional security products**, and its verdicts can be wrong in both directions.
- **The ML model reads only the URL string.** It uses lexical features, so a phishing page on a clean-looking URL (especially on a large trusted platform) can slip through, and an unusual legitimate URL can be flagged. On the held-out realistic set (unseen phishing campaigns and less-popular legitimate sites), the Random Forest on its own catches 84.7% of phishing URLs (it misses about 15%) and flags 11.9% of legitimate deep links, before the live checks and the popularity caps are applied.
- **Live checks depend on third parties.** WHOIS/RDAP, GeoIP, DNS blocklists and feed downloads can rate-limit, time out or be unreachable. A failed lookup is shown as an `error` check and counted in the scan's `coverage` figures (`checks_errored`); it never crashes the scan.
- **Demo-mode limits on Vercel.** Data added on the live site resets when the serverless function restarts, watchlist checks run once a day through Vercel Cron, and some network lookups behave differently from a local run.
- **Safe by design, but use it responsibly.** The scanner refuses private, loopback, link-local and other non-public addresses (SSRF guard, re-checked on every redirect) and only connects on ports 80, 443, 8080 and 8443. PhishGuard fetches suspicious pages from the server so you never need to open them in your own browser, and you should not. Only scan sites you are allowed to check.
- **Third-party terms.** The threat feeds and datasets are used under their own licences and terms (several are free for non-commercial use only).
- **No accounts.** The demo has no user accounts, login or rate limiting, so do not expose a local instance to the internet as-is.

## 🔭 Future scope

The synopsis listed these directions; the table shows what this version already covers and what is left.

| Direction (from the synopsis) | Status in this version | Next step |
|---|---|---|
| **Browser extension** for real-time URL checking | ✅ Chrome Manifest V3 extension (auto quick-scan, badge, context menu, popup deep scan) | Firefox/Edge builds, inline warnings on links inside web-mail pages |
| **Web-page content and HTML analysis** | ✅ HTTP and content checks, page category, language, resources, trackers, stored HTML | Visual similarity of the rendered page to the brand it imitates, analysis of JavaScript-heavy phishing kits |
| **Larger, continuously updated datasets** | 🟡 About 146k labelled URLs from five sources; feeds can be refreshed from the Threat Feeds page | Scheduled retraining on fresh feed data, drift monitoring of the model |
| **Advanced ML and deep learning** | ⏳ Four classical models (LR, DT, RF, SVM) on lexical features | Character-level CNN/LSTM or transformer URL models, gradient boosting, combining URL and page-content features in one model |
| **Mobile application** | 🟡 The dashboard is responsive and works on phones | A native Android/iOS app with share-sheet scanning of links from SMS and messengers |
| **Threat-intelligence integration** | ✅ Five local feeds, DNS blocklists, optional Google Safe Browsing / VirusTotal keys | More sources (for example abuse.ch ThreatFox), sharing confirmed community reports back to public feeds |

## 🙏 Credits

| | |
|---|---|
| **Student** | Ayushi Tiwari, B.Tech Computer Science & Engineering |
| **Project guide** | Mr. Vishal Gupta, Department of Computer Science & Engineering |
| **Institute** | Lloyd Institute of Engineering & Technology, Greater Noida, Uttar Pradesh |
| **University** | Dr. A.P.J. Abdul Kalam Technical University (AKTU), Lucknow |

**Datasets and threat intelligence:** [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI Machine Learning Repository) · [Tranco](https://tranco-list.eu/) top-sites ranking · [PhishTank](https://phishtank.org/) · [OpenPhish](https://openphish.com/) · [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) · [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) · [Phishing Army](https://phishing.army/) · DNS blocklists from Spamhaus, SURBL, URIBL and SpamCop · GeoIP from ip-api.com and ipwho.is.

**Key libraries:** [FastAPI](https://fastapi.tiangolo.com/), Uvicorn, Pydantic, [scikit-learn](https://scikit-learn.org/), pandas, NumPy, joblib, httpx, dnspython, python-whois, tldextract, Beautiful Soup, langdetect and mmh3 on the backend; [React](https://react.dev/), [Vite](https://vite.dev/), TypeScript, [Tailwind CSS](https://tailwindcss.com/), Recharts, TanStack Query, React Router, d3-force, lucide-react and jsQR on the frontend; Playwright and FFmpeg for the screenshots and the demo video; [Mermaid](https://mermaid.js.org/) for the diagrams.

**Feature research:** VirusTotal, urlscan.io, Google Safe Browsing, PhishTank, OpenPhish, URLVoid, CheckPhish, Sucuri SiteCheck, ScamAdviser, IPQualityScore, Norton Safe Web and Cisco Talos were studied for ideas. PhishGuard is not affiliated with any of them.

**References from the synopsis:** Ma et al., "Beyond Blacklists: Learning to Detect Malicious Web Sites from Suspicious URLs" (KDD 2009); Le et al., "URLNet: Learning a URL Representation with Deep Learning for Malicious URL Detection" (2018); Sahingoz et al., "Machine Learning Based Phishing Detection from URLs" (Expert Systems with Applications, 2019); Géron, *Hands-On Machine Learning*; Bishop, *Pattern Recognition and Machine Learning*; Han, Kamber and Pei, *Data Mining: Concepts and Techniques*.

No open-source licence has been chosen yet, so all rights are reserved by the author; the third-party datasets and feeds keep their own licences and terms of use.

---

<div align="center">

🎓 **PhishGuard is an educational prototype built for a B.Tech mini project. Use its verdicts as guidance, not as a guarantee.**

</div>
