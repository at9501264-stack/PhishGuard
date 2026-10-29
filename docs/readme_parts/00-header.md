<div align="center">

# 🛡️ PhishGuard

**AI-Based Phishing Website Detection and Risk Analysis System Using Machine Learning**

*Paste any link and get a 0-100 risk score you can trace back to its causes.*

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React 19 + TypeScript](https://img.shields.io/badge/React%2019-TypeScript-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.9-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Deployed on Vercel](https://img.shields.io/badge/Deployed%20on-Vercel-000000?logo=vercel&logoColor=white)](https://phishguard-mini-project.vercel.app)

[**🌐 Live demo**](https://phishguard-mini-project.vercel.app) · [**🎬 Demo video**](#-demo-video) · [**📘 API docs**](https://phishguard-mini-project.vercel.app/docs) · [**🏗️ Architecture**](#-architecture)

</div>

PhishGuard tells you whether a website is likely to be a phishing site, and why. It reads the URL with four trained machine-learning models (Logistic Regression, Decision Tree, Random Forest and SVM, with the best one, Random Forest, driving the score). At the same time it runs 50+ live checks on the domain, the certificate, the page and local threat-intelligence feeds, and it combines everything into a **0-100 risk score** with a **Legitimate / Suspicious / Phishing** verdict and the reasons behind it. A React dashboard, a documented REST API and a Chrome extension all use the same engine. The dashboard adds analytics, a model-comparison lab, monitoring and community reporting.

> 🎓 **B.Tech mini project** by **Ayushi Tiwari**, under the guidance of **Mr. Vishal Gupta**. Department of Computer Science & Engineering, Lloyd Institute of Engineering & Technology, Greater Noida. Affiliated to Dr. A.P.J. Abdul Kalam Technical University (AKTU), Lucknow.

> [!NOTE]
> The live demo runs in **demo mode** on a bundled snapshot of demo data. Anything you add (scans, reports, watchlist items) is reset when the serverless function restarts, and watchlist checks run once a day through a Vercel Cron job. Run it locally for the full experience.

<!-- TOC -->
