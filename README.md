# Phishing URL and Website Analysis System
A Python + Flask educational cybersecurity project that applies explainable rule-based checks. It does **not** use machine learning.

## Features
- Premium responsive security dashboard with Chart.js visualizations (scan trend, risk distribution, signal categories)
- Awareness center with social-engineering topics and an interactive knowledge quiz
- URL syntax and indicator checks (IP URL, HTTP, punycode, shorteners, suspicious words, long URLs, subdomains, port)
- DNS public-address guard and basic live HTTP status/redirect inspection
- HTTPS certificate connection check
- Explainable risk score (Low / Medium / High / Critical)
- SQLite scan history
- Security awareness page

## Run locally
1. Install Python 3.10+
2. Open terminal in this project folder:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\\Scripts\\activate
   # macOS/Linux:
   source .venv/bin/activate
   pip install -r requirements.txt
   python app.py
   ```
3. Visit http://127.0.0.1:5000

## Important safety and limitations
- Use only on URLs you are authorized to assess.
- This is a student demonstration, not a production security product. A low score does not prove a site is safe, and a high score is not definitive proof of phishing.
- Live checks require internet access. DNS/private-IP checks and redirect checks are implemented, but no crawler, exploit, credential collection, or automated login is performed.
- Do not enter passwords or other secrets into websites during testing.
- Before deployment, add authentication, CSRF protection, rate limits, logging controls, stricter DNS rebinding defenses, and a hardened outbound request proxy.

## Project structure
```
app.py
templates/
  base.html
  index.html
  history.html
  awareness.html
static/style.css
requirements.txt
```

## Risk scoring
Indicators add weighted points; total is capped at 100. Thresholds:
- 0–19 Low
- 20–39 Medium
- 40–59 High
- 60–100 Critical

Weights are heuristic and should be documented, tested, and calibrated using a labeled test set for your project report.


## Dashboard chart troubleshooting
- The dashboard starts with zero scans, so the charts show an instructional empty state rather than a misleading blank canvas.
- After submitting a scan, the report is rendered immediately below the URL scanner and the page automatically scrolls to it. The pasted URL remains in the input for quick re-scanning.
- Chart.js is loaded from a CDN. If your browser blocks the CDN or has no internet access, the dashboard displays a visible chart-loading message instead of silently leaving empty chart panels.
