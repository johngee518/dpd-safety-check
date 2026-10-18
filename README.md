# DownPayment Desk safety checker

Automated, $0 safety check for the public site https://downpaymentdesk.pages.dev.
Python standard library only, no dependencies. It only reads the public live site; no site code or data lives here.

**Target:** `config.json` → `site_base` (one change to switch domains; then run `python3 check.py baseline`).

**Schedule:** about hourly. Cron fires at :11/:26/:41/:56 and a gate skips the run if a check finished in the last 40 minutes, because GitHub drops many scheduled runs. The first run after 14:00 UTC (or any run when the last full check is over 26 h old) is the daily full run (adds outbound links).
Manual run: Actions → DownPayment Desk safety check → Run workflow.

**Quick checks:** site up; TLS valid and more than 14 days from expiry; HTTP redirects to HTTPS; security headers
(CSP, HSTS, X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy); every
sitemap page returns 200 with no injected external scripts, iframes, object tags, meta refreshes or unknown external
domains; key pages' title/heading/navigation skeleton matches `baseline.json` (numbers and dates are ignored, so normal
data refreshes don't trigger alerts); Google Safe Browsing (keyless Transparency Report lookup, plus the official API
when the optional `SAFE_BROWSING_KEY` secret is set).

**Daily full check:** every outbound link (state housing agencies, statutes, consumer resources). Broken links fail;
redirects to a different domain or parked/for-sale pages fail as possible hijacks (known official moves are listed in
`baseline.json`). Bot-blocked links (403/429/5xx) are warnings.

**Output:** the run summary (starts with `SAFETY_ALERT` on failure) and `status.json` on the `status` branch.
After an approved site change, refresh the expected structure with `python3 check.py baseline`.
