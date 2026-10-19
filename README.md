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

**Daily SEO check** (`seo_check.py`, part of the full run; adapted from setaside-safety-check): titles, meta
descriptions, canonicals, exactly one H1, robots.txt, sitemap (valid XML, right host, every language has the same page
count), unexpected noindex, JSON-LD validity, image alt text, Open Graph, viewport, `lang`, hreflang reciprocity on 9
language pages that rotate daily (not all 1,692 URLs), broken internal links (up to 120), and a real 404 for a missing
URL. Requests go one at a time, 1.5 s apart, and the run stops at the first 403 (reported as a warning: bot-blocked,
check incomplete). Any FAIL fails the run with an `SEO_ALERT` summary; length and heading-order notes are warnings.
AEO checks in the same run: FAQPage JSON-LD must equal the visible FAQ text (key pages plus one rotating language copy),
Article JSON-LD on blog posts (headline, datePublished, dateModified, author "DownPayment Desk"), `/llms.txt` present,
AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot, ...) allowed exactly like `User-agent: *`,
visible "Updated" dates within their windows (rates 10 days, daily pages 3 days, ZHVI month 80 days) and an
official-source citation on each key page.
Manual: `python3 seo_check.py` (target from `config.json`).

**Output:** the run summary (starts with `SAFETY_ALERT` on failure) and `status.json` on the `status` branch.
After an approved site change, refresh the expected structure with `python3 check.py baseline`.
