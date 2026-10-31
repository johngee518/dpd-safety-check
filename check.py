#!/usr/bin/env python3
"""DownPayment Desk public safety checker (target: config.json site_base). Python standard library only; looks only at the PUBLIC live site.

quick (hourly): site up, TLS valid >14 days, HTTP->HTTPS, security headers (CSP, HSTS, X-Frame-Options/frame-ancestors,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy), every sitemap page 200 and free of injected external
  scripts / iframes / object tags / unknown external domains, key-page title/h1/nav skeleton vs baseline.json
  (numbers and month names ignored, so normal data refreshes never alarm), Google Safe Browsing.
full (daily, 14:41 UTC): quick + every outbound link except Amazon Associates and CJ click domains (broken; redirect to another domain or parked page = possible hijack;
  403/429/5xx bot-blocks = warnings).
Exit 1 on any failure; Markdown summary -> $GITHUB_STEP_SUMMARY (first line SAFETY_ALERT on failure); JSON -> status.json.
Nothing here is secret: the only optional secret (SAFE_BROWSING_KEY) is never printed or written."""
from __future__ import annotations
import concurrent.futures as cf, hashlib, json, os, re, socket, ssl, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = (os.environ.get("SITE_BASE") or json.load(open(os.path.join(HERE, "config.json")))["site_base"]).rstrip("/")  # target lives in config.json
HOST = urllib.parse.urlparse(BASE).hostname
BASELINE_PATH = os.path.join(HERE, "baseline.json")
BASELINE = json.load(open(BASELINE_PATH)) if os.path.exists(BASELINE_PATH) else {"key_pages": {}}
ALLOWED_INLINE_HASHES = {"sha256-ECYsGc1sgmddihTzieo6EunLK0YzxopjbLsr+9GdTOw=", "sha256-Ni/TnjU4ve2ecbpdortoKdeVRg4rt+KrYzktKoUuX0g="}  # DPD intentional inline scripts (tip-off, compact-nav check)
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36 DPD-safety-check"
MODE = (sys.argv[1] if len(sys.argv) > 1 else "quick").lower()
REQUIRED_HEADERS = ["content-security-policy", "strict-transport-security", "x-content-type-options",
                    "referrer-policy", "permissions-policy"]
ALLOWED_SCRIPT_HOSTS = set(BASELINE.get("allowed_script_hosts", []))
ALLOWED_SCRIPT_SUFFIX = tuple(BASELINE.get("allowed_script_suffixes", []))
KNOWN_DOMAINS = set(BASELINE.get("external_domains", [])) | set(BASELINE.get("preapproved_domains", []))  # preapproved = official sources cited in queued blog posts (kept across baseline regens)
REDIRECT_ALLOW = BASELINE.get("redirect_allow", {})
PARKED = re.compile(r"domain (is|may be) for sale|buy this domain|this domain is parked|parked free|domain parking|hugedomains|sedo\.com/search", re.I)
SB_KEY = os.environ.get("SAFE_BROWSING_KEY", "").strip()
results: list[dict] = []


def clean(s: str) -> str:
    return s.replace(SB_KEY, "***") if SB_KEY else s


def add(check, status, detail=""):
    results.append({"check": check, "status": status, "detail": clean(str(detail))[:400]})
    print(f"[{status}] {check}: {clean(str(detail))}"[:300])


def get(url, timeout=20, follow=True, maxbytes=3_000_000, tries=2):
    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    last = None
    for i in range(tries):
        try:
            op = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedir)
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.8"})
            with op.open(req, timeout=timeout) as r:
                return r.status, r.geturl(), {k.lower(): v for k, v in r.headers.items()}, r.read(maxbytes).decode("utf-8", "replace"), None
        except urllib.error.HTTPError as e:
            res = (e.code, e.geturl() or url, {k.lower(): v for k, v in (e.headers or {}).items()}, "", None)
            if e.code < 500 and e.code != 429: return res
            last = res
        except Exception as e:
            last = (0, url, {}, "", f"{type(e).__name__}: {str(e)[:120]}")
        time.sleep(2)
    return last


# ---------- page skeleton ----------
class Skel(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts_ext, self.iframes, self.domains, self.inline_hosts = set(), set(), set(), set()
        self.inline_scripts = self.objects = 0; self.meta_refresh = []; self.links = set()
        self.title = self.h1 = ""; self.nav = []; self._in = None; self._buf = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        for k in ("href", "src", "action", "data", "formaction"):
            v = a.get(k) or ""
            if v.startswith(("http://", "https://", "//")):
                u = v if not v.startswith("//") else "https:" + v
                h = (urllib.parse.urlparse(u).hostname or "").lower()
                if h and h != HOST:
                    self.domains.add(h)
                    if tag == "a" and h != "schema.org": self.links.add(u.split("#")[0])
        if tag == "script":
            if a.get("src"):
                if a["src"].startswith(("http://", "https://", "//")): self.scripts_ext.add(a["src"])
            elif (a.get("type") or "").lower() != "application/ld+json":
                self.inline_scripts += 1; self._in, self._buf = "script", []
        elif tag in ("iframe", "frame"): self.iframes.add(a.get("src") or "(no src)")
        elif tag in ("object", "embed"): self.objects += 1
        elif tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh": self.meta_refresh.append(a.get("content") or "")
        elif tag in ("title", "h1") and not getattr(self, tag): self._in, self._buf = tag, []
        elif tag == "a" and "l" in (a.get("class") or "").split(): self.nav.append(a.get("href") or "")
    def handle_data(self, d):
        if self._in: self._buf.append(d)
    def handle_endtag(self, tag):
        if self._in and tag == self._in:
            t = "".join(self._buf)
            if tag == "script":
                import base64
                # skel() escapes bare "&" before parsing, so also hash the un-escaped script text
                if any("sha256-" + base64.b64encode(hashlib.sha256(x.encode()).digest()).decode() in ALLOWED_INLINE_HASHES for x in (t, t.replace("&amp;", "&"))):
                    self.inline_scripts -= 1; self._in = None; return
                self.inline_hosts |= {h.lower() for h in re.findall(r"https?://([a-zA-Z0-9.-]+)", t) if h.lower() != HOST}
            else: setattr(self, tag, t)
            self._in = None


def norm(s):
    s = re.sub(r"\d[\d,.:%$]*", "#", s)
    s = re.sub(r"(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b", "MON", s)
    return re.sub(r"\s+", " ", s).strip().lower()


BARE_AMP = re.compile(r"&(?![a-zA-Z][a-zA-Z0-9]*;|#[0-9]+;|#[xX][0-9a-fA-F]+;)")


def skel(html):
    # Browsers leave a bare "&name" in attribute values alone (e.g. "?a=1&sectionNum=2"); Python would turn it into "§ionNum".
    p = Skel(); p.feed(BARE_AMP.sub("&amp;", html))
    sk = "|".join([norm(p.title), norm(p.h1), ",".join(p.nav)])
    return p, hashlib.sha256(sk.encode()).hexdigest()[:16], sk


# ---------- checks ----------
def check_tls():
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((HOST, 443), timeout=15) as s, ctx.wrap_socket(s, server_hostname=HOST) as t:
            cert = t.getpeercert()
        exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        add("tls", "FAIL" if days <= 14 else "PASS", f"valid, expires {exp:%Y-%m-%d} ({days} days)")
    except Exception as e:
        add("tls", "FAIL", f"TLS handshake/validation failed: {type(e).__name__}: {str(e)[:120]}")


def check_headers(h, where):
    csp = h.get("content-security-policy", "")
    missing = [x for x in REQUIRED_HEADERS if not h.get(x)]
    if not h.get("x-frame-options") and "frame-ancestors" not in csp: missing.append("x-frame-options|frame-ancestors")
    probs = []
    m = re.search(r"max-age=(\d+)", h.get("strict-transport-security", ""))
    if h.get("strict-transport-security") and (not m or int(m.group(1)) < 15552000): probs.append("HSTS max-age < 180 days")
    if re.search(r"(?<!wasm-)'unsafe-eval'", csp): probs.append("CSP allows unsafe-eval")  # 'wasm-unsafe-eval' (WebAssembly only, Pagefind search) is fine
    if csp and "api.gold-api.com" not in csp: probs.append("CSP changed: no longer allows gold-api (metals would break)")
    if missing or probs: add(f"headers {where}", "FAIL", "; ".join((["missing: " + ", ".join(missing)] if missing else []) + probs))
    else: add(f"headers {where}", "PASS", "CSP, HSTS, frame protection, nosniff, Referrer-Policy, Permissions-Policy present")


def check_http_redirect():
    s, _, h, _, err = get(f"http://{HOST}/", follow=False, tries=1)
    loc = h.get("location", "")
    if s in (301, 302, 307, 308) and loc.startswith("https://"): add("http->https", "PASS", f"{s} to HTTPS")
    elif not s: add("http->https", "WARN", f"port 80 unreachable from this runner ({err}); HSTS still forces HTTPS")
    else: add("http->https", "FAIL", f"http:// does not redirect to HTTPS (status {s}, location {loc[:80]!r})")


LANG_RE = re.compile(r"^/(es|fr|pt|de|zh|ja|ko|vi|hi)/")  # translated copies of English pages: only the KEY_PAGES ones are fetched


def site_paths(body):
    """Sitemap paths minus language copies (they mirror English pages; a few language KEY_PAGES are checked instead)."""
    return sorted({p for p in (urllib.parse.urlparse(u).path or "/" for u in re.findall(r"<loc>([^<]+)</loc>", body)) if not LANG_RE.match(p)})


def sitemap_paths():
    s, _, _, body, err = get(BASE + "/sitemap.xml")
    if s != 200:
        add("sitemap", "FAIL", f"sitemap.xml returned {s or err}"); return []
    paths = site_paths(body)
    add("sitemap", "PASS" if len(paths) >= BASELINE.get("min_sitemap_pages", 1) else "FAIL", f"{len(paths)} pages listed")
    return paths


def page_check(path):
    s, final, h, body, err = get(BASE + path)
    out = {"path": path, "status": s, "headers": h, "issues": [], "links": set()}
    if s != 200: out["issues"].append(f"HTTP {s or err}"); return out
    if urllib.parse.urlparse(final).hostname != HOST: out["issues"].append(f"redirected off-site to {final}"); return out
    p, hsh, sk = skel(body)
    out["links"] = p.links
    ref = BASELINE["key_pages"].get(path)
    for src in p.scripts_ext:
        sh = (urllib.parse.urlparse(src if not src.startswith("//") else "https:" + src).hostname or "").lower()
        if sh not in ALLOWED_SCRIPT_HOSTS and not sh.endswith(ALLOWED_SCRIPT_SUFFIX): out["issues"].append(f"injected external script {src}")
    if p.iframes: out["issues"].append(f"unexpected iframe(s) {sorted(p.iframes)[:3]}")
    if p.objects: out["issues"].append("object/embed tag")
    if p.meta_refresh: out["issues"].append(f"meta refresh {p.meta_refresh[:2]}")
    new = (p.domains | p.inline_hosts) - KNOWN_DOMAINS
    if new: out["issues"].append(f"unknown external domains {sorted(new)[:5]}")
    if ref:
        if p.inline_scripts > ref["inline_scripts"]: out["issues"].append(f"inline scripts {ref['inline_scripts']}->{p.inline_scripts}")
        if hsh != ref["skeleton_hash"]: out["issues"].append(f"title/h1/nav changed: '{sk[:140]}' (expected '{ref['skeleton'][:140]}')")
    return out


def check_pages():
    st, final, h, body, err = get(BASE + "/")
    add("site up", "PASS" if st == 200 and len(body) > 500 else "FAIL", f"HTTP {st or err}, {len(body)} bytes")
    if st == 200: check_headers(h, "/")
    paths = sorted(set(sitemap_paths()) | set(BASELINE["key_pages"]))
    with cf.ThreadPoolExecutor(8) as ex:
        res = list(ex.map(page_check, paths))
    bad = [r for r in res if r["issues"]]
    for r in bad: add(f"page {r['path']}", "FAIL", "; ".join(r["issues"]))
    for r in res:
        if r["path"] in ("/rates/", "/sponsor/") and r["status"] == 200: check_headers(r["headers"], r["path"])
    add("pages", "FAIL" if bad else "PASS", f"{len(res)} pages checked: {len(res)-len(bad)} clean, {len(bad)} with problems")
    return set().union(*(r["links"] for r in res)) if res else set()


BOT_CHALLENGE = {"perfdrive.com"}  # bot-protection challenge hosts (Radware validate.perfdrive.com): a bot-block like 403, not a hijack


def regdom(h):
    parts = (h or "").lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "ac", "net") and len(parts[-1]) == 2: return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def link_check(u):
    s, final, h, body, err = get(u, maxbytes=60000)
    h0, h1 = urllib.parse.urlparse(u).hostname or "", urllib.parse.urlparse(final).hostname or ""
    if s and h1 and regdom(h0) != regdom(h1):
        if regdom(h1) in [regdom(x) for x in REDIRECT_ALLOW.get(h0, [])]: return "PASS", f"{u} -> {final} (known official move)"
        if regdom(h1) in BOT_CHALLENGE: return "WARN", f"{u} sent this runner to a bot challenge ({h1}); bot-block, not a hijack"
        return "FAIL", f"{u} redirects to a different domain {final} (possible hijack)"
    if s == 200 and PARKED.search(body or ""): return "FAIL", f"{u} looks like a parked/for-sale page (possible hijack)"
    if 200 <= (s or 0) < 400: return "PASS", u
    if s in (401, 403, 405, 406, 429) or (s or 0) >= 500: return "WARN", f"{u} HTTP {s} (bot-block or server error)"
    if not s:
        if re.search(r"(?i)name or service not known|getaddrinfo|no address|nodename", err or ""): return "FAIL", f"{u} DNS does not resolve (domain may have lapsed)"
        return "WARN", f"{u} unreachable ({err})"
    return "FAIL", f"{u} HTTP {s} (broken)"



# Amazon Associates + CJ click domains (John via Charles, 2026-10-30): never fetch/test-click these affiliate URLs.
SKIP_OUTBOUND_HOST_SUFFIXES = (
    "amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.fr", "amazon.co.jp", "amzn.to", "amzn.com",
    "jdoqocy.com", "dpbolvw.net", "tkqlhce.com", "anrdoezrs.net", "ftjcfx.com", "qksrv.net",
)


def skip_outbound(u: str) -> bool:
    h = (urllib.parse.urlparse(u).hostname or "").lower()
    if not h:
        return False
    return any(h == s or h.endswith("." + s) for s in SKIP_OUTBOUND_HOST_SUFFIXES)


def check_links(links):
    skipped = sorted(u for u in links if skip_outbound(u))
    links = {u for u in links if not skip_outbound(u)}
    if skipped:
        add("outbound links (affiliate skipped)", "PASS", f"skipped {len(skipped)} Amazon/CJ affiliate URL(s); never fetched")
    if not links: add("outbound links", "WARN", "no outbound links found"); return
    c = {"PASS": 0, "WARN": 0, "FAIL": 0}
    with cf.ThreadPoolExecutor(12) as ex:
        for st, d in ex.map(link_check, sorted(links)):
            c[st] += 1
            if st != "PASS": add("link", st, d)
    add("outbound links", "FAIL" if c["FAIL"] else "PASS", f"{len(links)} unique: {c['PASS']} ok, {c['WARN']} warn, {c['FAIL']} fail")


SB_TEXT = {1: "no unsafe content found", 2: "UNSAFE", 3: "SOME PAGES UNSAFE", 4: "no site-level verdict",
           5: "hosts uncommon downloads", 6: "no data yet (normal for a new site)"}


def check_safe_browsing():
    if SB_KEY:  # official Safe Browsing v4 Lookup API
        body = json.dumps({"client": {"clientId": "dpd-safety-check", "clientVersion": "1.0"},
                           "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                                          "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                          "threatEntries": [{"url": BASE + p} for p in ("/", "/rates/", "/homes/", "/sponsor/")]}}).encode()
        req = urllib.request.Request("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + urllib.parse.quote(SB_KEY),
                                     data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as r: m = json.loads(r.read() or b"{}").get("matches") or []
            add("safe browsing (API)", "FAIL" if m else "PASS", f"FLAGGED: {sorted({x.get('threatType') for x in m})}" if m else "not listed")
        except urllib.error.HTTPError as e: add("safe browsing (API)", "WARN", f"API error HTTP {e.code}")
        except Exception as e: add("safe browsing (API)", "WARN", f"API unreachable ({type(e).__name__})")
    else:
        add("safe browsing (API)", "WARN", "SAFE_BROWSING_KEY secret not set; official API skipped (keyless lookup below still runs)")
    s, _, _, body, err = get("https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=" + urllib.parse.quote(HOST))
    try:
        data = json.loads(body.split("\n", 1)[1].strip()) if body.startswith(")]}'") else json.loads(body)
        row = data[0]; code = row[1]; flags = row[2:7]
    except Exception:
        add("safe browsing (transparency report)", "WARN", f"lookup unavailable (status {s or err})"); return
    bad = code in (2, 3, 5) or any(f is True for f in flags)
    add("safe browsing (transparency report)", "FAIL" if bad else "PASS", SB_TEXT.get(code, str(code)))


KEY_PAGES = ["/", "/rates/", "/homes/", "/markets/", "/states/", "/tracker/", "/calculators/", "/down-payment-calculator/",
             "/how-long-to-save/", "/first-time-buyer-programs/", "/states/texas/", "/sponsor/", "/sponsor-terms/", "/blog/",
             "/es/", "/ja/", "/zh/tracker/", "/hi/states/texas/"]  # language copies (site i18n, docs/I18N.md in the site repo)


def make_baseline():
    """Run by hand (python3 check.py baseline) only right after a verified, approved deploy. Reads the public live site."""
    s, _, _, body, _ = get(BASE + "/sitemap.xml")
    paths = sorted(set(site_paths(body)) | set(KEY_PAGES))
    doms, kp = set(), {}
    for path in paths:
        st, _, _, html, _ = get(BASE + path)
        if st != 200: print("skip", path, st); continue
        p, hsh, sk = skel(html)
        doms |= p.domains | p.inline_hosts
        if path in KEY_PAGES: kp[path] = {"skeleton_hash": hsh, "skeleton": sk[:300], "inline_scripts": p.inline_scripts}
    old = BASELINE
    out = {"_note": "Expected public structure of the live site. Regenerate only after an approved deploy: python3 check.py baseline",
           "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "min_sitemap_pages": max(1, int(len(paths) * 0.8)),
           "allowed_script_hosts": old.get("allowed_script_hosts", ["f.convertkit.com"]),
           "allowed_script_suffixes": old.get("allowed_script_suffixes", [".kit.com"]),
           "redirect_allow": old.get("redirect_allow", {}), "preapproved_domains": old.get("preapproved_domains", []), "external_domains": sorted(doms), "key_pages": kp}
    json.dump(out, open(BASELINE_PATH, "w"), indent=1, sort_keys=True)
    print(f"baseline: {len(paths)} pages, {len(doms)} external domains, {len(kp)} key pages")
    return 0


def main():
    if MODE == "baseline": return make_baseline()
    check_tls(); check_http_redirect()
    links = check_pages()
    check_safe_browsing()
    if MODE == "full": check_links(links)
    fails = [r for r in results if r["status"] == "FAIL"]; warns = [r for r in results if r["status"] == "WARN"]
    status = "FAIL" if fails else ("WARN" if warns else "PASS")
    doc = {"site": BASE, "mode": MODE, "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "status": status, "fail_count": len(fails), "warn_count": len(warns),
           "run_url": f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}" if os.environ.get("GITHUB_RUN_ID") else None,
           "results": results}
    json.dump(doc, open(os.path.join(HERE, "status.json"), "w"), indent=1)
    lines = ([f"# SAFETY_ALERT: DownPayment Desk {MODE} safety check FAILED", "", f"{len(fails)} failure(s) at {doc['checked_at']}:"]
             + [f"- **{r['check']}**: {r['detail']}" for r in fails] + [""]) if fails else [f"# DownPayment Desk safety check ({MODE}): {status}", ""]
    if warns: lines += ["## Warnings"] + [f"- {r['check']}: {r['detail']}" for r in warns] + [""]
    lines += ["## All checks", "| check | status | detail |", "|---|---|---|"] + [f"| {r['check']} | {r['status']} | {r['detail'][:160].replace('|', '/')} |" for r in results]
    if os.environ.get("GITHUB_STEP_SUMMARY"): open(os.environ["GITHUB_STEP_SUMMARY"], "a").write(clean("\n".join(lines)) + "\n")
    print(f"\nSAFETY {MODE}: {status} ({len(fails)} fail, {len(warns)} warn)")
    if fails: print("SAFETY_ALERT")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
