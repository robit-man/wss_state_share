#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTPS dev launcher (mkcert-first) for the Phone Twins demo.

What it does:
- Generates/uses a locally-trusted mkcert certificate for your LAN IP + localhost
- Starts the Node websocket server (server.js) behind HTTPS by patching Node's http module
  so http.createServer(...) becomes https.createServer(...)

This is adapted from the provided cross-platform HTTPS dev server that:
- bootstraps a venv and installs deps (cryptography),
- can patch Node to force TLS,
- prints a LAN banner, etc.
"""

import os
import sys
import subprocess
import json
import shutil
import threading
import itertools
import time
import socket
import ssl
import urllib.request
import signal
import atexit
import argparse
import hashlib
import platform
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ─── OS Flags ────────────────────────────────────────────────────────────────
IS_WINDOWS = (os.name == "nt")
IS_POSIX   = (os.name == "posix")
PLATFORM   = platform.system().lower()

# ─── Paths & Constants ───────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH  = os.path.join(SCRIPT_DIR, "config.json")
VENV_FLAG    = "--in-venv"
DEFAULT_VENV = os.path.join(SCRIPT_DIR, ".venv")
CERT_DIR     = os.path.join(SCRIPT_DIR, "certs")

# Default HTTPS port (no root/admin needed). Override with env HTTPS_PORT or --https-port.
DEFAULT_HTTPS_PORT = int(os.environ.get("HTTPS_PORT", "8443"))
PORT_TRIES   = 100

_active_httpd = None
_child_proc   = None

# ─── Helpers ─────────────────────────────────────────────────────────────────
def _short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:10]

def _ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path

def _venv_bin(venv_dir: str) -> str:
    return os.path.join(venv_dir, "Scripts" if IS_WINDOWS else "bin")

def _path_len(p: str) -> int:
    try: return len(os.path.abspath(p))
    except Exception: return len(p)

class Spinner:
    def __init__(self, msg):
        self.msg = msg
        self.spin = itertools.cycle("|/-\\")
        self._stop = threading.Event()
        self._thr = threading.Thread(target=self._run, daemon=True)
    def _run(self):
        while not self._stop.is_set():
            sys.stdout.write(f"\r{self.msg} {next(self.spin)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " "*(len(self.msg)+2) + "\r"); sys.stdout.flush()
    def __enter__(self): self._thr.start()
    def __exit__(self, *a): self._stop.set(); self._thr.join()

def _readline_console(prompt: str) -> str:
    dev = "CONIN$" if IS_WINDOWS else "/dev/tty"
    try:
        sys.stdout.write(prompt); sys.stdout.flush()
        with open(dev, "r", encoding="utf-8", errors="ignore") as con:
            return con.readline()
    except Exception:
        return input(prompt)

def ask(prompt: str, *, default=None, required=False):
    suffix = f" [{default}]" if default is not None else ""
    while True:
        try:
            s = _readline_console(f"{prompt}{suffix}: ")
        except EOFError:
            s = ""
        s = (s or "").strip()
        if not s:
            if default is not None:
                return default
            if required:
                print("Please enter a value.")
                continue
            return ""
        return s

# ─── Venv bootstrap ──────────────────────────────────────────────────────────
def _choose_venv_dir() -> str:
    if IS_WINDOWS:
        long_or_spacey = (_path_len(SCRIPT_DIR) > 90) or (" " in SCRIPT_DIR)
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or SCRIPT_DIR
        if long_or_spacey and base:
            bucket = _ensure_dir(os.path.join(base, "pyvenvs"))
            folder = f"{os.path.basename(SCRIPT_DIR) or 'app'}-{_short_hash(SCRIPT_DIR)}"
            return os.path.join(bucket, folder, "venv")
    return DEFAULT_VENV

def _exec_in_venv(venv_dir: str):
    py = os.path.join(_venv_bin(venv_dir), "python.exe" if IS_WINDOWS else "python")
    os.execv(py, [py, __file__, VENV_FLAG] + sys.argv[1:])

def bootstrap_and_run():
    if VENV_FLAG not in sys.argv:
        venv_dir = _choose_venv_dir()
        if not os.path.isdir(venv_dir):
            with Spinner(f"Creating virtualenv at {venv_dir}…"):
                subprocess.check_call([sys.executable, "-m", "venv", venv_dir])

        py = os.path.join(_venv_bin(venv_dir), "python.exe" if IS_WINDOWS else "python")

        with Spinner("Upgrading pip/setuptools/wheel…"):
            subprocess.check_call([py, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])

        # Only needed for self-signed mode, but kept for parity with the upstream script.
        with Spinner("Installing dependencies (cryptography)…"):
            subprocess.check_call([py, "-m", "pip", "install", "--upgrade", "cryptography"])

        _exec_in_venv(venv_dir)
    else:
        try: sys.argv.remove(VENV_FLAG)
        except ValueError: pass
        main()

# ─── Config ──────────────────────────────────────────────────────────────────
def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "serve_path": SCRIPT_DIR,
        "extra_dns_sans": [],
        "cert_mode": "mkcert",  # mkcert | self
        "mkcert_install": True,
    }

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4)

# ─── CLI ─────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="mkcert-first HTTPS launcher for the Phone Twins demo.")
    p.add_argument("--cert-mode", choices=["mkcert","self"], help="mkcert (trusted) or self-signed.")
    p.add_argument("--https-port", type=int, default=DEFAULT_HTTPS_PORT, help="HTTPS port (default 8443).")
    p.add_argument("--no-mkcert-install", action="store_true", help="Don't run `mkcert -install` automatically.")
    p.add_argument("--extra-sans", help="Extra SANs (comma-separated).")
    return p.parse_args()

# ─── Net helpers ─────────────────────────────────────────────────────────────
def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 80))  # No packets sent; chooses interface
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def get_public_ip(timeout=3):
    try:
        return urllib.request.urlopen("https://api.ipify.org", timeout=timeout).read().decode().strip()
    except Exception:
        return None

def wait_for_listen(port, host="127.0.0.1", timeout_s=10.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False

def print_banner(port):
    lan    = get_lan_ip()
    public = get_public_ip()
    lines = [
        f"  Local : https://{lan}:{port}",
        f"  Public: https://{public}:{port}" if public else "  Public: <none>",
    ]
    w = max(len(l) for l in lines) + 4
    print("\n╔" + "═"*w + "╗")
    for l in lines: print("║" + l.ljust(w) + "║")
    print("╚" + "═"*w + "╝\n")

# ─── Certificates ────────────────────────────────────────────────────────────
def generate_self_signed(cert_file, key_file, extra_dns_sans):
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import NameOID, SubjectAlternativeName, DNSName, IPAddress
    import cryptography.x509 as x509
    import ipaddress as ipa

    lan_ip    = get_lan_ip()
    public_ip = get_public_ip()

    keyobj = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    san_list = [DNSName("localhost"), IPAddress(ipa.ip_address("127.0.0.1"))]
    for ip in (lan_ip, public_ip):
        if ip:
            try: san_list.append(IPAddress(ipa.ip_address(ip)))
            except ValueError: pass
    for host in (extra_dns_sans or []):
        host = str(host).strip()
        if host: san_list.append(DNSName(host))

    san  = SubjectAlternativeName(san_list)
    cn   = lan_ip or "localhost"
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    not_before = datetime.now(timezone.utc) - timedelta(minutes=5)
    not_after  = not_before + timedelta(days=365)

    with Spinner("Generating self-signed certificate…"):
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(keyobj.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(not_before).not_valid_after(not_after)
                .add_extension(san, critical=False)
                .sign(keyobj, hashes.SHA256()))

    with open(key_file, "wb") as f:
        f.write(keyobj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def ensure_mkcert_cert(extra_dns_sans, *, mkcert_install=True):
    mk = shutil.which("mkcert")
    if mk is None:
        raise SystemExit("mkcert not found in PATH. Install mkcert, or run with --cert-mode self.")

    _ensure_dir(CERT_DIR)
    cert_file = os.path.join(CERT_DIR, "cert.pem")
    key_file  = os.path.join(CERT_DIR, "key.pem")

    lan_ip = get_lan_ip()

    # If certs already exist, reuse them (fast restart)
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return os.path.abspath(cert_file), os.path.abspath(key_file)

    # (Optional) install mkcert's root CA on this machine (needed for local trust on THIS machine)
    if mkcert_install:
        try:
            with Spinner("Running mkcert -install…"):
                subprocess.check_call([mk, "-install"])
        except subprocess.CalledProcessError:
            print("⚠ mkcert -install failed (maybe needs admin privileges). Continuing…")

    hosts = [lan_ip, "localhost", "127.0.0.1"]
    for h in (extra_dns_sans or []):
        h = str(h).strip()
        if h and h not in hosts:
            hosts.append(h)

    with Spinner(f"Generating mkcert certificate for {', '.join(hosts)}…"):
        subprocess.check_call([mk, "-key-file", key_file, "-cert-file", cert_file, *hosts])

    return os.path.abspath(cert_file), os.path.abspath(key_file)

def ensure_certificates(cert_mode, cfg, args):
    # Merge extra SANs from config + CLI
    extra = list(cfg.get("extra_dns_sans") or [])
    if args.extra_sans:
        extra += [h.strip() for h in args.extra_sans.split(",") if h.strip()]
    extra = list(dict.fromkeys(extra))  # de-dupe, keep order
    cfg["extra_dns_sans"] = extra

    if cert_mode == "mkcert":
        return ensure_mkcert_cert(extra, mkcert_install=bool(cfg.get("mkcert_install", True) and not args.no_mkcert_install))
    if cert_mode == "self":
        cert_file = os.path.join(SCRIPT_DIR, "cert.pem")
        key_file  = os.path.join(SCRIPT_DIR, "key.pem")
        generate_self_signed(cert_file, key_file, extra)
        return os.path.abspath(cert_file), os.path.abspath(key_file)
    raise SystemExit(f"Unknown cert mode: {cert_mode}")

# ─── Cleanup ────────────────────────────────────────────────────────────────
def _cleanup(*, wait_httpd=True):
    global _active_httpd, _child_proc
    if _child_proc is not None:
        try: _child_proc.terminate()
        except Exception: pass
        try: _child_proc.wait(timeout=3)
        except Exception: pass
        _child_proc = None

atexit.register(_cleanup)

def _signal_handler(signum, frame):
    _cleanup(wait_httpd=False)
    sys.exit(0)

def install_signal_handlers():
    signal.signal(signal.SIGINT,  _signal_handler)
    if hasattr(signal, "SIGTERM"): signal.signal(signal.SIGTERM, _signal_handler)

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    install_signal_handlers()
    args = parse_args()

    cfg = load_config()
    updated = False

    # First run: quick config prompt (non-blocking defaults)
    if not os.path.exists(CONFIG_PATH):
        serve_path = ask("Serve path", default=cfg.get("serve_path") or SCRIPT_DIR)
        cfg["serve_path"] = serve_path or (cfg.get("serve_path") or SCRIPT_DIR)

        extra = ask("Extra DNS SANs (comma-separated, optional)", default="")
        cfg["extra_dns_sans"] = [h.strip() for h in extra.split(",") if h.strip()] if extra else []
        updated = True

    if args.cert_mode:
        cfg["cert_mode"] = args.cert_mode
        updated = True

    if updated:
        save_config(cfg)

    if not os.path.isdir(cfg["serve_path"]):
        raise SystemExit(f"Serve path does not exist: {cfg['serve_path']}")
    os.chdir(cfg["serve_path"])

    https_port = int(args.https_port)

    # Privileged ports on POSIX need sudo; on Windows you may need an elevated shell.
    if IS_POSIX and https_port < 1024 and hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"⚠ Need root to bind port {https_port}; re-running with sudo…")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

    cert_mode = cfg.get("cert_mode", "mkcert")
    cert_file, key_file = ensure_certificates(cert_mode, cfg, args)

    # Prepare Node TLS patch (same mechanism as the upstream server.py uses)
    node_path = shutil.which("node")
    npm_path  = shutil.which("npm")
    if not (os.path.exists("package.json") and os.path.exists("server.js") and node_path):
        raise SystemExit("Expected package.json + server.js + node. Run from the project folder and install Node.")

    # Install JS deps once
    if npm_path and not os.path.exists("node_modules"):
        with Spinner("Installing Node dependencies (npm install)…"):
            subprocess.check_call([npm_path, "install"], cwd=os.getcwd())

    patch_path = os.path.join(os.getcwd(), "tls_patch.cjs")
    CERT_ABS = os.path.abspath(cert_file)
    KEY_ABS  = os.path.abspath(key_file)

    # CJS preload so it can be -r'd regardless of package.json "type"
    with open(patch_path, "w", encoding="utf-8") as f:
        f.write(f"""\
const fs = require('fs');
const https = require('https');
const http = require('http');
const CERT = {json.dumps(CERT_ABS)};
const KEY  = {json.dumps(KEY_ABS)};

// Force HTTPS when app uses http.createServer(...)
const _create = http.createServer;
http.createServer = function (opts, listener) {{
  if (typeof opts === 'function') listener = opts;
  return https.createServer({{ key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) }}, listener);
}};
const _Server = http.Server;
http.Server = function (...args) {{
  return https.Server({{ key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) }}, ...args);
}};
http.Server.prototype = _Server.prototype;
""")

    env = os.environ.copy()
    env["PORT"] = str(https_port)
    env.setdefault("HOST", "0.0.0.0")

    cmd = [node_path, "-r", patch_path, "server.js"]
    global _child_proc
    with Spinner(f"Starting Node.js over HTTPS on port {https_port}…"):
        _child_proc = subprocess.Popen(cmd, env=env, cwd=os.getcwd())

    if wait_for_listen(https_port, host="127.0.0.1", timeout_s=10.0):
        print_banner(https_port)
        print("Tip: On a phone, open the LAN URL shown above.")
        print("      If the certificate is not trusted on the phone, install the mkcert root CA on the phone.")
        print("      You can find it via: mkcert -CAROOT")
    else:
        print("⚠ Started Node, but port not detected listening. Check logs above.")

    try:
        _child_proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        _cleanup()

if __name__ == "__main__":
    bootstrap_and_run()
