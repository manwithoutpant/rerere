#!/usr/bin/env python3
"""Isolated TUIC + XHTTP additions. Never changes existing relay/protocol settings."""
import argparse
import contextlib
import copy
import ctypes
import datetime
import fcntl
import getpass
import hashlib
import http.server
import ipaddress
import json
import os
import pathlib
import platform
import re
import secrets
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import zipfile

VERSION = "0.1.0"
ROOT = pathlib.Path("/opt/edge-addons")
PREFIX = "edge-addons"
SERVICES = tuple(PREFIX + "-" + name + ".service" for name in ("xray", "web", "tuic"))
CERT_SERVICE = PREFIX + "-renew.service"
CERT_TIMER = PREFIX + "-renew.timer"
GUARD = PREFIX + "-guard"
UNIT_ROOT = pathlib.Path("/etc/systemd/system")
MARKER = "# Managed exclusively by edge-addons 0.1"
BLOB = ("edge-addons:data-integrity:v1\n" * 4096).encode()
BLOB_PATH = "/health/data-v1"
ASSETS = {
    "xray": {
        "file": "Xray-linux-64.zip",
        "url": "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip",
        "sha256": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        "member": "xray",
    },
    "sing-box": {
        "file": "sing-box-1.14.3-linux-amd64.tar.gz",
        "url": "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz",
        "sha256": "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
        "member": "sing-box-1.14.3-linux-amd64/sing-box",
    },
    "caddy": {
        "file": "caddy_2.11.7_linux_amd64.tar.gz",
        "url": "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_amd64.tar.gz",
        "sha256": "727b91701a392de6ebc5027509f548bf39979e5216340d0faed8fa5e69c84f8b",
        "member": "caddy",
    },
    "lego": {
        "file": "lego_v5.5.2_linux_amd64.tar.gz",
        "url": "https://github.com/go-acme/lego/releases/download/v5.5.2/lego_v5.5.2_linux_amd64.tar.gz",
        "sha256": "2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef",
        "member": "lego",
    },
}

LIBC = ctypes.CDLL(None, use_errno=True)

class Failure(RuntimeError):
    pass

def say(message):
    print(message, flush=True)

def run(args, timeout=30, env=None, check=True):
    p = subprocess.run([str(x) for x in args], capture_output=True, text=True,
                       timeout=timeout, env=env)
    if check and p.returncode:
        # Configs/URLs may contain secrets. Detailed logs remain on the host.
        raise Failure(str(args[0]) + " failed (exit " + str(p.returncode) + ").")
    return p

def sha(path):
    with pathlib.Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def atomic(path, data, mode=0o600):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise Failure("Refusing symlink: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".edge-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), mode)
            f.write(data.encode() if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        pathlib.Path(name).unlink(missing_ok=True)

def write_json(path, data):
    atomic(path, json.dumps(data, indent=2) + "\n")

def read_json(path):
    return json.loads(pathlib.Path(path).read_text())

def hostport(address, port):
    return ("[" + address + "]" if ":" in address else address) + ":" + str(port)

def domain_name(value):
    name = value.strip().lower().rstrip(".")
    if (len(name) > 253 or "." not in name or
        any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
            for x in name.split("."))):
        raise Failure("Use an ASCII DNS hostname, not a URL or IP.")
    return name

def literal_ip(value):
    return str(ipaddress.ip_address(value))

def new_state(role, domain, address, ipv6=None, port=25443, peer=None):
    return {
        "schema": 1, "version": VERSION, "role": role,
        "domain": domain_name(domain), "address": literal_ip(address),
        "ipv6": literal_ip(ipv6) if ipv6 else None, "port": port,
        "uuid": str(uuid.uuid4()), "path": "/" + secrets.token_urlsafe(24) + "/",
        "tuic_uuid": str(uuid.uuid4()), "tuic_password": secrets.token_urlsafe(32),
        "peer": peer, "committed": False,
    }

def public_peer(state):
    # Only credentials for the NEW uplink; never certificate keys or DNS tokens.
    return {
        "schema": 1, "protocol": "vless-xhttp-tls", "domain": state["domain"],
        "address": state["address"], "transport_ip": state.get("ipv6") or state["address"],
        "port": state["port"], "uuid": state["uuid"], "path": state["path"],
    }

def validate_peer(peer):
    if peer.get("schema") != 1 or peer.get("protocol") != "vless-xhttp-tls":
        raise Failure("Unexpected peer manifest.")
    if set(peer) != {"schema", "protocol", "domain", "address", "transport_ip",
                     "port", "uuid", "path"}:
        raise Failure("Unexpected fields in peer manifest.")
    peer = dict(peer)
    peer["domain"] = domain_name(peer["domain"])
    for field in ("address", "transport_ip"):
        ip = ipaddress.ip_address(peer[field])
        if not ip.is_global:
            raise Failure("Peer address must be a public IP.")
        peer[field] = str(ip)
    uuid.UUID(peer["uuid"])
    if not isinstance(peer["port"], int) or not 1024 <= peer["port"] <= 65531:
        raise Failure("Unexpected peer port.")
    if not re.fullmatch(r"/[a-zA-Z0-9_-]{24,64}/", peer["path"]):
        raise Failure("Unexpected XHTTP path.")
    return peer

def xhttp_out(peer, tag="uplink", test_ca=None):
    tls = {"serverName": peer["domain"], "allowInsecure": False,
           "fingerprint": "chrome", "alpn": ["h2"]}
    if test_ca:
        tls["certificates"] = [{"usage": "verify", "certificateFile": str(test_ca)}]
    return {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{
            "address": peer["transport_ip"], "port": peer["port"],
            "users": [{"id": peer["uuid"], "encryption": "none"}],
        }]},
        "streamSettings": {
            "network": "xhttp", "security": "tls", "tlsSettings": tls,
            "xhttpSettings": {"path": peer["path"], "mode": "auto"},
        },
        "mux": {"enabled": False},
    }

def xray_config(state, test_ca=None):
    p = state["port"]
    outbound = (xhttp_out(state["peer"], test_ca=test_ca)
                if state["role"] == "iran"
                else {"tag": "uplink", "protocol": "freedom"})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "xhttp-in", "listen": "127.0.0.1", "port": p + 1,
            "protocol": "vless", "settings": {
                "clients": [{"id": state["uuid"]}], "decryption": "none"},
            "streamSettings": {"network": "xhttp", "security": "none",
                               "xhttpSettings": {"path": state["path"], "mode": "auto"}},
        }, {
            "tag": "tuic-bridge", "listen": "127.0.0.1", "port": p + 2,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
        }, {
            "tag": "acme-connect", "listen": "127.0.0.1", "port": p + 3,
            "protocol": "http", "settings": {},
        }],
        "outbounds": [outbound],
    }

def listen_ips(state):
    return list(dict.fromkeys([state["address"]] +
           ([state["ipv6"]] if state.get("ipv6") else []) + ["127.0.0.1"]))

def tuic_config(state, cert, key):
    p = state["port"]
    inbound = {
        "type": "tuic", "listen_port": p,
        "users": [{"uuid": state["tuic_uuid"], "password": state["tuic_password"]}],
        "congestion_control": "bbr", "zero_rtt_handshake": False, "heartbeat": "10s",
        "tls": {"enabled": True, "server_name": state["domain"], "alpn": ["h3"],
                "certificate_path": str(cert), "key_path": str(key)},
    }
    inbounds = []
    for i, address in enumerate(listen_ips(state)):
        node = copy.deepcopy(inbound)
        node.update(tag="tuic-" + str(i), listen=address)
        inbounds.append(node)
    if state["role"] == "iran":
        out = {"type": "socks", "tag": "uplink", "server": "127.0.0.1",
               "server_port": p + 2, "version": "5"}
    else:
        out = {"type": "direct", "tag": "uplink"}
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [{"type": "local", "tag": "system"}]},
        "inbounds": inbounds, "outbounds": [out],
        "route": {"final": "uplink", "default_domain_resolver": "system"},
    }

def caddy_config(state, cert, key):
    site = ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width">'
            '<title>Technology Notes</title><body><main><h1>Technology Notes</h1>'
            '<p>Short notes on software, networks and digital tools.</p>'
            '<article><h2>Keeping systems dependable</h2><p>Useful systems start with '
            'clear measurements, small changes and regular backups.</p></article>'
            '<article><h2>Open standards</h2><p>Open documentation makes it easier '
            'to build tools that work together.</p></article></main></body></html>')
    p = state["port"]
    return {
        "admin": {"disabled": True},
        "apps": {
            "tls": {"certificates": {"load_files": [{
                "certificate": str(cert), "key": str(key)}]}},
            "http": {"servers": {"edge": {
                "listen": [hostport(x, p) for x in listen_ips(state)],
                "protocols": ["h1", "h2"],
                "automatic_https": {"disable": True},
                "tls_connection_policies": [{}],
                "routes": [{
                    "match": [{"host": [state["domain"]], "path": [state["path"] + "*"]}],
                    "handle": [{"handler": "reverse_proxy",
                                "upstreams": [{"dial": "127.0.0.1:" + str(p + 1)}],
                                "transport": {"protocol": "http", "versions": ["h2c"]},
                                "flush_interval": -1}],
                    "terminal": True,
                }, {
                    "match": [{"host": [state["domain"]], "path": [BLOB_PATH]}],
                    "handle": [{"handler": "static_response", "status_code": 200,
                                "headers": {"Content-Type": ["application/octet-stream"],
                                            "Cache-Control": ["no-store"]},
                                "body": BLOB.decode()}],
                    "terminal": True,
                }, {
                    "handle": [{"handler": "static_response", "status_code": 200,
                                "headers": {"Content-Type": ["text/html; charset=utf-8"]},
                                "body": site}],
                }],
            }}},
        },
    }

def tuic_client_out(state, address=None, test_ca=None):
    tls = {"enabled": True, "server_name": state["domain"], "alpn": ["h3"],
           "insecure": False}
    if test_ca:
        tls["certificate_path"] = str(test_ca)
    return {
        "type": "tuic", "tag": "proxy", "server": address or state["address"],
        "server_port": state["port"], "uuid": state["tuic_uuid"],
        "password": state["tuic_password"], "congestion_control": "bbr",
        "udp_relay_mode": "native", "zero_rtt_handshake": False, "tls": tls,
    }

def client_links(state):
    query = urllib.parse.urlencode({
        "encryption": "none", "security": "tls", "sni": state["domain"],
        "fp": "chrome", "alpn": "h2", "type": "xhttp",
        "path": state["path"], "mode": "auto"})
    endpoint = hostport(state["address"], state["port"])
    x = "vless://" + state["uuid"] + "@" + endpoint + "?" + query + "#EDGE-XHTTP-" + state["role"]
    t = "tuic://" + state["tuic_uuid"] + ":" + state["tuic_password"] + "@" + endpoint + "?" + urllib.parse.urlencode({
        "sni": state["domain"], "alpn": "h3", "congestion_control": "bbr",
        "udp_relay_mode": "native", "allow_insecure": "0"}) + "#EDGE-TUIC-" + state["role"]
    return x, t

def require_root():
    if os.geteuid() != 0:
        raise Failure("Run with sudo python3.")
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise Failure("This pinned bundle supports Linux x86_64 only.")
    for cmd in ("systemctl", "systemd-run", "ip", "ss", "curl", "openssl"):
        if not shutil.which(cmd):
            raise Failure("Missing prerequisite: " + cmd)

def download_asset(asset, dest):
    dest = pathlib.Path(dest)
    if dest.exists() and sha(dest) == asset["sha256"]:
        return
    tmp = dest.with_name(dest.name + ".part")
    try:
        req = urllib.request.Request(asset["url"], headers={"User-Agent": "edge-addons/" + VERSION})
        with urllib.request.urlopen(req, timeout=90) as response, tmp.open("wb") as f:
            shutil.copyfileobj(response, f)
        if sha(tmp) != asset["sha256"]:
            raise Failure("Release checksum mismatch: " + asset["file"])
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)

def prepare_binaries(base, offline=None):
    cache = pathlib.Path(base) / "payload"
    bindir = pathlib.Path(base) / "bin"
    cache.mkdir(mode=0o700)
    bindir.mkdir(mode=0o755)
    os.chmod(bindir, 0o755)
    for name, asset in ASSETS.items():
        path = cache / asset["file"]
        if offline:
            src = pathlib.Path(offline) / "payload" / asset["file"]
            if not src.is_file() or sha(src) != asset["sha256"]:
                raise Failure("Offline archive is absent or checksum differs: " + asset["file"])
            shutil.copyfile(src, path)
        else:
            say("Downloading verified release: " + name)
            download_asset(asset, path)
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                data = archive.read(asset["member"])
        else:
            with tarfile.open(path, "r:gz") as archive:
                member = archive.getmember(asset["member"])
                if not member.isfile():
                    raise Failure("Unexpected archive member.")
                with archive.extractfile(member) as f:
                    data = f.read()
        atomic(bindir / name, data, 0o755)
    return bindir

def baseline():
    units = {}
    text = run(["systemctl", "list-units", "--type=service", "--state=running",
                "--no-legend", "--plain"]).stdout
    for line in text.splitlines():
        unit = line.split()[0]
        if re.search(r"(iran-relay|reality|xray|hysteria|anytls|shadow)", unit, re.I) and not unit.startswith(PREFIX):
            units[unit] = run(["systemctl", "show", unit, "-p", "MainPID", "--value"]).stdout.strip()
    files = {}
    for dirname in ("iran-relay", "reality-oneclick", "reality-extras", "hysteria-oneclick"):
        base = pathlib.Path("/opt") / dirname / "current"
        if base.is_dir():
            for path in base.glob("*.json"):
                if path.is_file():
                    files[str(path)] = sha(path)
    firewall = {}
    for cmd in (["nft", "list", "ruleset"], ["iptables-save"], ["ip6tables-save"]):
        if shutil.which(cmd[0]):
            p = run(cmd, check=False)
            if p.returncode == 0:
                firewall[cmd[0]] = hashlib.sha256(p.stdout.encode()).hexdigest()
    return {"pids": units, "file_sha256": files, "firewall_sha256": firewall}

def check_baseline(old):
    current = baseline()
    for kind, values in old.items():
        for key, value in values.items():
            if current[kind].get(key) != value:
                raise Failure("Existing state changed during installation (" + kind + "): " + key)
    say("PASS existing protocol PIDs, config hashes and firewall hashes unchanged.")

def preflight(state):
    ports = range(state["port"], state["port"] + 4)
    assigned = set()
    for interface in json.loads(run(["ip", "-j", "address"]).stdout):
        for address in interface.get("addr_info", []):
            assigned.add(address["local"])
    for address in listen_ips(state):
        if address not in assigned:
            raise Failure("Address is not assigned locally: " + address)
    for address in listen_ips(state):
        for port in ports:
            # Backend ports use loopback only.
            if port != state["port"] and address != "127.0.0.1":
                continue
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                with socket.socket(family, kind) as test:
                    if family == socket.AF_INET6:
                        test.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    try:
                        test.bind((address, port))
                    except OSError as e:
                        raise Failure("Port is busy: " + hostport(address, port)) from e
    for name in SERVICES + (CERT_SERVICE, CERT_TIMER):
        if (UNIT_ROOT / name).exists():
            raise Failure("Unit already exists: " + name)
        if run(["systemctl", "show", name, "-p", "LoadState", "--value"], check=False).stdout.strip() not in ("", "not-found"):
            raise Failure("A unit with this name is already loaded: " + name)
    say("PASS assigned IPs and all new TCP/UDP ports are free.")

def validate_cert(cert, key, domain):
    run(["openssl", "x509", "-in", cert, "-noout", "-checkhost", domain])
    run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "604800"])
    cpub = run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"]).stdout
    kpub = run(["openssl", "pkey", "-in", key, "-pubout"]).stdout
    if cpub.strip() != kpub.strip():
        raise Failure("TLS certificate and private key do not match.")
    # Trust, hostname and chain are additionally verified by native TLS probes.
    context = ssl.create_default_context()
    context.load_cert_chain(str(cert), str(key))

class ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True

@contextlib.contextmanager
def dns_bridge(proxy):
    """Let lego make DNS lookups over the authenticated HTTPS uplink."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy}))
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            if len(data) > 4096:
                return
            try:
                request = urllib.request.Request("https://cloudflare-dns.com/dns-query",
                    data=data, headers={"Content-Type": "application/dns-message",
                                        "Accept": "application/dns-message"})
                with opener.open(request, timeout=15) as response:
                    answer = response.read(65536)
                sock.sendto(answer, self.client_address)
            except Exception:
                return
    server = ThreadedUDP(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

@contextlib.contextmanager
def process(args, log):
    parent_pid = os.getpid()
    def lifetime():
        # Test clients and ACME jobs must not outlive a killed installer.
        if LIBC.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != parent_pid:
            os._exit(1)
    with open(log, "w") as output:
        p = subprocess.Popen([str(x) for x in args], stdout=output, stderr=output,
                             start_new_session=True, preexec_fn=lifetime)
        try:
            yield p
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()

def wait_tcp(port, proc=None, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc and proc.poll() is not None:
            raise Failure("Temporary client exited; see private native log.")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.1)
    raise Failure("Local process did not open its port.")

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

@contextlib.contextmanager
def certificate_proxy(state):
    if state["role"] != "iran":
        yield None
        return
    # Before service activation: bootstrap only the NEW foreign XHTTP uplink.
    with tempfile.TemporaryDirectory(prefix="edge-acme-") as tmp:
        port = free_port()
        config = {"log": {"loglevel": "warning"}, "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "http"}],
            "outbounds": [xhttp_out(state["peer"])]}
        path = pathlib.Path(tmp) / "config.json"
        write_json(path, config)
        with process([ROOT / "bin/xray", "run", "-c", path], pathlib.Path(tmp) / "client.log") as p:
            wait_tcp(port, p)
            yield "http://127.0.0.1:" + str(port)

def acme(state, renew=False, proxy=None):
    env = os.environ.copy()
    # Never reuse an unrelated host proxy or leak a DNS token to argv/export.
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            env.pop(key)
    env.update({
        "CF_DNS_API_TOKEN_FILE": str(ROOT / "private/cf-token"),
        "CF_ZONE_API_TOKEN_FILE": str(ROOT / "private/cf-token"),
        "CLOUDFLARE_HTTP_TIMEOUT": "25",
    })
    if proxy:
        env.update(HTTPS_PROXY=proxy, HTTP_PROXY=proxy, NO_PROXY="127.0.0.1,localhost")
    cm = dns_bridge(proxy) if proxy else contextlib.nullcontext(None)
    with cm as dns_port:
        args = [ROOT / "bin/lego", "--path", ROOT / "acme", "--email", state["email"],
                "--accept-tos", "--domains", state["domain"], "--dns", "cloudflare",
                "--dns.propagation-wait", "90s", "--http-timeout", "30"]
        if dns_port:
            args += ["--dns.resolvers", "127.0.0.1:" + str(dns_port)]
        args += ["renew", "--days", "30"] if renew else ["run"]
        say("ACME DNS-01: waiting for certificate; TCP/80 and TCP/443 remain untouched.")
        logfile = ROOT / "private/acme.log"
        with process(args, logfile) as p:
            deadline = time.monotonic() + 480
            while p.poll() is None:
                if time.monotonic() >= deadline:
                    raise Failure("ACME timed out. Private log: " + str(logfile))
                time.sleep(1)
            if p.returncode:
                raise Failure("ACME failed. Private log: " + str(logfile))
    cert = ROOT / "acme/certificates" / (state["domain"] + ".crt")
    key = ROOT / "acme/certificates" / (state["domain"] + ".key")
    validate_cert(cert, key, state["domain"])
    return cert, key

def install_certificate(state, cert=None, key=None):
    if bool(cert) != bool(key):
        raise Failure("Provide both --cert and --key.")
    if cert:
        state["certificate_mode"] = "provided"
        validate_cert(cert, key, state["domain"])
    else:
        state["certificate_mode"] = "cloudflare"
        state["email"] = input("ACME email (Let's Encrypt terms apply): ").strip()
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", state["email"]):
            raise Failure("Enter a valid ACME email.")
        token = os.environ.get("EDGE_CF_TOKEN") or getpass.getpass(
            "Cloudflare token: DNS Edit + Zone Read, scoped to this zone (hidden): ").strip()
        if not token or "\n" in token:
            raise Failure("A Cloudflare API token is required.")
        atomic(ROOT / "private/cf-token", token)
        del token
        with certificate_proxy(state) as proxy:
            cert, key = acme(state, proxy=proxy)
    atomic(ROOT / "private/tls.crt", pathlib.Path(cert).read_bytes())
    atomic(ROOT / "private/tls.key", pathlib.Path(key).read_bytes())

def configs(state, cert, key, test_ca=None):
    return {"xray.json": xray_config(state, test_ca),
            "tuic.json": tuic_config(state, cert, key),
            "web.json": caddy_config(state, cert, key)}

def native_checks(state):
    with tempfile.TemporaryDirectory(prefix="edge-validate-") as tmp:
        for name, config in configs(state, ROOT / "private/tls.crt", ROOT / "private/tls.key").items():
            write_json(pathlib.Path(tmp) / name, config)
        jobs = [
            [ROOT / "bin/xray", "run", "-test", "-c", pathlib.Path(tmp) / "xray.json"],
            [ROOT / "bin/sing-box", "check", "-c", pathlib.Path(tmp) / "tuic.json"],
            [ROOT / "bin/caddy", "validate", "--config", pathlib.Path(tmp) / "web.json"],
        ]
        for args in jobs:
            p = run(args, check=False)
            if p.returncode:
                atomic(ROOT / "private/validation.log", p.stdout + p.stderr)
                raise Failure("Native config validation failed: " + str(args[0]) +
                              "; private details in " + str(ROOT / "private/validation.log"))
    say("PASS native Xray, sing-box and Caddy configuration checks.")

def unit_text(name, executable, config_name, certs=False):
    credential = "/run/credentials/" + name + "/"
    text = MARKER + "\n[Unit]\nDescription=Isolated edge add-on\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n"
    text += ("Type=simple\nDynamicUser=yes\nNoNewPrivileges=yes\n"
             "PrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\n"
             "ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n"
             "RestrictSUIDSGID=yes\nLockPersonality=yes\nUMask=0077\n"
             "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n"
             "CapabilityBoundingSet=\nAmbientCapabilities=\n"
             "LimitNOFILE=16384\nNice=5\nCPUWeight=25\n")
    text += "LoadCredential=config.json:" + str(ROOT / "private" / config_name) + "\n"
    if certs:
        text += ("LoadCredential=tls.crt:" + str(ROOT / "private/tls.crt") + "\n"
                 "LoadCredential=tls.key:" + str(ROOT / "private/tls.key") + "\n")
    if "web" in name:
        text += "StateDirectory=edge-addons-web\nEnvironment=XDG_DATA_HOME=/var/lib/edge-addons-web\n"
    text += "ExecStart=" + str(ROOT / "bin" / executable[0]) + " " + " ".join(executable[1:]) + " " + credential + "config.json\n"
    text += "Restart=on-failure\nRestartSec=3\nTimeoutStopSec=10\n\n[Install]\nWantedBy=multi-user.target\n"
    return text

def stage_files(state):
    # Credential paths are intentionally suffixed .json; existing service is untouched.
    xc = xray_config(state)
    tc = tuic_config(state, "/run/credentials/edge-addons-tuic.service/tls.crt",
                     "/run/credentials/edge-addons-tuic.service/tls.key")
    wc = caddy_config(state, "/run/credentials/edge-addons-web.service/tls.crt",
                     "/run/credentials/edge-addons-web.service/tls.key")
    for name, config in (("xray.json", xc), ("tuic.json", tc), ("web.json", wc)):
        write_json(ROOT / "private" / name, config)
    units = {
        SERVICES[0]: unit_text(SERVICES[0], ["xray", "run", "-c"], "xray.json"),
        SERVICES[1]: unit_text(SERVICES[1], ["caddy", "run", "--config"], "web.json", True),
        SERVICES[2]: unit_text(SERVICES[2], ["sing-box", "run", "-c"], "tuic.json", True),
    }
    for name, text in units.items():
        atomic(UNIT_ROOT / name, text, 0o644)
    if state["certificate_mode"] == "cloudflare":
        atomic(UNIT_ROOT / CERT_SERVICE, MARKER + "\n[Unit]\nDescription=Renew edge add-on certificate\n"
            "After=network-online.target " + SERVICES[0] + "\n\n[Service]\nType=oneshot\n"
            "UMask=0077\nExecStart=/usr/bin/python3 " + str(ROOT / "edge_addons.py") + " renew\n", 0o644)
        atomic(UNIT_ROOT / CERT_TIMER, MARKER + "\n[Unit]\nDescription=Edge add-on certificate renewal\n\n"
            "[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n\n"
            "[Install]\nWantedBy=timers.target\n", 0o644)

def own_units_present():
    for name in SERVICES + (CERT_SERVICE, CERT_TIMER):
        path = UNIT_ROOT / name
        if path.exists():
            if path.is_symlink() or not path.read_text().startswith(MARKER + "\n"):
                raise Failure("Unit ownership mismatch; refusing to touch: " + name)
            yield name

def stop_owned():
    for name in list(own_units_present()):
        run(["systemctl", "disable", "--now", name], check=False)
        (UNIT_ROOT / name).unlink()
    run(["systemctl", "daemon-reload"], check=False)

def disarm():
    for suffix in (".timer", ".service"):
        run(["systemctl", "stop", GUARD + suffix], check=False)
    run(["systemctl", "reset-failed", GUARD + ".service"], check=False)

def guard(token):
    path = ROOT / "private/pending"
    if path.exists() and secrets.compare_digest(path.read_text().strip(), token):
        stop_owned()
        say("Guard stopped ONLY new add-on units; existing services were not touched.")

def socks_client_config(out, port):
    return {"log": {"loglevel": "warning"}, "inbounds": [{
        "listen": "127.0.0.1", "port": port, "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}],
        "outbounds": [out]}

def verified_data(socks_port, origin, output, ca=None):
    # The destination is loopback ON THE EXIT SERVER, through both proxy layers.
    url = "https://" + origin["domain"] + ":" + str(origin["port"]) + BLOB_PATH
    args = ["curl", "--silent", "--show-error", "--fail", "--max-time", "30",
            "--noproxy", "", "--socks5-hostname", "127.0.0.1:" + str(socks_port),
            "--connect-to", origin["domain"] + ":" + str(origin["port"]) +
            ":127.0.0.1:" + str(origin["port"]), "--output", str(output), url]
    if ca:
        args += ["--cacert", str(ca)]
    run(args, timeout=35)
    if pathlib.Path(output).read_bytes() != BLOB:
        raise Failure("Downloaded payload differs from the known reference.")
    say("PASS authenticated tunnel + hostname-verified HTTPS + " + str(len(BLOB)) +
        " bytes; SHA256=" + hashlib.sha256(BLOB).hexdigest())

def check_live(state):
    origin = state["peer"] if state["role"] == "iran" else public_peer(state)
    with tempfile.TemporaryDirectory(prefix="edge-live-check-") as tmp:
        tmp = pathlib.Path(tmp)
        port = free_port()
        peer = public_peer(state)
        peer["transport_ip"] = "127.0.0.1"
        write_json(tmp / "client.json", socks_client_config(xhttp_out(peer), port))
        with process([ROOT / "bin/xray", "run", "-c", tmp / "client.json"], tmp / "xray.log") as p:
            wait_tcp(port, p)
            verified_data(port, origin, tmp / "payload")
        port = free_port()
        config = {"log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [tuic_client_out(state, address="127.0.0.1")]}
        write_json(tmp / "tuic-client.json", config)
        with process([ROOT / "bin/sing-box", "run", "-c", tmp / "tuic-client.json"],
                     tmp / "tuic.log") as p:
            wait_tcp(port, p)
            verified_data(port, origin, tmp / "payload")
    say("PASS both local native clients. Internet-to-server reachability remains unverified.")

def self_lab():
    """Run native data-plane tests before ANY new systemd unit is written."""
    source = pathlib.Path(__file__).resolve().with_name("test_native.py")
    if not source.is_file() or source.is_symlink():
        raise Failure("Matching test_native.py is required beside the installer.")
    target = ROOT / "test_native.py"
    if source != target:
        shutil.copyfile(source, target)
    say("Running isolated native lab: real HTTPS upload/download and UDP payloads.")
    logfile = ROOT / "private/native-lab.log"
    with process([sys.executable, target, "--offline-dir", ROOT], logfile) as p:
        deadline = time.monotonic() + 240
        progress = time.monotonic() + 20
        while p.poll() is None:
            if time.monotonic() >= deadline:
                raise Failure("Native lab timed out; no new services activated. See " + str(logfile))
            if time.monotonic() >= progress:
                say("Native data-plane verification is still running ...")
                progress += 20
            time.sleep(.25)
        if p.returncode:
            raise Failure("Native data-plane lab failed; no new services activated. See " + str(logfile))
    say("PASS native lab: both protocols, direct and via foreign XHTTP, actual data checked.")

def installation(args):
    require_root()
    if ROOT.exists() or ROOT.is_symlink():
        raise Failure("Add-on directory already exists. Use status/check/uninstall; no overwrite performed.")
    if not 1024 <= args.port <= 65531:
        raise Failure("Port must be between 1024 and 65531.")
    if args.role == "iran" and not args.peer_file:
        raise Failure("Iran role needs --peer-file from the NEW foreign installation.")
    peer = validate_peer(read_json(args.peer_file)) if args.role == "iran" else None
    available = next((int(line.split()[1]) for line in pathlib.Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:")), 0)
    if available < 384 * 1024:
        raise Failure("Need at least 384 MiB available RAM for the bounded native lab; nothing changed.")
    state = new_state(args.role, args.domain, args.bind_ip, args.ipv6, args.port, peer)
    if ipaddress.ip_address(state["address"]).version != 4:
        raise Failure("--bind-ip must be an assigned IPv4 address.")
    preflight(state)
    before = baseline()
    token = secrets.token_hex(24)
    created = False
    try:
        ROOT.mkdir(mode=0o755)
        os.chmod(ROOT, 0o755)
        created = True
        (ROOT / "private").mkdir(mode=0o700)
        atomic(ROOT / "private/owner", token)
        shutil.copyfile(pathlib.Path(__file__).resolve(), ROOT / "edge_addons.py")
        os.chmod(ROOT / "edge_addons.py", 0o755)
        prepare_binaries(ROOT, args.offline_dir)
        self_lab()
        write_json(ROOT / "private/baseline.json", before)
        install_certificate(state, args.cert, args.key)
        native_checks(state)
        stage_files(state)
        write_json(ROOT / "private/state.json", state)
        atomic(ROOT / "private/pending", token)
        run(["systemctl", "daemon-reload"])
        run(["systemd-run", "--unit", GUARD, "--on-active=10m", "--timer-property=AccuracySec=1s",
             "/usr/bin/python3", ROOT / "edge_addons.py", "guard", "--token", token])
        for unit in SERVICES:
            run(["systemctl", "start", unit])
        check_live(state)
        check_baseline(before)
        # Enabling cannot alter old units, credentials, firewall or kernel settings.
        run(["systemctl", "enable", *SERVICES])
        if state["certificate_mode"] == "cloudflare":
            run(["systemctl", "enable", "--now", CERT_TIMER])
        state["committed"] = True
        write_json(ROOT / "private/state.json", state)
        if state["role"] == "foreign":
            write_json(ROOT / "private/peer.json", public_peer(state))
        write_json(ROOT / "private/tuic-client.json", {
            "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 10808}],
            "outbounds": [tuic_client_out(state)]})
        atomic(ROOT / "private/links.txt", "\n".join(client_links(state)) + "\n")
        (ROOT / "private/pending").unlink(missing_ok=True)
        disarm()
        say("READY: isolated XHTTP/TCP and TUIC/UDP on " + str(state["port"]) + ".")
        say("Client links: sudo python3 /opt/edge-addons/edge_addons.py links")
        if state["role"] == "foreign":
            say("Private uplink manifest: /opt/edge-addons/private/peer.json")
        say("Open ONLY the selected IP port in the provider firewall: TCP/" +
            str(state["port"]) + " and UDP/" + str(state["port"]) + ".")
        say("Host firewall was not changed. External client tests are still required.")
    except BaseException:
        if created and (ROOT / "private/owner").exists() and (ROOT / "private/owner").read_text() == token:
            stop_owned()
            disarm()
            # Leave private failure diagnostics available; never touch old service dirs.
            say("STOP: new units removed; private diagnostic directory retained at " + str(ROOT))
            say("To clear this failed addition: sudo python3 /opt/edge-addons/edge_addons.py uninstall")
        raise

def renewal(args):
    state = read_json(ROOT / "private/state.json")
    if args.cert or args.key:
        if not args.cert or not args.key:
            raise Failure("Provide both --cert and --key.")
        cert, key = pathlib.Path(args.cert), pathlib.Path(args.key)
        validate_cert(cert, key, state["domain"])
    elif state["certificate_mode"] == "cloudflare":
        proxy = "http://127.0.0.1:" + str(state["port"] + 3) if state["role"] == "iran" else None
        cert, key = acme(state, renew=True, proxy=proxy)
    else:
        raise Failure("Provided certificates: use renew --cert FULLCHAIN --key PRIVKEY.")
    cert_path, key_path = ROOT / "private/tls.crt", ROOT / "private/tls.key"
    old_cert, old_key = cert_path.read_bytes(), key_path.read_bytes()
    if pathlib.Path(cert).read_bytes() == old_cert and pathlib.Path(key).read_bytes() == old_key:
        say("Certificate unchanged.")
        return
    try:
        atomic(cert_path, pathlib.Path(cert).read_bytes())
        atomic(key_path, pathlib.Path(key).read_bytes())
        native_checks(state)
        for unit in SERVICES[1:]:
            run(["systemctl", "restart", unit])
        check_live(state)
    except BaseException:
        atomic(cert_path, old_cert)
        atomic(key_path, old_key)
        for unit in SERVICES[1:]:
            run(["systemctl", "restart", unit], check=False)
        raise
    say("New add-on certificate renewed; old services unchanged.")

def bundle(args):
    if not ROOT.exists():
        raise Failure("Create the foreign installation first.")
    output = pathlib.Path(args.output).resolve()
    if output.exists() or output.is_relative_to(ROOT):
        raise Failure("Bundle target exists or is inside the private installation.")
    # An explicit allowlist excludes state, passwords, CF token and certificate keys.
    with tarfile.open(output, "w:gz") as archive:
        archive.add(ROOT / "edge_addons.py", arcname="edge-offline/edge_addons.py")
        archive.add(ROOT / "test_native.py", arcname="edge-offline/test_native.py")
        for asset in ASSETS.values():
            source = ROOT / "payload" / asset["file"]
            if sha(source) != asset["sha256"]:
                raise Failure("Cached release checksum differs.")
            archive.add(source, arcname="edge-offline/payload/" + asset["file"])
    os.chmod(output, 0o600)
    say("Non-secret offline package: " + str(output))
    say("SHA256: " + sha(output))
    say("Copy the private peer.json separately; never upload it to GitHub.")

def uninstall():
    marker = ROOT / "private/owner"
    if ROOT.is_symlink() or not marker.is_file() or marker.is_symlink():
        raise Failure("Installation ownership is not recognized.")
    stop_owned()
    disarm()
    # Keep a root-only archive for rollback review; it includes NEW credentials.
    archive = ROOT.with_name("edge-addons-removed-" + str(int(time.time())))
    os.rename(ROOT, archive)
    os.chmod(archive, 0o700)
    say("Removed ONLY new units. Existing services unchanged.")
    say("Private retained files: " + str(archive))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install")
    p.add_argument("--role", choices=("foreign", "iran"), required=True)
    p.add_argument("--domain", required=True)
    p.add_argument("--bind-ip", required=True)
    p.add_argument("--ipv6")
    p.add_argument("--port", type=int, default=25443)
    p.add_argument("--peer-file")
    p.add_argument("--offline-dir")
    p.add_argument("--cert")
    p.add_argument("--key")
    for name in ("status", "check", "links", "uninstall"):
        sub.add_parser(name)
    p = sub.add_parser("guard")
    p.add_argument("--token", required=True)
    p = sub.add_parser("renew")
    p.add_argument("--cert")
    p.add_argument("--key")
    p = sub.add_parser("bundle")
    p.add_argument("--output", required=True)
    args = parser.parse_args()
    require_root()
    os.umask(0o077)
    # Serialize installs/renewal/undo. The guard may execute independently after a killed installer.
    with open("/run/edge-addons.lock", "w") as lock:
        if args.command != "guard":
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "install":
            installation(args)
        elif args.command == "guard":
            guard(args.token)
        elif args.command == "uninstall":
            uninstall()
        elif args.command == "renew":
            renewal(args)
        elif args.command == "bundle":
            bundle(args)
        else:
            state = read_json(ROOT / "private/state.json")
            if args.command == "links":
                say("\n".join(client_links(state)))
            elif args.command == "check":
                native_checks(state)
                check_live(state)
            else:
                say("EDGE ADDONS " + VERSION + " | " + state["role"] + " | " +
                    state["address"] + ":" + str(state["port"]) + " | committed=" + str(state["committed"]))
                for name in SERVICES:
                    say(name + ": " + run(["systemctl", "is-active", name], check=False).stdout.strip())
                say("Existing relay/protocol settings are outside this installer's ownership.")

if __name__ == "__main__":
    try:
        main()
    except (Failure, OSError, ValueError, KeyError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        say("STOP: " + (str(error) or "Cancelled."))
        sys.exit(1)
