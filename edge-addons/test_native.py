#!/usr/bin/env python3
"""Native interoperability and data-plane tests, on disposable Linux CI only."""
import argparse
import contextlib
import copy
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import edge_addons as e

HERE = pathlib.Path(__file__).resolve().parent
PAYLOAD = hashlib.shake_256(b"edge-addons-native-test").digest(524288)

def checked(args, **kw):
    return subprocess.run([str(x) for x in args], check=True, capture_output=True, **kw)

def certificates(base):
    ca, ca_key = base / "ca.crt", base / "ca.key"
    key, csr, cert = base / "tls.key", base / "tls.csr", base / "tls.crt"
    checked(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", ca_key, "-out", ca, "-days", "30", "-subj", "/CN=Edge test CA",
             "-addext", "basicConstraints=critical,CA:TRUE"])
    checked(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
             "-out", csr, "-subj", "/CN=edge-foreign.test"])
    ext = base / "ext.cnf"
    ext.write_text("subjectAltName=DNS:edge-foreign.test,DNS:edge-iran.test,DNS:origin.test\n"
                   "basicConstraints=critical,CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    checked(["openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
             "-CAcreateserial", "-out", cert, "-days", "14", "-extfile", ext])
    return ca, cert, key

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)

class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)
    def do_POST(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        answer = hashlib.sha256(data).hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

def recvn(s, length):
    data = b""
    while len(data) < length:
        part = s.recv(length - len(data))
        if not part:
            raise RuntimeError("SOCKS control connection closed.")
        data += part
    return data

def socks_address(s):
    kind = recvn(s, 1)[0]
    if kind == 1:
        address = socket.inet_ntoa(recvn(s, 4))
    elif kind == 4:
        address = socket.inet_ntop(socket.AF_INET6, recvn(s, 16))
    elif kind == 3:
        address = recvn(s, recvn(s, 1)[0]).decode()
    else:
        raise AssertionError("Unexpected SOCKS address type.")
    port = struct.unpack("!H", recvn(s, 2))[0]
    return address, port

def udp_roundtrip(socks_port, echo_port):
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as control:
        control.settimeout(10)
        control.sendall(b"\x05\x01\x00")
        assert recvn(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        assert recvn(control, 3) == b"\x05\x00\x00"
        host, port = socks_address(control)
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(10)
            for size in (64, 1200):
                nonce = os.urandom(size)
                header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo_port)
                udp.sendto(header + nonce, (host, port))
                answer = udp.recv(65535)
                assert answer[:3] == b"\x00\x00\x00"
                kind = answer[3]
                if kind == 1:
                    offset = 10
                elif kind == 4:
                    offset = 22
                elif kind == 3:
                    offset = 7 + answer[4]
                else:
                    raise AssertionError("Bad UDP address.")
                assert answer[offset:] == nonce, "UDP data changed."
    print("PASS UDP authenticated echo: random 64- and 1200-byte payloads", flush=True)

def data_roundtrip(socks_port, origin_port, ca, base):
    target = "https://origin.test:" + str(origin_port) + "/data"
    output = base / "result.bin"
    common = ["curl", "--silent", "--show-error", "--fail", "--max-time", "25",
        "--noproxy", "", "--socks5-hostname", "127.0.0.1:" + str(socks_port),
        "--connect-to", "origin.test:" + str(origin_port) + ":127.0.0.1:" + str(origin_port),
        "--cacert", ca]
    checked(common + ["--output", output, target], timeout=30)
    assert output.read_bytes() == PAYLOAD
    upload = base / "upload.bin"
    upload.write_bytes(PAYLOAD)
    p = checked(common + ["--data-binary", "@" + str(upload), target], timeout=30)
    assert p.stdout.decode() == hashlib.sha256(PAYLOAD).hexdigest()
    print("PASS verified HTTPS download + upload: 524288 bytes each; SHA256=" +
          hashlib.sha256(PAYLOAD).hexdigest(), flush=True)

def lab_port(avoid=None):
    """Find a genuinely free loopback block; never assume fixed lab ports are free."""
    for attempt in range(100):
        port = 20000 + int.from_bytes(os.urandom(2), "big") % 40000
        if avoid is not None and abs(port - avoid) < 8:
            continue
        sockets = []
        try:
            for address in ("127.0.0.1", "127.0.0.2", "127.0.0.3", "::1"):
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                for candidate in range(port, port + 4):
                    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                        s = socket.socket(family, kind)
                        sockets.append(s)
                        if family == socket.AF_INET6:
                            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        s.bind((address, candidate))
            return port
        except OSError:
            continue
        finally:
            for s in sockets:
                s.close()
    raise RuntimeError("No free loopback port block for the native lab.")

def native_tests(base, offline=None):
    bins = e.prepare_binaries(base, offline)
    ca, cert, key = certificates(base)
    foreign_port = lab_port()
    iran_port = lab_port(avoid=foreign_port)
    foreign = e.new_state("foreign", "edge-foreign.test", "127.0.0.2", ipv6="::1", port=foreign_port)
    peer = e.public_peer(foreign)
    iran = e.new_state("iran", "edge-iran.test", "127.0.0.3", ipv6="::1", port=iran_port, peer=peer)
    assert not e.xhttp_out(peer)["streamSettings"]["tlsSettings"]["allowInsecure"]
    assert not e.tuic_client_out(foreign)["tls"]["insecure"]
    help_text = checked([bins / "lego", "--help"]).stdout.decode()
    assert "--dns.propagation-wait" in help_text, "Pinned ACME flag unavailable"
    print("PASS pinned lego supports the exact DNS-01 flags.", flush=True)

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    origin.socket = ctx.wrap_socket(origin.socket, server_side=True)
    echo = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Echo)
    for server in (origin, echo):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        with contextlib.ExitStack() as stack:
            for label, state in (("foreign", foreign), ("iran", iran)):
                cfg = e.configs(state, cert, key, test_ca=ca)
                for name, config in cfg.items():
                    path = base / (label + "-" + name)
                    e.write_json(path, config)
                    if name == "xray.json":
                        checked([bins / "xray", "run", "-test", "-c", path])
                        command = [bins / "xray", "run", "-c", path]
                    elif name == "tuic.json":
                        checked([bins / "sing-box", "check", "-c", path])
                        command = [bins / "sing-box", "run", "-c", path]
                    else:
                        checked([bins / "caddy", "validate", "--config", path])
                        command = [bins / "caddy", "run", "--config", path]
                    stack.enter_context(e.process(command, base / (label + "-" + name + ".log")))
            e.wait_tcp(foreign["port"])
            e.wait_tcp(iran["port"])
            for label, state in (("foreign", foreign), ("iran", iran)):
                for protocol in ("xhttp", "tuic"):
                    print("\nCASE " + protocol + " -> " + label +
                          (" -> foreign XHTTP" if label == "iran" else ""), flush=True)
                    port = e.free_port()
                    if protocol == "xhttp":
                        peer_local = e.public_peer(state)
                        peer_local["transport_ip"] = "127.0.0.1"
                        cfg = e.socks_client_config(e.xhttp_out(peer_local, test_ca=ca), port)
                        command = [bins / "xray", "run", "-c"]
                    else:
                        cfg = {"inbounds": [{"type": "socks", "listen": "127.0.0.1",
                                            "listen_port": port}],
                               "outbounds": [e.tuic_client_out(state, "127.0.0.1", ca)]}
                        command = [bins / "sing-box", "run", "-c"]
                    path = base / (label + "-" + protocol + "-client.json")
                    e.write_json(path, cfg)
                    with e.process(command + [path], base / (label + "-" + protocol + "-client.log")) as p:
                        e.wait_tcp(port, p)
                        data_roundtrip(port, origin.server_port, ca, base)
                        udp_roundtrip(port, echo.server_address[1])

            bad = copy.deepcopy(foreign)
            bad["tuic_password"] += "-incorrect"
            port = e.free_port()
            cfg = {"inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
                   "outbounds": [e.tuic_client_out(bad, "127.0.0.1", ca)]}
            path = base / "wrong-password.json"
            e.write_json(path, cfg)
            with e.process([bins / "sing-box", "run", "-c", path], base / "wrong-password.log") as p:
                e.wait_tcp(port, p)
                attempt = subprocess.run(["curl", "--silent", "--max-time", "6", "--noproxy", "",
                    "--socks5-hostname", "127.0.0.1:" + str(port),
                    "--cacert", ca, "--connect-to", "origin.test:" + str(origin.server_port) + ":127.0.0.1:" + str(origin.server_port),
                    "https://origin.test:" + str(origin.server_port) + "/data"], capture_output=True, timeout=10)
                assert attempt.returncode != 0, "Incorrect TUIC password was accepted."
            print("PASS incorrect TUIC password rejected.", flush=True)
    except BaseException:
        for log in sorted(base.glob("*.log")):
            print("\nNATIVE LOG " + log.name + "\n" + log.read_text(errors="replace")[-10000:])
        raise
    finally:
        for server in (origin, echo):
            server.shutdown()
            server.server_close()
    return ca, cert, key

def systemd_test(base):
    """Exercise REAL DynamicUser credentials and rollback on a disposable runner."""
    assert os.environ.get("GITHUB_ACTIONS") == "true", "CI-only system test."
    assert os.geteuid() == 0
    ca, cert, key = certificates(base / "systemd-cert")
    ca_target = pathlib.Path("/usr/local/share/ca-certificates/edge-addons-ci.crt")
    sentinel = pathlib.Path("/opt/iran-relay/current/config.json")
    unit = pathlib.Path("/etc/systemd/system/iran-relay.service")
    assert not unit.exists() and not sentinel.exists() and not e.ROOT.exists()
    try:
        shutil.copyfile(ca, ca_target)
        checked(["update-ca-certificates"])
        checked(["ip", "address", "add", "127.0.0.2/32", "dev", "lo"])
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text('{"unchanged":"existing relay fixture"}\n')
        unit.write_text("[Unit]\nDescription=Existing relay test sentinel\n[Service]\nExecStart=/bin/sleep infinity\n")
        checked(["systemctl", "daemon-reload"])
        checked(["systemctl", "start", "iran-relay.service"])
        before_pid = checked(["systemctl", "show", "iran-relay.service", "-p", "MainPID", "--value"]).stdout
        before_hash = e.sha(sentinel)
        script = HERE / "edge_addons.py"
        checked([sys.executable, script, "install", "--role", "foreign",
                 "--domain", "edge-foreign.test", "--bind-ip", "127.0.0.2",
                 "--offline-dir", base, "--cert", cert, "--key", key], timeout=180)
        for name in e.SERVICES:
            checked(["systemctl", "is-active", "--quiet", name])
            user = checked(["systemctl", "show", name, "-p", "DynamicUser", "--value"]).stdout.strip()
            assert user == b"yes"
        checked([sys.executable, script, "check"], timeout=100)
        assert checked(["systemctl", "show", "iran-relay.service", "-p", "MainPID", "--value"]).stdout == before_pid
        assert e.sha(sentinel) == before_hash
        checked([sys.executable, script, "uninstall"], timeout=60)
        assert checked(["systemctl", "show", "iran-relay.service", "-p", "MainPID", "--value"]).stdout == before_pid
        assert e.sha(sentinel) == before_hash
        for name in e.SERVICES:
            assert not (e.UNIT_ROOT / name).exists()
        print("PASS real systemd DynamicUser + .json credentials, unchanged existing PID/config, and uninstall.", flush=True)
    except subprocess.CalledProcessError as error:
        print("SYSTEMD COMMAND FAILED:", error.cmd, flush=True)
        print((error.stdout or b"").decode(errors="replace"))
        print((error.stderr or b"").decode(errors="replace"))
        for name in e.SERVICES:
            print(checked(["journalctl", "-u", name, "-n", "35", "--no-pager"]).stdout.decode(errors="replace"))
        for path in (e.ROOT / "private").glob("*.log"):
            print(path.name, path.read_text(errors="replace")[-10000:])
        raise
    finally:
        subprocess.run(["systemctl", "stop", "iran-relay.service"], capture_output=True)
        unit.unlink(missing_ok=True)
        if e.ROOT.exists():
            subprocess.run([sys.executable, HERE / "edge_addons.py", "uninstall"], capture_output=True)
        ca_target.unlink(missing_ok=True)
        subprocess.run(["update-ca-certificates"], capture_output=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--systemd", action="store_true")
    parser.add_argument("--offline-dir")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="edge-native-ci-") as work:
        base = pathlib.Path(work)
        native_tests(base, args.offline_dir)
        if args.systemd:
            (base / "systemd-cert").mkdir()
            systemd_test(base)
    print("\nALL NATIVE DATA-PLANE CHECKS PASSED", flush=True)

if __name__ == "__main__":
    main()
