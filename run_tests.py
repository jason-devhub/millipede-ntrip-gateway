#!/usr/bin/env python3
"""Tests d'intégration de la passerelle NTRIP (recommandations _security_report.md).

Exécution : depuis la racine du dépôt `millipede-coolify/` :
    python3 run_tests.py
"""

import base64
import importlib
import os
import signal
import socket
import sys
import threading
import time
from typing import Tuple

_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _REPO_ROOT)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_clients_auth(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


class FakeUpstream(threading.Thread):
    """Faux serveur TCP qui renvoie une réponse HTTP simple."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(50)
        self._sock.settimeout(0.5)

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(1.0)
            data = b""
            while b"\r\n\r\n" not in data and b"\n\n" not in data and len(data) < 16384:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
            self.received.append(data)
            body = b"sourcetable\n"
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            try:
                conn.sendall(resp)
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


def http_request(host: str, port: int, raw: bytes, *, deadline: float = 2.0) -> bytes:
    s = socket.create_connection((host, port), timeout=deadline)
    try:
        s.settimeout(deadline)
        s.sendall(raw)
        s.shutdown(socket.SHUT_WR)
        chunks = []
        try:
            while True:
                buf = s.recv(4096)
                if not buf:
                    break
                chunks.append(buf)
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        try:
            s.close()
        except OSError:
            pass


def setup_proxy(
    *,
    listen_port: int,
    upstream_port: int,
    tokens_file: str,
    env_tokens: str = "",
    anonymize: str = "",
    rl_max_fails: str = "3",
    rl_lockout: str = "2",
    reject_delay: str = "0",
    max_connections: str = "10",
):
    os.environ["NTRIP_AUTH_LISTEN_HOST"] = "127.0.0.1"
    os.environ["NTRIP_AUTH_LISTEN_PORT"] = str(listen_port)
    os.environ["NTRIP_UPSTREAM_HOST"] = "127.0.0.1"
    os.environ["NTRIP_UPSTREAM_PORT"] = str(upstream_port)
    os.environ["NTRIP_AUTH_FILE"] = tokens_file
    os.environ["NTRIP_AUTH_TOKENS"] = env_tokens
    os.environ["NTRIP_ALLOW_PLAINTEXT"] = "1"
    os.environ["NTRIP_AUTH_RL_MAX_FAILS"] = rl_max_fails
    os.environ["NTRIP_AUTH_RL_LOCKOUT"] = rl_lockout
    os.environ["NTRIP_AUTH_REJECT_DELAY"] = reject_delay
    os.environ["NTRIP_AUTH_MAX_CONNECTIONS"] = max_connections
    os.environ["NTRIP_AUTH_HEADER_DEADLINE"] = "2"
    os.environ["NTRIP_AUTH_LOG_IP_ANONYMIZE"] = anonymize
    sys.modules.pop("ntrip_auth_proxy", None)
    return importlib.import_module("ntrip_auth_proxy")


def start_proxy_thread(module) -> Tuple[threading.Thread, object]:
    module.snapshot_env_tokens()
    module._validate_startup_safety()
    module.reload_tokens(strict=True)
    server = module.ThreadingNtripServer(
        (module.LISTEN_HOST, module.LISTEN_PORT), module.NtripAuthHandler
    )
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    t.start()
    return t, server


def main() -> int:
    tmp_dir = os.path.join(_REPO_ROOT, ".proxy_test_tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    tokens_file = os.path.join(tmp_dir, "clients.auth")
    write_clients_auth(tokens_file, "rover1:secrettoken123456\nrover2:autretokenABCDEF\n")

    upstream_port = free_port()
    listen_port = free_port()
    upstream = FakeUpstream("127.0.0.1", upstream_port)
    upstream.start()

    module = setup_proxy(
        listen_port=listen_port,
        upstream_port=upstream_port,
        tokens_file=tokens_file,
    )
    _t, server = start_proxy_thread(module)
    time.sleep(0.3)

    failures: list[str] = []

    def check(name: str, condition: bool, info: str = "") -> None:
        if condition:
            print(f"[OK] {name}")
        else:
            failures.append(name)
            print(f"[KO] {name} -- {info}")

    resp = http_request("127.0.0.1", listen_port, b"GET /healthz HTTP/1.0\r\nHost: x\r\n\r\n")
    check("healthz GET 200", resp.startswith(b"HTTP/1.1 200") and b"ok" in resp, resp[:100].decode("latin1"))

    resp = http_request("127.0.0.1", listen_port, b"HEAD /healthz HTTP/1.0\r\nHost: x\r\n\r\n")
    check("healthz HEAD 200", resp.startswith(b"HTTP/1.1 200"), resp[:100].decode("latin1"))

    resp = http_request("127.0.0.1", listen_port, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
    check("no auth -> 401", resp.startswith(b"HTTP/1.1 401"), resp[:100].decode("latin1"))

    creds = base64.b64encode(b"rover1:secrettoken123456").decode("ascii")
    raw = f"GET /SOMEMP HTTP/1.0\r\nHost: x\r\nAuthorization: Basic {creds}\r\n\r\n".encode()
    resp = http_request("127.0.0.1", listen_port, raw)
    check(
        "basic auth ok -> 200",
        resp.startswith(b"HTTP/1.1 200") and b"sourcetable" in resp,
        resp[:200].decode("latin1"),
    )

    raw = b"GET / HTTP/1.0\r\nHost: x\r\nAuthorization: Bearer secrettoken123456\r\n\r\n"
    resp = http_request("127.0.0.1", listen_port, raw)
    check("bearer auth ok -> 200", resp.startswith(b"HTTP/1.1 200"), resp[:200].decode("latin1"))

    raw = b"GET / HTTP/1.0\r\nHost: x\r\nX-Client-Token: autretokenABCDEF\r\n\r\n"
    resp = http_request("127.0.0.1", listen_port, raw)
    check("x-client-token ok -> 200", resp.startswith(b"HTTP/1.1 200"), resp[:200].decode("latin1"))

    raw = (
        b"GET /adm/api/sources HTTP/1.0\r\nHost: x\r\n"
        b"Authorization: Bearer secrettoken123456\r\n\r\n"
    )
    resp = http_request("127.0.0.1", listen_port, raw)
    check("path /adm blocked -> 403", resp.startswith(b"HTTP/1.1 403"), resp[:200].decode("latin1"))

    raw = (
        b"GET /api/v1 HTTP/1.0\r\nHost: x\r\n"
        b"Authorization: Bearer secrettoken123456\r\n\r\n"
    )
    resp = http_request("127.0.0.1", listen_port, raw)
    check("path /api blocked -> 403", resp.startswith(b"HTTP/1.1 403"), resp[:200].decode("latin1"))

    raw = (
        b"POST /MP HTTP/1.0\r\nHost: x\r\n"
        b"Authorization: Bearer secrettoken123456\r\n\r\n"
    )
    resp = http_request("127.0.0.1", listen_port, raw)
    check("method POST blocked -> 403", resp.startswith(b"HTTP/1.1 403"), resp[:200].decode("latin1"))

    raw = (
        b"GET / HTTP/1.0\r\nHost: x\r\n"
        b"Authorization: Bearer secrettoken123456\r\n"
        b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    resp = http_request("127.0.0.1", listen_port, raw)
    check("request smuggling blocked -> 403", resp.startswith(b"HTTP/1.1 403"), resp[:200].decode("latin1"))

    upstream.received.clear()
    raw = (
        b"GET /MOUNT HTTP/1.0\r\nHost: x\r\n"
        b"Authorization: Bearer secrettoken123456\r\n"
        b"X-Forwarded-For: 1.2.3.4\r\nVia: bad\r\nX-Real-IP: 9.9.9.9\r\n"
        b"CF-Connecting-IP: 8.8.8.8\r\nForwarded: for=10.0.0.1\r\n\r\n"
    )
    http_request("127.0.0.1", listen_port, raw)
    time.sleep(0.2)
    seen = upstream.received[0] if upstream.received else b""
    seen_lower = seen.lower()
    no_real = b"x-real-ip" not in seen_lower
    no_via = b"via:" not in seen_lower
    no_cf = b"cf-connecting" not in seen_lower
    no_fwd = b"\r\nforwarded:" not in seen_lower
    has_xff_127 = b"x-forwarded-for: 127.0.0.1" in seen_lower
    no_attacker_ip = b"1.2.3.4" not in seen_lower
    no_authorization = b"\r\nauthorization:" not in seen_lower
    check("provenance headers stripped", no_real and no_via and no_cf and no_fwd, repr(seen[:400]))
    check("x-forwarded-for rewritten to local", has_xff_127 and no_attacker_ip, repr(seen[:400]))
    check("authorization header not forwarded", no_authorization, repr(seen[:400]))

    for _ in range(3):
        http_request(
            "127.0.0.1",
            listen_port,
            b"GET / HTTP/1.0\r\nHost: x\r\nAuthorization: Bearer WRONGTOKEN\r\n\r\n",
        )
    resp = http_request(
        "127.0.0.1",
        listen_port,
        b"GET / HTTP/1.0\r\nHost: x\r\nAuthorization: Bearer WRONGTOKEN\r\n\r\n",
    )
    check("rate limit after fails -> 429", resp.startswith(b"HTTP/1.1 429"), resp[:200].decode("latin1"))
    raw = b"GET / HTTP/1.0\r\nHost: x\r\nAuthorization: Bearer secrettoken123456\r\n\r\n"
    resp = http_request("127.0.0.1", listen_port, raw)
    check("rate limit blocks even valid -> 429", resp.startswith(b"HTTP/1.1 429"), resp[:200].decode("latin1"))
    time.sleep(2.3)
    resp = http_request("127.0.0.1", listen_port, raw)
    check("rate limit expires after lockout", resp.startswith(b"HTTP/1.1 200"), resp[:200].decode("latin1"))

    big = b"X: " + b"A" * 20000 + b"\r\n"
    raw = b"GET / HTTP/1.0\r\nHost: x\r\n" + big + b"\r\n"
    try:
        resp = http_request("127.0.0.1", listen_port, raw, deadline=3.0)
    except OSError:
        resp = b""
    check("oversized headers rejected (closed/no 200)", not resp.startswith(b"HTTP/1.1 200"), resp[:100].decode("latin1"))

    write_clients_auth(
        tokens_file,
        "rover1:secrettoken123456\nrover2:autretokenABCDEF\nrover3:nouveau000\n",
    )
    signal.signal(signal.SIGHUP, lambda *_: module.reload_tokens(strict=False))
    os.kill(os.getpid(), signal.SIGHUP)
    time.sleep(0.3)
    raw = b"GET / HTTP/1.0\r\nHost: x\r\nAuthorization: Bearer nouveau000\r\n\r\n"
    resp = http_request("127.0.0.1", listen_port, raw)
    check("SIGHUP reload new token works", resp.startswith(b"HTTP/1.1 200"), resp[:200].decode("latin1"))

    check("env var snapshot cleared", os.environ.get("NTRIP_AUTH_TOKENS", "_NOT_SET") in ("", "_NOT_SET"))

    os.environ["NTRIP_ALLOW_PLAINTEXT"] = ""
    os.environ["NTRIP_AUTH_LISTEN_HOST"] = "0.0.0.0"
    sys.modules.pop("ntrip_auth_proxy", None)
    mod2 = importlib.import_module("ntrip_auth_proxy")
    try:
        mod2._validate_startup_safety()
        check("plaintext refused without consent", False, "did not raise SystemExit")
    except SystemExit as exc:
        check("plaintext refused without consent", exc.code == 2, f"got code={exc.code}")

    os.environ["NTRIP_AUTH_LISTEN_HOST"] = "127.0.0.1"
    os.environ["NTRIP_ALLOW_PLAINTEXT"] = ""
    sys.modules.pop("ntrip_auth_proxy", None)
    mod3 = importlib.import_module("ntrip_auth_proxy")
    try:
        mod3._validate_startup_safety()
        check("loopback allowed without consent", True)
    except SystemExit as exc:
        check("loopback allowed without consent", False, f"got code={exc.code}")

    sys.modules.pop("ntrip_auth_proxy", None)
    os.environ["NTRIP_AUTH_LOG_IP_ANONYMIZE"] = "1"
    mod4 = importlib.import_module("ntrip_auth_proxy")
    check("ipv4 anonymized to .0", mod4.anonymize_ip("1.2.3.4") == "1.2.3.0")
    check("ipv6 anonymized to /64", mod4.anonymize_ip("2001:db8::1234") == "2001:db8::")
    check("invalid ip preserved", mod4.anonymize_ip("notanip") == "notanip")

    write_clients_auth(tokens_file, "a:sametoken\nb:sametoken\n")
    sys.modules.pop("ntrip_auth_proxy", None)
    os.environ["NTRIP_AUTH_FILE"] = tokens_file
    os.environ["NTRIP_AUTH_TOKENS"] = ""
    mod5 = importlib.import_module("ntrip_auth_proxy")
    mod5.snapshot_env_tokens()
    try:
        mod5.reload_tokens(strict=True)
        check("duplicate tokens refused (strict)", False, "did not raise")
    except SystemExit:
        check("duplicate tokens refused (strict)", True)
    try:
        mod5.reload_tokens(strict=False)
        check("duplicate tokens accepted (non-strict)", True)
    except SystemExit:
        check("duplicate tokens accepted (non-strict)", False, "should not raise")

    server.shutdown()
    server.server_close()
    upstream.stop()

    print()
    if failures:
        print(f"FAILED: {len(failures)} test(s)")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
