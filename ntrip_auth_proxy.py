#!/usr/bin/env python3
import base64
import json
import os
import select
import signal
import socket
import socketserver
import sys
import time
from typing import Dict, Optional, Tuple


LISTEN_HOST = os.environ.get("NTRIP_AUTH_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("NTRIP_AUTH_LISTEN_PORT", "2101"))
UPSTREAM_HOST = os.environ.get("NTRIP_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("NTRIP_UPSTREAM_PORT", "2102"))
TOKEN_FILE = os.environ.get("NTRIP_AUTH_FILE", "/usr/local/etc/millipede/clients.auth")
TOKEN_ENV = os.environ.get("NTRIP_AUTH_TOKENS", "")
HEADER_LIMIT = int(os.environ.get("NTRIP_AUTH_HEADER_LIMIT", "16384"))
IDLE_TIMEOUT = int(os.environ.get("NTRIP_AUTH_IDLE_TIMEOUT", "7200"))


def log_event(event: str, **fields: object) -> None:
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    record.update(fields)
    print(json.dumps(record, separators=(",", ":"), sort_keys=True), flush=True)


def load_tokens() -> Tuple[Dict[str, str], Dict[str, str]]:
    client_tokens: Dict[str, str] = {}

    def add_entry(client_id: str, token: str) -> None:
        client_id = client_id.strip()
        token = token.strip()
        if client_id and token:
            client_tokens[client_id] = token

    if TOKEN_ENV:
        for item in TOKEN_ENV.split(","):
            if ":" not in item:
                log_event("auth_config_invalid_entry", source="env", entry=item)
                continue
            client_id, token = item.split(":", 1)
            add_entry(client_id, token)

    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as handle:
            for line_no, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    log_event("auth_config_invalid_entry", source=TOKEN_FILE, line=line_no)
                    continue
                client_id, token = line.split(":", 1)
                add_entry(client_id, token)
    except FileNotFoundError:
        pass

    token_clients = {token: client_id for client_id, token in client_tokens.items()}
    return client_tokens, token_clients


CLIENT_TOKENS, TOKEN_CLIENTS = load_tokens()


def parse_headers(header_bytes: bytes) -> Tuple[str, str, str, Dict[str, str]]:
    text = header_bytes.decode("iso-8859-1", errors="replace")
    lines = text.replace("\r\n", "\n").split("\n")
    request_line = lines[0].strip()
    parts = request_line.split()
    method = parts[0] if len(parts) >= 1 else ""
    path = parts[1] if len(parts) >= 2 else ""
    version = parts[2] if len(parts) >= 3 else ""
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return method, path, version, headers


def basic_auth_client(value: str) -> Optional[str]:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    client_id, token = decoded.split(":", 1)
    if CLIENT_TOKENS.get(client_id) == token:
        return client_id
    return None


def authenticate(headers: Dict[str, str]) -> Tuple[Optional[str], str]:
    authorization = headers.get("authorization", "")
    if authorization:
        scheme, _, value = authorization.partition(" ")
        scheme = scheme.lower()
        value = value.strip()
        if scheme == "basic":
            client_id = basic_auth_client(value)
            if client_id:
                return client_id, "basic"
        elif scheme == "bearer":
            client_id = TOKEN_CLIENTS.get(value)
            if client_id:
                return client_id, "bearer"

    header_token = headers.get("x-client-token") or headers.get("x-ntrip-token")
    if header_token:
        client_id = TOKEN_CLIENTS.get(header_token)
        if client_id:
            return client_id, "token_header"

    return None, "none"


def recv_headers(conn: socket.socket) -> Optional[bytes]:
    data = bytearray()
    while len(data) <= HEADER_LIMIT:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data.extend(chunk)
        if b"\r\n\r\n" in data or b"\n\n" in data:
            return bytes(data)
    return None


def inject_forwarded_for(request: bytes, remote_ip: str) -> bytes:
    marker = b"\r\n\r\n"
    separator = b"\r\n"
    if marker not in request:
        marker = b"\n\n"
        separator = b"\n"
        if marker not in request:
            return request
    head, body = request.split(marker, 1)
    lines = head.split(separator)
    filtered = [
        line
        for line in lines
        if not line.lower().startswith(b"x-forwarded-for:")
    ]
    filtered.append(b"X-Forwarded-For: " + remote_ip.encode("ascii", errors="ignore"))
    return separator.join(filtered) + marker + body


def send_unauthorized(conn: socket.socket) -> None:
    body = b"Unauthorized\n"
    response = (
        b"HTTP/1.1 401 Unauthorized\r\n"
        b'WWW-Authenticate: Basic realm="Millipede"\r\n'
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    conn.sendall(response)


class NtripAuthHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        start = time.monotonic()
        remote_ip, remote_port = self.client_address[:2]
        client_id = None
        method = ""
        path = ""
        upstream_bytes = 0
        downstream_bytes = 0
        status = "accepted"

        self.request.settimeout(15)
        first_request = recv_headers(self.request)
        if not first_request:
            log_event("request_rejected", reason="invalid_or_too_large_header", remote_ip=remote_ip)
            return

        method, path, version, headers = parse_headers(first_request)
        client_id, auth_method = authenticate(headers)
        if not client_id:
            status = "rejected"
            log_event(
                "request_rejected",
                method=method,
                path=path,
                reason="invalid_token",
                remote_ip=remote_ip,
                remote_port=remote_port,
                user_agent=headers.get("user-agent", ""),
            )
            send_unauthorized(self.request)
            return

        log_event(
            "request_accepted",
            auth_method=auth_method,
            client_id=client_id,
            method=method,
            path=path,
            remote_ip=remote_ip,
            remote_port=remote_port,
            user_agent=headers.get("user-agent", ""),
        )

        upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=15)
        upstream.settimeout(None)
        self.request.settimeout(None)
        forwarded_request = inject_forwarded_for(first_request, remote_ip)
        upstream.sendall(forwarded_request)
        upstream_bytes += len(forwarded_request)

        sockets = [self.request, upstream]
        try:
            while sockets:
                readable, _, exceptional = select.select(sockets, [], sockets, IDLE_TIMEOUT)
                if exceptional or not readable:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        if sock is self.request:
                            sockets.remove(self.request)
                            try:
                                upstream.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            continue
                        sockets = []
                        break
                    if sock is self.request:
                        upstream.sendall(data)
                        upstream_bytes += len(data)
                    else:
                        self.request.sendall(data)
                        downstream_bytes += len(data)
        finally:
            upstream.close()
            duration_ms = int((time.monotonic() - start) * 1000)
            log_event(
                "request_closed",
                client_id=client_id,
                downstream_bytes=downstream_bytes,
                duration_ms=duration_ms,
                method=method,
                path=path,
                remote_ip=remote_ip,
                status=status,
                upstream_bytes=upstream_bytes,
            )


class ThreadingNtripServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    if not CLIENT_TOKENS:
        log_event("auth_config_empty", message="no clients configured; all requests will be rejected")
    else:
        log_event("auth_config_loaded", clients=len(CLIENT_TOKENS))

    server = ThreadingNtripServer((LISTEN_HOST, LISTEN_PORT), NtripAuthHandler)

    def stop(signum, _frame) -> None:
        log_event("proxy_stopping", signal=signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log_event("proxy_started", listen_host=LISTEN_HOST, listen_port=LISTEN_PORT, upstream_host=UPSTREAM_HOST, upstream_port=UPSTREAM_PORT)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
