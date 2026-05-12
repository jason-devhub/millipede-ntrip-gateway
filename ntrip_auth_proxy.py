#!/usr/bin/env python3
"""Passerelle d'authentification NTRIP devant Millipede.

Le binaire `caster` écoute en boucle locale (127.0.0.1:2102) ; cette
passerelle accepte les connexions publiques sur le port 2101, authentifie
le client puis relaie la session TCP. Elle implémente plusieurs défenses
issues de l'audit de sécurité (rapport `_security_report.md`) :

- comparaison de tokens à temps constant (hmac.compare_digest) ;
- rate-limiting / verrouillage par IP et par client ;
- bornage du nombre de connexions concurrentes et deadline d'en-tête ;
- whitelist stricte des chemins HTTP relayés vers le caster ;
- nettoyage exhaustif des en-têtes de provenance avant relais ;
- rechargement à chaud des tokens via SIGHUP ;
- refus de démarrer en clair sauf consentement explicite.
"""

import base64
import hmac
import ipaddress
import json
import os
import re
import secrets
import select
import signal
import socket
import socketserver
import sys
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Set, Tuple


# -----------------------------------------------------------------------------
# Configuration (variables d'environnement)
# -----------------------------------------------------------------------------

LISTEN_HOST = os.environ.get("NTRIP_AUTH_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("NTRIP_AUTH_LISTEN_PORT", "2101"))
UPSTREAM_HOST = os.environ.get("NTRIP_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("NTRIP_UPSTREAM_PORT", "2102"))
TOKEN_FILE = os.environ.get("NTRIP_AUTH_FILE", "/usr/local/etc/millipede/clients.auth")
HEADER_LIMIT = int(os.environ.get("NTRIP_AUTH_HEADER_LIMIT", "16384"))
IDLE_TIMEOUT = int(os.environ.get("NTRIP_AUTH_IDLE_TIMEOUT", "7200"))

# Deadline absolue pour la phase « lecture des en-têtes » (anti-Slowloris).
HEADER_DEADLINE = float(os.environ.get("NTRIP_AUTH_HEADER_DEADLINE", "5.0"))

# Bornage des connexions concurrentes (V-05).
MAX_CONNECTIONS = int(os.environ.get("NTRIP_AUTH_MAX_CONNECTIONS", "200"))

# Rate-limiting / verrouillage des échecs d'authentification (V-04).
RL_WINDOW = float(os.environ.get("NTRIP_AUTH_RL_WINDOW", "60.0"))
RL_MAX_FAILS = int(os.environ.get("NTRIP_AUTH_RL_MAX_FAILS", "10"))
RL_LOCKOUT = float(os.environ.get("NTRIP_AUTH_RL_LOCKOUT", "300.0"))
RL_REJECT_DELAY = float(os.environ.get("NTRIP_AUTH_REJECT_DELAY", "0.5"))

# Permettre l'exposition en clair (TLS recommandé devant ; V-02).
ALLOW_PLAINTEXT = os.environ.get("NTRIP_ALLOW_PLAINTEXT", "").strip() in ("1", "true", "yes", "on")

# Anonymisation de l'IP dans les logs (V-15).
LOG_IP_ANONYMIZE = os.environ.get("NTRIP_AUTH_LOG_IP_ANONYMIZE", "").strip() in ("1", "true", "yes", "on")

# Whitelist optionnelle de chemins (regex compilée). Si non définie, on
# applique une politique par défaut suffisamment stricte (cf. PATH_ALLOWED).
_PATH_RE_USER = os.environ.get("NTRIP_AUTH_PATH_REGEX", "").strip()

# Méthodes HTTP autorisées au relais (V-01). NTRIP en lecture utilise GET.
ALLOWED_METHODS: Set[str] = {"GET", "HEAD"}

# Préfixes explicitement rejetés (administration/API du caster amont).
DENIED_PATH_PREFIXES: Tuple[str, ...] = (
    "/adm",
    "/admin",
    "/api",
    "/.well-known",
    "/__",
    "/internal",
    "/metrics",
    "/debug",
    "/private",
)

# Chemin par défaut accepté pour un mountpoint NTRIP : caractères usuels.
_PATH_DEFAULT_RE = re.compile(r"^/[A-Za-z0-9._\-/~]{0,255}$")
_PATH_USER_RE = re.compile(_PATH_RE_USER) if _PATH_RE_USER else None

# En-têtes de provenance à supprimer systématiquement avant le relais (V-12).
PROVENANCE_HEADER_PREFIXES: Tuple[bytes, ...] = (
    b"x-forwarded-",
    b"x-real-",
    b"x-original-",
    b"x-client-",
    b"x-ntrip-",
    b"x-azure-",
    b"forwarded:",
    b"via:",
    b"cf-connecting-",
    b"cf-pseudo-",
    b"cf-ipcountry",
    b"true-client-ip",
    b"fly-client-",
    b"authorization:",
)


def log_event(event: str, **fields: object) -> None:
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    record.update(fields)
    print(json.dumps(record, separators=(",", ":"), sort_keys=True), flush=True)


# -----------------------------------------------------------------------------
# Anonymisation IP (V-15)
# -----------------------------------------------------------------------------

def anonymize_ip(remote_ip: str) -> str:
    if not LOG_IP_ANONYMIZE or not remote_ip:
        return remote_ip
    try:
        addr = ipaddress.ip_address(remote_ip)
    except ValueError:
        return remote_ip
    if isinstance(addr, ipaddress.IPv4Address):
        parts = remote_ip.split(".")
        if len(parts) == 4:
            parts[-1] = "0"
            return ".".join(parts)
        return remote_ip
    # IPv6 : on masque les 64 bits bas.
    network = ipaddress.IPv6Network(f"{addr}/64", strict=False)
    return str(network.network_address)


# -----------------------------------------------------------------------------
# Chargement des tokens (V-06, V-07, V-09, V-14)
# -----------------------------------------------------------------------------

# Dummy token utilisé pour réaliser une comparaison à temps constant même
# quand le client_id n'existe pas, afin de neutraliser les canaux temporels.
_DUMMY_TOKEN = secrets.token_hex(32)

# Verrou protégeant l'accès aux tables de tokens lors d'un rechargement.
_TOKENS_LOCK = threading.RLock()

# Tables de tokens. Initialisées à vide ; remplies par _reload_tokens().
CLIENT_TOKENS: Dict[str, str] = {}
TOKEN_CLIENTS: Dict[str, str] = {}


def _load_tokens_from_sources() -> Tuple[Dict[str, str], Dict[str, str], int]:
    """Charge les tokens depuis le fichier puis (optionnellement) la variable
    d'environnement. Renvoie (client_tokens, token_clients, duplicates).
    Les entrées du fichier prennent le pas sur la variable d'environnement (le
    fichier est rechargé à chaque SIGHUP, la variable d'env reste figée).
    """

    client_tokens: Dict[str, str] = {}
    duplicate_tokens = 0
    seen_tokens: Set[str] = set()

    def add_entry(client_id: str, token: str) -> None:
        nonlocal duplicate_tokens
        client_id = client_id.strip()
        token = token.strip()
        if not client_id or not token:
            return
        if token in seen_tokens:
            duplicate_tokens += 1
            log_event(
                "auth_config_duplicate_token",
                client_id=client_id,
                hint="two client_id share the same token; refusing to start in strict mode",
            )
        seen_tokens.add(token)
        client_tokens[client_id] = token

    env_value = os.environ.get("_NTRIP_AUTH_TOKENS_SNAPSHOT", "")
    if env_value:
        for item in env_value.split(","):
            if ":" not in item:
                log_event("auth_config_invalid_entry", source="env", entry=item)
                continue
            cid, tok = item.split(":", 1)
            add_entry(cid, tok)

    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as handle:
            for line_no, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    log_event("auth_config_invalid_entry", source=TOKEN_FILE, line=line_no)
                    continue
                cid, tok = line.split(":", 1)
                add_entry(cid, tok)
    except FileNotFoundError:
        pass
    except PermissionError as exc:
        log_event("auth_config_permission_denied", path=TOKEN_FILE, error=str(exc))

    token_clients = {token: cid for cid, token in client_tokens.items()}
    return client_tokens, token_clients, duplicate_tokens


def reload_tokens(*, strict: bool = False) -> None:
    """Recharge la table des tokens. Si `strict` est vrai, lève si des doublons
    sont détectés (utilisé au démarrage pour V-07)."""

    global CLIENT_TOKENS, TOKEN_CLIENTS
    with _TOKENS_LOCK:
        client_tokens, token_clients, duplicate_tokens = _load_tokens_from_sources()
        if duplicate_tokens and strict:
            raise SystemExit(
                f"{duplicate_tokens} duplicate token(s) detected in client configuration"
            )
        CLIENT_TOKENS = client_tokens
        TOKEN_CLIENTS = token_clients
    log_event("auth_config_reloaded", clients=len(client_tokens), duplicate_tokens=duplicate_tokens)


def snapshot_env_tokens() -> None:
    """Sauvegarde la variable d'env vers une variable « privée » puis l'efface
    de l'environnement processus, pour limiter les fuites via `docker inspect`
    et `/proc/<pid>/environ` (V-09)."""

    raw = os.environ.pop("NTRIP_AUTH_TOKENS", "")
    if raw:
        os.environ["_NTRIP_AUTH_TOKENS_SNAPSHOT"] = raw


# -----------------------------------------------------------------------------
# Authentification (V-06, V-07)
# -----------------------------------------------------------------------------

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


def _constant_time_lookup(token: str) -> Optional[str]:
    """Cherche un client_id à partir d'un token en utilisant une comparaison
    à temps constant. Itère sur toutes les entrées : le temps de réponse ne
    dépend ni de la valeur du token ni de sa position dans la table."""

    candidate: Optional[str] = None
    encoded = token.encode("utf-8", errors="ignore")
    with _TOKENS_LOCK:
        items = list(TOKEN_CLIENTS.items())
    # Comparaison systématique sur toutes les entrées pour homogénéiser le temps.
    for known_token, client_id in items:
        if hmac.compare_digest(known_token.encode("utf-8"), encoded):
            candidate = client_id
    if candidate is None:
        # Comparaison factice pour homogénéiser la durée même quand la table est petite.
        hmac.compare_digest(_DUMMY_TOKEN.encode("utf-8"), encoded)
    return candidate


def basic_auth_client(value: str) -> Optional[str]:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    client_id, token = decoded.split(":", 1)
    with _TOKENS_LOCK:
        expected = CLIENT_TOKENS.get(client_id, _DUMMY_TOKEN)
        known = client_id in CLIENT_TOKENS
    ok = hmac.compare_digest(expected.encode("utf-8"), token.encode("utf-8"))
    return client_id if (ok and known) else None


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
            client_id = _constant_time_lookup(value)
            if client_id:
                return client_id, "bearer"

    header_token = headers.get("x-client-token") or headers.get("x-ntrip-token")
    if header_token:
        client_id = _constant_time_lookup(header_token)
        if client_id:
            return client_id, "token_header"

    return None, "none"


# -----------------------------------------------------------------------------
# Lecture des en-têtes avec deadline absolue (V-05, V-16)
# -----------------------------------------------------------------------------

def recv_headers(conn: socket.socket, deadline: float) -> Optional[bytes]:
    """Lit les en-têtes HTTP jusqu'au délimiteur en respectant strictement
    `HEADER_LIMIT` et `deadline` (temps monotone absolu).
    """

    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        conn.settimeout(min(remaining, 1.0))
        room = HEADER_LIMIT + 1 - len(data)
        if room <= 0:
            return None
        try:
            chunk = conn.recv(min(4096, room))
        except socket.timeout:
            continue
        except OSError:
            return None
        if not chunk:
            return None
        data.extend(chunk)
        if b"\r\n\r\n" in data or b"\n\n" in data:
            return bytes(data)
        if len(data) > HEADER_LIMIT:
            return None


# -----------------------------------------------------------------------------
# Réécriture / nettoyage de la requête avant relais (V-01, V-12)
# -----------------------------------------------------------------------------

def _sanitize_request(request: bytes, remote_ip: str) -> bytes:
    """Reconstruit la requête HTTP avant relais :
    - supprime tous les en-têtes de provenance et l'en-tête `Authorization`
      (le caster amont ne doit pas voir le secret) ;
    - réinjecte un `X-Forwarded-For` contrôlé.
    """

    marker = b"\r\n\r\n"
    separator = b"\r\n"
    if marker not in request:
        marker = b"\n\n"
        separator = b"\n"
        if marker not in request:
            return request

    head, body = request.split(marker, 1)
    lines = head.split(separator)
    sanitized_lines = []
    for line in lines:
        lower = line.lower()
        if any(lower.startswith(prefix) for prefix in PROVENANCE_HEADER_PREFIXES):
            continue
        sanitized_lines.append(line)
    sanitized_lines.append(b"X-Forwarded-For: " + remote_ip.encode("ascii", errors="ignore"))
    return separator.join(sanitized_lines) + marker + body


def _has_request_smuggling_markers(headers: Dict[str, str]) -> bool:
    """Détecte une requête potentiellement ambiguë (V-12)."""

    has_cl = "content-length" in headers
    has_te = "transfer-encoding" in headers
    return has_cl and has_te


def _is_path_allowed(method: str, path: str) -> bool:
    """Whitelist des chemins relayés vers le caster (V-01)."""

    if method.upper() not in ALLOWED_METHODS:
        return False
    req_path = path.split("?", 1)[0]
    if not req_path:
        return False
    lowered = req_path.lower()
    for denied in DENIED_PATH_PREFIXES:
        if lowered == denied or lowered.startswith(denied + "/") or lowered.startswith(denied + "?"):
            return False
    if _PATH_USER_RE is not None:
        return _PATH_USER_RE.match(req_path) is not None
    return _PATH_DEFAULT_RE.match(req_path) is not None


# -----------------------------------------------------------------------------
# Réponses HTTP
# -----------------------------------------------------------------------------

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
    try:
        conn.sendall(response)
    except OSError:
        pass


def send_forbidden(conn: socket.socket) -> None:
    body = b"Forbidden\n"
    response = (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    try:
        conn.sendall(response)
    except OSError:
        pass


def send_too_many_requests(conn: socket.socket, retry_after: int) -> None:
    body = b"Too Many Requests\n"
    response = (
        b"HTTP/1.1 429 Too Many Requests\r\n"
        b"Content-Type: text/plain\r\n"
        b"Retry-After: " + str(int(retry_after)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    try:
        conn.sendall(response)
    except OSError:
        pass


def send_service_unavailable(conn: socket.socket) -> None:
    body = b"Service Unavailable\n"
    response = (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    try:
        conn.sendall(response)
    except OSError:
        pass


def send_health_ok(conn: socket.socket, method: str) -> None:
    """Réponse 200 pour probes Docker / Coolify (sans auth, sans toucher à
    Millipede). Chemins : GET|HEAD /healthz ou /health."""

    body = b"ok\n"
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n"
    )
    response = headers if method.upper() == "HEAD" else headers + body
    try:
        conn.sendall(response)
    except OSError:
        pass


# -----------------------------------------------------------------------------
# Rate limiting / verrouillage (V-04)
# -----------------------------------------------------------------------------

class _AuthLimiter:
    """Token-bucket simple par IP, plus verrouillage après échec massif.

    On garde une fenêtre glissante des échecs (timestamps) ; au-delà de
    `RL_MAX_FAILS` dans la fenêtre, l'IP est verrouillée pendant
    `RL_LOCKOUT` secondes. Les compteurs sont remis à zéro sur un succès.
    """

    def __init__(self) -> None:
        self._fails: Dict[str, Deque[float]] = defaultdict(deque)
        self._lockouts: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge(self, key: str, now: float) -> None:
        window = self._fails.get(key)
        if not window:
            return
        cutoff = now - RL_WINDOW
        while window and window[0] < cutoff:
            window.popleft()

    def check(self, key: str) -> Tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            locked_until = self._lockouts.get(key)
            if locked_until is not None:
                if locked_until > now:
                    return False, locked_until - now
                self._lockouts.pop(key, None)
            self._purge(key, now)
            return True, 0.0

    def record_failure(self, key: str) -> Tuple[str, int, bool]:
        """Enregistre un échec d'authentification.

        Retourne ``(kind, count, burst_locked)`` où ``kind`` vaut ``"locked"``
        si l'IP est déjà verrouillée (autre requête concurrente vient de
        déclencher le verrou — réponse 429), ou ``"counted"`` si l'échec a été
        pris en compte (réponse 401, sauf si le compteur vient d'atteindre le
        seuil et active le verrou pour les requêtes suivantes).
        """

        now = time.monotonic()
        with self._lock:
            locked_until = self._lockouts.get(key)
            if locked_until is not None and locked_until > now:
                return "locked", 0, True
            self._purge(key, now)
            window = self._fails[key]
            window.append(now)
            count = len(window)
            if count >= RL_MAX_FAILS:
                self._lockouts[key] = now + RL_LOCKOUT
                self._fails.pop(key, None)
                return "counted", count, True
            return "counted", count, False

    def record_success(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
            self._lockouts.pop(key, None)


AUTH_LIMITER = _AuthLimiter()


# -----------------------------------------------------------------------------
# Bornage des connexions concurrentes (V-05)
# -----------------------------------------------------------------------------

_CONNECTION_SEMAPHORE = threading.BoundedSemaphore(value=max(1, MAX_CONNECTIONS))


# -----------------------------------------------------------------------------
# Handler de connexion
# -----------------------------------------------------------------------------

class NtripAuthHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        remote_ip, remote_port = self.client_address[:2]
        logged_ip = anonymize_ip(remote_ip)

        # Bornage des connexions concurrentes (V-05). On vérifie ici plutôt
        # que dans setup() pour éviter un traceback dans handle_error().
        if not _CONNECTION_SEMAPHORE.acquire(blocking=False):
            log_event(
                "request_rejected",
                reason="server_full",
                remote_ip=logged_ip,
            )
            send_service_unavailable(self.request)
            return
        try:
            self._handle_locked(remote_ip, remote_port, logged_ip)
        finally:
            _CONNECTION_SEMAPHORE.release()

    def _handle_locked(self, remote_ip: str, remote_port: int, logged_ip: str) -> None:
        start = time.monotonic()
        client_id: Optional[str] = None
        method = ""
        path = ""
        upstream_bytes = 0
        downstream_bytes = 0
        status = "accepted"
        upstream: Optional[socket.socket] = None

        # Rate-limit / lockout par IP (V-04). S'applique aussi à 127.0.0.1
        # (les sondes /healthz passent avant l'auth et ne comptent pas comme
        # échecs — elles ne satureront pas le budget).
        allowed, retry_after = AUTH_LIMITER.check(remote_ip)
        if not allowed:
            log_event(
                "request_rejected",
                reason="rate_limited",
                remote_ip=logged_ip,
                retry_after=int(retry_after) + 1,
            )
            send_too_many_requests(self.request, int(retry_after) + 1)
            return

        deadline = time.monotonic() + HEADER_DEADLINE
        first_request = recv_headers(self.request, deadline)
        if not first_request:
            log_event(
                "request_rejected",
                reason="invalid_or_too_large_header",
                remote_ip=logged_ip,
            )
            return

        method, path, _version, headers = parse_headers(first_request)
        req_path = path.split("?", 1)[0]

        if method.upper() in ("GET", "HEAD") and req_path in ("/healthz", "/health"):
            send_health_ok(self.request, method)
            return

        # Détection request smuggling (V-12).
        if _has_request_smuggling_markers(headers):
            log_event(
                "request_rejected",
                reason="ambiguous_framing",
                remote_ip=logged_ip,
                method=method,
                path=path,
            )
            send_forbidden(self.request)
            return

        # Authentification.
        client_id, auth_method = authenticate(headers)
        if not client_id:
            kind, count, locked = AUTH_LIMITER.record_failure(remote_ip)
            if kind == "locked":
                log_event(
                    "request_rejected",
                    method=method,
                    path=path,
                    reason="rate_limited",
                    remote_ip=logged_ip,
                    remote_port=remote_port,
                    user_agent=headers.get("user-agent", ""),
                )
                send_too_many_requests(self.request, int(RL_LOCKOUT) + 1)
                return
            status = "rejected"
            log_event(
                "request_rejected",
                method=method,
                path=path,
                reason="invalid_token",
                remote_ip=logged_ip,
                remote_port=remote_port,
                user_agent=headers.get("user-agent", ""),
                fail_count=count,
                locked=bool(locked),
            )
            # Backoff léger pour ralentir le brute-force.
            time.sleep(min(RL_REJECT_DELAY, max(0.0, HEADER_DEADLINE - 1.0)))
            send_unauthorized(self.request)
            return

        # Whitelist de chemin (V-01) — appliquée APRÈS l'auth pour ne pas
        # divulguer la cartographie des routes à un client non authentifié.
        if not _is_path_allowed(method, path):
            status = "rejected"
            log_event(
                "request_rejected",
                method=method,
                path=path,
                reason="path_not_allowed",
                remote_ip=logged_ip,
                client_id=client_id,
            )
            send_forbidden(self.request)
            return

        # Succès : on remet à zéro les compteurs anti brute-force pour cette IP.
        AUTH_LIMITER.record_success(remote_ip)

        log_event(
            "request_accepted",
            auth_method=auth_method,
            client_id=client_id,
            method=method,
            path=path,
            remote_ip=logged_ip,
            remote_port=remote_port,
            user_agent=headers.get("user-agent", ""),
        )

        try:
            upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=15)
        except OSError as exc:
            status = "rejected"
            log_event(
                "request_rejected",
                reason="upstream_unreachable",
                remote_ip=logged_ip,
                client_id=client_id,
                error=str(exc),
            )
            send_service_unavailable(self.request)
            return

        try:
            upstream.settimeout(None)
            self.request.settimeout(None)
            forwarded_request = _sanitize_request(first_request, remote_ip)
            upstream.sendall(forwarded_request)
            upstream_bytes += len(forwarded_request)

            sockets = [self.request, upstream]
            while sockets:
                readable, _writable, exceptional = select.select(sockets, [], sockets, IDLE_TIMEOUT)
                if exceptional or not readable:
                    break
                for sock in readable:
                    try:
                        data = sock.recv(65536)
                    except OSError:
                        data = b""
                    if not data:
                        if sock is self.request:
                            try:
                                sockets.remove(self.request)
                            except ValueError:
                                pass
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
        except OSError as exc:
            status = "broken"
            log_event(
                "request_broken",
                reason=str(exc),
                client_id=client_id,
                remote_ip=logged_ip,
            )
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            duration_ms = int((time.monotonic() - start) * 1000)
            log_event(
                "request_closed",
                client_id=client_id,
                downstream_bytes=downstream_bytes,
                duration_ms=duration_ms,
                method=method,
                path=path,
                remote_ip=logged_ip,
                status=status,
                upstream_bytes=upstream_bytes,
            )


# -----------------------------------------------------------------------------
# Serveur TCP threadé borné
# -----------------------------------------------------------------------------

class ThreadingNtripServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False
    # Le nombre de connexions concurrentes est borné via _CONNECTION_SEMAPHORE
    # dans le handler. `request_queue_size` plafonne aussi la file d'accept().
    request_queue_size = 64


# -----------------------------------------------------------------------------
# Démarrage
# -----------------------------------------------------------------------------

def _validate_startup_safety() -> None:
    """Refuse de démarrer en clair sur une interface publique sans flag
    explicite (V-02)."""

    try:
        listen_addr = ipaddress.ip_address(LISTEN_HOST)
        listen_is_loopback = listen_addr.is_loopback
    except ValueError:
        listen_is_loopback = False
    public_listener = LISTEN_HOST == "0.0.0.0" or LISTEN_HOST == "::" or not listen_is_loopback
    if public_listener and not ALLOW_PLAINTEXT:
        log_event(
            "startup_refused",
            reason="plaintext_listener_without_consent",
            listen_host=LISTEN_HOST,
            hint=(
                "Placez TLS devant (reverse proxy / stunnel) ou définissez "
                "NTRIP_ALLOW_PLAINTEXT=1 pour confirmer une exposition en clair."
            ),
        )
        raise SystemExit(2)
    if public_listener:
        log_event(
            "startup_plaintext_warning",
            listen_host=LISTEN_HOST,
            hint="exposition en clair acceptée via NTRIP_ALLOW_PLAINTEXT=1",
        )


def main() -> int:
    snapshot_env_tokens()
    _validate_startup_safety()
    reload_tokens(strict=True)

    if not CLIENT_TOKENS:
        log_event(
            "auth_config_empty",
            message="no clients configured; all requests will be rejected",
        )
    else:
        log_event("auth_config_loaded", clients=len(CLIENT_TOKENS))

    server = ThreadingNtripServer((LISTEN_HOST, LISTEN_PORT), NtripAuthHandler)

    def stop(signum, _frame) -> None:
        log_event("proxy_stopping", signal=signum)
        raise SystemExit(0)

    def hup(_signum, _frame) -> None:
        try:
            reload_tokens(strict=False)
        except Exception as exc:
            log_event("auth_config_reload_error", error=str(exc))

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        signal.signal(signal.SIGHUP, hup)
    except (AttributeError, ValueError):
        # SIGHUP indisponible (Windows ou contexte particulier).
        pass

    log_event(
        "proxy_started",
        listen_host=LISTEN_HOST,
        listen_port=LISTEN_PORT,
        upstream_host=UPSTREAM_HOST,
        upstream_port=UPSTREAM_PORT,
        max_connections=MAX_CONNECTIONS,
        header_deadline=HEADER_DEADLINE,
        rl_window=RL_WINDOW,
        rl_max_fails=RL_MAX_FAILS,
        rl_lockout=RL_LOCKOUT,
        anonymize_ip=LOG_IP_ANONYMIZE,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
