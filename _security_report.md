# Rapport d'audit de sécurité — Millipede NTRIP Gateway

> **Date** : 2026-05-12
> **Périmètre** : `millipede-coolify/` (passerelle d'auth NTRIP + image Docker + déploiement Compose)
> **Posture** : audit *grey-box* du code source, dans la peau d'un attaquant disposant d'un accès réseau au port 2101 (et, pour certains scénarios, d'un token valide).
> **Avertissement** : ce rapport est *uniquement consultatif*. Aucun code n'a été modifié.

---

## 1. Résumé exécutif

La passerelle remplit correctement son rôle de premier filtre devant le binaire `caster` (qui, *bonne pratique* déjà en place, n'écoute qu'en boucle locale sur `127.0.0.1:2102`). L'architecture choisie est saine sur le plan macroscopique.

En revanche, dès qu'on entre dans le détail du code et de l'image Docker, plusieurs angles morts laissent passer des attaques classiques de l'écosystème HTTP/TCP : énumération de comptes par canal temporel, brute-force sans rate-limit, DoS par épuisement de threads (Slowloris-friendly), absence totale de cloisonnement après l'auth (l'API d'administration interne peut être atteinte), absence de TLS pour transporter des secrets, conteneur exécuté en `root`, et un pinning de dépendances inexistant qui ouvre la porte à une compromission *supply-chain* trivialement reproductible.

Aucun bug ne permet à un attaquant non authentifié de récupérer directement un token, mais la combinaison « pas de TLS + Basic Auth conseillé + brute-force illimité + énumération par timing » rend l'authentification **fragile dans la durée**, surtout sur une exposition Internet directe.

### Tableau de bord des vulnérabilités

| # | Sévérité | Vulnérabilité | Composant |
|---|----------|---------------|-----------|
| V-01 | **Critique** | API d'administration `caster` joignable après auth (pas de cloisonnement de chemin) | `ntrip_auth_proxy.py`, `caster.yaml` |
| V-02 | **Critique** | Tokens transmis en clair (Basic Auth / `X-Client-Token`) sans TLS imposé | `ntrip_auth_proxy.py`, déploiement |
| V-03 | **Élevée** | Conteneur exécuté en `root` (pas de `USER`, pas de `cap_drop`, pas de `no-new-privileges`) | `Dockerfile`, `docker-compose.yml` |
| V-04 | **Élevée** | Pas de rate-limiting / brute-force illimité sur les tokens | `ntrip_auth_proxy.py` |
| V-05 | **Élevée** | DoS trivial : threads non bornés + Slowloris possible | `ntrip_auth_proxy.py`, `docker-compose.yml` |
| V-06 | **Élevée** | Énumération de `client_id` par canal temporel (timing attack) sur Basic Auth | `ntrip_auth_proxy.py` |
| V-07 | **Élevée** | Comparaison de tokens non constante en temps (`==` sur strings Python) | `ntrip_auth_proxy.py` |
| V-08 | **Élevée** | Supply-chain non verrouillée : `git clone --depth 1` sans pin, `debian:stable-slim` flottant, `apt` sans pin | `Dockerfile` |
| V-09 | **Moyenne** | Tokens injectés via variable d'environnement (lisibles via `docker inspect`, `/proc/*/environ`) | `docker-compose.yml`, `Dockerfile` |
| V-10 | **Moyenne** | `clients.auth` versionné et copié dans l'image, sans entrée dans `.gitignore` | `Dockerfile`, `.gitignore` |
| V-11 | **Moyenne** | `blocklist` par défaut désactivée (`0.0.0.0/0 -1`), aucun quota | `blocklist` |
| V-12 | **Moyenne** | Filtrage incomplet des en-têtes de provenance (`Forwarded`, `X-Real-IP`, `Via`…) | `ntrip_auth_proxy.py` |
| V-13 | **Moyenne** | Pas de limites de ressources Docker (CPU/mémoire/pids) → fork/thread bomb | `docker-compose.yml` |
| V-14 | **Moyenne** | Pas de rechargement à chaud des tokens (révocation = redémarrage = coupure) | `ntrip_auth_proxy.py` |
| V-15 | **Faible** | Logs PII : `user-agent` brut, `remote_ip` complet, pas d'anonymisation | `ntrip_auth_proxy.py` |
| V-16 | **Faible** | `recv_headers` peut dépasser `HEADER_LIMIT` jusqu'à +4095 octets | `ntrip_auth_proxy.py` |
| V-17 | **Faible** | Pas d'`init` (`tini`/`dumb-init`) → signaux mal propagés, zombies possibles | `Dockerfile`, `entrypoint.sh` |
| V-18 | **Faible** | Healthcheck via `python3 -c …` → surface d'attaque locale et coût mémoire | `Dockerfile`, `docker-compose.yml` |
| V-19 | **Informatif** | Pas de SBOM, pas de signature d'image, pas de scan CI (Trivy/Grype) | CI/CD |
| V-20 | **Informatif** | Pas de durcissement `caster` (`admin_user: admin` sans politique documentée) | `caster.yaml` |

---

## 2. Détail des vulnérabilités

### V-01 — *Critique* — Endpoints d'administration de `caster` joignables après auth

**Constat.** Dans `caster.yaml` (ligne 31), `admin_user: admin` est défini. Le binaire Millipede expose typiquement des routes d'administration (préfixe `/adm/` ou équivalent, à vérifier dans le binaire upstream `pbeyssac/millipede-caster`) sur le port d'écoute. Ici, `caster` écoute sur `127.0.0.1:2102` *et* la passerelle relaie **tout le trafic après authentification** sans filtrer la méthode HTTP ni le chemin.

Voir `ntrip_auth_proxy.py` autour de la phase post-auth :

```239:244:ntrip_auth_proxy.py
        upstream = socket.create_connection((UPSTREAM_HOST, UPSTREAM_PORT), timeout=15)
        upstream.settimeout(None)
        self.request.settimeout(None)
        forwarded_request = inject_forwarded_for(first_request, remote_ip)
        upstream.sendall(forwarded_request)
        upstream_bytes += len(forwarded_request)
```

Une fois l'authentification franchie, *n'importe quelle requête HTTP* — y compris `GET /adm/...` ou tout autre chemin d'admin/stats de Millipede — est transmise telle quelle au backend. Le `trusted_http_proxy: 127.0.0.1/32` aggrave la situation : `caster` fait confiance au `X-Forwarded-For` que la passerelle réécrit, ce qui peut influencer un éventuel ACL IP côté Millipede.

**Impact.** Un client légitime (rover) ou un attaquant ayant exfiltré *un seul* token devient virtuellement *administrateur* du caster (consultation stats, listing sources, voire commandes selon la version Millipede).

**Scénario d'attaque.**

```http
GET /adm/api/sources HTTP/1.1
Host: x
Authorization: Bearer <token-rover-quelconque>

```

**Recommandations.**
- Dans la passerelle, **liste blanche stricte des chemins** autorisés (typiquement `/`, `/SOURCETABLE`, et les mountpoints connus). Tout ce qui commence par `/adm`, `/api`, `/.well-known/...` doit renvoyer 404/403 avant relais.
- Forcer la méthode à `GET` (ou `SOURCE`/`POST` *uniquement* si vous acceptez des sources locales — ce n'est pas le cas en mode proxy pur ici).
- Documenter explicitement quel utilisateur a le rôle `admin` et avec quel mot de passe ; à défaut, **supprimer** la ligne `admin_user: admin` du `caster.yaml` ou la rendre conditionnelle.
- Si Millipede expose un port d'admin séparé, faire écouter `caster` sur deux interfaces : 127.0.0.1:2102 (NTRIP public-via-proxy) et un *socket Unix* (admin), jamais accessible depuis le réseau.

---

### V-02 — *Critique* — Secrets transmis en clair, Basic Auth recommandé

**Constat.** Le port 2101 expose un protocole *HTTP-like* en clair. Le README le mentionne en garde-fou (« Les flux NTRIP sont en clair sur le port 2101 sauf si vous placez TLS devant »), mais :

- La passerelle annonce explicitement Basic Auth dans son challenge :

```155:165:ntrip_auth_proxy.py
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
```

- Basic Auth = `base64(client_id:token)` → trivialement décodable par n'importe quel attaquant en MITM, sur Wi-Fi ouvert, sur un réseau opérateur compromis, etc.
- Aucune redirection HTTPS, aucun support TLS natif.

**Impact.** Capture passive d'un token sur le réseau = compromission complète du compte.

**Recommandations.**
- **Imposer TLS** côté infrastructure : reverse-proxy TLS (HAProxy, Caddy, nginx-stream) devant 2101, ou `stunnel`, ou un sidecar Coolify.
- Documenter une *configuration de référence* avec TLS, et lever un *warning de démarrage* si la passerelle détecte qu'elle est exposée en clair (variable explicite `NTRIP_ALLOW_PLAINTEXT=1` requise sinon refuser de démarrer).
- À long terme : envisager un mode token **HMAC + nonce + timestamp** (signature plutôt que secret transmis) pour les clients capables.
- Limiter la durée de vie des tokens (rotation programmée).

---

### V-03 — *Élevée* — Conteneur exécuté en `root`

**Constat.** Le `Dockerfile` ne définit **aucun** `USER`. Le processus `caster` (binaire C linké à libssl/libevent) **et** la passerelle Python tournent en `root` à l'intérieur du conteneur. Aucun durcissement Compose :

- pas de `read_only: true`
- pas de `cap_drop: [ALL]`
- pas de `security_opt: ["no-new-privileges:true"]`
- pas de `user:`

**Impact.** Toute RCE dans Millipede (binaire C parsant du protocole réseau, donc *surface d'attaque significative*) ou dans la passerelle Python conduit immédiatement à `root` dans le conteneur, puis aux capacités par défaut de Docker (mount, ptrace, etc.), facilitant un breakout selon la version du kernel/runtime.

**Recommandations.**
- Créer un utilisateur dédié dans le `Dockerfile` :
  ```dockerfile
  RUN useradd --system --no-create-home --uid 10001 millipede
  USER 10001:10001
  ```
- Compose :
  ```yaml
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  tmpfs:
    - /tmp:size=16m,mode=1777
  ```
- Si `caster` doit écrire des logs locaux, prévoir un volume `tmpfs` ou un volume dédié non exécutable (`noexec,nosuid`).

---

### V-04 — *Élevée* — Pas de rate-limiting ni de verrouillage anti brute-force

**Constat.** La passerelle accepte un nombre illimité de tentatives d'authentification par IP, par client_id, et globalement.

```213:226:ntrip_auth_proxy.py
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
```

**Impact.** Brute-force en ligne réaliste sur des tokens faibles. Combinée à V-06/V-07, l'attaque devient encore plus efficace.

**Recommandations.**
- Implémenter un *token bucket* par IP source (ex. : 5 tentatives échouées / minute) et un *backoff exponentiel* (`time.sleep`) avant d'envoyer `401`.
- Compter les échecs par `client_id` et déclencher un verrouillage temporaire (avec log d'alerte `auth_lockout`).
- Externaliser : `fail2ban` lisant les logs JSON `request_rejected` peut suffire (filtre regex sur `event=request_rejected`).
- À défaut, exiger une **politique de tokens** (≥ 32 octets aléatoires, charset uniforme) validée à `load_tokens()` et logger `auth_weak_token` si non conforme.

---

### V-05 — *Élevée* — DoS par épuisement de threads + Slowloris

**Constat.** Le serveur est un `ThreadingMixIn` *sans plafond* :

```286:288:ntrip_auth_proxy.py
class ThreadingNtripServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
```

Chaque connexion crée un thread Python (`daemon_threads = True`), sans `max_children`, sans semaphore global, sans limite de file. Couplé à :

```124:133:ntrip_auth_proxy.py
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
```

Le `settimeout(15)` ligne 201 est un timeout **par appel `recv()`**, pas un timeout global. Un attaquant qui envoie 1 octet toutes les 14 secondes maintient une connexion ouverte jusqu'à ~63 heures avant d'atteindre `HEADER_LIMIT = 16384`. Multiplié par N connexions, N threads sont occupés.

**Impact.**
- Slowloris : indisponibilité totale du service avec quelques centaines de sockets ouverts.
- Aucune limite de threads → consommation mémoire en O(N), risque d'OOM-kill du conteneur (qui n'a *en plus* aucune limite de mémoire Compose).

**Recommandations.**
- Borner les connexions concurrentes : `socketserver.ThreadingMixIn` + `max_children` (Python ≥ 3.7) **ou** un sémaphore explicite avant `handle()`.
- Imposer un *deadline absolu* sur la phase « lecture des en-têtes » : `deadline = time.monotonic() + 5`, sortie immédiate si dépassé, indépendamment du débit.
- Documenter et fixer un `ulimit -n` raisonnable sur le conteneur.
- Ajouter dans `docker-compose.yml` :
  ```yaml
  ulimits:
    nofile: 4096
  deploy:
    resources:
      limits: { cpus: '1.0', memory: 256M, pids: 256 }
  ```

---

### V-06 — *Élevée* — Énumération de `client_id` par canal temporel (Basic Auth)

**Constat.**

```87:97:ntrip_auth_proxy.py
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
```

Deux chemins temporellement distinguables :
1. `CLIENT_TOKENS.get(client_id)` ⇒ `None` : retour immédiat.
2. `CLIENT_TOKENS.get(client_id)` ⇒ valeur, puis comparaison `==` qui *court-circuite* dès le premier caractère divergent.

**Impact.** Un attaquant peut déterminer **quels `client_id` existent** (énumération préalable au brute-force) puis caractériser le premier octet du token. C'est mesurable sur le réseau, surtout à proximité du serveur (LAN, datacenter voisin).

**Recommandations.**
- Toujours exécuter la comparaison, même si le `client_id` n'existe pas, en utilisant une valeur factice de longueur fixe.
- Remplacer `==` par `hmac.compare_digest(...)` :
  ```python
  expected = CLIENT_TOKENS.get(client_id, _DUMMY_TOKEN)
  ok = hmac.compare_digest(expected.encode(), token.encode())
  return client_id if (ok and client_id in CLIENT_TOKENS) else None
  ```
- Idem côté Bearer et `X-*-Token` : itérer sur **tous** les tokens connus avec `compare_digest`, ou indexer par `sha256(token)` constant-time-friendly.

---

### V-07 — *Élevée* — Comparaison non constante en temps

Identique à V-06 mais plus largement : toute égalité `==` sur des secrets/tokens est exploitable. La table inverse `TOKEN_CLIENTS = {token: client_id}` (ligne 61) protège partiellement le mode Bearer (lookup par hash de dict), mais :
- `dict.__getitem__` n'est **pas formellement** constant-time pour les strings (collisions de hash, comparaison finale `==`).
- Si deux clients ont le même token (cas dégradé), seule la dernière entrée est conservée silencieusement.

**Recommandations.**
- Voir V-06 (constant-time comparison).
- Détecter et **refuser de démarrer** si deux `client_id` partagent un token (`auth_config_duplicate_token`).

---

### V-08 — *Élevée* — Supply-chain non verrouillée

**Constat.**

```4:14:Dockerfile
FROM debian:stable-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ca-certificates \
    libcyaml-dev \
    libevent-dev \
    libjson-c-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
```

```16:20:Dockerfile
WORKDIR /src
RUN git clone --depth 1 https://github.com/pbeyssac/millipede-caster.git .

WORKDIR /src/caster
RUN make clean all
```

- `debian:stable-slim` : tag flottant (= `bookworm` aujourd'hui, `trixie` demain).
- `apt-get install` sans `=version` : versions de bibliothèques différentes à chaque build.
- `git clone --depth 1` sans `--branch v0.8.x` ni pin de commit SHA : si l'upstream est compromis ou qu'un commit malveillant est introduit, le prochain build l'embarque silencieusement.
- Aucune vérification de signature GPG, aucun `git verify-tag`.

**Impact.** Compromission *supply-chain* triviale ; build non reproductible ; régressions silencieuses.

**Recommandations.**
- Pinner explicitement : `FROM debian:bookworm-20260101-slim@sha256:<digest>`.
- `git clone … && git -C . checkout <commit_sha>` ou utiliser un *release tarball* signé avec vérification du SHA-256.
- Pinner les paquets `apt` (`build-essential=...`) ou utiliser `apt-get install --no-install-recommends` + `Hash-Pin` via `apt-pinning`.
- Activer Docker BuildKit avec `--provenance` et générer un **SBOM** (`docker buildx … --sbom=true`).
- Scanner l'image dans la CI (Trivy, Grype) et faire échouer le pipeline sur CVE critiques.
- Pour le binaire `caster` : envisager un build *reproductible* dans un job CI distinct, puis copier le binaire avec son SHA-256 vérifié.

---

### V-09 — *Moyenne* — Tokens exposés via variables d'environnement

**Constat.**

```6:8:docker-compose.yml
    environment:
      # Format: client_id:token,client_id2:token2
      NTRIP_AUTH_TOKENS: ${NTRIP_AUTH_TOKENS:-}
```

Les variables d'environnement Docker sont :
- visibles dans `docker inspect <container>` (souvent accessible à tout utilisateur du groupe `docker`),
- lisibles dans `/proc/$pid/environ` (par root et le propriétaire du processus),
- potentiellement journalisées dans des outils d'observabilité,
- héritées par les processus enfants.

**Impact.** Fuite de tokens via un accès non-root au socket Docker, un processus parent compromis, ou des logs d'orchestrateur.

**Recommandations.**
- Utiliser **Docker secrets** (`/run/secrets/...`) ou un *secret manager* (Vault, SOPS, Coolify secrets chiffrés).
- Monter `clients.auth` comme **fichier secret en lecture seule** :
  ```yaml
  secrets:
    clients_auth:
      file: ./secrets/clients.auth
  services:
    millipede:
      secrets:
        - source: clients_auth
          target: /usr/local/etc/millipede/clients.auth
          mode: 0400
  ```
- Forcer `mode: 0400` (lecture seule pour l'utilisateur dédié, V-03).
- Effacer la variable d'env après lecture (`os.environ.pop("NTRIP_AUTH_TOKENS", None)`) pour éviter qu'un sous-processus en hérite.

---

### V-10 — *Moyenne* — `clients.auth` versionné et embarqué dans l'image

**Constat.**

```41:41:Dockerfile
COPY caster.yaml host.auth source.auth sourcetable.dat blocklist clients.auth /usr/local/etc/millipede/
```

```1:5:.gitignore
__pycache__/
*.py[cod]
.env
*.log
```

Le fichier `clients.auth` :
- est commité dans le dépôt (`git log` confirme : commit initial l'inclut),
- est copié dans chaque layer de l'image Docker (donc présent dans tous les registries où l'image est poussée),
- n'est pas dans `.gitignore` ⇒ un opérateur qui ajoute un vrai token et fait `git add -A && git push` le publie.

Actuellement le fichier ne contient que des commentaires, mais la *structure du dépôt invite à l'erreur*.

**Impact.** Fuite massive de tokens sur GitHub ou sur un registry public.

**Recommandations.**
- Renommer la version versionnée en `clients.auth.example` (sans entrée réelle), retirer `clients.auth` du `COPY` et le monter en runtime via volume / secret.
- Ajouter au `.gitignore` :
  ```
  clients.auth
  host.auth
  source.auth
  ```
- Ajouter un *pre-commit hook* (`gitleaks`, `detect-secrets`) pour bloquer un commit qui ressemble à un token.
- Scanner l'historique : `git log --all -p -- clients.auth host.auth source.auth` et **purger** (BFG, `git filter-repo`) si des secrets ont déjà été commités.

---

### V-11 — *Moyenne* — Blocklist Millipede neutralisée par défaut

**Constat.**

```1:3:blocklist
# Par défaut : pas de blocage (quota illimité pour tout le monde)
0.0.0.0/0 -1
::/0 -1
```

Le commentaire reconnaît explicitement l'absence de quota. C'est la *seule* défense restante côté `caster` en cas de contournement de la passerelle ou de client autorisé mal intentionné.

**Impact.** Un seul client authentifié peut ouvrir des centaines de connexions et saturer la bande passante / les ressources du caster, sans aucun frein.

**Recommandations.**
- Fixer un quota raisonnable par préfixe :
  ```
  0.0.0.0/0 50
  ::/0 50
  ```
  puis dérogations explicites par sous-réseau de confiance.
- Documenter la signification de la valeur et la procédure de mise à jour.

---

### V-12 — *Moyenne* — Filtrage incomplet des en-têtes de provenance

**Constat.**

```136:152:ntrip_auth_proxy.py
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
```

Seul `X-Forwarded-For` envoyé par le client est purgé. Les en-têtes équivalents passent :
- `Forwarded:` (RFC 7239)
- `X-Real-IP:`
- `X-Forwarded-Host:`, `X-Forwarded-Proto:`
- `Via:`
- en-têtes spécifiques (`CF-Connecting-IP`, `True-Client-IP`, etc.)

Si `caster` ou un futur composant consomme l'un de ces en-têtes pour les ACL, l'attaquant peut **usurper son IP** côté backend.

**Impact.** Contournement potentiel des règles `blocklist` / ACL IP de Millipede.

**Recommandations.**
- Établir une liste blanche : supprimer **tous** les en-têtes commençant par `x-forwarded-`, `x-real-`, `forwarded`, `via`, `x-original-`, `cf-connecting-`, `true-client-`, etc., puis injecter les en-têtes contrôlés.
- Normaliser l'en-tête `Host` (le réécrire vers une valeur fixe contrôlée).
- Refuser ou *neutraliser* les requêtes contenant simultanément `Content-Length` et `Transfer-Encoding` (défense en profondeur contre le *request smuggling*).

---

### V-13 — *Moyenne* — Pas de limites de ressources sur le conteneur

**Constat.** Le `docker-compose.yml` ne fixe ni `mem_limit`, ni `pids_limit`, ni `cpus`.

**Impact.** Une fuite mémoire dans `caster`, un fork-bomb depuis un sous-processus, ou simplement V-05 peuvent affecter l'hôte entier sans plafond.

**Recommandations.** (voir aussi V-05)
```yaml
deploy:
  resources:
    limits:
      cpus: '1.5'
      memory: 512M
      pids: 512
restart: unless-stopped
```

---

### V-14 — *Moyenne* — Tokens chargés une seule fois au démarrage

**Constat.**

```65:65:ntrip_auth_proxy.py
CLIENT_TOKENS, TOKEN_CLIENTS = load_tokens()
```

Le chargement se fait à l'import (variables globales), jamais relu. Pour *révoquer* un token compromis, il faut redémarrer le conteneur ⇒ coupure de toutes les sessions actives.

**Impact.** Latence de réaction en cas de compromission ; en pratique, on tarde à révoquer ⇒ fenêtre d'exploitation accrue.

**Recommandations.**
- Recharger `clients.auth` sur `SIGHUP` (déjà standard Unix) :
  ```python
  signal.signal(signal.SIGHUP, lambda *_: reload_tokens())
  ```
- Ou surveiller le `mtime` du fichier avec un thread dédié.
- Lors d'une révocation, **fermer activement** les sockets actifs portant le `client_id` concerné (maintenir un registre).

---

### V-15 — *Faible* — PII journalisées sans modération

**Constat.** `user_agent`, `remote_ip`, `remote_port` sont journalisés en clair (lignes 222-237). Selon la juridiction et l'usage (RGPD : l'IP est une donnée personnelle), un audit pourrait demander :
- une *durée de rétention* limitée,
- une *anonymisation* (tronquer le dernier octet IPv4 / les 64 bits bas IPv6),
- un log distinct *audit* (long terme) vs *debug* (court terme).

**Recommandations.**
- Documenter la durée de rétention et la finalité dans une politique de confidentialité.
- Option `NTRIP_AUTH_LOG_IP_ANONYMIZE=1` qui masque `a.b.c.0` / `2001:db8::/64`.

---

### V-16 — *Faible* — `recv_headers` peut dépasser `HEADER_LIMIT`

**Constat.**

```126:133:ntrip_auth_proxy.py
    while len(data) <= HEADER_LIMIT:
        chunk = conn.recv(4096)
        ...
        data.extend(chunk)
```

La condition `len(data) <= HEADER_LIMIT` est vérifiée **avant** la lecture du chunk de 4096 octets, donc la taille effective peut atteindre `HEADER_LIMIT + 4095`. Pour un usage normal c'est anecdotique, mais c'est un écart vis-à-vis de la limite annoncée.

**Recommandations.** Lire `min(4096, HEADER_LIMIT + 1 - len(data))` ou comparer après extension.

---

### V-17 — *Faible* — Absence d'`init` (PID 1)

**Constat.** Le `entrypoint.sh` lance `caster` puis `ntrip_auth_proxy.py` en arrière-plan et boucle. Sans `tini`/`dumb-init` comme PID 1 :
- les processus zombies ne sont pas reapés,
- les signaux peuvent être mal propagés aux enfants,
- en cas de plantage d'un seul des deux, l'autre peut rester actif sans supervision (la boucle gère ce cas mais via `kill -0`, sans `waitpid`).

**Recommandations.**
- `apt-get install -y tini` puis `ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]`.
- Ou utiliser `s6-overlay`/`supervisord` pour un contrôle plus fin.

---

### V-18 — *Faible* — Healthcheck coûteux et bavard

**Constat.**

```48:49:Dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
    CMD python3 -c "import socket as S;s=S.create_connection(('127.0.0.1',2101),5);s.sendall(b'GET /healthz HTTP/1.0\\r\\nHost:127.0.0.1\\r\\n\\r\\n');d=s.recv(256);s.close();exit(0 if b'200' in d and b'OK' in d else 1)"
```

- Toutes les 30 s, on démarre un interpréteur Python complet : coûteux en CPU et en mémoire.
- L'endpoint `/healthz` est ouvert sans auth (acceptable, mais permet un fingerprinting trivial : `nc host 2101 → "ok"`).

**Recommandations.**
- Remplacer par un binaire léger : `curl --fail --silent http://127.0.0.1:2101/healthz` (ou `wget`), ou un petit binaire statique compilé.
- Si vous gardez Python : pré-compiler en `.pyc` ou monter un script unique en `/usr/local/bin/healthcheck`.
- N'exposer `/healthz` qu'à `127.0.0.1` (l'utiliser depuis l'hôte/Coolify via le réseau Docker interne suffit, voire un *bind sur localhost* du conteneur si le check est in-container).

---

### V-19 — *Informatif* — Pas de SBOM, pas de signature, pas de scan CI

**Recommandations.**
- Générer une **SBOM CycloneDX/SPDX** à chaque build.
- Signer l'image avec **Cosign** (Sigstore) ou Notation.
- Activer un job CI qui :
  - lint le `Dockerfile` (Hadolint),
  - analyse statiquement le Python (Bandit, Semgrep),
  - scanne l'image (Trivy / Grype) sur CVE critiques,
  - exécute `gitleaks` pour les secrets,
  - publie l'image avec son digest et son attestation.

---

### V-20 — *Informatif* — Durcissement `caster.yaml`

```31:31:caster.yaml
admin_user: admin
```

**Recommandations.**
- Soit définir explicitement un mot de passe robuste (via la directive Millipede appropriée), documenté et stocké en secret.
- Soit retirer la directive si l'API admin n'est pas utilisée.
- Documenter `hysteresis_m`, `backlog_socket` et `backlog_evbuffer` (valeurs grandes ⇒ acceptables mais ouvrent à un *amplification* de buffer en cas d'attaque ciblée).

---

## 3. Surfaces d'attaque par type d'attaquant

| Profil | Capacités | Vecteurs prioritaires |
|--------|-----------|------------------------|
| **Internet anonyme** | TCP/2101 | V-04 (brute-force), V-05 (DoS Slowloris), V-06 (énumération `client_id`), V-02 (sniff si MITM) |
| **Wi-Fi/LAN partagé avec un client légitime** | MITM, sniff passif | V-02 (capture Basic Auth → take over) |
| **Client authentifié hostile** (rover compromis, token légitimé) | Auth valide | V-01 (admin caster), V-12 (usurpation IP backend), V-11 (saturation sans quota) |
| **Opérateur DevOps malveillant ou compromis** | Accès socket Docker | V-09 (tokens via `inspect`), V-03 (root container → host) |
| **Attaquant supply-chain** | Compromission upstream | V-08 (build flottant, `git clone --depth 1`) |
| **Insider git** | Accès au dépôt | V-10 (commit accidentel de `clients.auth`) |

---

## 4. Roadmap de remédiation recommandée

**Sprint 1 (priorité immédiate, sans changement architectural)**
1. V-01 : whitelister les chemins HTTP relayés.
2. V-04 + V-06 + V-07 : `hmac.compare_digest`, comparaison à temps constant systématique, rate-limit IP.
3. V-05 + V-13 : `max_children` côté Python, `mem_limit`/`pids_limit` côté Compose.
4. V-10 : retirer `clients.auth` du `COPY` Docker, ajouter au `.gitignore`, fournir `.example`.

**Sprint 2 (durcissement Docker)**
5. V-03 : utilisateur dédié, `cap_drop`, `read_only`, `no-new-privileges`.
6. V-08 : pinning `debian` + commit SHA Millipede + scan Trivy en CI.
7. V-09 : passage en Docker secrets / fichier monté.

**Sprint 3 (TLS + observabilité)**
8. V-02 : reverse proxy TLS documenté et imposé (refus de démarrer en mode clair sans flag explicite).
9. V-12 : nettoyage des en-têtes de provenance.
10. V-19 : SBOM, signature Cosign, CI complète.

**Sprint 4 (qualité de vie)**
11. V-11 : quotas réalistes dans `blocklist`.
12. V-14 : rechargement `SIGHUP`.
13. V-15, V-17, V-18 : ajustements logging / init / healthcheck.

---

## 5. Notes pour l'équipe

- L'audit confirme que la *séparation* passerelle Python ↔ binaire `caster` sur localhost est une **bonne décision architecturale**. La majeure partie des recommandations renforce ce périmètre plutôt que de le refondre.
- Les vulnérabilités **V-01** et **V-02** sont celles qu'un attaquant *opportuniste* exploiterait en priorité ; les traiter en premier réduit drastiquement le risque résiduel.
- Aucune des vulnérabilités identifiées n'a de CVE associée connue (il s'agit de code applicatif maison). L'audit n'a pas trouvé d'injection de commande, de désérialisation non sûre, de SSRF ni de bug mémoire ; le code Python est globalement sobre et lisible — c'est le *contexte d'exploitation* qui doit être durci.

— *Fin du rapport*
