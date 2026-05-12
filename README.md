# Millipede NTRIP Gateway — proxy Centipede avec authentification par token

Ce dépôt construit une image Docker basée sur [Millipede](https://github.com/pbeyssac/millipede-caster) (caster NTRIP haute performance du projet Centipede-RTK), configurée en **proxy** vers `caster.centipede.fr`.

Une **passerelle d'authentification** Python écoute sur le port **2101** (accès public). Le binaire Millipede (`caster`) n'écoute qu'en **127.0.0.1:2102** à l'intérieur du conteneur, ce qui empêche tout contournement direct.

> Cette base intègre les recommandations de l'audit de sécurité [`_security_report.md`](_security_report.md) (sprints 1 à 4) :
> authentification à temps constant, rate-limit anti brute-force, whitelist de chemins, conteneur non-root et FS lecture seule, pin Debian + commit Millipede, secrets Docker, refus de démarrer en clair sans consentement, etc.

## Sommaire

- [Prérequis](#prérequis)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration des clients (tokens)](#configuration-des-clients-tokens)
- [TLS, secrets et déploiement production](#tls-secrets-et-déploiement-production)
- [Variables d'environnement](#variables-denvironnement)
- [Durcissement de l'image et du conteneur](#durcissement-de-limage-et-du-conteneur)
- [Rechargement à chaud des tokens](#rechargement-à-chaud-des-tokens)
- [Healthcheck](#healthcheck)
- [Journalisation](#journalisation)
- [CI / SBOM / scans (recommandé)](#ci--sbom--scans-recommandé)
- [Fichiers du dépôt](#fichiers-du-dépôt)

## Prérequis

- Docker 24+ et Docker Compose v2 (plugin `docker compose`).
- Un terminateur TLS en amont (reverse proxy : HAProxy, Caddy, nginx-stream, Traefik, sidecar Coolify, etc.) si vous exposez la passerelle sur Internet. **Le port 2101 est en clair**, comme NTRIP : sans TLS, les tokens sont sniffables.

## Démarrage rapide

```bash
# 1. (production) Préparez vos tokens en Docker secret.
mkdir -p secrets
chmod 700 secrets
printf 'rover-001:%s\n' "$(openssl rand -base64 48 | tr -d '/+=' | head -c 48)" > secrets/clients.auth
chmod 600 secrets/clients.auth

# 2. Décommentez les blocs `secrets:` du `docker-compose.yml`
#    (deux blocs : sous le service et au bas du fichier).

# 3. Configurez le mode TLS / clair :
echo 'NTRIP_ALLOW_PLAINTEXT=0' > .env   # forcer un reverse proxy TLS en amont
# OU bien (déconseillé en prod) :
echo 'NTRIP_ALLOW_PLAINTEXT=1' > .env

# 4. Construisez et démarrez.
docker compose build
docker compose up -d
docker compose logs -f
```

La passerelle écoute sur **2101/tcp**. Le caster Millipede n'est joignable que via la passerelle.

> Si `NTRIP_ALLOW_PLAINTEXT` vaut `0` (défaut) et que `NTRIP_AUTH_LISTEN_HOST` est public (typiquement `0.0.0.0`), **la passerelle refuse de démarrer** et journalise `startup_refused`. C'est volontaire (V-02). Levez le flag uniquement quand TLS est terminé en amont OU pour un test LAN explicite.

## Configuration des clients (tokens)

Chaque client est identifié par un **`client_id`** (libellé visible dans les logs) et un **token** secret. Les tokens doivent être **longs, aléatoires et uniques** : ≥ 32 octets, par exemple via `openssl rand -base64 48`.

Format d'une ligne :

```text
client_id:token
```

Trois mécanismes d'injection, par ordre de préférence en production :

1. **Docker secret** (recommandé) : montez `./secrets/clients.auth` sur `/run/secrets/clients_auth`. L'entrypoint détecte automatiquement le chemin et configure la passerelle dessus. Le fichier est read-only, owned UID 10001 (`millipede`), mode 0400.
2. **Fichier monté en volume** : `-v ./mon_clients.auth:/usr/local/etc/millipede/clients.auth:ro` (ou la directive Compose équivalente).
3. **Variable `NTRIP_AUTH_TOKENS`** : `client1:token1,client2:token2`. Pratique pour des essais, déconseillée en production : les variables d'environnement sont lisibles par `docker inspect` et `/proc/<pid>/environ` (V-09). La passerelle efface la variable d'environnement après lecture pour limiter la fuite vers les sous-processus.

> **Anti pied-de-balle** : le `.gitignore` exclut désormais `clients.auth`, `host.auth`, `source.auth` et tout le dossier `secrets/`. Seuls les fichiers `*.example` sont commités. Si vous avez déjà commité un vrai token, **purger l'historique** (`git filter-repo` ou BFG) et faites tourner les tokens compromis.

### Modes d'authentification acceptés

La passerelle accepte trois modes, tous en comparaison à temps constant (V-06 / V-07) :

- `Authorization: Bearer <token>` (recommandé) ;
- `Authorization: Basic base64(client_id:token)` (compatibilité NTRIP) ;
- En-têtes dédiés `X-Client-Token: <token>` ou `X-Ntrip-Token: <token>`.

L'en-tête `Authorization` est **toujours supprimé** avant relais au caster amont : le binaire Millipede ne voit jamais le secret.

## TLS, secrets et déploiement production

### TLS — toujours

NTRIP sur 2101 est en clair. Sans terminaison TLS en amont, vos tokens transitent en Basic Auth (donc `base64`) lisibles par tout MITM (Wi-Fi public, hop opérateur, etc.). Recommandation :

- **HAProxy/Caddy/Traefik/nginx-stream** devant 2101 → terminaison TLS → passerelle (réseau Docker interne).
- Ou **stunnel** côté serveur.
- Ou un **sidecar Coolify** TLS si vous utilisez Coolify.

La passerelle **refuse de démarrer en clair** sans `NTRIP_ALLOW_PLAINTEXT=1`. Mettez ce flag à `1` UNIQUEMENT si :

1. TLS est terminé en amont (publique chiffrée, passerelle joignable uniquement en interne) ;
2. OU vous êtes sur un LAN de confiance pour des tests ;
3. OU vous acceptez explicitement le risque (réseau privé, etc.).

### Secrets

`docker-compose.yml` inclut un bloc `secrets:` commenté. Pour l'activer :

```yaml
# Sous le service millipede :
    secrets:
      - source: clients_auth
        target: clients_auth
        mode: 0400
        uid: "10001"
        gid: "10001"

# Au bas du fichier :
secrets:
  clients_auth:
    file: ./secrets/clients.auth
```

Avec Coolify / Swarm / Kubernetes, utilisez plutôt le secret manager natif (Vault, SOPS, Kubernetes Secrets, etc.) et montez-le sur `/run/secrets/clients_auth`.

### Rotation

Mettez à jour le fichier monté puis envoyez `SIGHUP` au conteneur :

```bash
docker compose kill -s HUP millipede   # rechargement à chaud, pas de coupure
```

L'entrypoint propage le SIGHUP au proxy Python qui rappelle `reload_tokens()`. Les sessions existantes ne sont pas interrompues (V-14). Les nouveaux clients utilisent immédiatement la table à jour.

## Variables d'environnement

| Variable | Défaut | Rôle |
|----------|--------|------|
| `NTRIP_AUTH_LISTEN_HOST` | `0.0.0.0` | Adresse d'écoute de la passerelle |
| `NTRIP_AUTH_LISTEN_PORT` | `2101` | Port d'écoute |
| `NTRIP_UPSTREAM_HOST` | `127.0.0.1` | Hôte Millipede (interne au conteneur) |
| `NTRIP_UPSTREAM_PORT` | `2102` | Port Millipede |
| `NTRIP_AUTH_FILE` | `/usr/local/etc/millipede/clients.auth` | Chemin du fichier de tokens |
| `NTRIP_AUTH_TOKENS` | *(vide)* | Tokens injectés par variable d'env (déconseillé en prod) |
| `NTRIP_AUTH_HEADER_LIMIT` | `16384` | Taille max des en-têtes HTTP |
| `NTRIP_AUTH_HEADER_DEADLINE` | `5.0` | Temps max pour recevoir les en-têtes (anti-Slowloris, V-05) |
| `NTRIP_AUTH_IDLE_TIMEOUT` | `7200` | Timeout d'inactivité du relais bidirectionnel |
| `NTRIP_AUTH_MAX_CONNECTIONS` | `200` | Connexions concurrentes acceptées (V-05) |
| `NTRIP_AUTH_RL_WINDOW` | `60.0` | Fenêtre de comptage des échecs d'auth (s) |
| `NTRIP_AUTH_RL_MAX_FAILS` | `10` | Échecs avant verrouillage de l'IP (V-04) |
| `NTRIP_AUTH_RL_LOCKOUT` | `300.0` | Durée du verrouillage en secondes (V-04) |
| `NTRIP_AUTH_REJECT_DELAY` | `0.5` | Backoff appliqué avant chaque 401 |
| `NTRIP_AUTH_PATH_REGEX` | *(vide)* | Whitelist regex personnalisée des chemins relayés (V-01) |
| `NTRIP_AUTH_LOG_IP_ANONYMIZE` | `0` | `1` pour masquer le dernier octet IPv4 / les 64 bits bas IPv6 (V-15) |
| `NTRIP_ALLOW_PLAINTEXT` | `0` | `1` pour accepter l'exposition en clair (V-02) |

## Durcissement de l'image et du conteneur

Le `Dockerfile` et le `docker-compose.yml` appliquent les défenses suivantes (cf. rapport sécurité) :

| Mesure | Référence |
|---|---|
| Image de base pinnée (`debian:bookworm-20260505-slim`) | V-08 |
| Commit Millipede pinné (`MILLIPEDE_COMMIT`) | V-08 |
| Utilisateur dédié non-root `millipede` (UID 10001) | V-03 |
| Capabilities purgées (`cap_drop: ALL`) | V-03 |
| `security_opt: ["no-new-privileges:true"]` | V-03 |
| `read_only: true` + tmpfs `/tmp` (nosuid, nodev, noexec) | V-03 |
| Limites ressources : `mem_limit`, `pids_limit`, `cpus`, `ulimits.nofile` | V-13 |
| `tini` en PID 1 pour reaper les zombies | V-17 |
| Healthcheck via `wget` (pas de démarrage Python toutes les 30 s) | V-18 |

Pour mettre à jour la base ou Millipede, **revoyez explicitement** le diff upstream puis :

```bash
docker compose build --build-arg DEBIAN_TAG=bookworm-AAAAMMJJ-slim \
                     --build-arg MILLIPEDE_COMMIT=<sha> .
```

## Healthcheck

- `GET /healthz` sur `127.0.0.1:2101` répond `HTTP/1.1 200 OK` + corps `ok\n` **sans** authentification (pour les sondes Docker/Coolify, V-18).
- Le healthcheck Docker (et Compose) utilise `wget`.

## Journalisation

La passerelle écrit une ligne JSON par évènement sur stdout (Loki / SIEM friendly). Évènements typiques :

- `proxy_started` / `proxy_stopping`
- `auth_config_loaded` / `auth_config_empty` / `auth_config_reloaded`
- `auth_config_duplicate_token` (refus de démarrer en `strict`)
- `request_accepted` / `request_rejected` / `request_closed` / `request_broken`
- `startup_refused` / `startup_plaintext_warning`

Champ `reason` des rejets : `invalid_token`, `path_not_allowed`, `rate_limited`, `server_full`, `invalid_or_too_large_header`, `ambiguous_framing`, `upstream_unreachable`.

Avec `NTRIP_AUTH_LOG_IP_ANONYMIZE=1`, les IP des logs sont anonymisées (RGPD friendly, V-15).

## CI / SBOM / scans (recommandé)

Le rapport (V-19) recommande d'industrialiser :

```bash
# Génération SBOM (CycloneDX) :
docker buildx build --sbom=true --provenance=true -t millipede-ntrip-gateway:local .

# Scan CVE :
trivy image --severity CRITICAL,HIGH millipede-ntrip-gateway:local

# Lint Dockerfile :
hadolint Dockerfile

# Analyse Python :
bandit -r ntrip_auth_proxy.py
semgrep --config p/python ntrip_auth_proxy.py

# Recherche de secrets dans l'historique git :
gitleaks detect --no-banner --redact
```

Signez l'image en CD : `cosign sign --key cosign.key <registry>/millipede-ntrip-gateway:<tag>`.

## Fichiers du dépôt

| Fichier | Rôle |
|---------|------|
| `Dockerfile` | Build multi-stage (Debian pinné, USER non-root, tini, healthcheck wget) |
| `docker-compose.yml` | Déploiement durci (read-only, cap_drop, limites, secrets optionnels) |
| `entrypoint.sh` | Démarre caster + proxy ; propage SIGTERM/SIGINT/SIGHUP |
| `ntrip_auth_proxy.py` | Passerelle d'authentification (rate-limit, whitelist, compare_digest, etc.) |
| `caster.yaml` | Config Millipede (écoute loopback, `admin_user` désactivé par défaut) |
| `sourcetable.dat` | Sourcetable locale (publique) |
| `blocklist` | Quotas Millipede par préfixe IP (V-11) |
| `host.auth.example` / `source.auth.example` / `clients.auth.example` | Templates de fichiers de secrets — ne JAMAIS commettre les versions sans `.example` |
| `_security_report.md` | Audit de sécurité de référence (lecture conseillée) |

## Licence

Millipede est sous licence BSD 3-Clause (voir le dépôt upstream). La passerelle Python et les fichiers de ce dépôt suivent la même intention open source.
