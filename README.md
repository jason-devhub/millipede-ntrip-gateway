# Millipede NTRIP Gateway — proxy Centipede avec authentification par token

Ce dépôt construit une image Docker basée sur [Millipede](https://github.com/pbeyssac/millipede-caster) (caster NTRIP haute performance du projet Centipede-RTK), configurée en **proxy** vers `caster.centipede.fr`.

Une **passerelle d'authentification** Python écoute sur le port **2101** (accès public). Le binaire Millipede (`caster`) n'écoute qu'en **127.0.0.1:2102** à l'intérieur du conteneur, ce qui empêche tout contournement direct.

> Cette base intègre les recommandations de l'audit de sécurité [`_security_report.md`](_security_report.md) (sprints 1 à 4) :
> authentification à temps constant, rate-limit anti brute-force, whitelist de chemins, conteneur non-root et FS lecture seule, pin Debian + commit Millipede, secrets Docker, refus de démarrer en clair sans consentement, etc.

## Sommaire

- [Prérequis](#prérequis)
- [Architecture](#architecture)
- [Déploiement sur Coolify (recommandé)](#déploiement-sur-coolify-recommandé)
- [Démarrage rapide (Docker Compose local)](#démarrage-rapide-docker-compose-local)
- [Configuration des clients (tokens)](#configuration-des-clients-tokens)
- [Variables d'environnement](#variables-denvironnement)
- [Durcissement de l'image et du conteneur](#durcissement-de-limage-et-du-conteneur)
- [Rechargement à chaud des tokens](#rechargement-à-chaud-des-tokens)
- [Healthcheck](#healthcheck)
- [Journalisation](#journalisation)
- [CI / SBOM / scans (recommandé)](#ci--sbom--scans-recommandé)
- [Fichiers du dépôt](#fichiers-du-dépôt)

## Tests automatisés (passerelle)

À la racine du dépôt :

```bash
python3 run_tests.py
```

Les scénarios couvrent whitelist de chemins, rate-limit, en-têtes de provenance, refus d'exposition en clair, rechargement `SIGHUP`, etc.

## Prérequis

- Docker 24+ et Docker Compose v2 (plugin `docker compose`).
- En production sur Coolify : Traefik (proxy intégré de Coolify) avec un entrypoint TCP sur le port NTRIP (voir [Déploiement sur Coolify](#déploiement-sur-coolify-recommandé)).

## Architecture

```
Client NTRIP  ──TLS TCP──▶  Traefik (Coolify, port 2101)
                                   ──TCP clair──▶  millipede:2101 (réseau Docker interne)
                                                        │
                                                  authentification
                                                  rate-limit, whitelist
                                                        │
                                                        ▼
                                              caster Millipede (127.0.0.1:2102)
```

Traefik assure la **terminaison TLS** et le renouvellement automatique des certificats Let's Encrypt. Le contrôle d'accès (tokens, rate-limit, etc.) reste entièrement dans `millipede`. Le segment `Traefik → millipede` est en clair **sur le réseau Docker interne uniquement** (conforme à l'intention V-02 du rapport).

## Déploiement sur Coolify (recommandé)

### 1. Ajouter l'entrypoint TCP à Traefik (une seule fois par serveur)

Coolify gère Traefik automatiquement pour HTTP/HTTPS. Pour exposer un port TCP personnalisé, il faut déclarer un entrypoint supplémentaire.

**Coolify → votre Serveur → Proxy**

Dans la section des **ports exposés** (ou "Additional Ports"), ajoutez :

```
2101:2101/tcp
```

Coolify injecte cet entrypoint dans la configuration statique de Traefik et redémarre le proxy. Cette opération est **unique** : elle n'est pas à refaire lors des redéploiements de l'application.

> Si votre Coolify affiche un éditeur de configuration Traefik directe, ajoutez dans la config statique :
> ```yaml
> entryPoints:
>   ntrip:
>     address: ":2101"
> ```

### 2. Configurer l'application dans Coolify

Dans **Application → Environment Variables**, définissez :

| Variable | Exemple | Obligatoire |
|----------|---------|-------------|
| `NTRIP_DOMAIN` | `ntrip.exemple.fr` | Oui |
| `NTRIP_AUTH_TOKENS` | `rover-001:token,...` | Oui (ou via secret) |
| `NTRIP_AUTH_MAX_CONNECTIONS` | `200` | Non (défaut) |

### 3. Pointer le DNS

Enregistrement A : `ntrip.exemple.fr` → IP du serveur Coolify.

### 4. Déployer

Lancez un déploiement depuis Coolify. Traefik :
- détecte les labels `traefik.tcp.*` dans le `docker-compose.yml` ;
- obtient automatiquement le certificat Let's Encrypt via le challenge HTTP-01 (port 80) ;
- expose le service NTRIP en TLS sur le port 2101.

### Note sur la compatibilité clients

Le routage TCP Traefik utilise le **SNI** (Server Name Indication) pour identifier le domaine. Les clients NTRIP qui supportent TLS envoient le SNI dans la poignée de main TLS. Si vous avez des clients anciens sans SNI, ouvrez une issue pour ajouter un fallback `HostSNI(*)`.

---

## Démarrage rapide (Docker Compose local)

Pour un test local sans Coolify, sans TLS (à ne jamais exposer sur Internet tel quel) :

```bash
# 1. Définissez vos tokens
export NTRIP_AUTH_TOKENS="rover-001:$(openssl rand -base64 36 | tr -d '/+=')"
export NTRIP_ALLOW_PLAINTEXT=1   # uniquement en local / LAN
export NTRIP_DOMAIN=localhost

# 2. Construisez et démarrez
docker compose build
docker compose up -d
docker compose logs -f
```

Les clients NTRIP se connectent sur `localhost:2101` (TCP clair, local uniquement).

> Pour un vrai déploiement local avec TLS, utilisez `docker/tls/` (nginx stream) :
> générez des certificats avec `openssl req -x509 ...`, montez-les dans un service nginx,
> et adaptez le compose en conséquence.

---

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

## TLS et secrets

### TLS sur Coolify

La terminaison TLS est assurée par Traefik (proxy Coolify) via les labels `traefik.tcp.*` du `docker-compose.yml`. Les certificats Let's Encrypt sont gérés automatiquement par Coolify. Aucun fichier de certificat à maintenir.

### TLS en dehors de Coolify

Le répertoire `docker/tls/` contient un `Dockerfile` et une configuration nginx (`nginx-stream.conf`) pour monter un service de terminaison TLS TCP indépendant. À adapter selon votre infrastructure si vous n'utilisez pas Coolify/Traefik.

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

### Rotation des tokens

Mettez à jour le fichier monté puis envoyez `SIGHUP` au conteneur :

```bash
docker compose kill -s HUP millipede   # rechargement à chaud, pas de coupure
```

L'entrypoint propage le SIGHUP au proxy Python qui rappelle `reload_tokens()`. Les sessions existantes ne sont pas interrompues (V-14). Les nouveaux clients utilisent immédiatement la table à jour.

## Variables d'environnement

| Variable | Défaut | Rôle |
|----------|--------|------|
| `NTRIP_DOMAIN` | *(vide)* | Nom de domaine exposé — utilisé par Traefik pour le routage TCP TLS et le certificat Let's Encrypt. **Obligatoire sur Coolify.** |
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
| `NTRIP_ALLOW_PLAINTEXT` | `0` | `1` si l'écoute en clair est acceptable (TLS en amont assuré par Traefik — V-02). Fixé à `1` dans le `docker-compose.yml` fourni car Traefik termine TLS avant de transmettre à `millipede`. |

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
| `docker-compose.yml` | Service `millipede` avec labels Traefik TCP TLS, réseau `coolify` + `ntrip`, secrets optionnels |
| `docker/tls/` | Terminaison TLS TCP autonome (nginx stream) — usage hors Coolify/Traefik |
| `entrypoint.sh` | Démarre caster + proxy ; propage SIGTERM/SIGINT/SIGHUP |
| `ntrip_auth_proxy.py` | Passerelle d'authentification (rate-limit, whitelist, compare_digest, etc.) |
| `caster.yaml` | Config Millipede (écoute loopback, `admin_user` désactivé par défaut) |
| `sourcetable.dat` | Sourcetable locale (publique) |
| `blocklist` | Quotas Millipede par préfixe IP (V-11) |
| `host.auth.example` / `source.auth.example` / `clients.auth.example` | Templates de fichiers de secrets — ne JAMAIS commettre les versions sans `.example` |
| `_security_report.md` | Audit de sécurité de référence (lecture conseillée) |

## Licence

Millipede est sous licence BSD 3-Clause (voir le dépôt upstream). La passerelle Python et les fichiers de ce dépôt suivent la même intention open source.
