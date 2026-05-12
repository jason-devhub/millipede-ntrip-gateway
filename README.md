# Millipede NTRIP Gateway — proxy Centipede avec authentification par token

Ce dépôt construit une image Docker basée sur [Millipede](https://github.com/pbeyssac/millipede-caster) (caster NTRIP haute performance du projet Centipede-RTK), configurée en **proxy** vers `caster.centipede.fr`.

Une **passerelle d’authentification** écoute sur le port **2101** (accès public). Le binaire Millipede (`caster`) n’écoute qu’en **127.0.0.1:2102** à l’intérieur du conteneur, ce qui évite de contourner la passerelle depuis l’extérieur.

## Prérequis

- Docker et Docker Compose v2 (plugin `docker compose`)

## Installation

### Construction et démarrage

À la racine du dépôt :

```bash
docker compose build
docker compose up -d
```

Le service NTRIP est exposé sur **2101/tcp** (hôte → conteneur).

### Healthcheck (Docker / Coolify)

- L’image définit une directive **`HEALTHCHECK`** Docker : requête **`GET /healthz`** sur `127.0.0.1:2101` (passerelle uniquement, **sans** token). Réponse attendue : `HTTP/1.1 200 OK` et corps `ok`.
- **Coolify** s’appuie en général sur le healthcheck Docker de l’image : aucune URL HTTP publique n’est obligatoire si le service est publié en TCP brut. Si l’interface propose une sonde HTTP, pointez vers **`/healthz`** sur le port exposé (même chemin que la passerelle).
- Avec **Docker Compose**, un bloc `healthcheck` équivalent est déjà défini dans [`docker-compose.yml`](docker-compose.yml).

### Variables d’environnement (Compose)

Dans [`docker-compose.yml`](docker-compose.yml), la variable **`NTRIP_AUTH_TOKENS`** peut être renseignée pour injecter des clients sans modifier l’image :

| Variable | Description |
|----------|-------------|
| `NTRIP_AUTH_TOKENS` | Liste de paires `client_id:token` séparées par des virgules. Exemple : `rover1:secret1,rover2:secret2` |

En production, préférez un fichier monté ou les secrets de votre plateforme (variables d’environnement chiffrées) plutôt que de coller des tokens en clair dans le dépôt.

### Autres variables (passerelle)

La passerelle lit aussi les variables suivantes (valeurs par défaut entre parenthèses) :

| Variable | Rôle |
|----------|------|
| `NTRIP_AUTH_LISTEN_HOST` | Adresse d’écoute de la passerelle (`0.0.0.0`) |
| `NTRIP_AUTH_LISTEN_PORT` | Port d’écoute (`2101`) |
| `NTRIP_UPSTREAM_HOST` | Hôte Millipede (`127.0.0.1`) |
| `NTRIP_UPSTREAM_PORT` | Port Millipede (`2102`) |
| `NTRIP_AUTH_FILE` | Chemin du fichier clients dans le conteneur (`/usr/local/etc/millipede/clients.auth`) |
| `NTRIP_AUTH_HEADER_LIMIT` | Taille max des en-têtes HTTP reçus (`16384`) |
| `NTRIP_AUTH_IDLE_TIMEOUT` | Timeout d’inactivité en secondes pour le relais bidirectionnel (`7200`) |

## Configuration des clients autorisés (Bearer et équivalents)

Chaque client est identifié par un **`client_id`** (libellé pour les logs et les statistiques) et un **`token`** secret partagé. Le format de stockage est une ligne par client :

```text
client_id:token
```

Les tokens doivent être **longs et aléatoires** (évitez les mots de passe faibles).

### Fichier `clients.auth`

Le fichier [`clients.auth`](clients.auth) est copié dans l’image vers `/usr/local/etc/millipede/clients.auth`. Exemple :

```text
# commentaire ignoré
rover-chantier-01:K7gH3mN9pQ2vX5zR8wT1yU4sA6dF0jL
tablette-002:Z9xC8vB7nM6qW5eR4tY3uI2oP1aS0dF
```

Les lignes vides et les lignes commençant par `#` sont ignorées.

**Persistance sans reconstruire l’image :** montez votre propre fichier sur ce chemin dans le conteneur (volume Docker ou bind-mount), ou surchargez `NTRIP_AUTH_FILE` pour pointer vers un autre chemin monté.

### Variable `NTRIP_AUTH_TOKENS`

Les entrées définies dans `NTRIP_AUTH_TOKENS` sont **fusionnées** avec celles du fichier. L’ordre de chargement est : d’abord la variable d’environnement, puis le fichier. En cas de même `client_id`, la valeur du **fichier** écrase celle de la variable (voir `ntrip_auth_proxy.py`). Utilisez des **tokens distincts** par client : deux `client_id` ne doivent pas partager le même token si vous voulez des statistiques fiables par identifiant (le token sert aussi de clé inverse vers le `client_id`).

Exemple avec un fichier `.env` à côté de `docker-compose.yml` :

```env
NTRIP_AUTH_TOKENS=rover-demo:mon-token-demo-long-et-unique
```

### Comment le client NTRIP s’authentifie

Trois modes sont acceptés par la passerelle (au moins un doit correspondre à un client configuré).

#### 1. Bearer (recommandé si le client supporte `Authorization: Bearer`)

En-tête HTTP :

```http
Authorization: Bearer <token>
```

Le `<token>` doit être exactement celui configuré après `client_id:` dans `clients.auth` ou dans `NTRIP_AUTH_TOKENS`. Le `client_id` est retrouvé automatiquement pour les logs.

#### 2. Basic Auth (compatibilité maximale NTRIP)

Beaucoup de clients envoient `Authorization: Basic` avec `base64(client_id:token)` :

```http
Authorization: Basic <base64(client_id:token)>
```

Exemple pour `rover1` / `secret` :

```bash
echo -n 'rover1:secret' | base64 -w0
```

Puis utilisez la valeur produite dans l’en-tête `Authorization: Basic …`.

#### 3. En-tête dédié (si votre matériel permet des en-têtes personnalisés)

```http
X-Client-Token: <token>
```

ou

```http
X-Ntrip-Token: <token>
```

## Journalisation et statistiques

La passerelle écrit sur la sortie standard des **lignes JSON** (une par événement), exploitables par Loki, un SIEM, ou tout agrégateur de logs.

Événements typiques :

- `auth_config_loaded` / `auth_config_empty` — chargement des clients
- `request_accepted` — client authentifié, méthode HTTP, chemin (mountpoint), IP
- `request_rejected` — token absent ou invalide
- `request_closed` — fin de session : `duration_ms`, `upstream_bytes`, `downstream_bytes`, `client_id`

Les logs Millipede restent configurés dans [`caster.yaml`](caster.yaml) (`access_log` / `log` vers `/dev/stdout`).

## Fichiers de configuration Millipede

| Fichier | Rôle |
|---------|------|
| [`caster.yaml`](caster.yaml) | Écoute interne, proxy vers Centipede, `trusted_http_proxy` pour `X-Forwarded-For` |
| [`host.auth`](host.auth) | Identifiants vers casters distants (proxy) |
| [`source.auth`](source.auth) | Authentification des **sources** locales (poussées vers le caster), pas des rovers en lecture |
| [`sourcetable.dat`](sourcetable.dat) | Sourcetable locale fusionnée avec le proxy |
| [`blocklist`](blocklist) | Quotas / blocage par préfixe IP côté Millipede (complément à l’auth par token) |

## Déploiement en production

1. Construisez l’image ou utilisez Docker Compose à partir de ce dépôt.
2. Définissez **`NTRIP_AUTH_TOKENS`** ou montez un **`clients.auth`** personnalisé.
3. Publiez le port **2101** (TCP) vers vos clients NTRIP (pare-feu, reverse proxy TLS, etc. selon votre infra).

## Sécurité — rappels

- Ne versionnez pas de vrais tokens dans Git.
- Les flux NTRIP sont en clair sur le port 2101 sauf si vous placez TLS devant (reverse proxy ou tunnel).
- Limitez l’accès réseau (pare-feu) en complément des tokens.

## Licence

Millipede est sous licence BSD 3-Clause (voir le dépôt upstream). La passerelle et les fichiers de ce dépôt suivent la même intention open source.
