# Millipede + passerelle NTRIP — image Docker (proxy vers Centipede)
# Upstream : https://github.com/pbeyssac/millipede-caster
#
# Sécurité (cf. _security_report.md) :
#   - V-03 : utilisateur dédié non-root (`millipede`, UID 10001).
#   - V-08 : tag Debian daté + commit SHA Millipede pinné → builds
#            reproductibles, plus aucun `--depth 1` flottant.
#   - V-17 : `tini` (PID 1) pour reaper les zombies et propager les signaux.
#   - V-18 : healthcheck via `wget` (binaire léger, forme CMD sans grep).
#   - V-10 : `clients.auth` n'est plus copié dans l'image ; seul le fichier
#            `.example` est embarqué pour documentation.

ARG DEBIAN_TAG=bookworm-20260505-slim
# SHA du commit Millipede vérifié au moment de la release de cette image.
# À mettre à jour explicitement après revue du diff upstream.
ARG MILLIPEDE_COMMIT=3c8b64cfdc776a253794172e93ea3cc1b9ca4509

FROM debian:${DEBIAN_TAG} AS builder

ARG MILLIPEDE_COMMIT

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
        libcyaml-dev \
        libevent-dev \
        libjson-c-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/pbeyssac/millipede-caster.git . \
 && git checkout "${MILLIPEDE_COMMIT}" \
 && git log -1 --format='Millipede commit: %H (%cd)' --date=iso

WORKDIR /src/caster
RUN make clean all \
 && sha256sum caster > caster.sha256 \
 && cat caster.sha256

# -----------------------------------------------------------------------------
# Image finale
# -----------------------------------------------------------------------------

FROM debian:${DEBIAN_TAG}

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libcyaml1 \
        libevent-core-2.1-7t64 \
        libevent-extra-2.1-7t64 \
        libevent-openssl-2.1-7t64 \
        libevent-pthreads-2.1-7t64 \
        libjson-c5 \
        libssl3t64 \
        python3 \
        tini \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Utilisateur dédié non-root (V-03). UID/GID fixes pour homogénéité avec
# `docker-compose.yml` (`user: "10001:10001"`).
RUN groupadd --system --gid 10001 millipede \
 && useradd --system --no-create-home --uid 10001 --gid millipede --shell /usr/sbin/nologin millipede

COPY --from=builder /src/caster/caster /usr/local/sbin/caster
COPY ntrip_auth_proxy.py /usr/local/bin/ntrip_auth_proxy.py

RUN mkdir -p /usr/local/etc/millipede /var/log/millipede \
 && chown -R millipede:millipede /usr/local/etc/millipede /var/log/millipede \
 && chmod 755 /usr/local/etc/millipede

# Configuration par défaut (publique, pas de secrets).
COPY caster.yaml sourcetable.dat blocklist /usr/local/etc/millipede/
# Les fichiers `*.auth` ne contiennent que des commentaires : on les fournit
# sous leur nom attendu mais leur contenu réel doit être monté en runtime
# (Docker secrets ou volume read-only). cf. V-09 / V-10.
COPY host.auth.example /usr/local/etc/millipede/host.auth
COPY source.auth.example /usr/local/etc/millipede/source.auth
COPY clients.auth.example /usr/local/etc/millipede/clients.auth.example

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh \
 && chown root:root /entrypoint.sh /usr/local/bin/ntrip_auth_proxy.py /usr/local/sbin/caster

# À partir d'ici, plus aucune commande RUN ne tourne en root.
USER 10001:10001
WORKDIR /usr/local/etc/millipede

EXPOSE 2101

# Healthcheck léger : wget seul (code HTTP), sans shell ni grep — fiable pour
# Coolify / Traefik qui s'appuient sur l'état « healthy » du conteneur (V-18).
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
    CMD ["wget", "-q", "--tries=1", "--timeout=3", "-O", "/dev/null", "http://127.0.0.1:2101/healthz"]

# `tini` reape les zombies et propage proprement SIGTERM/SIGINT/SIGHUP (V-17).
ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
