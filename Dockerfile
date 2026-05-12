# Millipede + passerelle NTRIP — image Docker (proxy vers Centipede)
# Upstream : https://github.com/pbeyssac/millipede-caster

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

WORKDIR /src
RUN git clone --depth 1 https://github.com/pbeyssac/millipede-caster.git .

WORKDIR /src/caster
RUN make clean all

FROM debian:stable-slim

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
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/caster/caster /usr/local/sbin/caster
COPY ntrip_auth_proxy.py /usr/local/bin/ntrip_auth_proxy.py

RUN mkdir -p /usr/local/etc/millipede /var/log/millipede

COPY caster.yaml host.auth source.auth sourcetable.dat blocklist clients.auth /usr/local/etc/millipede/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2101

# Coolify et Docker utilisent cette sonde (GET /healthz sur la passerelle, sans token).
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
    CMD python3 -c "import socket as S;s=S.create_connection(('127.0.0.1',2101),5);s.sendall(b'GET /healthz HTTP/1.0\\r\\nHost:127.0.0.1\\r\\n\\r\\n');d=s.recv(256);s.close();exit(0 if b'200' in d and b'OK' in d else 1)"

ENTRYPOINT ["/entrypoint.sh"]
