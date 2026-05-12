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

ENTRYPOINT ["/entrypoint.sh"]
