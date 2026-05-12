#!/bin/sh
# Entrypoint du conteneur Millipede :
# - démarre le binaire `caster` (écoute locale 127.0.0.1:2102)
# - démarre la passerelle Python (écoute publique 0.0.0.0:2101)
# - propage SIGTERM/SIGINT/SIGHUP aux deux processus
# - quitte si l'un des deux meurt (le HEALTHCHECK fera le reste).
#
# Sécurité (cf. _security_report.md) :
# - V-17 : ce script est exécuté par `tini` (PID 1), qui réapproprie les
#   zombies et propage les signaux ; on garde toutefois la boucle de
#   surveillance pour fast-fail si un des deux process s'arrête.
# - V-14 : un `kill -HUP $proxy_pid` recharge les tokens sans coupure
#   des sessions en cours.

set -eu

CASTER_BIN="${CASTER_BIN:-/usr/local/sbin/caster}"
CASTER_CONF="${CASTER_CONF:-/usr/local/etc/millipede/caster.yaml}"
PROXY_BIN="${PROXY_BIN:-/usr/local/bin/ntrip_auth_proxy.py}"

# Si un Docker secret est monté sur /run/secrets/clients_auth, on bascule
# automatiquement la passerelle sur ce chemin (V-09).
if [ -r /run/secrets/clients_auth ] && [ -z "${NTRIP_AUTH_FILE:-}" ]; then
    export NTRIP_AUTH_FILE=/run/secrets/clients_auth
fi

"$CASTER_BIN" -c "$CASTER_CONF" &
caster_pid=$!

python3 "$PROXY_BIN" &
proxy_pid=$!

shutdown() {
    kill -TERM "$proxy_pid" "$caster_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    wait "$caster_pid" 2>/dev/null || true
}

reload() {
    # SIGHUP recharge les tokens dans la passerelle (V-14).
    kill -HUP "$proxy_pid" 2>/dev/null || true
}

trap 'shutdown; exit 0' INT TERM
trap 'reload' HUP

while :; do
    if ! kill -0 "$caster_pid" 2>/dev/null; then
        wait "$caster_pid" 2>/dev/null
        status=$?
        kill -TERM "$proxy_pid" 2>/dev/null || true
        wait "$proxy_pid" 2>/dev/null || true
        exit "$status"
    fi
    if ! kill -0 "$proxy_pid" 2>/dev/null; then
        wait "$proxy_pid" 2>/dev/null
        status=$?
        kill -TERM "$caster_pid" 2>/dev/null || true
        wait "$caster_pid" 2>/dev/null || true
        exit "$status"
    fi
    sleep 1
done
