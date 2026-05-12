#!/bin/sh
set -e

/usr/local/sbin/caster -c /usr/local/etc/millipede/caster.yaml &
caster_pid=$!

python3 /usr/local/bin/ntrip_auth_proxy.py &
proxy_pid=$!

stop() {
  kill "$proxy_pid" "$caster_pid" 2>/dev/null || true
  wait "$proxy_pid" "$caster_pid" 2>/dev/null || true
}

trap 'stop; exit 0' INT TERM

while :; do
  if ! kill -0 "$caster_pid" 2>/dev/null; then
    wait "$caster_pid"
    exit $?
  fi
  if ! kill -0 "$proxy_pid" 2>/dev/null; then
    wait "$proxy_pid"
    status=$?
    kill "$caster_pid" 2>/dev/null || true
    wait "$caster_pid" 2>/dev/null || true
    exit "$status"
  fi
  sleep 1
done
