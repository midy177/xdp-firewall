#!/bin/sh
set -eu

: "${DATABASE_URL:=sqlite:///var/lib/xdp-firewall/xdp-firewall.db?mode=rwc}"
: "${API_BIND:=0.0.0.0:8080}"
: "${XDS_BIND:=0.0.0.0:50051}"
: "${RUST_LOG:=xdp_firewall=info}"
export DATABASE_URL
export RUST_LOG

if [ -n "${XDP_FIREWALL_API_TOKEN:-}" ]; then
    API_TOKEN_CONFIGURED=true
else
    API_TOKEN_CONFIGURED=false
fi

if [ "$#" -eq 0 ]; then
    echo "xdp-firewall entrypoint: command=api bind=${API_BIND} xds_bind=${XDS_BIND} api_token_configured=${API_TOKEN_CONFIGURED} rust_log=${RUST_LOG}"
    /usr/local/bin/xdp-firewall migrate
    exec /usr/local/bin/xdp-firewall api --bind "$API_BIND" --xds-bind "$XDS_BIND"
fi

echo "xdp-firewall entrypoint: command=$1 api_token_configured=${API_TOKEN_CONFIGURED} rust_log=${RUST_LOG}"

case "$1" in
    xds)
        shift
        if [ "$#" -eq 0 ]; then
            exec /usr/local/bin/xdp-firewall xds --bind "$XDS_BIND"
        fi
        exec /usr/local/bin/xdp-firewall xds "$@"
        ;;
    migrate|api|agent|sync-once|policy|help|-h|--help|-V|--version|--database-url)
        exec /usr/local/bin/xdp-firewall "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
