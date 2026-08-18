#!/bin/sh
set -eu

DEFAULT_DATABASE_URL="sqlite:///var/lib/xdp-firewall/xdp-firewall.db?mode=rwc"
: "${API_BIND:=0.0.0.0:8080}"
: "${XDS_BIND:=0.0.0.0:50051}"
: "${RUST_LOG:=xdp_firewall=info}"
export RUST_LOG

if [ -n "${XDP_FIREWALL_API_TOKEN:-}" ]; then
    API_TOKEN_CONFIGURED=true
else
    API_TOKEN_CONFIGURED=false
fi

if [ "$#" -eq 0 ]; then
    : "${DATABASE_URL:=$DEFAULT_DATABASE_URL}"
    export DATABASE_URL
    standby_enabled=false
    case "$(printf '%s' "${XDP_FIREWALL_STANDBY:-}" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes) standby_enabled=true ;;
    esac
    echo "xdp-firewall entrypoint: command=api bind=${API_BIND} xds_bind=${XDS_BIND} api_token_configured=${API_TOKEN_CONFIGURED} standby=${standby_enabled} rust_log=${RUST_LOG}"
    if [ "$standby_enabled" = "false" ]; then
        /usr/local/bin/xdp-firewall migrate
    else
        echo "xdp-firewall entrypoint: standby read-only mode, skipping migrations (the primary control plane must have migrated the database)"
    fi
    exec /usr/local/bin/xdp-firewall api --bind "$API_BIND" --xds-bind "$XDS_BIND"
fi

echo "xdp-firewall entrypoint: command=$1 api_token_configured=${API_TOKEN_CONFIGURED} rust_log=${RUST_LOG}"

case "$1" in
    xds)
        : "${DATABASE_URL:=$DEFAULT_DATABASE_URL}"
        export DATABASE_URL
        shift
        if [ "$#" -eq 0 ]; then
            exec /usr/local/bin/xdp-firewall xds --bind "$XDS_BIND"
        fi
        exec /usr/local/bin/xdp-firewall xds "$@"
        ;;
    migrate|api|policy)
        : "${DATABASE_URL:=$DEFAULT_DATABASE_URL}"
        export DATABASE_URL
        exec /usr/local/bin/xdp-firewall "$@"
        ;;
    agent|sync-once|help|-h|--help|-V|--version|--database-url)
        exec /usr/local/bin/xdp-firewall "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
