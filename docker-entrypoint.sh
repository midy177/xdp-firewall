#!/bin/sh
set -eu

: "${DATABASE_URL:=sqlite:///var/lib/xdp-firewall/xdp-firewall.db?mode=rwc}"
: "${API_BIND:=0.0.0.0:8080}"
export DATABASE_URL

if [ "$#" -eq 0 ]; then
    /usr/local/bin/xdp-firewall migrate
    exec /usr/local/bin/xdp-firewall api --bind "$API_BIND"
fi

case "$1" in
    migrate|api|agent|sync-once|policy|help|-h|--help|-V|--version|--database-url)
        exec /usr/local/bin/xdp-firewall "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
