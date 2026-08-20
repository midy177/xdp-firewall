# xdp-firewall

Distributed XDP firewall control plane written in Rust.

Each server runs the same agent. A single firewall policy is stored in SQLite, PostgreSQL, or MySQL with SeaORM. The API control-plane process writes configuration to the database and exposes both the Axum HTTP API/UI and a gRPC xDS stream; agents subscribe to xDS and apply the latest policy to local XDP maps through Aya. SQLite is intended for a single-server deployment; PostgreSQL/MySQL are the distributed configuration source for multiple servers. The policy is initialized with built-in threat intelligence feeds for `ipsum`, `spamhaus-drop`, and `voipbl`.

## Quick Start

```bash
export DATABASE_URL='sqlite://xdp-firewall.db?mode=rwc'
cargo run -- migrate
cargo run -- policy seed-example
XDP_FIREWALL_API_TOKEN='change-this-token' \
XDP_FIREWALL_AGENT_TOKEN='change-this-agent-token' \
cargo run -- api
XDP_FIREWALL_XDS_URL=http://127.0.0.1:50051 cargo run -- agent
```

PostgreSQL works with a `postgres://user:pass@host:5432/db` URL. MySQL works with a `mysql://user:pass@host:3306/db` URL.

## API

```bash
export DATABASE_URL='sqlite://xdp-firewall.db?mode=rwc'
cargo run -- migrate
XDP_FIREWALL_API_TOKEN='change-this-token' \
XDP_FIREWALL_AGENT_TOKEN='change-this-agent-token' \
cargo run -- api --bind 0.0.0.0:8080 --xds-bind 0.0.0.0:50051
```

Useful endpoints:

- `GET /health`
- `GET /countries`
- `GET /policy/version`
- `POST /policy/seed-example`
- `POST /policy/bump-version`
- `GET /rules?page=1&page_size=20&rule_key=edge-web-deny&action=deny&cidr=203.0.113.0/24&protocol=tcp&port=443&priority=10`
- `POST /rules`
- `POST /rules/batch`
- `DELETE /rules/{id}`
- `DELETE /rules/batch`
- `DELETE /rules?rule_key=edge-web-deny`
- `DELETE /rules?action=deny&cidr=203.0.113.0/24&protocol=tcp&port=443&priority=10`
- `GET /geo-countries?page=1&page_size=20&country=CN&action=deny&enabled=true`
- `POST /geo-countries`
- `POST /geo-countries/batch`
- `DELETE /geo-countries/{id}`
- `DELETE /geo-countries/batch`
- `DELETE /geo-countries?country=CN&action=deny&enabled=true`
- `POST /geo-countries/refresh`
- `GET /geo/lookup?ip=8.8.8.8`
- `GET /temp-bans?page=1&page_size=20&cidr=203.0.113.10/32&protocol=tcp&port=443`
- `POST /temp-bans`
- `POST /temp-bans/batch`
- `DELETE /temp-bans/{id}`
- `DELETE /temp-bans/batch`
- `GET /threat-sources?page=1&page_size=20&name=test-feed&format=ipsum&enabled=true`
- `POST /threat-sources/refresh`
- `POST /threat-sources`
- `POST /threat-sources/batch`
- `PUT /threat-sources/{id}`
- `DELETE /threat-sources/{id}`
- `DELETE /threat-sources/batch`
- `DELETE /threat-sources?name=test-feed`
- `GET /dynamic-defense`
- `PUT /dynamic-defense`
- `GET /dynamic-rate-limits?page=1&page_size=20&enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000`
- `POST /dynamic-rate-limits`
- `POST /dynamic-rate-limits/batch`
- `DELETE /dynamic-rate-limits/{id}`
- `DELETE /dynamic-rate-limits/batch`
- `DELETE /dynamic-rate-limits?enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000`
- `GET /trusted-cidrs?page=1&page_size=20&cidr=10.0.0.0/8&enabled=true`
- `POST /trusted-cidrs`
- `POST /trusted-cidrs/batch`
- `DELETE /trusted-cidrs/{id}`
- `DELETE /trusted-cidrs/batch`
- `DELETE /trusted-cidrs?cidr=10.0.0.0/8`
- `GET /nodes?page=1&page_size=20`
- `GET /nodes/{node_id}`
- `POST /nodes/maintenance?max_age_seconds=300`
- `GET /drop-events/stream`
- `GET /drop-events/stream?node_id=node-1`

Example:

```bash
curl -X POST http://127.0.0.1:8080/rules \
  -H "authorization: Bearer $XDP_FIREWALL_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"rule_key":"edge-web-deny","priority":10,"action":"deny","cidr":"203.0.113.0/24","protocol":"any"}'
```

Every mutating endpoint that immediately changes the active firewall policy increments the policy version so the xDS control plane can push a fresh snapshot to running agents. Disabled configuration rows are persisted for management but are excluded from active snapshots, so creating, deleting, or editing only disabled rows does not increment the policy version. Creating an enabled threat-intelligence source increments the version for the source configuration, then the asynchronous refresh increments it again only if refreshed prefixes change.

List endpoints return `items`, `total`, `page`, `page_size`, and `total_pages`. The default page size is `20`; the maximum is `500`.

Batch create endpoints use `{"items":[...]}` and accept the same item shape as the single-row `POST` endpoint. Batch delete endpoints use `{"ids":[1,2]}`. `DELETE /rules/batch` also accepts `{"rule_keys":["edge-web-deny"]}` as an alternative to `ids`; effective `ids` and `rule_keys` cannot be used together. Batch requests are limited to 500 entries, run in a single transaction, and bump the policy version once only when the batch actually changes active policy state.

Write endpoints that change policy state return `{"version":...,"data":...}`. Error responses use `{"error":"..."}`. `enabled` defaults to `true` for configuration resources when omitted. `action` accepts `allow` and `deny`; `drop` is accepted and normalized to `deny`. `protocol` accepts `any`, `tcp`, `udp`, and `icmp`; `port` must be 1-65535 and cannot be set for `icmp`.

`GET /rules` supports optional filters for `rule_key`, `action`, `cidr`, `protocol`, `port`, and `priority`; omit all filters to page through all rules. Filters are combined with AND semantics. `rule_key` may be omitted on create; omitted or blank values are generated from the normalized `priority`, `action`, `cidr`, `protocol`, and `port` tuple and stored as a non-null UUID-like hash. Rule keys must be globally unique. Creating the same rule key with identical fields is idempotent and returns `200 OK`; creating the same key with different fields returns `409 Conflict`. `DELETE /rules` deletes by `rule_key` when supplied, otherwise by the complete rule tuple and requires all five fields: `action`, `cidr`, `protocol`, `port`, and `priority`. `protocol=any` also matches older rules whose protocol field is unset.

`GET /geo-countries`, `GET /temp-bans`, `GET /threat-sources`, `GET /dynamic-rate-limits`, and `GET /trusted-cidrs` also support optional field filters combined with AND semantics. Temporary bans support `cidr`, `protocol`, and `port` filters and should still be deleted by ID. `PUT /threat-sources/{id}` accepts `{"enabled":true}` or `{"enabled":false}` to turn a threat source on or off. Their collection DELETE endpoints require the identifying fields: country rules require `country`, `action`, and `enabled`; threat sources require the unique `name`; dynamic rate limits require `enabled`, `priority`, `protocol`, `port`, `packets_per_second`, and `burst`; trusted CIDRs require the unique `cidr`. Use the existing ID DELETE endpoints for configurations whose identifying fields are not stable or unique. Dynamic rate limits without a stored port must also be deleted by ID.

The removed multi-policy endpoints `/policies` and `/policies/{path}` return 404 with a migration message; use the single-policy resource endpoints above.

Set `XDP_FIREWALL_API_TOKEN` to protect configuration and `/nodes` API routes. The API refuses to bind to a non-loopback address without a token unless `XDP_FIREWALL_ALLOW_UNAUTHENTICATED=true` is explicitly set. Clients can send either `Authorization: Bearer <token>` or `X-API-Token: <token>`. `/health`, `/countries`, and embedded frontend assets stay public for probes and page loading. When the embedded frontend is used with auth enabled, enter the token in the API token field; it is kept in memory only and is cleared when leaving the page.

## Frontend

The API server embeds `frontend/dist` into the Rust binary and serves the console from `/`. The console uses hash-based tab routing and relative API URLs so it also works behind Rancher or Kubernetes service proxy paths.

```bash
make frontend-install
make frontend-build
cargo build --release
```

The frontend source is Vue 3. `frontend/package.json` aliases Vite to Rolldown Vite and includes the shadcn-vue toolchain dependencies. `Makefile` auto-selects `bun`, `pnpm`, or `npm` for frontend commands.

## Data Model

- `firewall_policy_versions`: monotonically increasing version for the single firewall policy.
- `firewall_rules`: static allow/deny CIDR rules with a required unique `rule_key`, protocol, and port match.
- `firewall_geo_country_policies`: per-country allow/deny policy.
- `firewall_temp_bans`: temporary source-CIDR bans with optional protocol and destination-port match.
- `firewall_dynamic_defense`: global `ip_rate_limit` and `flood` policy.
- `firewall_dynamic_rate_limits`: custom dynamic defense rate limits by protocol and/or destination port.
- `firewall_trusted_cidrs`: highest-priority source CIDR whitelist.
- `firewall_threat_sources`: threat-intelligence feed definitions.
- `firewall_threat_source_states`: last-seen threat feed fingerprints used by automatic refresh.
- `firewall_threat_prefixes`: last successfully downloaded and normalized threat CIDR lists, stored per feed so agents do not directly access threat providers.
- `firewall_nodes`: distributed node heartbeat and last applied version.

Built-in threat sources:

- `ipsum`: `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`, format `ipsum`, minimum score `3`.
- `spamhaus-drop`: `https://www.spamhaus.org/drop/drop.txt`, format `spamhaus_drop`.
- `voipbl`: `https://voipbl.org/update/`, format `voipbl`.

Threat source `format` accepts `cidr`, `ips`, `ipsum`, `voipbl`, and `spamhaus_drop`. The aliases `voipbl_cidr`, `voipbl-cidr`, and `spamhaus-drop` are accepted and normalized.

Threat feed URLs must use `http` or `https`; hosts and URL credentials are not restricted. Refresh fetches feeds with the HTTP client timeout, up to 3 redirects, and a 16 MiB response limit. Text formats (`cidr`, `ips`, `ipsum`, and `voipbl`) are parsed line-by-line from the response; invalid IP/CIDR lines are skipped with a warning. `voipbl` ignores comment lines and compiles each valid IP/CIDR line as a deny prefix rule. `spamhaus_drop` keeps the existing JSON-compatible parser and may buffer the response body within the same 16 MiB cap; invalid JSON CIDR entries are skipped.

The xDS control plane automatically refreshes enabled threat feeds every 86400 seconds, using the same normal refresh interval as country IP lists. It also polls every 1800 seconds for enabled feeds whose persisted prefix set is missing, so newly added feeds are materialized without waiting a full day. Each refresh normalizes the fetched prefixes, stores the last successful CIDR set in `firewall_threat_prefixes`, and compares a stable fingerprint with `firewall_threat_source_states`; the policy version is bumped only when at least one enabled feed changes or a persisted prefix set is missing. Policy snapshots compile threat intelligence from the database, so agents keep using the last successful feed result when a provider is unavailable.

## XDP Object

`bpf/xdp_firewall.c` is the kernel program source. Build it with your normal eBPF toolchain, for example:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/xdp_firewall.c -o bpf/xdp_firewall.o
```

The userspace agent defaults to `/usr/local/share/xdp-firewall/xdp_firewall.o`. Pass `--xdp-object ./bpf/xdp_firewall.o` for local development or custom packaging.

## Whitelist

Trusted CIDRs are the highest-priority source whitelist. Source IPs matching these prefixes are allowed before ordinary firewall rules, threat-intelligence deny prefixes, country allow/deny rules, and global dynamic defense checks.

Database-managed whitelist entries are created through the API/frontend and are stored in the database so the control plane can push the same whitelist to every agent over xDS. Agents apply the pushed whitelist; they do not mutate whitelist configuration.

```bash
xdp-firewall api \
  --trusted-cidr 10.0.0.0/8 \
  --trusted-cidr 192.168.0.0/16
```

Equivalent environment form:

```bash
XDP_FIREWALL_TRUSTED_CIDRS=10.0.0.0/8,192.168.0.0/16 xdp-firewall api
```

When `api` or `xds` is started with trusted CIDR flags or `XDP_FIREWALL_TRUSTED_CIDRS`, those prefixes are runtime-only additions injected into xDS snapshots. They are not written to `firewall_trusted_cidrs` and do not change API/frontend-managed database whitelist entries.

For Docker Compose, put the same comma-separated value in `deploy/docker-compose/compose-env` or your copied local env file:

```dotenv
XDP_FIREWALL_TRUSTED_CIDRS=10.0.0.0/8,192.168.0.0/16,203.0.113.10/32
```

The same whitelist can be managed through:

- `GET /trusted-cidrs`
- `POST /trusted-cidrs`
- `POST /trusted-cidrs/batch`
- `DELETE /trusted-cidrs/{id}`
- `DELETE /trusted-cidrs/batch`

## Kubernetes Runtime Discovery

The control plane can optionally discover Kubernetes network addresses and inject them into xDS snapshots as runtime-only trusted CIDRs. This is useful when agents must always allow cluster control and cluster-internal address ranges without storing those ranges in the policy database.

Enable it on the API/control-plane process:

```bash
xdp-firewall api --k8s-discovery
```

or:

```bash
XDP_FIREWALL_K8S_DISCOVERY=true xdp-firewall api
```

When enabled, the control plane reads the Kubernetes API with its service account token and discovers:

- Node `InternalIP` and `ExternalIP` as host CIDRs.
- Node `spec.podCIDRs` / `spec.podCIDR`.
- `networking.k8s.io/v1 ServiceCIDR` ranges when the API is available.
- Existing Service `clusterIP/clusterIPs` as a partial fallback when `ServiceCIDR` is not available.

Discovered CIDRs are cached in the control plane and merged into the xDS snapshot before it is sent to agents. The control plane performs one initial Kubernetes list, then uses Kubernetes watch streams for Nodes plus ServiceCIDR or Services fallback changes; it does not poll Kubernetes on every xDS push tick. Discovery failures fall back to the last successful discovery plus static runtime CIDRs instead of interrupting policy delivery. They are not persisted and are not shown as API/frontend-managed whitelist rows.

## Enforcement Priority

Ingress packets are evaluated in this order:

1. Whitelist (`trusted_cidrs`): matching source CIDRs are allowed immediately.
2. Temporary bans: matching source IPs are dropped until their expiration time.
3. Ordinary firewall rules and threat-intelligence deny prefixes: the XDP map uses longest-prefix matching first; when two entries produce the same effective key, lower numeric `priority` values have higher priority, and threat-intelligence deny prefixes win over duplicate user rules.
4. Country allow/deny rules.
5. Custom dynamic defense rate limits: protocol and/or destination-port token buckets.
6. Global dynamic defense: `ip_rate_limit` and `flood`.

## Country IP Lists

Country metadata is crawled from the IPdeny country block page:

```text
https://www.ipdeny.com/ipblocks/
```

That page provides the provider-wide `Zone files last updated` value plus country names and two-letter country codes, such as `CHINA (CN)`.

Country IP prefixes are still downloaded from IPdeny aggregated country lists:

```text
https://www.ipdeny.com/ipblocks/data/aggregated/{country}-aggregated.zone
```

For example, China is `https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone`.

The control plane stores the country catalog in `firewall_geo_country_catalog`, per-country source metadata in `firewall_geo_ip_list_states`, and each country's CIDR list as one JSON-array row in `firewall_geo_ip_prefixes`. `GET /countries` is served from the persisted country catalog instead of a hard-coded list. `POST /geo-countries/refresh` starts an asynchronous refresh for all countries; the background task checks the crawled IPdeny page metadata and downloads/replaces a country's single JSON CIDR row only when the upstream timestamp changed or the country has no local CIDR state. Country CIDR downloads are parsed line-by-line from the HTTP response rather than buffered as a full response string. Manual refresh starts are limited to once every 5 minutes per control-plane process; calls during the window return the last completed refresh result instead of starting another crawl. A policy version bump and xDS redistribution happen only when at least one country list changed.

The xDS control plane runs the same IPdeny index check from a dedicated background loop, at most once per day. If an enabled country has no persisted CIDR list row, the daily throttle is bypassed so newly added country rules can be populated without waiting for the next daily refresh. xDS request and stream push paths do not run country downloads or MMDB rebuilds inline. Agents do not download country IP lists; persisted CIDRs are included in the xDS policy snapshot.

On control-plane startup and after a changed country refresh, Rust rebuilds an MMDB from the persisted `firewall_geo_ip_prefixes.cidrs_json` arrays. The IPdeny aggregated source is IPv4, so the generated lookup database uses an IPv4 MMDB tree and includes all persisted IPv4 country prefixes; any unexpected IPv6 prefixes in the table are skipped with a warning until an IPv6 country feed is added. The rebuild reads prefix rows in small pages and the active reader uses a memory-mapped temporary MMDB file instead of keeping the final database bytes in a heap `Vec`. This lowers steady-state heap use, while the writer still needs temporary memory for the build tree during refresh. MMDB records include both `country.iso_code` and `country.names.en`. The UI country page can query this lookup through `GET /geo/lookup?ip=8.8.8.8`, and realtime Drop events are enriched with a country code from the same MMDB when the agent/BPF event does not already include one.

The control-plane database pool is explicitly configurable and defaults to `XDP_FIREWALL_DB_MAX_CONNECTIONS=16`, `XDP_FIREWALL_DB_MIN_CONNECTIONS=1`, `XDP_FIREWALL_DB_IDLE_TIMEOUT_SECONDS=300`, and `XDP_FIREWALL_DB_MAX_LIFETIME_SECONDS=1800`. Lower the max/min connection counts for small control-plane deployments if idle database connections become visible in steady RSS; raise them only when database acquisition is a measured bottleneck.

For memory troubleshooting during country refresh or lookup rebuilds, run the control plane with `RUST_LOG=xdp_firewall=debug`. The GeoIP path logs cgroup memory and `/proc/self/status` RSS/HWM after each country CIDR JSON row is persisted, after the temporary MMDB file is written, and after the mmap reader is opened.

## Temporary Bans

Temporary bans block one source IP, optionally scoped by protocol and destination port. The default duration is 300 seconds. `duration_seconds` must be greater than 0 and at most 31536000.

- `GET /temp-bans?page=1&page_size=20`
- `POST /temp-bans`
- `POST /temp-bans/batch`
- `DELETE /temp-bans/{id}`
- `DELETE /temp-bans/batch`

Example:

```bash
curl -X POST http://127.0.0.1:8080/temp-bans \
  -H "X-API-Token: $XDP_FIREWALL_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"cidr":"203.0.113.10/32","protocol":"tcp","port":443,"duration_seconds":300,"comment":"manual block"}'
```

Only unexpired temporary bans are sent to agents. The BPF map stores a monotonic expiration timestamp, so an already-applied ban stops dropping packets when it expires even if no new policy version is pushed. Whitelist entries remain higher priority than temporary bans so trusted control-plane, Kubernetes, or operator CIDRs are still allowed.

## Dynamic Defense

Global dynamic defense is enabled by default and applies after ordinary firewall, threat intelligence, and country allow/deny decisions:

- `ip_rate_limit`: per-source-IP token bucket.
- `flood`: per-source-IP token bucket with a temporary block window after the threshold is exceeded.

Whitelist entries are evaluated before dynamic defense, so matching sources are allowed immediately. Configure dynamic defense through:

- `GET /dynamic-defense`
- `PUT /dynamic-defense`
- `GET /dynamic-rate-limits?page=1&page_size=20`
- `POST /dynamic-rate-limits`
- `POST /dynamic-rate-limits/batch`
- `DELETE /dynamic-rate-limits/{id}`
- `DELETE /dynamic-rate-limits/batch`
- `DELETE /dynamic-rate-limits?enabled=true&priority=10&protocol=tcp&port=443&packets_per_second=1000&burst=2000`

Custom dynamic rate limits are enabled rows with `priority`, `protocol`, optional `port`, `packets_per_second`, `burst`, and optional `comment`. Lower numeric priority is higher priority when multiple rows compile to the same effective key. A row with `protocol=any` and `port=443` rate-limits traffic to destination port 443 for protocols that expose a destination port; `protocol=tcp` with no port rate-limits all TCP traffic per source IP. Custom limits run before the global `ip_rate_limit` and `flood` checks.

## Agent Mode

Use `agent` for persistent enforcement. The agent does not connect to the configuration database. It subscribes to the xDS control plane configured by `--control-url` or `XDP_FIREWALL_XDS_URL`; authenticate it with `--agent-token` or `XDP_FIREWALL_AGENT_TOKEN`.

`sync-once` fetches one policy snapshot from xDS, applies it, then exits; on Linux this means the process no longer owns the XDP attachment. It is useful for validation workflows, not for keeping a node protected.

Do not use `xdp-firewall policy show` inside an agent-only container to inspect the applied policy. `policy show` is a database command, while agent containers intentionally do not receive `DATABASE_URL` and set `XDP_FIREWALL_AGENT_ONLY=true` to reject control-plane database commands. Use the API container's per-resource endpoints (`GET /rules`, `GET /geo-countries`, etc.), or the agent apply log instead.

The control plane controls push cadence with `xdp-firewall api --xds-push-interval-seconds 5`. Agents do not poll the database. They keep a streaming gRPC subscription open and apply updates when xDS pushes a newer version. Heartbeats still run from the agent to xDS with `--heartbeat-seconds`.

Before compiling each pushed snapshot, if the xDS control-plane host is an IP literal, the agent adds a local in-memory trusted CIDR for that controller IP. Hostnames are not resolved for this bypass to avoid DNS-based policy bypass. The current XDP program is ingress-only, so egress traffic from the agent to the controller is not restricted by this firewall.

## Agent Monitor

`monitor` is an agent-side troubleshooting command. It does not connect to the database and is allowed inside `XDP_FIREWALL_AGENT_ONLY=true` containers.

```bash
xdp-firewall monitor --once
```

By default it prints one line every five seconds. Use `--interval-seconds` to change the cadence, `--once` for a single sample, or `--json` for JSON lines. Each sample includes node identity, detected interface, xDS control URL, interface state, MTU, bpffs mount status, agent-only mode, whether `DATABASE_URL` is present, whether a local SQLite file exists in `/var/lib/xdp-firewall`, local `xdp-firewall` process count, xDS connectivity, and the current xDS policy snapshot summary when xDS is reachable.

Example output:

```text
time=2026-07-23T12:13:12Z node_id=node-1 interface=ens5 control_url=http://127.0.0.1:50051 operstate=up mtu=9001 carrier=1 bpffs_mounted=true agent_only=true database_url_present=false local_db_file_present=false xdp_firewall_processes=1 xds_status=ok policy_version=5 rules=0 geo_countries=0 trusted_cidrs=3 threat_sources=2 threat_prefixes=120 dynamic_defense=true ip_rate_limit=true flood=true
```

## Drop Visibility

The agent owns the loaded XDP maps and logs cumulative packet counters after each policy apply and on every heartbeat:

```bash
docker compose logs -f agent | grep "xdp stats"
```

Counters:

- `rule_drop`: ordinary firewall rules and threat-intelligence deny prefixes.
- `geo_drop`: country deny rules.
- `temp_ban_drop`: temporary source-CIDR ban.
- `custom_rate_drop`: custom dynamic defense protocol/port rate limit.
- `rate_drop`: global `ip_rate_limit`.
- `flood_drop`: global `flood` temporary block/limit.
- `parse_drop`: malformed packet parse drops.
- `drop_total`: sum of all drop counters.
- `pass`: allowed packets, including whitelist matches.

These counters show which class is dropping traffic. Use realtime drop events when you need source IP and packet metadata.

The embedded frontend has a realtime Drop page. Press Start to subscribe to all nodes, or select one node to subscribe only to that agent. The API tells agents through xDS to enable Drop monitoring only while a matching frontend subscriber is connected. When the last matching subscriber disconnects, xDS pushes the disabled state and agents stop reading the perf event buffer. The events are kept in memory and are not persisted to the database.

For `threat_intel` drops, the control plane enriches streamed events with `threat_source` by looking up the source IP in an mmap-backed MMDB rebuilt from `firewall_threat_prefixes`. If multiple persisted feeds contain the same prefix, their names are returned as a comma-separated value.

The HTTP stream also supports node filtering directly:

```bash
curl -H "X-API-Token: $XDP_FIREWALL_API_TOKEN" \
  "http://127.0.0.1:8080/drop-events/stream?node_id=node-1"
```

Each NDJSON event includes `node_id`, `interface_name`, `time`, `event_time_ns`, `cpu`, `reason`, `src`, `family`, `proto`, `dport`, `country`, `threat_source`, and `action`.

For realtime drop events, start the agent with the current image and run:

```bash
xdp-firewall monitor --drop
```

The agent pins the drop event map at `/sys/fs/bpf/xdp-firewall/<interface>/drop_events`; `monitor --drop` opens that pinned map and prints one line per dropped packet. It also temporarily enables the pinned `/sys/fs/bpf/xdp-firewall/<interface>/drop_config` switch while the command is running and resets it on Ctrl-C or SIGTERM. SIGKILL cannot be caught. Use `--json` for JSON lines.

Realtime event `reason` values are product-oriented:

- `firewall_rule`: ordinary firewall rule.
- `threat_intel`: built-in or configured threat intelligence prefix.
- `temporary_ban`: temporary source-CIDR ban.
- `country`: country rule.
- `dynamic_defense.custom_rate_limit`: custom protocol/port rate limit.
- `dynamic_defense.ip_rate_limit`: global per-source-IP rate limit.
- `dynamic_defense.flood`: flood temporary block/limit.
- `parse_error`: malformed packet parse drop.

## xDS Control Plane

The `api` command starts xDS by default on `0.0.0.0:50051`:

```bash
XDP_FIREWALL_AGENT_TOKEN='change-this-agent-token' \
xdp-firewall api --bind 0.0.0.0:8080 --xds-bind 0.0.0.0:50051 --xds-push-interval-seconds 5
```

xDS runs in the same control-plane process as the HTTP API. It reads policy snapshots from the database and accepts node heartbeats. Node list responses include derived `sync_status`, `healthy`, `seconds_since_seen`, and `current_policy_version` fields so stale/offline agents are visible even when their last raw status was `ok`. The control plane runs node maintenance every 60 seconds and prunes node heartbeat rows that have not checked in for more than 300 seconds; `POST /nodes/maintenance?max_age_seconds=300` runs the same cleanup manually. Agents that recover later recreate their heartbeat row automatically. `XDP_FIREWALL_AGENT_TOKEN` is required when xDS binds to a non-loopback address. Agents must send the token with `Authorization: Bearer <token>` or `x-agent-token`.

`xdp-firewall xds` is still available for debugging or intentionally split control-plane deployments, but the provided Docker Compose and Kubernetes templates run xDS inside the API service to keep production configuration smaller.

### xDS TLS / mutual TLS (optional, disabled by default)

The gRPC xDS listener is plaintext HTTP/2 protected by the agent token by default. TLS and mutual TLS are opt-in through certificate flags on the control plane; agents enable TLS automatically when their control URL starts with `https://`.

Control plane (both `api` and the standalone `xds` command):

- `--xds-tls-cert` / `XDP_FIREWALL_XDS_TLS_CERT`: PEM server certificate. Setting this together with `--xds-tls-key` enables TLS.
- `--xds-tls-key` / `XDP_FIREWALL_XDS_TLS_KEY`: PEM server private key. Must be paired with `--xds-tls-cert`.
- `--xds-tls-client-ca` / `XDP_FIREWALL_XDS_TLS_CLIENT_CA`: PEM CA used to verify agent client certificates. Setting this upgrades TLS to mutual TLS; agents must then present a client certificate signed by this CA.
- `--xds-tls-auto` / `XDP_FIREWALL_XDS_TLS_AUTO`: generate the whole PKI automatically in `--xds-tls-dir` (default `/var/lib/xdp-firewall/tls`): a private CA (`ca.pem`/`ca.key`), a server certificate (`server.pem`/`server.key`), and one agent client certificate (`client.pem`/`client.key`). Auto mode always enables mutual TLS, reuses existing files on restart, and cannot be combined with the explicit PEM flags. Distribute `ca.pem` plus `client.pem`/`client.key` to agents; single-host agents can reference the directory directly.
- `--xds-tls-san` / `XDP_FIREWALL_XDS_TLS_SAN`: comma-separated DNS names or IPs for the auto-generated server certificate SANs. Defaults to `localhost,127.0.0.1,::1`.
- `--xds-tls-validity-days` / `XDP_FIREWALL_XDS_TLS_VALIDITY_DAYS`: validity in days for the auto-generated CA, server, and agent client certificates. Defaults to `36500` days (about 100 years); values below 1 are rejected.

Cert and key must be configured as a pair, `--xds-tls-client-ca` requires server TLS, and `--xds-tls-auto` excludes the explicit PEM flags; mismatches abort startup. With none of the flags set the listener stays plaintext, so existing deployments keep working unchanged. The agent token still applies on top of TLS.

Agent side (same flags apply to `agent`, `sync-once`, and `monitor`):

- `--control-url https://host:50051` enables TLS on the client; `http://` stays plaintext.
- `--xds-ca-cert` / `XDP_FIREWALL_XDS_CA_CERT`: PEM CA used to verify the control plane. Required for private/self-signed CAs; system root certificates are used when omitted.
- `--xds-client-cert` + `--xds-client-key` / `XDP_FIREWALL_XDS_CLIENT_CERT`, `XDP_FIREWALL_XDS_CLIENT_KEY`: client certificate pair for mutual TLS. Must be configured as a pair.
- `--xds-tls-insecure` / `XDP_FIREWALL_XDS_TLS_INSECURE`: skip control-plane certificate verification for https URLs (like `curl -k`). The connection stays encrypted but the server identity is not authenticated. Cannot be combined with `--xds-ca-cert`.
- An `http://` control URL combined with any TLS option is rejected at startup instead of silently connecting in plaintext.

HTTP API TLS (optional): `--api-tls` / `XDP_FIREWALL_API_TLS` serves the HTTP API and web console over HTTPS with the same server certificate (file-based or auto-generated). It requires xDS TLS to be configured and aborts startup otherwise; the API stays on plain HTTP when omitted. The bundled Docker Compose healthchecks probe both `https` and `http`.

Example with a private CA:

```bash
xdp-firewall api --xds-bind 0.0.0.0:50051 \
  --xds-tls-cert /etc/xdp-firewall/tls/server.pem \
  --xds-tls-key /etc/xdp-firewall/tls/server.key \
  --xds-tls-client-ca /etc/xdp-firewall/tls/ca.pem

xdp-firewall agent --control-url https://control.example:50051 \
  --xds-ca-cert /etc/xdp-firewall/tls/ca.pem \
  --xds-client-cert /etc/xdp-firewall/tls/client.pem \
  --xds-client-key /etc/xdp-firewall/tls/client.key
```

Fully automatic mode — no certificates to prepare, everything generated on first start and reused afterwards:

```bash
xdp-firewall api --xds-bind 0.0.0.0:50051 \
  --xds-tls-auto \
  --xds-tls-dir /var/lib/xdp-firewall/tls \
  --xds-tls-san control.example,127.0.0.1 \
  --api-tls

xdp-firewall agent --control-url https://control.example:50051 \
  --xds-ca-cert /var/lib/xdp-firewall/tls/ca.pem \
  --xds-client-cert /var/lib/xdp-firewall/tls/client.pem \
  --xds-client-key /var/lib/xdp-firewall/tls/client.key
```

Quick self-signed CA for testing:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 -subj "/CN=xdp-firewall-ca"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=control.example"
printf "subjectAltName=DNS:control.example\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 3650 -extfile server.ext
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=xdp-agent"
printf "extendedKeyUsage=clientAuth\n" > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 3650 -extfile client.ext
```

XDP attach mode is selected with `--xdp-mode` or `XDP_FIREWALL_XDP_MODE`:

- `auto` is the default. It tries driver/native XDP first and falls back to skb/generic XDP when the NIC or MTU does not support driver mode.
- `driver` requires native XDP and fails startup if it cannot attach.
- `skb` skips native XDP and attaches generic XDP directly. Use this on AWS ENA instances that keep jumbo MTU enabled and report `current MTU is larger than the maximum allowed MTU`.

XDP attach strategy is selected with `--xdp-attach-strategy` or `XDP_FIREWALL_XDP_ATTACH_STRATEGY`:

- `direct` is the default. The agent loads the Aya-owned XDP object and updates its maps directly. In this mode startup refuses to attach when the interface already has an XDP program, so an existing program is not replaced accidentally.
- `--xdp-allow-replace` / `XDP_FIREWALL_XDP_ALLOW_REPLACE=true` enables direct-mode compare-and-replace through netlink when the selected interface already has an XDP program. The replacement is intentional and does not restore the previous program when this agent exits; use dispatcher mode for shared interfaces where multiple programs must coexist.
- `dispatcher` uses `xdp-loader`/libxdp multiprogram attach. The agent creates or reuses pinned maps under `/sys/fs/bpf/xdp-firewall/<interface>`, unloads an existing dispatcher entry with the same program name on the same interface, runs `xdp-loader load --pin-path ... --prog-name ... --prio ...`, verifies with `bpftool` that the loaded dispatcher program references the same pinned map IDs, and then updates those same live maps. Lower `--xdp-run-priority` values run earlier in the dispatcher chain; the default is `10`.
- `XDP_FIREWALL_XDP_ALLOW_REPLACE` is not needed in dispatcher mode because dispatcher attach already converges by replacing the same program name in the libxdp chain.
- Dispatcher mode requires `xdp-loader` from `xdp-tools` and `bpftool` in the agent image or host. The provided Dockerfile installs both.
- Dispatcher attachments are owned by libxdp/xdp-loader, so they are not automatically detached when the agent process exits. Use `xdp-loader status` and `xdp-loader unload` for manual dispatcher cleanup.
- `xdp-firewall monitor` prints `xdp_attached` and `xdp_summary` to help detect an existing XDP attachment before starting the agent.
- Interface names used for bpffs pin paths are sanitized and cannot be empty, `.`, or `..`; VLAN-style names such as `eth0.10` remain valid.

Dispatcher lifecycle commands are available through `xdp-firewall xdp`:

```bash
# Show interface XDP state plus xdp-loader's dispatcher table.
xdp-firewall xdp status --interface ens5

# Decode temporary bans currently present in the pinned temp_bans map.
xdp-firewall xdp temp-bans --interface ens5
xdp-firewall xdp temp-bans --interface ens5 --json

# Unload every dispatcher program from the interface. Pinned policy maps are kept by default.
xdp-firewall xdp unload --interface ens5 --all --clean

# Unload all dispatcher programs and remove pinned policy maps.
xdp-firewall xdp unload --interface ens5 --all --remove-pins --clean

# Replace the dispatcher-managed xdp-firewall program while keeping pinned maps and policy state.
xdp-firewall xdp replace --interface ens5 --xdp-object /usr/local/share/xdp-firewall/xdp_firewall.o --program xdp_firewall --xdp-run-priority 10

# Replace one program ID from `xdp-firewall xdp status`.
xdp-firewall xdp replace --interface ens5 --id 55
```

`unload` always requires an explicit `--interface` plus either `--all` or `--id <program-id>` so removal is intentional. `replace` also requires an explicit `--interface`; `--all` or `--id` are optional and only needed when you want an explicit pre-unload step before the new dispatcher attach. The normal replace path unloads existing entries with the same program name before loading the new one. `--all` removes every dispatcher-managed XDP program on that interface, not just xdp-firewall; prefer `--id` when replacing only one program in a shared chain. `--remove-pins` is accepted only with `--all`, because pinned maps may still be used by another dispatcher program when only one program ID is removed.

## Standby Mode

`--standby` runs the control plane in a read-only mode that performs no database writes. It is intended for a standby/replica control plane that shares the same database as the primary but must not compete with it for writes.

```bash
XDP_FIREWALL_API_TOKEN='...' XDP_FIREWALL_AGENT_TOKEN='...' \
xdp-firewall api --standby
```

Equivalent environment form:

```bash
XDP_FIREWALL_STANDBY=true xdp-firewall api
```

In standby mode the control plane:

- Skips startup database migrations and builtin policy seeding — the primary control plane is expected to have already migrated and seeded the shared database.
- Rejects every mutating API endpoint (POST/PUT/DELETE/PATCH) with HTTP 503; read endpoints (`GET /rules`, `GET /geo-countries`, `GET /policy/version`, `GET /nodes`, `/health`, `/countries`, `/geo/lookup`), the realtime Drop SSE stream, and the embedded frontend remain available.
- Disables the xDS background country-IP refresh, threat-intelligence refresh, and node-maintenance loops; the in-memory threat lookup rebuild (read-only) still runs.
- Skips temporary-ban cleanup during xDS push ticks.
- Accepts agent heartbeats (returns `accepted: true`) but does not persist them to `firewall_nodes`, so agent state is not durable while the standby plane is the only reachable control plane.

The `XDP_FIREWALL_STANDBY` environment variable is also honored by one-shot commands: `xdp-firewall migrate` and `xdp-firewall policy seed-example` are rejected with an error in standby mode, while `xdp-firewall policy show` (read-only) still works. Use the primary control plane to migrate or seed.

A standby control plane can still serve agents: it loads and pushes policy snapshots from the shared database over xDS. Because realtime Drop subscription state is held in process memory, run only one active control plane (primary or standby) as the reachable xDS endpoint per agent, or add sticky routing / a shared pub/sub backend before running multiple replicas concurrently.

## XDP Map Sizing

The BPF object has conservative built-in defaults, and the agent can override map capacities before loading the object with Aya:

- `--rule-map-entries` / `XDP_FIREWALL_RULE_MAP_ENTRIES`, default `262144`.
- `--geo-map-entries` / `XDP_FIREWALL_GEO_MAP_ENTRIES`, default `262144`.
- `--trusted-map-entries` / `XDP_FIREWALL_TRUSTED_MAP_ENTRIES`, default `4096`.
- `--country-map-entries` / `XDP_FIREWALL_COUNTRY_MAP_ENTRIES`, default `676`.
- `--rate-map-entries` / `XDP_FIREWALL_RATE_MAP_ENTRIES`, default `1048576`.
- `--custom-rate-limit-map-entries` / `XDP_FIREWALL_CUSTOM_RATE_LIMIT_MAP_ENTRIES`, default `4096`.
- `--temp-ban-map-entries` / `XDP_FIREWALL_TEMP_BAN_MAP_ENTRIES`, default `4096`.
- `--auto-resize-maps` / `XDP_FIREWALL_AUTO_RESIZE_MAPS`, default `true`.

When dispatcher mode reuses existing pinned maps, the kernel keeps the old map capacities. The agent reads the real pinned-map capacities after attach and validates future policy updates against those real values, not just the requested CLI/env values. If `XDP_FIREWALL_AUTO_RESIZE_MAPS` is enabled, a policy that exceeds the current `rule_cidrs`, `geo_cidrs`, `trusted_cidrs`, `country_rules`, `custom_rate_limits`, or `temp_bans` capacity automatically unloads XDP, removes pinned maps, recreates them at `max(required, current * 2)` rounded up to a power of two, and reapplies the same policy. This causes a brief XDP reload window. Disable auto resize and run an explicit unload with `--remove-pins` during a controlled maintenance window if capacity changes must be manually scheduled.

Default capacity and approximate key/value payload:

| Map | Default entries | Purpose | Approximate key/value payload |
| --- | ---: | --- | ---: |
| `rule_cidrs` | `262144` | Ordinary firewall CIDR rules | `8 MiB` |
| `geo_cidrs` | `262144` | Country CIDR prefixes | `6.5 MiB` |
| `trusted_cidrs` | `4096` | Highest-priority source CIDR whitelist | `0.1 MiB` |
| `temp_bans` | `4096` | Temporary source-CIDR bans | `0.1 MiB` |
| `country_rules` | `676` | Country-code allow/deny actions | A few KiB |
| `defense_policy` | `1` | Global dynamic defense configuration | Negligible |
| `custom_rate_limits` | `4096` | Custom protocol/port dynamic rate-limit definitions | `0.1 MiB` |
| `rate_buckets` | `1048576` | Per-source-IP `ip_rate_limit` and `flood` token buckets | `46-48 MiB` |
| `stats` | `8` | Per-CPU counters: pass, rule, country, temp ban, custom rate, global rate, flood, and parse drops | Negligible |

The payload estimates count only the BPF key/value structs. Actual kernel memory is higher because hash tables, LRU bookkeeping, allocator rounding, per-CPU storage, and map metadata add overhead.

`rule_cidrs`, `geo_cidrs`, `trusted_cidrs`, and `temp_bans` are LPM trie maps with `BPF_F_NO_PREALLOC`, so they grow with inserted prefixes instead of allocating the full capacity at startup. `custom_rate_limits` is a small hash map for configured exact-match keys. `rate_buckets` is the main memory driver because it can hold up to `XDP_FIREWALL_RATE_MAP_ENTRIES` source-IP state entries for dynamic defense.

Default Docker Compose deployments do not set explicit map entry values. Keep the defaults unless an agent reports a map capacity error or the deployment has a measured memory target that requires explicit sizing. These sizes are chosen at XDP load time; changing them for an existing pinned-map deployment requires map recreation, either through automatic resize or an explicit unload with pin removal.

## Packaging

```bash
make zig-build-all
make docker-build
make docker-run
make docker-api
```

`cargo-zigbuild` and Zig must be installed on the build host. The Docker image compiles `bpf/xdp_firewall.c` into `/usr/local/share/xdp-firewall/xdp_firewall.o` during image build.

The Docker image defaults to single-node SQLite API mode. With no arguments it runs migrations and starts the embedded web console/API:

```bash
docker run --rm --privileged --net host \
  -e XDP_FIREWALL_API_TOKEN='change-this-token' \
  -v xdp-firewall-data:/var/lib/xdp-firewall \
  1228022817/xdp-firewall:0.1.9
```

Explicit CLI arguments still work:

```bash
docker run --rm --privileged --net host \
  -e XDP_FIREWALL_API_TOKEN='change-this-token' \
  -v xdp-firewall-data:/var/lib/xdp-firewall \
  1228022817/xdp-firewall:0.1.9 \
  api --database-url 'sqlite:///var/lib/xdp-firewall/xdp-firewall.db?mode=rwc'
```

## Deployment

Docker Compose and Kubernetes templates are in [deploy](deploy/README.md).
