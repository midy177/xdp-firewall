# xdp-firewall

Distributed XDP firewall control plane written in Rust.

Each server runs the same agent. A single firewall policy is stored in SQLite, PostgreSQL, or MySQL with SeaORM. The API control-plane process writes configuration to the database and exposes both the Axum HTTP API/UI and a gRPC xDS stream; agents subscribe to xDS and apply the latest policy to local XDP maps through Aya. SQLite is intended for a single-server deployment; PostgreSQL/MySQL are the distributed configuration source for multiple servers. The policy is initialized with built-in threat intelligence feeds for `ipsum` and `spamhaus-drop`.

## Quick Start

```bash
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
cargo run -- migrate
XDP_FIREWALL_API_TOKEN='change-this-token' \
XDP_FIREWALL_AGENT_TOKEN='change-this-agent-token' \
cargo run -- api --bind 0.0.0.0:8080 --xds-bind 0.0.0.0:50051
```

Useful endpoints:

- `GET /health`
- `GET /countries`
- `GET /policy`
- `POST /policy/seed-example`
- `POST /policy/bump-version`
- `GET /rules?page=1&page_size=100`
- `POST /rules`
- `DELETE /rules/{id}`
- `GET /geo-countries?page=1&page_size=100`
- `POST /geo-countries`
- `GET /threat-sources?page=1&page_size=100`
- `POST /threat-sources`
- `GET /nodes?page=1&page_size=100`

Example:

```bash
curl -X POST http://127.0.0.1:8080/rules \
  -H "authorization: Bearer $XDP_FIREWALL_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"priority":10,"action":"deny","cidr":"203.0.113.0/24","protocol":"any"}'
```

Every mutating endpoint increments the policy version so the xDS control plane can push a fresh snapshot to running agents.

List endpoints return `items`, `total`, `page`, `page_size`, and `total_pages`. The default page size is `100`; the maximum is `500`.

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
- `firewall_rules`: static allow/deny CIDR rules, optional protocol and port match.
- `firewall_geo_country_policies`: per-country allow/deny policy.
- `firewall_dynamic_defense`: global `ip_rate_limit` and `flood` policy.
- `firewall_trusted_cidrs`: CIDR whitelist for global dynamic defense.
- `firewall_threat_sources`: threat-intelligence feed definitions.
- `firewall_nodes`: distributed node heartbeat and last applied version.

Built-in threat sources:

- `ipsum`: `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`, format `ipsum`, minimum score `3`.
- `spamhaus-drop`: `https://www.spamhaus.org/drop/drop.txt`, format `spamhaus_drop`.

Threat feeds are fetched with a timeout, no redirects, and a 16 MiB response limit. Only built-in feed hosts are allowed by default; add comma-separated custom hosts with `XDP_FIREWALL_ALLOWED_THREAT_HOSTS` before enabling custom feed URLs.

## XDP Object

`bpf/xdp_firewall.c` is the kernel program source. Build it with your normal eBPF toolchain, for example:

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c bpf/xdp_firewall.c -o bpf/xdp_firewall.o
```

The userspace agent defaults to `/usr/local/share/xdp-firewall/xdp_firewall.o`. Pass `--xdp-object ./bpf/xdp_firewall.o` for local development or custom packaging.

## Trusted CIDRs

Trusted CIDRs are the whitelist for global dynamic defense. Source IPs matching these prefixes still go through ordinary firewall rules, threat intelligence, and country allow/deny rules, but skip global `ip_rate_limit` and `flood` checks.

They are stored in the database so every agent sees the same whitelist. Initialize entries from the API process with Clap arguments or environment variables, or manage them later through the API/frontend. Agents read the database and apply the whitelist; they do not mutate whitelist configuration.

```bash
xdp-firewall api \
  --trusted-cidr 10.0.0.0/8 \
  --trusted-cidr 192.168.0.0/16
```

Equivalent environment form:

```bash
XDP_FIREWALL_TRUSTED_CIDRS=10.0.0.0/8,192.168.0.0/16 xdp-firewall api
```

The same whitelist can be managed through:

- `GET /trusted-cidrs`
- `POST /trusted-cidrs`
- `DELETE /trusted-cidrs/{id}`

## Dynamic Defense

Global dynamic defense is enabled by default and applies after ordinary firewall, threat intelligence, and country allow/deny decisions:

- `ip_rate_limit`: per-source-IP token bucket.
- `flood`: per-source-IP token bucket with a temporary block window after the threshold is exceeded.

Trusted CIDRs skip these global dynamic defense checks. Configure dynamic defense through:

- `GET /dynamic-defense`
- `PUT /dynamic-defense`

## Agent Mode

Use `agent` for persistent enforcement. The agent does not connect to the configuration database. It subscribes to the xDS control plane configured by `--control-url` or `XDP_FIREWALL_XDS_URL`; authenticate it with `--agent-token` or `XDP_FIREWALL_AGENT_TOKEN`.

`sync-once` fetches one policy snapshot from xDS, applies it, then exits; on Linux this means the process no longer owns the XDP attachment. It is useful for validation workflows, not for keeping a node protected.

The control plane controls push cadence with `xdp-firewall api --xds-push-interval-seconds 5`. Agents do not poll the database. They keep a streaming gRPC subscription open and apply updates when xDS pushes a newer version. Heartbeats still run from the agent to xDS with `--heartbeat-seconds`.

Before compiling each pushed snapshot, the agent resolves the xDS control-plane host and adds local in-memory allow rules for those controller IPs. This protects the controller-to-agent path from accidental ingress blocks. The current XDP program is ingress-only, so egress traffic from the agent to the controller is not restricted by this firewall.

## xDS Control Plane

The `api` command starts xDS by default on `0.0.0.0:50051`:

```bash
XDP_FIREWALL_AGENT_TOKEN='change-this-agent-token' \
xdp-firewall api --bind 0.0.0.0:8080 --xds-bind 0.0.0.0:50051 --xds-push-interval-seconds 5
```

xDS runs in the same control-plane process as the HTTP API. It reads policy snapshots from the database and accepts node heartbeats. If `XDP_FIREWALL_AGENT_TOKEN` is set, agents must send the same token with `Authorization: Bearer <token>` or `x-agent-token`.

`xdp-firewall xds` is still available for debugging or intentionally split control-plane deployments, but the provided Docker Compose and Kubernetes templates run xDS inside the API service to keep production configuration smaller.

XDP attach mode is selected with `--xdp-mode` or `XDP_FIREWALL_XDP_MODE`:

- `auto` is the default. It tries driver/native XDP first and falls back to skb/generic XDP when the NIC or MTU does not support driver mode.
- `driver` requires native XDP and fails startup if it cannot attach.
- `skb` skips native XDP and attaches generic XDP directly. Use this on AWS ENA instances that keep jumbo MTU enabled and report `current MTU is larger than the maximum allowed MTU`.

## XDP Map Sizing

The BPF object has conservative built-in defaults, and the agent can override map capacities before loading the object with Aya:

- `--rule-map-entries` / `XDP_FIREWALL_RULE_MAP_ENTRIES`, default `262144`.
- `--geo-map-entries` / `XDP_FIREWALL_GEO_MAP_ENTRIES`, default `262144`.
- `--trusted-map-entries` / `XDP_FIREWALL_TRUSTED_MAP_ENTRIES`, default `4096`.
- `--country-map-entries` / `XDP_FIREWALL_COUNTRY_MAP_ENTRIES`, default `676`.
- `--rate-map-entries` / `XDP_FIREWALL_RATE_MAP_ENTRIES`, default `1048576`.

These sizes are chosen at XDP load time. To change them on a running node, restart the agent so the eBPF maps are recreated with the new capacity.

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
  1228022817/xdp-firewall:0.1.0
```

Explicit CLI arguments still work:

```bash
docker run --rm --privileged --net host \
  -e XDP_FIREWALL_API_TOKEN='change-this-token' \
  -v xdp-firewall-data:/var/lib/xdp-firewall \
  1228022817/xdp-firewall:0.1.0 \
  --database-url 'sqlite:///var/lib/xdp-firewall/xdp-firewall.db?mode=rwc' api
```

## Deployment

Docker Compose and Kubernetes templates are in [deploy](deploy/README.md).
