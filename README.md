# xdp-firewall

Distributed XDP firewall control plane written in Rust.

Each server runs the same agent. Policy is stored in SQLite, PostgreSQL, or MySQL with SeaORM; agents poll the database by policy version and apply the latest enabled firewall policy to local XDP maps through Aya. SQLite is intended for a single-server deployment; PostgreSQL/MySQL are the distributed configuration source for multiple servers. A new policy is initialized with built-in threat intelligence feeds for `ipsum` and `spamhaus-drop`.

## Quick Start

```bash
cargo run -- migrate
cargo run -- policy seed-example
cargo run -- agent
```

PostgreSQL works with a `postgres://user:pass@host:5432/db` URL. MySQL works with a `mysql://user:pass@host:3306/db` URL.

## API

```bash
cargo run -- migrate
XDP_FIREWALL_API_TOKEN='change-this-token' cargo run -- api --bind 0.0.0.0:8080
```

Useful endpoints:

- `GET /health`
- `GET /policies?page=1&page_size=100`
- `GET /policies/{policy}`
- `POST /policies/{policy}/seed-example`
- `POST /policies/{policy}/bump-version`
- `GET /policies/{policy}/rules?page=1&page_size=100`
- `POST /policies/{policy}/rules`
- `DELETE /policies/{policy}/rules/{id}`
- `GET /policies/{policy}/geo-countries?page=1&page_size=100`
- `POST /policies/{policy}/geo-countries`
- `GET /policies/{policy}/threat-sources?page=1&page_size=100`
- `POST /policies/{policy}/threat-sources`
- `GET /nodes?page=1&page_size=100`

Example:

```bash
curl -X POST http://127.0.0.1:8080/policies/edge/rules \
  -H "authorization: Bearer $XDP_FIREWALL_API_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"priority":10,"action":"deny","cidr":"203.0.113.0/24","protocol":"any"}'
```

Every mutating endpoint increments the policy version so running agents can pick up the change on their next poll.

List endpoints return `items`, `total`, `page`, `page_size`, and `total_pages`. The default page size is `100`; the maximum is `500`.

Set `XDP_FIREWALL_API_TOKEN` to protect `/policies` and `/nodes` API routes. The API refuses to bind to a non-loopback address without a token unless `XDP_FIREWALL_ALLOW_UNAUTHENTICATED=true` is explicitly set. Clients can send either `Authorization: Bearer <token>` or `X-API-Token: <token>`. `/health` and embedded frontend assets stay public for probes and page loading. When the embedded frontend is used with auth enabled, enter the token in the API token field; it is stored in browser local storage.

## Frontend

The API server embeds `frontend/dist` into the Rust binary and serves the console from `/`. The console uses hash-based tab routing and relative API URLs so it also works behind Rancher or Kubernetes service proxy paths.

```bash
make frontend-install
make frontend-build
cargo build --release
```

The frontend source is Vue 3. `frontend/package.json` aliases Vite to Rolldown Vite and includes the shadcn-vue toolchain dependencies. `Makefile` auto-selects `bun`, `pnpm`, or `npm` for frontend commands.

## Data Model

- `firewall_policy_versions`: monotonically increasing policy versions.
- `firewall_rules`: static allow/deny CIDR rules, optional protocol and port match.
- `firewall_geo_country_policies`: per-country allow/deny/rate-limit policy.
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

Trusted CIDRs are configured on the agent with Clap arguments or environment variables and are applied before normal firewall rules, threat intelligence, country rules, and rate limits.

```bash
xdp-firewall agent \
  --trusted-cidr 10.0.0.0/8 \
  --trusted-cidr 192.168.0.0/16
```

Equivalent environment form:

```bash
XDP_FIREWALL_TRUSTED_CIDRS=10.0.0.0/8,192.168.0.0/16 xdp-firewall agent
```

## Agent Mode

Use `agent` for persistent enforcement. `sync-once` loads and applies one policy snapshot, then exits; on Linux this means the process no longer owns the XDP attachment. It is useful for validation workflows, not for keeping a node protected.

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
