# Deployment Templates

## Docker Compose

Single-node SQLite:

```bash
make docker-build
cp deploy/docker-compose/compose-env deploy/docker-compose/compose-env.local
vi deploy/docker-compose/compose-env.local
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml up -d
```

After rebuilding or retagging the same image tag, recreate containers so the running agent receives the latest binary and environment:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml up -d --force-recreate
```

PostgreSQL-backed deployment:

```bash
make docker-build
cp deploy/docker-compose/compose-env deploy/docker-compose/compose-env.local
vi deploy/docker-compose/compose-env.local
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.postgres.yml up -d
```

Agent pointed at an external xDS control plane:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.agent.yml up -d
```

Set `XDP_FIREWALL_XDS_URL` in `compose-env.local` to the reachable control-plane address before starting an external agent.

Seed the example firewall policy through the API:

```bash
curl -X POST http://127.0.0.1:8080/policy/seed-example \
  -H "authorization: Bearer $XDP_FIREWALL_API_TOKEN"
```

The API control-plane service writes configuration to the database and also exposes gRPC xDS on port `50051`. Agents subscribe to that xDS endpoint. The agent service uses host networking, privileged mode, and `/sys/fs/bpf` from the host so XDP can attach to the selected network interface. Agents do not need database credentials.

The SQLite and PostgreSQL Compose templates start `api` first and start `agent` only after the API healthcheck passes. This is implemented with `depends_on: condition: service_healthy`. The standalone `compose.agent.yml` template points at an external control plane, so startup ordering must be handled outside that file.

Run `xdp-firewall policy show` only in the API/control-plane container or in a shell that has the same `DATABASE_URL`. The agent container intentionally does not receive database credentials and sets `XDP_FIREWALL_AGENT_ONLY=true`, so control-plane database commands are rejected inside agent containers. To inspect the live policy through the control plane, use:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml exec api xdp-firewall policy show
```

or the authenticated API:

```bash
curl http://127.0.0.1:8080/policy \
  -H "authorization: Bearer $XDP_FIREWALL_API_TOKEN"
```

Agent logs print a policy snapshot summary each time xDS pushes and the agent applies a version, including `trusted_cidrs`, rule counts, threat source count, and dynamic defense settings.

To verify an agent container is using the hardened runtime environment:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml exec agent printenv XDP_FIREWALL_AGENT_ONLY
```

The output should be `true`. In that mode, `docker compose exec agent xdp-firewall policy show` must fail with `control-plane database commands are disabled in this agent-only container`.

Use `monitor` inside the agent container for Cilium-style troubleshooting without database access:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml exec agent xdp-firewall monitor --once
```

For continuous output:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml exec agent xdp-firewall monitor
```

The monitor line includes interface state, MTU, bpffs mount status, agent-only mode, whether `DATABASE_URL` is present, whether `/var/lib/xdp-firewall/xdp-firewall.db` exists, local `xdp-firewall` process count, xDS connectivity, and current xDS policy snapshot counts. Add `--json` for JSON lines.

To see drop counters, follow the agent logs:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml logs -f agent | grep "xdp stats"
```

`rule_drop` means ordinary firewall or threat-intelligence deny prefixes, `geo_drop` means country denies, `temp_ban_drop` means temporary source-IP bans, `custom_rate_drop` means custom dynamic defense protocol/port limits, `rate_drop` means global `ip_rate_limit`, `flood_drop` means global `flood`, and `parse_drop` means malformed packet parse drops.

The embedded frontend includes a realtime Drop page. Press Start to subscribe through the API. It can subscribe to all nodes or a single selected node. The API asks matching agents over xDS to enable Drop monitoring only while at least one matching frontend subscriber is connected; when the last matching subscriber disconnects, agents stop the perf-buffer reader and disable the BPF event-output switch. Events are streamed in memory and are not written to the database.

For Cilium-style realtime drop events:

```bash
docker compose --env-file deploy/docker-compose/compose-env.local \
  -f deploy/docker-compose/compose.sqlite.yml exec agent xdp-firewall monitor --drop
```

Add `--json` to print JSON lines. The running agent must be from an image that pins `/sys/fs/bpf/xdp-firewall/<interface>/drop_events`; recreate the agent after upgrading the image.

Realtime event `reason` values are `firewall_rule`, `threat_intel`, `temporary_ban`, `country`, `dynamic_defense.custom_rate_limit`, `dynamic_defense.ip_rate_limit`, `dynamic_defense.flood`, and `parse_error`.

`XDP_FIREWALL_TRUSTED_CIDRS` accepts multiple CIDRs as a comma-separated value in `compose-env.local`, with no spaces:

```dotenv
XDP_FIREWALL_TRUSTED_CIDRS=10.0.0.0/8,192.168.0.0/16,203.0.113.10/32
```

This is equivalent to starting the API/control plane with repeated clap flags:

```bash
xdp-firewall api --trusted-cidr 10.0.0.0/8 --trusted-cidr 192.168.0.0/16 --trusted-cidr 203.0.113.10/32
```

`XDP_FIREWALL_TRUSTED_CIDRS` and `--trusted-cidr` are runtime-only xDS additions. They are merged into snapshots sent to agents and are not persisted in the database. Use the API/frontend whitelist page when you need database-managed whitelist entries.

## Kubernetes

Edit this file before applying:

- `deploy/kubernetes/secret.yaml`: set `database_url` to your PostgreSQL or MySQL connection string, `api_token` to the API bearer token, and `agent_token` to the xDS agent token.
- `deploy/kubernetes/kustomization.yaml`: set the image name and tag pushed to your registry.
- `deploy/kubernetes/api-deployment.yaml`: set `XDP_FIREWALL_K8S_DISCOVERY=true` if the control plane should discover Node IPs, Pod CIDRs, and Service CIDRs and inject them into xDS as runtime-only whitelist entries. Keep the API control plane at one replica unless you add sticky routing or shared pub/sub for realtime Drop streams.

Apply:

```bash
kubectl apply -k deploy/kubernetes
```

Port-forward API:

```bash
kubectl -n xdp-firewall port-forward svc/xdp-firewall-api 8080:8080
```

Port-forward xDS for an external host agent:

```bash
kubectl -n xdp-firewall port-forward svc/xdp-firewall-api 50051:50051
```

Notes:

- API automatically runs idempotent migrations at startup and starts the embedded xDS gRPC control-plane endpoint.
- Agents subscribe to xDS with `XDP_FIREWALL_XDS_URL` and `XDP_FIREWALL_AGENT_TOKEN`; they do not connect to the database.
- xDS push cadence is controlled by `api --xds-push-interval-seconds`, default `5`.
- API token authentication is required for non-loopback API binds unless `XDP_FIREWALL_ALLOW_UNAUTHENTICATED=true` is explicitly set. Change the template token before deploying.
- xDS agent authentication is required for non-loopback xDS binds. Change the template token before deploying.
- The single firewall policy is initialized with default dynamic defense and built-in `ipsum` and `spamhaus-drop` threat intelligence feeds.
- Custom threat feed hosts must be added to `XDP_FIREWALL_ALLOWED_THREAT_HOSTS`; built-in feed hosts are allowed by default.
- The DaemonSet is privileged and uses `hostNetwork` because XDP attach is a host-network operation.
- The agent auto-selects the default-route interface when `--interface` is omitted.
- If the configured xDS host is an IP literal, the agent adds a local in-memory trusted CIDR for that controller IP before applying each policy snapshot. Hostnames are not resolved for this bypass. The current XDP program is ingress-only, so egress from the agent to the controller is not limited by this firewall.
- XDP attach mode can be set with `XDP_FIREWALL_XDP_MODE=auto|driver|skb`. Use `skb` on AWS ENA instances with jumbo MTU if native driver XDP reports that the MTU is too large.
- XDP attach strategy defaults to `direct`. Direct mode refuses to start if the interface already has an XDP program attached; set `XDP_FIREWALL_XDP_ALLOW_REPLACE=true` only when compare-and-replace is intentional. Direct replacement does not restore the previous XDP program when this agent exits. `dispatcher` uses `xdp-loader`/libxdp multiprogram attach, pins maps under `/sys/fs/bpf/xdp-firewall/<interface>`, verifies with `bpftool` that the attached dispatcher program references those pinned map IDs, and orders this firewall by `XDP_FIREWALL_XDP_RUN_PRIORITY` where lower values run earlier. Dispatcher mode does not need `XDP_FIREWALL_XDP_ALLOW_REPLACE` because it replaces the same program name in the libxdp chain. Dispatcher programs are managed by xdp-loader and are not detached automatically when the agent process exits.
- The Kubernetes DaemonSet template uses dispatcher attach by default so restarts converge on one `xdp_firewall` entry instead of failing or stacking duplicate direct attachments.
- The Kubernetes API template uses a 512Mi memory limit because loading the persisted country IP lookup database and refreshing country IP metadata can exceed a small 256Mi control-plane limit.
- Use `xdp-firewall xdp status`, `xdp-firewall xdp unload --all`, or `xdp-firewall xdp replace --all` inside the privileged agent container for explicit dispatcher lifecycle operations. Pinned maps are preserved unless `--remove-pins` is provided with `--all`.
- Trusted source prefixes can be managed through the API/frontend for persistence. `--trusted-cidr` and `XDP_FIREWALL_TRUSTED_CIDRS` are runtime-only xDS additions and do not mutate database rows. Trusted prefixes are the highest-priority whitelist and are allowed before firewall, threat-intelligence, country, and dynamic defense checks.
- Dynamic defense supports global per-source-IP `ip_rate_limit` and `flood`, plus custom protocol/destination-port rate limits managed through the API/frontend. Custom dynamic limits are evaluated after country rules and before the global dynamic defense checks.
- Temporary bans can be managed through the API/frontend. They block one source IP, optionally scoped by protocol and destination port, default to 300 seconds, and are evaluated after whitelist but before ordinary firewall rules and threat intelligence.
- Kubernetes discovery RBAC is included in `deploy/kubernetes/rbac.yaml`: the API ServiceAccount has `get`, `list`, and `watch` permissions for `nodes`, `services`, and `networking.k8s.io/servicecidrs`. The control plane caches discovery results after an initial list and then uses Kubernetes watch streams instead of polling at the xDS push cadence. ServiceCIDR is preferred; existing Service ClusterIPs are used as a partial fallback when ServiceCIDR is unavailable or forbidden.
- XDP map sizes have built-in defaults. Do not set map capacity variables unless an agent reports a map capacity error or you have a measured memory target.
- Nodes must have bpffs mounted at `/sys/fs/bpf`.
- Use PostgreSQL/MySQL for multi-node Kubernetes deployments. SQLite is only appropriate for a single server.
