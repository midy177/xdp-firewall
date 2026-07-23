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

The monitor line includes interface state, MTU, bpffs mount status, agent-only mode, whether `DATABASE_URL` is present, whether `/var/lib/xdp-firewall/xdp-firewall.db` exists, local agent process count, xDS connectivity, and current xDS policy snapshot counts. Add `--json` for JSON lines.

`XDP_FIREWALL_TRUSTED_CIDRS` accepts multiple CIDRs as a comma-separated value in `compose-env.local`, with no spaces:

```dotenv
XDP_FIREWALL_TRUSTED_CIDRS=10.0.0.0/8,192.168.0.0/16,203.0.113.10/32
```

This is equivalent to starting the API with repeated clap flags:

```bash
xdp-firewall api --trusted-cidr 10.0.0.0/8 --trusted-cidr 192.168.0.0/16 --trusted-cidr 203.0.113.10/32
```

## Kubernetes

Edit this file before applying:

- `deploy/kubernetes/secret.yaml`: set `database_url` to your PostgreSQL or MySQL connection string, `api_token` to the API bearer token, and `agent_token` to the xDS agent token.
- `deploy/kubernetes/kustomization.yaml`: set the image name and tag pushed to your registry.

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
- xDS agent authentication is required when `XDP_FIREWALL_AGENT_TOKEN` is set. Change the template token before deploying.
- The single firewall policy is initialized with default dynamic defense and built-in `ipsum` and `spamhaus-drop` threat intelligence feeds.
- Custom threat feed hosts must be added to `XDP_FIREWALL_ALLOWED_THREAT_HOSTS`; built-in feed hosts are allowed by default.
- The DaemonSet is privileged and uses `hostNetwork` because XDP attach is a host-network operation.
- The agent auto-selects the default-route interface when `--interface` is omitted.
- The agent resolves the configured xDS host and adds local in-memory allow rules for those controller IPs before applying each policy snapshot. The current XDP program is ingress-only, so egress from the agent to the controller is not limited by this firewall.
- XDP attach mode can be set with `XDP_FIREWALL_XDP_MODE=auto|driver|skb`. Use `skb` on AWS ENA instances with jumbo MTU if native driver XDP reports that the MTU is too large.
- Trusted source prefixes can be initialized on `api` with `--trusted-cidr` or `XDP_FIREWALL_TRUSTED_CIDRS` and then managed through the API/frontend; agents apply the xDS-pushed whitelist and do not mutate it. Trusted prefixes are the highest-priority whitelist and are allowed before firewall, threat-intelligence, country, and dynamic defense checks.
- XDP map sizes have built-in defaults. Do not set map capacity variables unless an agent reports a map capacity error or you have a measured memory target.
- Nodes must have bpffs mounted at `/sys/fs/bpf`.
- Use PostgreSQL/MySQL for multi-node Kubernetes deployments. SQLite is only appropriate for a single server.
