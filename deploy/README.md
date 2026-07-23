# Deployment Templates

## Docker Compose

Single-node SQLite:

```bash
make docker-build
export XDP_FIREWALL_API_TOKEN='change-this-token'
docker compose -f deploy/docker-compose/compose.sqlite.yml up -d
```

PostgreSQL-backed deployment:

```bash
make docker-build
export XDP_FIREWALL_API_TOKEN='change-this-token'
docker compose -f deploy/docker-compose/compose.postgres.yml up -d
```

Agent pointed at an external or already reachable database:

```bash
DATABASE_URL=postgres://xdp_firewall:xdp_firewall@127.0.0.1:5432/xdp_firewall \
docker compose -f deploy/docker-compose/compose.agent.yml up -d
```

Seed the example firewall policy through the API:

```bash
curl -X POST http://127.0.0.1:8080/policy/seed-example \
  -H "authorization: Bearer $XDP_FIREWALL_API_TOKEN"
```

The agent service uses host networking, privileged mode, and `/sys/fs/bpf` from the host so XDP can attach to the selected network interface. Keep host-network agents separate from bridge-network database services unless the database address is reachable from the host namespace.

## Kubernetes

Edit this file before applying:

- `deploy/kubernetes/secret.yaml`: set `database_url` to your PostgreSQL or MySQL connection string and `api_token` to the API bearer token.
- `deploy/kubernetes/kustomization.yaml`: set the image name and tag pushed to your registry.

Apply:

```bash
kubectl apply -k deploy/kubernetes
```

Port-forward API:

```bash
kubectl -n xdp-firewall port-forward svc/xdp-firewall-api 8080:8080
```

Notes:

- API and agent automatically run idempotent migrations at startup.
- API token authentication is required for non-loopback API binds unless `XDP_FIREWALL_ALLOW_UNAUTHENTICATED=true` is explicitly set. Change the template token before deploying.
- The single firewall policy is initialized with default dynamic defense and built-in `ipsum` and `spamhaus-drop` threat intelligence feeds.
- Custom threat feed hosts must be added to `XDP_FIREWALL_ALLOWED_THREAT_HOSTS`; built-in feed hosts are allowed by default.
- The DaemonSet is privileged and uses `hostNetwork` because XDP attach is a host-network operation.
- The agent auto-selects the default-route interface when `--interface` is omitted.
- XDP attach mode can be set with `XDP_FIREWALL_XDP_MODE=auto|driver|skb`. Use `skb` on AWS ENA instances with jumbo MTU if native driver XDP reports that the MTU is too large.
- Trusted source prefixes can be initialized on `api` with `--trusted-cidr` or `XDP_FIREWALL_TRUSTED_CIDRS` and then managed through the API/frontend; agents only read and apply them. Trusted prefixes skip global `ip_rate_limit` and `flood`, but still go through firewall, threat, and country allow/deny decisions.
- XDP map sizes can be tuned with `XDP_FIREWALL_RULE_MAP_ENTRIES`, `XDP_FIREWALL_GEO_MAP_ENTRIES`, `XDP_FIREWALL_TRUSTED_MAP_ENTRIES`, `XDP_FIREWALL_COUNTRY_MAP_ENTRIES`, and `XDP_FIREWALL_RATE_MAP_ENTRIES`.
- Nodes must have bpffs mounted at `/sys/fs/bpf`.
- Use PostgreSQL/MySQL for multi-node Kubernetes deployments. SQLite is only appropriate for a single server.
