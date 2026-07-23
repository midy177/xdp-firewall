# XDP Firewall Plan

## Active Plan

- [completed] Add gRPC xDS control-plane support.
- [completed] Change xDS policy delivery from agent polling to server-side streaming push.
- [completed] Add control-plane push frequency control.
- [completed] Change agent to subscribe to xDS and remove direct DB access.
- [completed] Auto-allow control-plane IPs locally on agents before applying policy.
- [completed] Update Docker Compose, Kubernetes, README, and deployment docs for xDS.
- [completed] Merge API and xDS into one default control-plane service while keeping `xds` as an optional standalone command.
- [completed] Re-validate frontend build, Rust tests, clippy, and release packaging after the merged control-plane change.
- [completed] Add Docker Compose env template and document comma-separated trusted CIDR configuration.
- [completed] Keep default Compose configuration from exposing BPF map capacity tuning; document map sizing as advanced defaults only.
- [completed] Document that `policy show` is a control-plane database command, not an agent applied-policy inspection command.
- [completed] Add agent-side xDS policy snapshot summary logs with trusted CIDR and dynamic defense counts.
- [completed] Remove default database fallback from the CLI and stop exporting `DATABASE_URL` in agent container entrypoint paths.
- [completed] Move `--database-url` off the global CLI so `agent --help` does not show DB configuration.
- [completed] Keep Compose trusted CIDR template empty by default to avoid inserting example prefixes into real policy.
- [completed] Hide advanced agent map capacity flags from normal help output while keeping env/CLI overrides available.
- [completed] Add `XDP_FIREWALL_AGENT_ONLY=true` to agent deployments and reject control-plane commands inside agent-only containers.
- [completed] Add agent-side `monitor` command for troubleshooting without database access.
- [completed] Extend monitor output with agent-only, database-env, local-db-file, control URL, and JSON-line diagnostics.
- [completed] Change trusted CIDR whitelist semantics to highest-priority allow before firewall, threat, country, and dynamic defense checks.
- [completed] Update frontend UI to show global enforcement priority and mark the highest-priority ordinary rule on the current rules page.
- [completed] Rename frontend trusted CIDR wording from rate-limit whitelist to whitelist.

## Completed

- Implemented a distributed XDP firewall control plane backed by SQLite, PostgreSQL, or MySQL.
- Added automatic database migration on `api`, `agent`, `sync-once`, and policy commands.
- Added Axum API and embedded Vue 3 frontend.
- Added API token authentication with `XDP_FIREWALL_API_TOKEN`.
- Added support for both `Authorization: Bearer <token>` and `X-API-Token: <token>`.
- Added frontend login overlay when the API returns missing or invalid token.
- Fixed frontend `Input` and `Select` components so Vue `v-model` actually updates state.
- Added frontend bilingual support, defaulting to Chinese.
- Added hash routing for frontend navigation so it works behind Rancher and proxy paths.
- Added relative API URL construction for Rancher/Kubernetes service proxy compatibility.
- Added frontend validation for firewall rules, country rules, and threat source forms.
- Added API pagination for list endpoints.
- Added request logs, startup logs, agent attach logs, policy apply logs, and auth rejection logs.
- Added interface auto-discovery from the default route when `--interface` is omitted.
- Added default XDP object path: `/usr/local/share/xdp-firewall/xdp_firewall.o`.
- Added tunable XDP map sizes via Clap/env:
  - `XDP_FIREWALL_RULE_MAP_ENTRIES`
  - `XDP_FIREWALL_GEO_MAP_ENTRIES`
  - `XDP_FIREWALL_TRUSTED_MAP_ENTRIES`
  - `XDP_FIREWALL_COUNTRY_MAP_ENTRIES`
  - `XDP_FIREWALL_RATE_MAP_ENTRIES`
- Added XDP attach mode selection:
  - `XDP_FIREWALL_XDP_MODE=auto`
  - `XDP_FIREWALL_XDP_MODE=driver`
  - `XDP_FIREWALL_XDP_MODE=skb`
- Changed `auto` mode so native driver attach failure followed by successful skb attach is logged as `INFO`, not `WARN`.
- Added Docker, Docker Compose, and Kubernetes deployment templates.
- Updated deploy templates to use image `1228022817/xdp-firewall:0.1.0`.
- Added Makefile packaging flow similar to zigbuild Docker packaging.
- Confirmed `make docker-build` runs frontend build before Rust release packaging.
- Changed frontend Vite output to hash-based asset names.
- Added `build.rs` to embed hash-named frontend assets into the Rust binary.
- Added Axum static asset route `/assets/{*path}` for embedded hash assets.
- Set `index.html` cache policy to `no-store`.
- Set hash assets cache policy to `public, max-age=31536000, immutable`.
- Added built-in threat intelligence sources matching the sigproxy defaults:
  - `ipsum`
  - `spamhaus-drop`
- Added threat source safety checks:
  - no URL credentials
  - allowed hosts
  - timeout
  - no redirects
  - response size limit
- Added redaction for node error messages exposed through the API.
- Fixed BPF rule lookup so `protocol=any` with a specific port can match.
- Improved IPv6 extension header parsing.
- Added IPv4 IHL lower-bound validation.
- Added validation for non-negative numeric API fields.
- Added policy apply capacity checks for configured map sizes.
- Added BPF `defense_policy` array map for global dynamic defense config.
- Added BPF rate bucket key separation for global ip/flood buckets.
- Added BPF flood drop stat index.
- Changed BPF trusted CIDR handling so trusted sources are allowed before ordinary firewall, threat intelligence, country, and dynamic defense checks.
- Removed country rate-limit behavior from the BPF data path.
- Added DB entity and migration for `firewall_dynamic_defense`.
- Added DB entity and migration for `firewall_trusted_cidrs`.
- Added `DynamicDefensePolicy` to policy snapshots.
- Added `TrustedCidrPolicy` to policy snapshots.
- Added compilation of DB trusted CIDRs into XDP trusted prefix LPM entries.
- Added dynamic defense API:
  - `GET /policies/{policy}/dynamic-defense`
  - `PUT /policies/{policy}/dynamic-defense`
- Added trusted CIDR API:
  - `GET /trusted-cidrs`
  - `POST /trusted-cidrs`
  - `DELETE /trusted-cidrs/{id}`
- Added `api --trusted-cidr` / `XDP_FIREWALL_TRUSTED_CIDRS` persistence into `firewall_trusted_cidrs`.
- Removed `--trusted-cidr` / `XDP_FIREWALL_TRUSTED_CIDRS` from `agent` and `sync-once` so agents do not mutate whitelist configuration.
- Added gRPC xDS policy delivery.
- Changed the default control plane so `api` serves both Axum HTTP/UI and gRPC xDS.
- Added `api --xds-bind`, `api --xds-push-interval-seconds`, and `api --agent-token`.
- Kept `xds` as an optional standalone command for debugging or explicitly split deployments.
- Changed `agent` and `sync-once` to fetch policy snapshots from xDS instead of connecting to the database.
- Added agent-side local allow rules for resolved xDS controller IPs before policy compilation.
- Updated Docker Compose and Kubernetes templates so only the API service uses `DATABASE_URL`; agents use `XDP_FIREWALL_XDS_URL` and `XDP_FIREWALL_AGENT_TOKEN`.
- Changed country defense frontend to only show country code and allow/deny action.
- Added backend country list endpoint:
  - `GET /countries`
- Changed country defense frontend from manual country input to a backend-driven country dropdown.
- Changed dynamic defense defaults to enabled:
  - `ip_rate_limit` enabled, PPS `5000`, burst `10000`
  - `flood` enabled, PPS `20000`, burst `40000`, block seconds `60`
- Added frontend dynamic defense page.
- Added frontend trusted CIDR whitelist page.
- Removed user-facing multi-policy support:
  - API uses single-policy routes such as `/policy`, `/rules`, `/geo-countries`, `/dynamic-defense`, and `/trusted-cidrs`
  - frontend no longer shows or sends a policy name
  - `agent` and `sync-once` no longer accept `--policy` / `XDP_FIREWALL_POLICY`
  - internal DB `policy_name` remains as a compatibility key for the single built-in policy `edge`
- Removed `policy_name` from frontend node tables and API node responses.
- Updated README and deploy docs for global dynamic defense and trusted CIDR semantics.
- Updated tests for trusted CIDR normalization.
- Verified Docker image build and BPF C compilation after struct/map changes.

## Current Design Decisions

- Ordinary firewall rules are CIDR/protocol/port allow or deny rules.
- Threat intelligence is compiled into deny prefix rules.
- Country defense must only use country code plus allow/deny.
- Country defense must not expose or use PPS/Burst rate-limit fields in the frontend.
- Global dynamic defense owns rate-limit behavior:
  - `ip_rate_limit`: per-source-IP token bucket.
  - `flood`: per-source-IP token bucket plus temporary block window after threshold exceed.
- Global dynamic defense is enabled by default for new or missing dynamic defense rows.
- The product exposes exactly one firewall policy; no user-facing multi-policy creation or selection is allowed.
- `edge` remains the internal DB key only to avoid a destructive schema migration.
- `trusted-cidr` is the highest-priority source whitelist.
- If source IP matches `trusted-cidr`, it is allowed before ordinary firewall, threat intelligence, country, and dynamic defense checks.
- `trusted-cidr` must be persisted in DB so the control plane can push the same whitelist to all agents.
- `trusted-cidr` must support initialization from API Clap/env and management through API/frontend.
- `agent` and `sync-once` must not connect to the database or mutate firewall configuration tables; they receive policy snapshots and send heartbeat state through xDS.

## Remaining Tasks

- Optionally add deeper integration tests for dynamic defense API persistence.
- Retry `make docker-build IMAGE_REPO=1228022817/xdp-firewall` when Docker Hub is healthy. The code build, frontend build, and zigbuild steps pass; Docker image creation is currently blocked by Docker Hub returning `Bad Gateway` while resolving `debian:bookworm-slim`.

## Validation Commands

- `make frontend-build`
- `cargo fmt -- --check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `make zig-build-amd64`
- `make docker-build IMAGE_REPO=1228022817/xdp-firewall`

## Deployment Notes

- For AWS ENA with jumbo MTU where native XDP fails, set:
  - `XDP_FIREWALL_XDP_MODE=skb`
- For native XDP performance, lower MTU if required and set:
  - `XDP_FIREWALL_XDP_MODE=driver`
- For automatic best effort, keep:
  - `XDP_FIREWALL_XDP_MODE=auto`
- After frontend changes, rebuild the image so the Rust binary embeds the new hash assets.
