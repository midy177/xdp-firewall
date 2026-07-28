BIN ?= xdp-firewall
VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
IMAGE_REPO ?= xdp-firewall
IMAGE ?= $(IMAGE_REPO):$(VERSION)
CONTAINER_NAME ?= xdp-firewall
API_BIND ?= 0.0.0.0:8080
API_PORT ?= 8080
ZIG_TARGET_AMD64 ?= x86_64-unknown-linux-musl
ZIG_TARGET_ARM64 ?= aarch64-unknown-linux-musl
ZIG ?= zig
DOCKER_PLATFORM ?= linux/amd64
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64
DIST_DIR ?= dist
FRONTEND_DIR ?= frontend
FRONTEND_PM ?= $(shell if command -v bun >/dev/null 2>&1; then echo bun; elif command -v pnpm >/dev/null 2>&1; then echo pnpm; else echo npm; fi)

.PHONY: build
build:
	cargo build --bin $(BIN)

.PHONY: frontend-install
frontend-install:
	cd $(FRONTEND_DIR) && $(FRONTEND_PM) install

.PHONY: frontend-build
frontend-build:
	cd $(FRONTEND_DIR) && $(FRONTEND_PM) run build

.PHONY: release
release: frontend-build
	cargo build --release --bin $(BIN)

.PHONY: zig-build
zig-build: zig-build-amd64

.PHONY: zig-build-amd64
zig-build-amd64: frontend-build
	cargo zigbuild --release --bin $(BIN) --target $(ZIG_TARGET_AMD64)
	mkdir -p $(DIST_DIR)/linux-amd64
	cp target/$(ZIG_TARGET_AMD64)/release/$(BIN) $(DIST_DIR)/linux-amd64/$(BIN)

.PHONY: zig-build-arm64
zig-build-arm64: frontend-build
	cargo zigbuild --release --bin $(BIN) --target $(ZIG_TARGET_ARM64)
	mkdir -p $(DIST_DIR)/linux-arm64
	cp target/$(ZIG_TARGET_ARM64)/release/$(BIN) $(DIST_DIR)/linux-arm64/$(BIN)

.PHONY: zig-build-all
zig-build-all: zig-build-amd64 zig-build-arm64

.PHONY: run
run:
	cargo run --bin $(BIN) -- agent

.PHONY: api
api:
	cargo run --bin $(BIN) -- api --bind $(API_BIND)

.PHONY: migrate
migrate:
	cargo run --bin $(BIN) -- migrate

.PHONY: seed-example
seed-example:
	cargo run --bin $(BIN) -- policy seed-example

.PHONY: show-policy
show-policy:
	cargo run --bin $(BIN) -- policy show

.PHONY: test
test:
	cargo test

.PHONY: fmt
fmt:
	cargo fmt --check

.PHONY: clippy
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

.PHONY: docker-build
docker-build: zig-build
	docker build --platform $(DOCKER_PLATFORM) -t $(IMAGE) .

.PHONY: docker-build-amd64
docker-build-amd64: zig-build-amd64
	docker build --platform linux/amd64 -t $(IMAGE) .

.PHONY: docker-build-arm64
docker-build-arm64: zig-build-arm64
	docker build --platform linux/arm64 -t $(IMAGE) .

.PHONY: docker-buildx-push
docker-buildx-push: zig-build-all
	docker buildx build --platform $(DOCKER_PLATFORMS) -t $(IMAGE) --push .

.PHONY: docker-run
docker-run:
	docker run --rm --name $(CONTAINER_NAME) \
		--cap-add NET_ADMIN \
		--cap-add BPF \
		--cap-add PERFMON \
		--network host \
		--uts host \
		--mount type=bind,source=/sys/fs/bpf,target=/sys/fs/bpf \
		$(IMAGE) agent

.PHONY: docker-api
docker-api:
	docker run --rm --name $(CONTAINER_NAME)-api \
		-p $(API_PORT):8080 \
		-v $(PWD)/xdp-firewall.db:/var/lib/xdp-firewall/xdp-firewall.db \
		-e DATABASE_URL=sqlite:///var/lib/xdp-firewall/xdp-firewall.db?mode=rwc \
		$(IMAGE) api --bind 0.0.0.0:8080

.PHONY: docker-shell
docker-shell:
	docker run --rm -it --entrypoint /bin/sh \
		--name $(CONTAINER_NAME)-shell \
		--network host \
		$(IMAGE)

.PHONY: compose-sqlite-up
compose-sqlite-up:
	docker compose -f deploy/docker-compose/compose.sqlite.yml up -d

.PHONY: compose-postgres-up
compose-postgres-up:
	docker compose -f deploy/docker-compose/compose.postgres.yml up -d

.PHONY: compose-agent-up
compose-agent-up:
	docker compose -f deploy/docker-compose/compose.agent.yml up -d

.PHONY: compose-sqlite-down
compose-sqlite-down:
	docker compose -f deploy/docker-compose/compose.sqlite.yml down

.PHONY: compose-postgres-down
compose-postgres-down:
	docker compose -f deploy/docker-compose/compose.postgres.yml down

.PHONY: compose-agent-down
compose-agent-down:
	docker compose -f deploy/docker-compose/compose.agent.yml down

.PHONY: k8s-apply
k8s-apply:
	kubectl apply -k deploy/kubernetes

.PHONY: k8s-delete
k8s-delete:
	kubectl delete -k deploy/kubernetes
