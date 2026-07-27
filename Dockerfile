FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        bpftool \
        clang \
        curl \
        iproute2 \
        libbpf-dev \
        llvm \
        procps \
        tcpdump \
        xdp-tools \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/xdp-firewall

ARG TARGETARCH
COPY --chmod=755 dist/linux-${TARGETARCH}/xdp-firewall /usr/local/bin/xdp-firewall
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY bpf/xdp_firewall.c /usr/local/share/xdp-firewall/xdp_firewall.c

RUN clang -O2 -g -target bpf \
        -I/usr/include/$(uname -m)-linux-gnu \
        -c /usr/local/share/xdp-firewall/xdp_firewall.c \
        -o /usr/local/share/xdp-firewall/xdp_firewall.o

EXPOSE 8080

ENV DATABASE_URL=sqlite:///var/lib/xdp-firewall/xdp-firewall.db?mode=rwc
ENV API_BIND=0.0.0.0:8080
ENV RUST_LOG=xdp_firewall=info

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
