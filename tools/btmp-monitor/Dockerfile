FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
COPY --chmod=755 dist/linux-${TARGETARCH}/btmp-monitor /usr/local/bin/btmp-monitor

ENV RUST_LOG=btmp_monitor=info

ENTRYPOINT ["/usr/local/bin/btmp-monitor"]
