# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM rust:1.86-slim AS builder

WORKDIR /usr/src/safegate

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy cargo manifest files first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY safegate-core/Cargo.toml safegate-core/
COPY safegate-wasm/Cargo.toml safegate-wasm/
COPY safegate-audit/Cargo.toml safegate-audit/
COPY safegate-proxy/Cargo.toml safegate-proxy/

# Copy full source code
COPY safegate-core safegate-core
COPY safegate-wasm safegate-wasm
COPY safegate-audit safegate-audit
COPY safegate-proxy safegate-proxy

# Build release binary for safegate-proxy
RUN cargo build --release -p safegate-proxy

# ── Stage 2: Production Runtime ──────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies and curl for health check probe
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Security Hardening: Create non-root user and group (uid/gid 10001)
RUN groupadd -g 10001 safegate \
    && useradd -u 10001 -g safegate -m -s /bin/false safegate

WORKDIR /app

# Create policies directories with unprivileged user ownership
RUN mkdir -p /app/policies/tenants \
    && chown -R safegate:safegate /app

# Copy binary from builder stage
COPY --from=builder --chown=safegate:safegate /usr/src/safegate/target/release/safegate-proxy /app/safegate-proxy

# Switch to non-root user
USER safegate:safegate

# Environment variables with sensible defaults inside container
ENV SAFEGATE_LISTEN_ADDR="0.0.0.0:8080" \
    SAFEGATE_TARGET_MCP_URL="http://127.0.0.1:3000" \
    SAFEGATE_POLICY_DIR="/app/policies" \
    SAFEGATE_TENANT_POLICY_DIR="/app/policies/tenants"

EXPOSE 8080
EXPOSE 9090

# Health check probe using /healthz endpoint
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/safegate-proxy"]
