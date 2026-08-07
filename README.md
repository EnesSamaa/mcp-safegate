# MCP SafeGate — High-Performance Agent Security Proxy

[![CI/CD Pipeline](https://github.com/EnesSamaa/mcp-safegate/actions/workflows/ci.yml/badge.svg)](https://github.com/EnesSamaa/mcp-safegate/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 1.85+](https://img.shields.io/badge/Rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

MCP SafeGate is a production-ready, ultra-low-latency Rust reverse proxy designed to enforce strict security boundaries in front of Model Context Protocol (MCP) servers. It validates agent identity, intercepts tool calls via WASI 0.2 sandboxed WebAssembly policies, redacts sensitive PII/secrets, mitigates outlier flooding via circuit breaking, and records tamper-evident HMAC-SHA256 audit logs before requests touch upstream infrastructure.

---

## 🌟 Key Features

- **Agentic Identity & RBAC**: Extracts agent and tenant context from HTTP headers (`x-agent-id`, `x-tenant-id`), validating bearer credentials at the network edge.
- **WASI 0.2 Policy Engine**: Sandboxed WASM evaluation (`wasmtime` Component Model) with epoch interrupts (5 ms timeout) and 16 MiB memory limits.
- **Lock-Free Hot-Reloading**: Dynamic watcher reloads `.wasm` policy binaries on the fly via `ArcSwap` with zero request downtime.
- **Context Redaction & PII Eraser**: Automatically detects and redacts API keys (`sk-…`), Bearer tokens, email addresses, credit cards (Luhn algorithm), and high Shannon Entropy secrets.
- **Multi-Tenant Policy Routing**: Dynamically maps requests by `x-tenant-id` to dedicated tenant policies (`policies/tenants/<tenant_id>.wasm`) with automatic fallback to `default.wasm`.
- **Circuit Breaker & Outlier Interceptor**: Isolates malicious or looping agents (5+ Denies in 10s → 30s HTTP 429 quarantine).
- **HMAC-SHA256 Audit Logging**: Non-blocking asynchronous audit logger producing tamper-evident cryptographic log signatures.
- **Prometheus Metrics & Probe**: Integrated `/metrics` exposition and `/healthz` container readiness probe.
- **Security-Hardened Docker**: Multi-stage, unprivileged non-root container (`uid 10001`) with container health checks.

---

## ⚡ Performance Summary

| Metric | Measured Value | Notes |
| --- | --- | --- |
| **CircuitBreaker Check** | `< 1 µs` | In-memory atomic quarantine state verification |
| **PolicyRegistry Lookup** | `< 1 µs` | Lock-free `ArcSwap` tenant pointer resolution |
| **PII Clean String Scan** | `~1.8 µs` | Fast-path RegexSet clean-text verification |
| **PII JSON Sanitization** | `~2.8 ms` | Deep JSON tree sanitization (Regex + Luhn + Entropy) |
| **E2E Proxy Pipeline** | `~600 µs - 1.2 ms` | Full round-trip including auth, rate-limit, PII, WASM & audit |
| **Stress Throughput** | `200 req / 80 ms` | 100% success under high-concurrency stress test |

*Micro-benchmarks generated via Criterion and verified with 50+ E2E integration tests.*

---

## 🏗️ Architecture

```mermaid
flowchart TD
    Client[Agent / MCP Client] -->|POST /| Proxy[SafeGate Reverse Proxy]

    subgraph Pipeline [Request Processing Pipeline]
        Proxy --> Health{Path Check}
        Health -->|/healthz | HRes[200 OK Healthy]
        Health -->|/metrics| MRes[Prometheus Metrics]
        Health -->|/ (RPC)  | Auth[1. Bearer Token Auth]

        Auth -->|Unauthorized| 401[401 Unauthorized]
        Auth -->|Authenticated| Rate[2. Sliding-Window Rate Limiter]

        Rate -->|Exceeded| 429R[429 Rate Limit Exceeded]
        Rate -->|OK| CB[2.5 Circuit Breaker Check]

        CB -->|Open/Quarantined| 429C[429 Circuit Breaker Open]
        CB -->|Closed/OK| Body[3. JSON-RPC Read & Parse]

        Body --> Redact[3.5 PII & Secret Eraser]
        Redact --> Reg[4. Multi-Tenant WASM Registry]

        Reg -->|tenant_id| WASM[WASI 0.2 Sandbox Engine]

        WASM -->|Deny| 403[403 Guardrail Violation\nRecord Failure in CB]
        WASM -->|Allow / RedactArgs| Upstream[5. Upstream MCP Server]
    end

    Upstream -->|200 OK| Audit[6. HMAC-SHA256 Audit Logger]
    Audit -->|Metrics| Prom[7. Prometheus Exposer]
    Prom --> Client
```

---

## 🐳 Production Deployment with Docker Compose

Start SafeGate Proxy alongside Prometheus in 1 second:

```bash
# 1. Clone repository
git clone https://github.com/EnesSamaa/mcp-safegate.git
cd mcp-safegate

# 2. Start container stack
docker-compose up -d
```

Verify services:
- **Proxy Boundary**: `http://localhost:8080`
- **Health Check**: `curl http://localhost:8080/healthz`
- **Metrics Endpoint**: `curl http://localhost:8080/metrics`
- **Prometheus Dashboard**: `http://localhost:9090`

---

## ⚙️ Environment Variables Configuration

| Variable | Default Value | Description |
| --- | --- | --- |
| `SAFEGATE_LISTEN_ADDR` | `0.0.0.0:8080` | Network socket address for proxy listener |
| `SAFEGATE_TARGET_MCP_URL` | `http://127.0.0.1:3000` | Target upstream MCP server base URL |
| `SAFEGATE_POLICY_DIR` | `./policies` | Directory containing `default.wasm` fallback policy |
| `SAFEGATE_TENANT_POLICY_DIR` | `./policies/tenants` | Directory containing per-tenant `<tenant_id>.wasm` policies |
| `SAFEGATE_AUDIT_HMAC_SECRET` | `change-me-in-production` | Secret key used for signing audit log entries |

---

## 🔒 Security Hardening

- **Unprivileged Container User**: Docker image executes under non-root UID/GID `10001:10001` (`USER safegate`).
- **Capability-Free Sandbox**: WebAssembly guest components execute in a zero-capability WASI 0.2 environment (no filesystem, network, or env access).
- **Resource Limits**: WASM instances are restricted to 16 MiB RAM and hard-terminated after 5 ms via epoch interrupt.
- **Cryptographic Audit Integrity**: All audit entries are signed with HMAC-SHA256; any tampering invalidates the log entry signature.

---

## 💻 Local Development & Testing

Run full verification suite:

```bash
# Code formatting check
cargo fmt --all -- --check

# Strict Clippy linter
cargo clippy --workspace --benches --tests -- -D warnings

# Full workspace test suite (Unit + E2E + Chaos Stress)
cargo test --workspace

# Benchmark compilation test
cargo test --benches
```

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more details.
