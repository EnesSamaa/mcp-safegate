# MCP SafeGate - High-Performance Agent Security Proxy

MCP SafeGate is a Rust workspace for enforcing security controls in front of Model Context Protocol (MCP) servers. It provides a low-latency reverse-proxy boundary where agent identity, authorization, quotas, policy execution, and tamper-evident auditing can be applied before a request reaches an MCP tool server.

## Features

- **Agentic Identity**: Extracts agent and tenant context from HTTP headers and validates bearer credentials at the proxy boundary.
- **RBAC Tool-level evaluation**: Supports policy-driven authorization decisions scoped to individual MCP tool calls.
- **Sliding-Window Rate Limiter**: Provides concurrent, per-agent in-memory request quotas using `DashMap`.
- **Zero-Trust Architecture**: Rejects requests that lack a valid identity before parsing or forwarding the request body.

## Performance

| Metric | Result |
| --- | --- |
| Preprocessing Latency | < 2 µs (~1.82 µs) |
| Serialization/Deserialization | ~1.47 µs |
| Concurrent Capacity | 10,000+ RPS |

Measurements are produced with Criterion on the local development environment. Treat them as micro-benchmark reference values; validate throughput and tail latency against your deployment hardware and upstream workload.

## Architecture

```mermaid
flowchart LR
    A[Agent / MCP Client] --> B[SafeGate Proxy]
    B --> C[Identity Interceptor]
    C --> D[RBAC and Policy Evaluation]
    D --> E[Sliding-Window Rate Limiter]
    E --> F[WASM Policy Engine]
    F -->|Allow| G[MCP Upstream Server]
    F -->|Deny| R[403 Forbidden]
    F -->|RedactArgs| G
    W[PolicyWatcher\nHot-Reload] -->|ArcSwap| F
    B --> I[Merkle and Ed25519 Audit Layer]
```

The workspace is organized into four focused crates:

- `safegate-core`: shared MCP/JSON-RPC models, identity types, errors, and traits.
- `safegate-proxy`: Tokio and Hyper reverse proxy with identity enforcement and rate limiting.
- `safegate-wasm`: WASI 0.2 runtime, policy engine, and hot-reload watcher.
- `safegate-audit`: Merkle-tree and Ed25519 audit primitives.

---

## WASI 0.2 Policy Engine & Sandbox Isolation

SafeGate's policy layer compiles and executes WebAssembly components that implement the `safegate-policy` WIT world. Each evaluation runs in a fully isolated, zero-capability WASI 0.2 guest.

### Isolation Guarantees

| Property | Value |
|----------|-------|
| Capability model | Zero-capability — no filesystem, network, stdio, or env access |
| Execution model | `wasmtime` Component Model, async |
| Timeout mechanism | Epoch-based interrupt (`increment_epoch` after 5 ms wall-clock) |
| Memory limit | 16 MiB per evaluation (`StoreLimitsBuilder::memory_size`) |
| Decision surface | `Allow` · `Deny(reason)` · `RedactArgs(json)` |

### Lock-Free Hot-Reloading

When a `.wasm` file is created or modified inside `./policies/`, the `PolicyWatcher` background task:

1. Receives an OS-level `notify` event.
2. Waits 50 ms to debounce burst writes.
3. Compiles the new component with the current sandbox limits.
4. If compilation succeeds → atomically swaps it via `ArcSwap::store()`.
5. If compilation fails → logs a `warn!` and keeps the previous engine intact.

Requests in flight hold an `arc_swap::Guard` snapshot of the old engine and finish normally; new requests immediately see the replacement.

### WASM Evaluation Sequence

```mermaid
sequenceDiagram
    participant C as MCP Client
    participant P as SafeGate Proxy
    participant E as WasmPolicyEngine (ArcSwap)
    participant U as MCP Upstream

    C->>P: POST /  (tools/call)
    P->>P: 1. Authenticate + Rate-limit
    P->>E: engine_guard = policy_engine.load()
    P->>E: evaluate_policy(agent_ctx, tool_params)

    alt PolicyDecision::Allow
        E-->>P: Allow
        P->>U: Forward request
        U-->>P: 200 OK
        P-->>C: 200 OK
    else PolicyDecision::Deny(reason)
        E-->>P: Deny("reason")
        P-->>C: 403 Forbidden (GuardrailViolation)
    else PolicyDecision::RedactArgs(json)
        E-->>P: RedactArgs("{\"query\":\"[REDACTED]\"}")
        P->>P: rebuild_tool_call_body()
        P->>U: Forward rewritten request
        U-->>P: 200 OK
        P-->>C: 200 OK
    end

    note over P,E: Hot-reload (background)
    note over P,E: PolicyWatcher detects .wasm change
    note over P,E: ArcSwap::store(new_engine) — zero downtime
```



## Quickstart

Prerequisites: the stable Rust toolchain and an MCP-compatible upstream listening on `http://127.0.0.1:3000`.

Start SafeGate:

```bash
cargo run -p safegate-proxy
```

Send an authenticated JSON-RPC tool call through the proxy:

```bash
curl --request POST http://127.0.0.1:8080/ \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer safegate-dev-token' \
  --header 'x-agent-id: example-agent' \
  --header 'x-tenant-id: example-tenant' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "lookup",
      "arguments": { "query": "SafeGate" }
    }
  }'
```

The development token is intentionally a deterministic mock. Replace it with your identity-provider validation mechanism before deploying to production.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo bench -p safegate-proxy
```

## Security Notes

SafeGate is designed as a security boundary, but the current development bearer-token check is not a production authentication scheme. Use a verified JWT, mTLS, or an external identity provider; enforce secret rotation; and configure policy and audit retention to meet your operational requirements.
