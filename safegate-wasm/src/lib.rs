//! WASI Component Model runtime support for SafeGate policy modules.

use std::{path::Path, sync::Arc};

use safegate_core::{AgentContext, McpToolCallParams, SafeGateError};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

/// Multi-tenant WASM policy registry with hot-reload support.
pub mod registry;
/// Resource limits and execution deadlines for policy components.
pub mod sandbox;
/// Live file-watcher that hot-reloads `.wasm` policy modules without downtime.
pub mod watcher;

pub use registry::PolicyRegistry;

use crate::sandbox::WasmSandboxConfig;

/// Bindings generated directly from the SafeGate WIT policy contract.
///
/// This macro expands at compile time, so an invalid `wit/policy.wit` schema
/// prevents the crate from compiling.
pub mod bindings {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "safegate-policy",
        async: true,
    });
}

/// WASI state made available to each policy component invocation.
pub struct WasiState {
    ctx: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiState {
    /// Creates a capability-free WASI host state with the supplied resource limits.
    ///
    /// No environment, standard I/O streams, preopened directories, sockets, or
    /// outbound HTTP capabilities are inherited or registered with this context.
    pub fn new(sandbox: &WasmSandboxConfig) -> Self {
        Self {
            // This deliberately has no `inherit_*` or preopen/network calls.
            ctx: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(sandbox.max_memory_bytes)
                .trap_on_grow_failure(true)
                .build(),
        }
    }
}

impl WasiView for WasiState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.ctx
    }
}

impl bindings::safegate::policy::types::Host for WasiState {}

/// Result produced by a policy component after evaluating a tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The request may proceed to the upstream MCP server.
    Allow,
    /// The request must be rejected with the supplied reason.
    Deny(String),
    /// The supplied replacement JSON arguments must be used before forwarding.
    RedactArgs(String),
}

/// Owns the Wasmtime runtime, WASI linker, and currently loaded policy component.
pub struct WasmPolicyEngine {
    engine: Engine,
    linker: Linker<WasiState>,
    component: Option<Arc<Component>>,
    sandbox: WasmSandboxConfig,
}

impl WasmPolicyEngine {
    /// Creates an engine configured for WASI Component Model execution.
    pub fn new() -> Result<Self, SafeGateError> {
        Self::with_sandbox_config(WasmSandboxConfig::default())
    }

    /// Creates an engine using explicit resource and deadline limits.
    pub fn with_sandbox_config(sandbox: WasmSandboxConfig) -> Result<Self, SafeGateError> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(wasm_execution_error)?;
        let mut linker = Linker::new(&engine);

        wasmtime_wasi::add_to_linker_async(&mut linker).map_err(wasm_execution_error)?;
        bindings::SafegatePolicy::add_to_linker(&mut linker, |state| state)
            .map_err(wasm_execution_error)?;

        Ok(Self {
            engine,
            linker,
            component: None,
            sandbox,
        })
    }

    /// Compiles and retains a policy component loaded from a `.wasm` file.
    pub fn load_component_from_file(&mut self, path: &Path) -> Result<(), SafeGateError> {
        let component = Component::from_file(&self.engine, path).map_err(wasm_execution_error)?;
        self.component = Some(Arc::new(component));
        Ok(())
    }

    /// Evaluates the currently loaded policy component for an MCP tool call.
    pub async fn evaluate_policy(
        &self,
        ctx: &AgentContext,
        req: &McpToolCallParams,
    ) -> Result<PolicyDecision, SafeGateError> {
        let component = self.component.as_ref().ok_or_else(|| {
            SafeGateError::WasmExecutionError("no policy component has been loaded".to_owned())
        })?;
        let wit_context = bindings::AgentContext {
            agent_id: ctx.agent_id.clone(),
            tenant_id: ctx.tenant_id.clone(),
            roles: ctx.roles.clone(),
        };
        let wit_request = bindings::ToolRequest {
            tool_name: req.name.clone(),
            arguments_json: req
                .arguments
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "null".to_owned()),
        };
        let mut store = Store::new(&self.engine, WasiState::new(&self.sandbox));
        store.limiter(|state| &mut state.limits);
        store.set_epoch_deadline(self.sandbox.epoch_deadlines);

        let interrupt_engine = self.engine.clone();
        let epoch_deadlines = self.sandbox.epoch_deadlines;
        let timeout_task = tokio::spawn(async move {
            tokio::time::sleep(WasmSandboxConfig::EXECUTION_TIMEOUT).await;
            for _ in 0..epoch_deadlines {
                interrupt_engine.increment_epoch();
            }
        });
        let policy = match bindings::SafegatePolicy::instantiate_async(
            &mut store,
            component.as_ref(),
            &self.linker,
        )
        .await
        {
            Ok(policy) => policy,
            Err(error) => {
                timeout_task.abort();
                return Err(wasm_execution_error(error));
            }
        };
        let decision = policy
            .call_evaluate(&mut store, &wit_context, &wit_request)
            .await
            .map_err(wasm_execution_error);
        timeout_task.abort();
        let decision = decision?;

        Ok(match decision {
            bindings::PolicyDecision::Allow => PolicyDecision::Allow,
            bindings::PolicyDecision::Deny(reason) => PolicyDecision::Deny(reason),
            bindings::PolicyDecision::RedactArgs(arguments) => {
                PolicyDecision::RedactArgs(arguments)
            }
        })
    }

    /// Returns the Wasmtime engine used by this policy runtime.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Returns the sandbox resource-limit configuration attached to this engine.
    ///
    /// Used by the hot-reload watcher to clone the limits into a replacement engine.
    pub fn sandbox_config(&self) -> &WasmSandboxConfig {
        &self.sandbox
    }
}

/// Converts Wasmtime runtime and component loading errors into SafeGate errors.
fn wasm_execution_error(error: impl std::fmt::Display) -> SafeGateError {
    SafeGateError::WasmExecutionError(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use safegate_core::SafeGateError;

    use super::WasmPolicyEngine;

    #[test]
    fn wit_bindings_compile_and_engine_initializes() {
        // The generated `bindings` module is compiled before this test can run.
        // Initializing the engine additionally validates the Component Model setup.
        let engine = WasmPolicyEngine::new().expect("component model engine should initialize");
        let _ = engine.engine();
    }

    #[test]
    fn loading_a_missing_component_returns_a_controlled_wasm_error() {
        let mut engine = WasmPolicyEngine::new().expect("engine should initialize");
        let result = engine.load_component_from_file(Path::new("missing-policy-component.wasm"));

        assert!(matches!(result, Err(SafeGateError::WasmExecutionError(_))));
    }

    #[test]
    fn loading_a_corrupt_component_returns_a_controlled_wasm_error() {
        let path = std::env::temp_dir().join(format!(
            "safegate-corrupt-policy-{}.wasm",
            std::process::id()
        ));
        fs::write(&path, b"not a wasm component").expect("corrupt fixture should be written");
        let mut engine = WasmPolicyEngine::new().expect("engine should initialize");
        let result = engine.load_component_from_file(&path);
        fs::remove_file(&path).expect("corrupt fixture should be removed");

        assert!(matches!(result, Err(SafeGateError::WasmExecutionError(_))));
    }
}
