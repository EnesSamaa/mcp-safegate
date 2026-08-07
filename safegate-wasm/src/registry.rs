//! Multi-tenant WASM policy registry.
//!
//! [`PolicyRegistry`] maintains a map of `tenant_id → WasmPolicyEngine` and
//! keeps it live by watching a directory for `.wasm` file changes via the
//! [`notify`] crate. A separate **default engine** is used as a fallback for
//! tenants that have no dedicated policy file.
//!
//! # Directory layout expected by the registry
//!
//! ```text
//! policies/
//! ├── default.wasm          ← watched by the existing PolicyWatcher (fallback)
//! └── tenants/
//!     ├── acme.wasm         ← loaded as tenant "acme"
//!     └── corp.wasm         ← loaded as tenant "corp"
//! ```
//!
//! # Concurrency model
//!
//! The full tenant map (`HashMap<String, Arc<WasmPolicyEngine>>`) is stored
//! inside an [`ArcSwap`]. Updates create a new `HashMap` with the changed
//! entry and atomically swap it in – no reader ever blocks.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecursiveMode, Watcher as _};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::WasmPolicyEngine;

// ── Message sent through the watcher channel ─────────────────────────────────

/// Internal event dispatched from the `notify` callback to the async task.
#[derive(Debug)]
enum RegistryEvent {
    /// A `.wasm` file was created or modified.
    Upsert(PathBuf),
    /// A `.wasm` file was removed.
    Remove(PathBuf),
}

// ── PolicyRegistry ────────────────────────────────────────────────────────────

/// Manages per-tenant WASM policy engines with hot-reload support.
///
/// Call [`PolicyRegistry::new`] to create a registry, then [`PolicyRegistry::start`]
/// to begin watching the tenant directory.  Use [`PolicyRegistry::get`] to obtain
/// the engine for a given tenant – it falls back to the default engine if the
/// tenant has no dedicated policy.
pub struct PolicyRegistry {
    /// Watched directory that contains `<tenant_id>.wasm` files.
    tenant_dir: PathBuf,
    /// Atomically-swappable map of `tenant_id → engine`.
    engines: Arc<ArcSwap<HashMap<String, Arc<WasmPolicyEngine>>>>,
    /// Default fallback engine (watched by the top-level `PolicyWatcher`).
    default_engine: Arc<ArcSwap<WasmPolicyEngine>>,
}

impl PolicyRegistry {
    /// Creates a registry.
    ///
    /// `tenant_dir`     — path to the directory containing per-tenant `.wasm` files.
    /// `default_engine` — fallback engine produced by `PolicyWatcher::shared()`.
    ///
    /// Any `.wasm` files **already present** in `tenant_dir` are loaded
    /// synchronously before this function returns.
    pub fn new(
        tenant_dir: impl Into<PathBuf>,
        default_engine: Arc<ArcSwap<WasmPolicyEngine>>,
    ) -> Self {
        let tenant_dir = tenant_dir.into();
        let engines = Arc::new(ArcSwap::from_pointee(HashMap::new()));

        // Pre-load any .wasm files that already exist in the directory.
        if tenant_dir.is_dir() {
            let initial = load_all_from_dir(&tenant_dir);
            engines.store(Arc::new(initial));
        }

        Self {
            tenant_dir,
            engines,
            default_engine,
        }
    }

    /// Returns a cheaply cloneable handle to the engine for `tenant_id`.
    ///
    /// If `tenant_id` has no dedicated policy the **default engine** is
    /// returned so every request is always handled by *some* policy.
    pub fn get(&self, tenant_id: &str) -> Arc<ArcSwap<WasmPolicyEngine>> {
        let map = self.engines.load();
        if let Some(engine) = map.get(tenant_id) {
            // Wrap the tenant engine in its own ArcSwap so callers get the
            // same interface as the single-engine path.
            Arc::new(ArcSwap::from(Arc::clone(engine)))
        } else {
            Arc::clone(&self.default_engine)
        }
    }

    /// Returns a read-only snapshot of the currently loaded tenant map.
    ///
    /// Primarily useful for health checks and observability.
    pub fn tenant_ids(&self) -> Vec<String> {
        self.engines.load().keys().cloned().collect()
    }

    /// Spawns the background file-watcher that keeps the tenant map live.
    ///
    /// Dropping the returned [`tokio::task::JoinHandle`] detaches the task
    /// (it keeps running).  To stop watching, abort the handle.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let tenant_dir = self.tenant_dir.clone();
        let engines = Arc::clone(&self.engines);

        tokio::spawn(async move {
            watch_tenant_dir(tenant_dir, engines).await;
        })
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Scans `dir` for `.wasm` files and loads each as a policy engine.
/// Files that fail to compile are skipped with a warning.
fn load_all_from_dir(dir: &Path) -> HashMap<String, Arc<WasmPolicyEngine>> {
    let mut map = HashMap::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(error) => {
            warn!(dir = %dir.display(), %error, "failed to read tenant policy directory");
            return map;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wasm")
            && let Some((tenant_id, engine)) = load_tenant_engine(&path)
        {
            map.insert(tenant_id, Arc::new(engine));
        }
    }
    map
}

/// Derives the tenant ID from the file stem (e.g., `acme.wasm` → `"acme"`).
/// Returns `None` if the stem is empty or the file fails to compile.
fn load_tenant_engine(path: &Path) -> Option<(String, WasmPolicyEngine)> {
    let tenant_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)?;

    let mut engine = match WasmPolicyEngine::new() {
        Ok(e) => e,
        Err(error) => {
            warn!(%error, path = %path.display(), "failed to create WASM engine for tenant");
            return None;
        }
    };

    match engine.load_component_from_file(path) {
        Ok(()) => {
            info!(tenant = %tenant_id, path = %path.display(), "tenant policy loaded");
            Some((tenant_id, engine))
        }
        Err(error) => {
            warn!(
                tenant = %tenant_id,
                path = %path.display(),
                %error,
                "tenant .wasm failed validation – skipped"
            );
            None
        }
    }
}

/// Atomically inserts or replaces a tenant engine in the shared map.
fn upsert_tenant(engines: &Arc<ArcSwap<HashMap<String, Arc<WasmPolicyEngine>>>>, path: &Path) {
    if let Some((tenant_id, engine)) = load_tenant_engine(path) {
        let mut new_map = (**engines.load()).clone();
        new_map.insert(tenant_id.clone(), Arc::new(engine));
        engines.store(Arc::new(new_map));
        info!(tenant = %tenant_id, "tenant policy hot-reloaded");
    }
}

/// Atomically removes a tenant engine from the shared map.
fn remove_tenant(engines: &Arc<ArcSwap<HashMap<String, Arc<WasmPolicyEngine>>>>, path: &Path) {
    let tenant_id = match path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
    {
        Some(id) => id.to_owned(),
        None => return,
    };
    let mut new_map = (**engines.load()).clone();
    if new_map.remove(&tenant_id).is_some() {
        engines.store(Arc::new(new_map));
        info!(tenant = %tenant_id, "tenant policy removed");
    }
}

/// Blocking async watcher loop — runs inside a Tokio task.
async fn watch_tenant_dir(
    tenant_dir: PathBuf,
    engines: Arc<ArcSwap<HashMap<String, Arc<WasmPolicyEngine>>>>,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<RegistryEvent>();

    let tx_clone = tx.clone();
    let mut watcher =
        match notify::recommended_watcher(move |result: notify::Result<Event>| match result {
            Ok(event) => handle_notify_event(event, &tx_clone),
            Err(error) => warn!(%error, "tenant registry file-watcher error"),
        }) {
            Ok(w) => w,
            Err(error) => {
                warn!(%error, "failed to create tenant registry file-watcher; hot-reload disabled");
                return;
            }
        };

    if !tenant_dir.exists()
        && let Err(error) = std::fs::create_dir_all(&tenant_dir)
    {
        warn!(
            dir = %tenant_dir.display(),
            %error,
            "failed to create tenant policy directory; hot-reload disabled"
        );
        return;
    }

    if let Err(error) = watcher.watch(&tenant_dir, RecursiveMode::NonRecursive) {
        warn!(
            dir = %tenant_dir.display(),
            %error,
            "failed to watch tenant policy directory; hot-reload disabled"
        );
        return;
    }

    info!(dir = %tenant_dir.display(), "tenant policy hot-reload watcher started");

    while let Some(event) = rx.recv().await {
        // Debounce rapid burst events.
        tokio::time::sleep(Duration::from_millis(50)).await;
        while rx.try_recv().is_ok() {}

        match event {
            RegistryEvent::Upsert(path) => upsert_tenant(&engines, &path),
            RegistryEvent::Remove(path) => remove_tenant(&engines, &path),
        }
    }
}

/// Converts a `notify` event into a [`RegistryEvent`] and sends it over the channel.
fn handle_notify_event(event: Event, tx: &mpsc::UnboundedSender<RegistryEvent>) {
    for path in &event.paths {
        if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
            continue;
        }
        let registry_event = match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => RegistryEvent::Upsert(path.clone()),
            EventKind::Remove(_) => RegistryEvent::Remove(path.clone()),
            _ => continue,
        };
        let _ = tx.send(registry_event);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use super::*;

    /// Builds a default engine handle (component-less) for use in tests.
    fn default_engine_handle() -> Arc<ArcSwap<WasmPolicyEngine>> {
        Arc::new(ArcSwap::from_pointee(
            WasmPolicyEngine::new().expect("engine should initialize"),
        ))
    }

    // ── get() / fallback ──────────────────────────────────────────────────────

    #[test]
    fn get_returns_default_for_unknown_tenant() {
        let registry = PolicyRegistry::new(
            std::env::temp_dir().join("no-such-tenants"),
            default_engine_handle(),
        );

        // Any tenant ID not in the map must fall back to the default engine handle.
        let handle = registry.get("unknown-tenant");
        // The handle must be loadable (it wraps a valid engine).
        let _engine = handle.load();
    }

    #[test]
    fn tenant_ids_empty_when_no_wasm_files_present() {
        let dir =
            std::env::temp_dir().join(format!("safegate-registry-empty-{}", std::process::id()));
        fs::create_dir_all(&dir).ok();
        let registry = PolicyRegistry::new(&dir, default_engine_handle());
        assert!(
            registry.tenant_ids().is_empty(),
            "fresh empty directory should yield no tenant IDs"
        );
        fs::remove_dir_all(&dir).ok();
    }

    // ── pre-load ──────────────────────────────────────────────────────────────

    #[test]
    fn corrupt_wasm_in_dir_does_not_panic_during_load() {
        let dir =
            std::env::temp_dir().join(format!("safegate-registry-corrupt-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        // A corrupt .wasm file – must be silently skipped, not panic.
        fs::write(dir.join("bad-tenant.wasm"), b"not a wasm component")
            .expect("fixture write should succeed");

        let registry = PolicyRegistry::new(&dir, default_engine_handle());
        // The corrupt file should have been skipped → tenant map is empty.
        assert!(
            registry.tenant_ids().is_empty(),
            "corrupt .wasm should be skipped; no tenant should be registered"
        );

        fs::remove_dir_all(&dir).ok();
    }

    // ── tenant ID derivation ──────────────────────────────────────────────────

    #[test]
    fn tenant_id_derived_from_filename_stem() {
        let path = PathBuf::from("/policies/tenants/acme.wasm");
        let stem = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned);
        assert_eq!(stem.as_deref(), Some("acme"));
    }

    #[test]
    fn non_wasm_file_yields_no_tenant_id() {
        let dir =
            std::env::temp_dir().join(format!("safegate-registry-non-wasm-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("tmp dir should be created");
        fs::write(dir.join("readme.txt"), b"ignore me").expect("fixture write should succeed");

        let registry = PolicyRegistry::new(&dir, default_engine_handle());
        assert!(
            registry.tenant_ids().is_empty(),
            "non-.wasm file must not be registered as a tenant"
        );

        fs::remove_dir_all(&dir).ok();
    }

    // ── watcher lifecycle ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn watcher_starts_and_aborts_cleanly() {
        let dir = std::env::temp_dir().join(format!(
            "safegate-registry-watch-smoke-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("tmp dir should be created");

        let registry = PolicyRegistry::new(&dir, default_engine_handle());
        let handle = registry.start();

        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.abort();
        let _ = handle.await;

        fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn corrupt_wasm_dropped_into_watched_dir_does_not_corrupt_map() {
        let dir = std::env::temp_dir().join(format!(
            "safegate-registry-watch-corrupt-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("tmp dir should be created");

        let registry = PolicyRegistry::new(&dir, default_engine_handle());
        let handle = registry.start();

        // Allow watcher to register.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Drop a corrupt .wasm – must be rejected by the engine loader.
        fs::write(dir.join("evil.wasm"), b"garbage bytes")
            .expect("corrupt fixture write should succeed");

        // Wait for debounce + reload attempt.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // "evil" must NOT appear in the tenant list.
        assert!(
            !registry.tenant_ids().contains(&"evil".to_owned()),
            "corrupt .wasm must not be registered as a tenant"
        );

        handle.abort();
        let _ = handle.await;
        fs::remove_dir_all(&dir).ok();
    }
}
