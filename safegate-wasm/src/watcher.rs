//! Live file-watcher that hot-reloads `.wasm` policy modules without downtime.
//!
//! # Design
//!
//! - [`PolicyWatcher`] owns an [`arc_swap::ArcSwap`]`<`[`WasmPolicyEngine`]`>`.
//! - Calling [`PolicyWatcher::start`] spawns a background Tokio task that uses
//!   the [`notify`] crate to watch a given directory for `.wasm` file changes.
//! - When a `Create` or `Modify` event arrives the module is compiled and, if
//!   successful, atomically swapped via [`ArcSwap::store`].
//! - If compilation fails the **current engine remains untouched** and a warning
//!   is logged, so the proxy keeps serving traffic without interruption.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecursiveMode, Watcher as _};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::WasmPolicyEngine;

/// Manages a shared, atomically-swappable [`WasmPolicyEngine`] and a background
/// directory watcher that keeps it up-to-date as `.wasm` files change on disk.
pub struct PolicyWatcher {
    /// Directory that is monitored for `.wasm` file changes.
    policy_dir: PathBuf,
    /// Live handle shared between the watcher task and every request handler.
    shared: Arc<ArcSwap<WasmPolicyEngine>>,
}

impl PolicyWatcher {
    /// Wraps `engine` in an [`ArcSwap`] and prepares a watcher for `policy_dir`.
    ///
    /// Call [`PolicyWatcher::start`] after construction to begin watching.
    pub fn new(policy_dir: impl Into<PathBuf>, engine: WasmPolicyEngine) -> Self {
        Self {
            policy_dir: policy_dir.into(),
            shared: Arc::new(ArcSwap::from_pointee(engine)),
        }
    }

    /// Returns a cheaply cloneable handle to the current policy engine.
    ///
    /// Callers should call [`ArcSwap::load`] on the returned value to obtain
    /// a snapshot of the engine that is valid for the duration of one request.
    pub fn shared(&self) -> Arc<ArcSwap<WasmPolicyEngine>> {
        Arc::clone(&self.shared)
    }

    /// Spawns the background file-watcher task.
    ///
    /// The task runs indefinitely; dropping the returned [`tokio::task::JoinHandle`]
    /// detaches it (it keeps running).  To stop watching, abort the handle.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let policy_dir = self.policy_dir.clone();
        let shared = Arc::clone(&self.shared);

        tokio::spawn(async move {
            watch_policy_dir(policy_dir, shared).await;
        })
    }
}

/// Blocking watcher loop – runs inside a Tokio task.
///
/// Creates a native OS file-watcher, registers `policy_dir`, and then feeds
/// events through an [`mpsc`] channel so the async task can process them.
async fn watch_policy_dir(policy_dir: PathBuf, shared: Arc<ArcSwap<WasmPolicyEngine>>) {
    // Channel used to bridge the synchronous notify callback into async code.
    let (tx, mut rx) = mpsc::unbounded_channel::<PathBuf>();

    // `notify::recommended_watcher` requires a *synchronous* closure, so we
    // clone the sender and move it in.
    let tx_clone = tx.clone();
    let mut watcher =
        match notify::recommended_watcher(move |result: notify::Result<Event>| match result {
            Ok(event) => handle_notify_event(event, &tx_clone),
            Err(error) => warn!(%error, "file-watcher error"),
        }) {
            Ok(w) => w,
            Err(error) => {
                warn!(%error, "failed to create file-watcher; hot-reload disabled");
                return;
            }
        };

    // Ensure the policy directory exists before we try to watch it.
    if !policy_dir.exists()
        && let Err(error) = std::fs::create_dir_all(&policy_dir)
    {
        warn!(
            dir = %policy_dir.display(),
            %error,
            "failed to create policy directory; hot-reload disabled"
        );
        return;
    }

    if let Err(error) = watcher.watch(&policy_dir, RecursiveMode::NonRecursive) {
        warn!(
            dir = %policy_dir.display(),
            %error,
            "failed to watch policy directory; hot-reload disabled"
        );
        return;
    }

    info!(
        dir = %policy_dir.display(),
        "hot-reload watcher started"
    );

    // Debounce: wait a short moment after each event before reloading, in case
    // a single logical write produces multiple rapid events.
    while let Some(wasm_path) = rx.recv().await {
        // Drain any additional events for the same burst.
        tokio::time::sleep(Duration::from_millis(50)).await;
        while rx.try_recv().is_ok() {}

        reload_policy(&wasm_path, &shared);
    }
}

/// Filters notify events: only `.wasm` Create / Modify events are forwarded.
fn handle_notify_event(event: Event, tx: &mpsc::UnboundedSender<PathBuf>) {
    let is_relevant = matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
    if !is_relevant {
        return;
    }
    for path in event.paths {
        if path.extension().and_then(|e| e.to_str()) == Some("wasm") {
            // Best-effort send; if the channel is closed we are shutting down.
            let _ = tx.send(path);
        }
    }
}

/// Compiles a `.wasm` file and, if successful, atomically installs it.
///
/// If compilation fails the current engine is preserved and a warning is logged.
fn reload_policy(wasm_path: &Path, shared: &Arc<ArcSwap<WasmPolicyEngine>>) {
    info!(path = %wasm_path.display(), "detected .wasm change – reloading policy");

    // Load the *current* sandbox config so the new engine inherits the same limits.
    let sandbox = shared.load().sandbox_config().clone();

    let mut new_engine = match WasmPolicyEngine::with_sandbox_config(sandbox) {
        Ok(e) => e,
        Err(error) => {
            warn!(%error, "failed to create engine for hot-reload");
            return;
        }
    };

    match new_engine.load_component_from_file(wasm_path) {
        Ok(()) => {
            shared.store(Arc::new(new_engine));
            info!(path = %wasm_path.display(), "policy hot-reloaded successfully");
        }
        Err(error) => {
            warn!(
                path = %wasm_path.display(),
                %error,
                "new .wasm failed validation – keeping current policy"
            );
        }
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use arc_swap::ArcSwap;

    use super::*;
    use crate::WasmPolicyEngine;

    // Helper: build an ArcSwap wrapping a fresh, component-less engine.
    fn make_shared() -> Arc<ArcSwap<WasmPolicyEngine>> {
        Arc::new(ArcSwap::from_pointee(
            WasmPolicyEngine::new().expect("engine should initialize"),
        ))
    }

    /// A corrupt (non-WASM) file must leave the shared engine untouched.
    #[test]
    fn corrupt_wasm_does_not_replace_current_engine() {
        let shared = make_shared();

        // Pointer to the current engine – should remain the same after the call.
        let before = Arc::as_ptr(&shared.load_full());

        let tmp = std::env::temp_dir().join(format!(
            "safegate-hot-reload-bad-{}.wasm",
            std::process::id()
        ));
        fs::write(&tmp, b"not a real wasm component").expect("fixture write should succeed");

        reload_policy(&tmp, &shared);

        let after = Arc::as_ptr(&shared.load_full());
        fs::remove_file(&tmp).expect("fixture removal should succeed");

        // The pointer must be identical – reload must have been a no-op.
        assert_eq!(
            before, after,
            "corrupt .wasm must not replace the current policy engine"
        );
    }

    /// `PolicyWatcher::shared()` must hand out the same ArcSwap instance.
    #[test]
    fn policy_watcher_shared_returns_same_arc() {
        let engine = WasmPolicyEngine::new().expect("engine should initialize");
        let watcher = PolicyWatcher::new(std::env::temp_dir(), engine);

        let h1 = watcher.shared();
        let h2 = watcher.shared();

        assert!(
            Arc::ptr_eq(&h1, &h2),
            "shared() must return the same underlying ArcSwap"
        );
    }

    /// Verifies that the watcher task starts and can be immediately aborted
    /// without panicking (basic smoke-test for the Tokio spawn path).
    #[tokio::test]
    async fn watcher_task_starts_and_aborts_cleanly() {
        let engine = WasmPolicyEngine::new().expect("engine should initialize");
        let tmp_dir =
            std::env::temp_dir().join(format!("safegate-watch-smoke-{}", std::process::id()));
        fs::create_dir_all(&tmp_dir).expect("tmp dir creation should succeed");

        let watcher = PolicyWatcher::new(&tmp_dir, engine);
        let handle = watcher.start();

        // Give the watcher a moment to initialize.
        tokio::time::sleep(Duration::from_millis(100)).await;

        handle.abort();
        // Awaiting an aborted task returns a `JoinError`; that is expected.
        let _ = handle.await;

        fs::remove_dir_all(&tmp_dir).ok();
    }

    /// Writes a corrupt `.wasm` to a watched directory while the watcher is
    /// running; confirms the engine pointer is unchanged after the debounce window.
    #[tokio::test]
    async fn live_watcher_ignores_corrupt_wasm_file() {
        let engine = WasmPolicyEngine::new().expect("engine should initialize");
        let tmp_dir =
            std::env::temp_dir().join(format!("safegate-hot-reload-live-{}", std::process::id()));
        fs::create_dir_all(&tmp_dir).expect("tmp dir should be created");

        let watcher = PolicyWatcher::new(&tmp_dir, engine);
        let shared = watcher.shared();
        let before = Arc::as_ptr(&shared.load_full());

        let handle = watcher.start();
        // Allow the OS watcher to fully register the directory.
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Drop a corrupt .wasm into the watched dir.
        let bad_wasm = tmp_dir.join("bad_policy.wasm");
        fs::write(&bad_wasm, b"garbage").expect("corrupt fixture write should succeed");

        // Wait long enough for debounce (50 ms) + reload attempt to complete.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let after = Arc::as_ptr(&shared.load_full());
        handle.abort();
        let _ = handle.await;
        fs::remove_dir_all(&tmp_dir).ok();

        assert_eq!(
            before, after,
            "corrupt .wasm written to watched dir must not replace the engine"
        );
    }
}
