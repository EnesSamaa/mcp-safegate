//! Non-blocking async audit writer.
//!
//! [`AuditLogger`] accepts [`AuditLogEntry`] values through a
//! [`tokio::sync::mpsc`] channel and writes them as JSON-Lines (one compact
//! JSON object per line) to either a file or stdout without blocking the
//! request path.

use std::{io, path::PathBuf};

use tokio::{
    fs::OpenOptions,
    io::{AsyncWriteExt, BufWriter},
    sync::mpsc,
};
use tracing::{error, info};

use crate::AuditLogEntry;

// ─── Sink ─────────────────────────────────────────────────────────────────────

/// Where finished audit records are written.
#[derive(Debug, Clone)]
pub enum AuditSink {
    /// Append to a `.jsonl` file at the given path.
    File(PathBuf),
    /// Write to stdout (useful for container/log-aggregator environments).
    Stdout,
}

// ─── AuditLogger ─────────────────────────────────────────────────────────────

/// Non-blocking audit logger that serialises [`AuditLogEntry`] records to a
/// JSON-Lines sink.
///
/// # Usage
///
/// 1. Call [`AuditLogger::new`] (or [`AuditLogger::stdout`]) to build the
///    logger and spawn the background writer task.
/// 2. Keep the returned `AuditLogger` alive for the lifetime of the proxy.
/// 3. Call [`AuditLogger::log`] on every completed request; the send is
///    asynchronous and never blocks the caller.
#[derive(Clone, Debug)]
pub struct AuditLogger {
    tx: mpsc::UnboundedSender<AuditLogEntry>,
    /// HMAC secret used when creating new entries via [`AuditLogger::build_entry`].
    hmac_secret: Vec<u8>,
}

impl AuditLogger {
    /// Creates a logger that appends to `sink` and spawns the background writer.
    pub fn new(sink: AuditSink, hmac_secret: impl Into<Vec<u8>>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let secret = hmac_secret.into();

        tokio::spawn(writer_task(rx, sink));

        Self {
            tx,
            hmac_secret: secret,
        }
    }

    /// Convenience constructor that writes to stdout.
    pub fn stdout(hmac_secret: impl Into<Vec<u8>>) -> Self {
        Self::new(AuditSink::Stdout, hmac_secret)
    }

    /// Enqueues `entry` for writing.  The call returns immediately; any write
    /// errors are logged at the `error` level inside the background task.
    pub fn log(&self, entry: AuditLogEntry) {
        // If the receiver has been dropped (i.e., the writer task panicked) we
        // silently discard the entry rather than panicking the request path.
        let _ = self.tx.send(entry);
    }

    /// Returns the HMAC secret key for signing entries created externally.
    pub fn hmac_secret(&self) -> &[u8] {
        &self.hmac_secret
    }
}

// ─── Background writer task ───────────────────────────────────────────────────

async fn writer_task(mut rx: mpsc::UnboundedReceiver<AuditLogEntry>, sink: AuditSink) {
    match sink {
        AuditSink::File(path) => {
            let file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(f) => f,
                Err(error) => {
                    error!(path = %path.display(), %error, "failed to open audit log file");
                    return;
                }
            };
            info!(path = %path.display(), "audit log writer started");
            let mut writer = BufWriter::new(file);
            write_entries(&mut writer, &mut rx).await;
        }
        AuditSink::Stdout => {
            info!("audit log writer started (stdout)");
            let stdout = tokio::io::stdout();
            let mut writer = BufWriter::new(stdout);
            write_entries(&mut writer, &mut rx).await;
        }
    }
}

/// Core loop: drain the channel and write one JSON line per entry.
async fn write_entries<W: AsyncWriteExt + Unpin>(
    writer: &mut BufWriter<W>,
    rx: &mut mpsc::UnboundedReceiver<AuditLogEntry>,
) {
    while let Some(entry) = rx.recv().await {
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(error) => {
                error!(%error, "failed to serialise audit log entry");
                continue;
            }
        };
        if let Err(error) = write_line(writer, &line).await {
            error!(%error, "failed to write audit log entry");
        }
    }
    // Channel closed → flush remaining buffered data.
    let _ = writer.flush().await;
}

async fn write_line<W: AsyncWriteExt + Unpin>(
    writer: &mut BufWriter<W>,
    line: &str,
) -> io::Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::Utc;

    use super::*;
    use crate::{AuditDecision, AuditLogEntry};

    const SECRET: &[u8] = b"writer-test-key";

    fn make_entry(decision: AuditDecision, latency_us: u128) -> AuditLogEntry {
        AuditLogEntry::new(
            Utc::now(),
            uuid::Uuid::new_v4().to_string(),
            Some("tenant-writer-test".to_owned()),
            "test-agent".to_owned(),
            "lookup".to_owned(),
            decision,
            latency_us,
            SECRET,
        )
    }

    /// Verifies that the logger can be created, entries can be enqueued, and the
    /// background task does not panic.  We use a temporary file and read it back.
    #[tokio::test]
    async fn logger_writes_entries_to_file() {
        let tmp = std::env::temp_dir().join(format!("safegate-audit-{}.jsonl", std::process::id()));

        {
            let logger = AuditLogger::new(AuditSink::File(tmp.clone()), SECRET);
            logger.log(make_entry(AuditDecision::Allow, 100));
            logger.log(make_entry(AuditDecision::Deny("blocked".to_owned()), 250));
            // Give the background task a moment to flush.
            tokio::time::sleep(Duration::from_millis(100)).await;
        } // logger dropped → sender half closed → background task finishes

        let content = tokio::fs::read_to_string(&tmp)
            .await
            .expect("audit log file should be readable");
        tokio::fs::remove_file(&tmp).await.ok();

        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "exactly 2 entries should be written");

        // Each line should parse as a valid AuditLogEntry with a good signature.
        for line in &lines {
            let entry: AuditLogEntry =
                serde_json::from_str(line).expect("each line must be valid JSON");
            assert!(entry.verify(SECRET), "written entry signature must verify");
        }
    }

    /// Deny entries must carry the correct latency value.
    #[tokio::test]
    async fn deny_entry_latency_is_preserved_through_file_roundtrip() {
        let tmp = std::env::temp_dir().join(format!(
            "safegate-audit-latency-{}.jsonl",
            std::process::id()
        ));

        {
            let logger = AuditLogger::new(AuditSink::File(tmp.clone()), SECRET);
            logger.log(make_entry(
                AuditDecision::Deny("policy violation".to_owned()),
                999,
            ));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let content = tokio::fs::read_to_string(&tmp)
            .await
            .expect("audit file should be readable");
        tokio::fs::remove_file(&tmp).await.ok();

        let entry: AuditLogEntry =
            serde_json::from_str(content.trim()).expect("must be valid JSON");
        assert_eq!(entry.latency_us, 999);
        assert!(matches!(entry.decision, AuditDecision::Deny(_)));
        assert!(entry.verify(SECRET));
    }

    /// Dropping the logger before reading is safe (no panic).
    #[tokio::test]
    async fn logger_stdout_does_not_panic() {
        let logger = AuditLogger::stdout(SECRET);
        logger.log(make_entry(AuditDecision::Allow, 1));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // If we reach here without a panic the test passes.
    }
}
