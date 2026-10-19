use crate::error::{IngestError, UpstreamError};
use crate::ring::LiveRingBuffer;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, watch};
use tokio::time::sleep;

/// Lifecycle state of an in-flight ingest session.
#[derive(Clone, Debug, PartialEq)]
pub enum IngestState {
    /// Ingest is actively buffering initial chunks before playback release.
    Buffering { downloaded_bytes: u64 },
    /// Ingest is actively streaming data to local storage/ring buffer.
    Streaming {
        downloaded_bytes: u64,
        total_bytes: Option<u64>,
    },
    /// Ingest has finished completely (full file cached or clean EOF).
    Completed { total_bytes: u64 },
    /// Ingest failed prematurely (network RST, HTTP 500, timeout).
    Failed {
        downloaded_bytes: u64,
        reason: String,
    },
    /// Ingest was explicitly cancelled (channel zapping / teardown).
    Cancelled,
}

/// A coordinated streaming session connecting the upstream downloader with progressive readers.
pub struct StreamBufferSession {
    pub stream_id: String,
    pub progress_tx: watch::Sender<IngestState>,
    pub bytes_written: AtomicU64,
    pub ring_buffer: Option<Arc<LiveRingBuffer>>,
}

impl StreamBufferSession {
    pub fn new(
        stream_id: &str,
        ring_buffer_bytes: Option<usize>,
    ) -> (Arc<Self>, watch::Receiver<IngestState>) {
        let (tx, rx) = watch::channel(IngestState::Buffering {
            downloaded_bytes: 0,
        });
        let ring = ring_buffer_bytes.map(|cap| Arc::new(LiveRingBuffer::new(cap)));

        let session = Arc::new(Self {
            stream_id: stream_id.to_string(),
            progress_tx: tx,
            bytes_written: AtomicU64::new(0),
            ring_buffer: ring,
        });

        (session, rx)
    }

    /// Notify that new bytes have been flushed to disk or ring buffer.
    pub fn notify_progress(&self, total_downloaded: u64, total_size: Option<u64>) {
        self.bytes_written
            .store(total_downloaded, Ordering::Release);
        let _ = self.progress_tx.send(IngestState::Streaming {
            downloaded_bytes: total_downloaded,
            total_bytes: total_size,
        });
    }

    /// Mark ingest as failed, immediately notifying all waiting progressive readers.
    pub fn mark_failed(&self, reason: &str) {
        let total = self.bytes_written.load(Ordering::Acquire);
        let _ = self.progress_tx.send(IngestState::Failed {
            downloaded_bytes: total,
            reason: reason.to_string(),
        });
    }

    /// Mark ingest as cleanly completed.
    pub fn mark_completed(&self) {
        let total = self.bytes_written.load(Ordering::Acquire);
        let _ = self
            .progress_tx
            .send(IngestState::Completed { total_bytes: total });
    }

    /// Mark ingest as cancelled.
    pub fn mark_cancelled(&self) {
        let _ = self.progress_tx.send(IngestState::Cancelled);
    }
}

/// Progressive reader wait helper: awaits until target byte offset is reached, or aborts if upstream fails.
pub async fn await_byte_offset(
    rx: &mut watch::Receiver<IngestState>,
    target_offset: u64,
) -> Result<u64, IngestError> {
    loop {
        let state = rx.borrow().clone();
        match state {
            IngestState::Buffering { downloaded_bytes }
            | IngestState::Streaming {
                downloaded_bytes, ..
            } => {
                if downloaded_bytes > target_offset {
                    return Ok(downloaded_bytes);
                }
            }
            IngestState::Completed { total_bytes } => {
                if target_offset < total_bytes {
                    return Ok(total_bytes);
                } else {
                    return Err(IngestError::PrematureEof {
                        expected: target_offset,
                        received: total_bytes,
                    });
                }
            }
            IngestState::Failed { reason, .. } => {
                return Err(IngestError::Aborted(reason));
            }
            IngestState::Cancelled => {
                return Err(IngestError::Aborted("Session cancelled".to_string()));
            }
        }

        // Wait for next update from upstream worker
        if rx.changed().await.is_err() {
            return Err(IngestError::ChannelClosed);
        }
    }
}

/// Upstream connection coordinator strictly enforcing `max_upstream = 1`.
pub struct UpstreamHub {
    active_session_id: Mutex<Option<String>>,
    active_connections: Arc<AtomicUsize>,
    cooldown_duration: Duration,
    last_disconnect: Mutex<Instant>,
}

impl UpstreamHub {
    pub fn new(cooldown_duration: Duration) -> Self {
        Self {
            active_session_id: Mutex::new(None),
            active_connections: Arc::new(AtomicUsize::new(0)),
            cooldown_duration,
            last_disconnect: Mutex::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(10))
                    .unwrap_or_else(Instant::now),
            ),
        }
    }

    /// Invariant inspection: number of currently active upstream sockets.
    pub fn active_count(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    /// Acquire the single upstream connection lock for a channel/VOD stream.
    /// If an active stream exists, it cancels it and enforces a teardown cooldown barrier.
    pub async fn switch_stream(
        &self,
        new_stream_id: &str,
    ) -> Result<Arc<AtomicUsize>, UpstreamError> {
        let mut active_lock = self.active_session_id.lock().await;

        if let Some(ref current_id) = *active_lock {
            if current_id == new_stream_id {
                // Already playing this stream - reuse existing upstream
                return Ok(self.active_connections.clone());
            }

            // Teardown previous stream: simulate atomic cancellation and socket close
            self.active_connections.store(0, Ordering::SeqCst);
            *active_lock = None;
            let mut last_disc = self.last_disconnect.lock().await;
            *last_disc = Instant::now();
        }

        // Enforce cooldown barrier to guarantee socket destruction at kernel/provider level
        let last_disc = *self.last_disconnect.lock().await;
        let elapsed = last_disc.elapsed();
        if elapsed < self.cooldown_duration {
            sleep(self.cooldown_duration - elapsed).await;
        }

        // Invariant assertion: active sockets must be strictly 0 before acquiring
        let prev = self.active_connections.swap(1, Ordering::SeqCst);
        if prev > 0 {
            self.active_connections.store(0, Ordering::SeqCst);
            return Err(UpstreamError::ConnectionLimitExceeded {
                stream_id: new_stream_id.to_string(),
            });
        }

        *active_lock = Some(new_stream_id.to_string());
        Ok(self.active_connections.clone())
    }

    /// Release active upstream connection upon completion or disconnect.
    pub async fn release(&self, stream_id: &str) {
        let mut active_lock = self.active_session_id.lock().await;
        if active_lock.as_deref() == Some(stream_id) {
            *active_lock = None;
            self.active_connections.store(0, Ordering::SeqCst);
            let mut last_disc = self.last_disconnect.lock().await;
            *last_disc = Instant::now();
        }
    }
}
