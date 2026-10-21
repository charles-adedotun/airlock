use crate::error::{IngestError, UpstreamError};
use crate::ring::LiveRingBuffer;
use crate::security::{RedactedString, RedactedUrl};
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

    /// Returns the currently active stream identifier, if any.
    pub async fn active_stream(&self) -> Option<String> {
        self.active_session_id.lock().await.clone()
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

use crate::engine::{AdaptiveJitterShield, TsStreamRing, create_null_packets_chunk};
use bytes::Bytes;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// An active shared live broadcast session.
pub struct LiveBroadcastSession {
    pub stream_id: String,
    pub ts_ring: Arc<TsStreamRing>,
    pub broadcast_tx: broadcast::Sender<Bytes>,
    pub subscribers: Arc<AtomicUsize>,
    pub abort_handle: tokio::task::AbortHandle,
    pub created_at: Instant,
    pub jitter_shield: Arc<AdaptiveJitterShield>,
}

/// RAII Drop Guard for an active subscriber to a live broadcast session.
/// Decrements the subscriber count on drop and triggers debounced session teardown
/// when the last client disconnects.
pub struct LiveSubscriberGuard {
    sessions: Arc<Mutex<HashMap<String, Arc<LiveBroadcastSession>>>>,
    upstream_hub: Arc<UpstreamHub>,
    stream_id: String,
    active: bool,
}

impl LiveSubscriberGuard {
    pub fn new(
        sessions: Arc<Mutex<HashMap<String, Arc<LiveBroadcastSession>>>>,
        upstream_hub: Arc<UpstreamHub>,
        stream_id: String,
    ) -> Self {
        Self {
            sessions,
            upstream_hub,
            stream_id,
            active: true,
        }
    }
}

impl Drop for LiveSubscriberGuard {
    fn drop(&mut self) {
        if self.active {
            let sessions = Arc::clone(&self.sessions);
            let hub = Arc::clone(&self.upstream_hub);
            let sid = self.stream_id.clone();
            tokio::spawn(async move {
                let mut should_teardown = false;
                {
                    let map = sessions.lock().await;
                    if let Some(session) = map.get(&sid) {
                        let prev = session.subscribers.fetch_sub(1, Ordering::SeqCst);
                        if prev <= 1 {
                            should_teardown = true;
                        }
                    }
                }

                if should_teardown {
                    // Option A: Instant Preemption (0ms) - terminate immediately on disconnect
                    let mut map = sessions.lock().await;
                    if let Some(session) = map.get(&sid) {
                        if session.subscribers.load(Ordering::SeqCst) == 0 {
                            if let Some(removed) = map.remove(&sid) {
                                removed.abort_handle.abort();
                                hub.release(&sid).await;
                                tracing::info!(stream_id = %sid, "Live broadcast session torn down cleanly after last client disconnected");
                            }
                        }
                    }
                }
            });
        }
    }
}

/// Stream wrapper pairing an in-flight byte stream with an RAII `LiveSubscriberGuard`.
pub struct GuardedBroadcastStream<S> {
    stream: S,
    _guard: LiveSubscriberGuard,
}

impl<S: futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Unpin> futures_util::Stream
    for GuardedBroadcastStream<S>
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

/// Shared coordinator for in-flight live IPTV broadcast sessions.
pub struct LiveBroadcastHub {
    upstream_hub: Arc<UpstreamHub>,
    sessions: Arc<Mutex<HashMap<String, Arc<LiveBroadcastSession>>>>,
    outbound_client: reqwest::Client,
    upstream_base_url: String,
    ring_capacity: usize,
    upstream_user: Option<RedactedString>,
    upstream_pass: Option<RedactedString>,
}

impl LiveBroadcastHub {
    pub fn new(
        upstream_hub: Arc<UpstreamHub>,
        outbound_client: reqwest::Client,
        upstream_base_url: String,
        ring_capacity: usize,
    ) -> Self {
        Self::with_credentials(
            upstream_hub,
            outbound_client,
            upstream_base_url,
            ring_capacity,
            None,
            None,
        )
    }

    pub fn with_credentials(
        upstream_hub: Arc<UpstreamHub>,
        outbound_client: reqwest::Client,
        upstream_base_url: String,
        ring_capacity: usize,
        upstream_user: Option<RedactedString>,
        upstream_pass: Option<RedactedString>,
    ) -> Self {
        Self {
            upstream_hub,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            outbound_client,
            upstream_base_url,
            ring_capacity,
            upstream_user,
            upstream_pass,
        }
    }

    /// Subscribe to a live stream.
    /// If an active session already exists for `stream_id`, attaches to the existing stream
    /// without opening a new upstream socket (fan-out). If new, initiates single upstream
    /// ingest task through `TsStreamRing`.
    pub async fn subscribe(
        &self,
        stream_id: &str,
    ) -> Result<
        GuardedBroadcastStream<
            Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send>>,
        >,
        UpstreamError,
    > {
        let mut map = self.sessions.lock().await;

        if let Some(session) = map.get(stream_id) {
            // Channel already playing: attach to existing broadcast session!
            session.subscribers.fetch_add(1, Ordering::SeqCst);
            let rx = session.broadcast_tx.subscribe();
            let cushion_sec = session.jitter_shield.recommended_cushion_sec();
            let burst = session
                .ts_ring
                .get_reservoir_burst(cushion_sec)
                .ok()
                .filter(|b| !b.is_empty());

            let live_stream = BroadcastStream::new(rx).filter_map(|res| async move {
                match res {
                    Ok(chunk) => Some(Ok(chunk)),
                    Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "Subscriber lagged in live broadcast, skipping ahead"
                        );
                        None
                    }
                }
            });

            let combined_stream: Pin<
                Box<dyn futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send>,
            > = match burst {
                Some(b) => {
                    Box::pin(futures_util::stream::once(async move { Ok(b) }).chain(live_stream))
                }
                None => Box::pin(live_stream),
            };

            let guard = LiveSubscriberGuard::new(
                Arc::clone(&self.sessions),
                Arc::clone(&self.upstream_hub),
                stream_id.to_string(),
            );

            tracing::info!(
                stream_id = %stream_id,
                subscribers = session.subscribers.load(Ordering::SeqCst),
                "Attached new subscriber to existing in-flight broadcast session"
            );

            return Ok(GuardedBroadcastStream {
                stream: combined_stream,
                _guard: guard,
            });
        }

        // Strictly enforce single-upstream invariant: abort any previous in-flight sessions
        // before switching upstream connection to new channel.
        for (sid, sess) in map.drain() {
            sess.abort_handle.abort();
            tracing::info!(stream_id = %sid, "Aborted previous in-flight broadcast session for channel switch");
        }

        // Acquire arbiter lock (enforces single connection invariant and cooldown)
        self.upstream_hub.switch_stream(stream_id).await?;

        let upstream_base = self.upstream_base_url.trim_end_matches('/');
        let user = self.upstream_user.as_deref().unwrap_or("airlock");
        let pass = self.upstream_pass.as_deref().unwrap_or("proxy");
        let target_url = format!("{upstream_base}/live/{user}/{pass}/{stream_id}.ts");

        let resp = match self.outbound_client.get(&target_url).send().await {
            Ok(r) => {
                if !r.status().is_success() {
                    self.upstream_hub.release(stream_id).await;
                    return Err(UpstreamError::UpstreamStatusError {
                        status: r.status().as_u16(),
                    });
                }
                r
            }
            Err(e) => {
                self.upstream_hub.release(stream_id).await;
                let sanitized_err = RedactedUrl::sanitize_str(&e.to_string());
                tracing::warn!(stream_id = %stream_id, error = %sanitized_err, "Failed to connect to upstream live stream");
                return Err(UpstreamError::ConnectionFailed(sanitized_err));
            }
        };

        let (broadcast_tx, broadcast_rx) = broadcast::channel(256);
        let ts_ring = Arc::new(TsStreamRing::new(self.ring_capacity));
        let subscribers = Arc::new(AtomicUsize::new(1));
        let jitter_shield = Arc::new(AdaptiveJitterShield::default());

        let ring_clone = Arc::clone(&ts_ring);
        let tx_clone = broadcast_tx.clone();
        let shield_clone = Arc::clone(&jitter_shield);
        let sid = stream_id.to_string();
        let mut byte_stream = resp.bytes_stream();
        let sessions_clone = Arc::clone(&self.sessions);
        let hub_clone = Arc::clone(&self.upstream_hub);

        let join_handle = tokio::spawn(async move {
            let stall_detection_interval = Duration::from_millis(750);
            let null_packet_limit = Duration::from_secs(8);
            let mut stall_started: Option<Instant> = None;
            let mut stall_timed_out = false;

            loop {
                tokio::select! {
                    biased;
                    chunk_res = byte_stream.next() => {
                        match chunk_res {
                            Some(Ok(chunk)) => {
                                stall_started = None;
                                shield_clone.record_chunk_arrival(chunk.len());
                                if let Ok(Some(aligned)) = ring_clone.ingest_raw_aligned(&chunk) {
                                    let _ = tx_clone.send(aligned);
                                }
                            }
                            Some(Err(err)) => {
                                let sanitized_err = RedactedUrl::sanitize_str(&err.to_string());
                                tracing::warn!(stream_id = %sid, error = %sanitized_err, "Upstream live stream closed or reset");
                                break;
                            }
                            None => {
                                tracing::info!(stream_id = %sid, "Upstream live stream closed (EOF)");
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(stall_detection_interval) => {
                        let now = Instant::now();
                        let stall_start = *stall_started.get_or_insert(now);
                        let duration = now.duration_since(stall_start);

                        if duration > null_packet_limit {
                            tracing::warn!(stream_id = %sid, duration_secs = duration.as_secs_f64(), "Upstream stall exceeded 8.0s hard ceiling, terminating cleanly");
                            stall_timed_out = true;
                            break;
                        }

                        // Inject standard MPEG-TS null packet chunk (7 TS packets = 1316 bytes MTU aligned)
                        let null_chunk = create_null_packets_chunk();
                        let _ = tx_clone.send(null_chunk);
                    }
                }
            }

            // If upstream stall exceeded 8.0s ceiling, trigger clean teardown immediately:
            // Remove in-flight session and release upstream hub lock to prevent resource leaks/deadlocks.
            if stall_timed_out {
                let mut map = sessions_clone.lock().await;
                map.remove(&sid);
                hub_clone.release(&sid).await;
                tracing::info!(stream_id = %sid, "Upstream stall exceeded 8.0s ceiling: session torn down cleanly");
            }
            tracing::info!(stream_id = %sid, "Upstream ingest task completed");
        });

        let session = Arc::new(LiveBroadcastSession {
            stream_id: stream_id.to_string(),
            ts_ring: Arc::clone(&ts_ring),
            broadcast_tx,
            subscribers,
            abort_handle: join_handle.abort_handle(),
            created_at: Instant::now(),
            jitter_shield,
        });

        map.insert(stream_id.to_string(), Arc::clone(&session));

        let burst = ts_ring.get_zapping_burst().ok().filter(|b| !b.is_empty());

        let live_stream = BroadcastStream::new(broadcast_rx).filter_map(|res| async move {
            match res {
                Ok(chunk) => Some(Ok(chunk)),
                Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        skipped,
                        "Subscriber lagged in live broadcast, skipping ahead"
                    );
                    None
                }
            }
        });

        let boxed_stream: Pin<
            Box<dyn futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Send>,
        > = match burst {
            Some(b) => {
                Box::pin(futures_util::stream::once(async move { Ok(b) }).chain(live_stream))
            }
            None => Box::pin(live_stream),
        };

        let guard = LiveSubscriberGuard::new(
            Arc::clone(&self.sessions),
            Arc::clone(&self.upstream_hub),
            stream_id.to_string(),
        );

        tracing::info!(
            stream_id = %stream_id,
            "Spawned new live broadcast session and single upstream worker"
        );

        Ok(GuardedBroadcastStream {
            stream: boxed_stream,
            _guard: guard,
        })
    }

    /// Number of active broadcast sessions.
    pub async fn active_sessions_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Number of active subscribers for a given stream.
    pub async fn subscribers_count(&self, stream_id: &str) -> usize {
        let map = self.sessions.lock().await;
        map.get(stream_id)
            .map(|s| s.subscribers.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Retrieve the active broadcast session for a stream if in-flight.
    pub async fn get_session(&self, stream_id: &str) -> Option<Arc<LiveBroadcastSession>> {
        self.sessions.lock().await.get(stream_id).cloned()
    }

    /// Retrieve active session jitter metrics: (recommended_cushion_sec, measured_jitter_ms, stalls_absorbed, total_bytes).
    pub async fn get_session_metrics(&self, stream_id: &str) -> Option<(f64, f64, u64, u64)> {
        let map = self.sessions.lock().await;
        let session = map.get(stream_id)?;
        Some((
            session.jitter_shield.recommended_cushion_sec(),
            session.jitter_shield.measured_jitter_ms(),
            session.jitter_shield.stalls_absorbed(),
            session.jitter_shield.total_bytes_ingested(),
        ))
    }

    /// Report a client playback stall for closed-loop self-healing cushion expansion.
    pub async fn record_client_stall(&self, stream_id: &str) {
        let map = self.sessions.lock().await;
        if let Some(session) = map.get(stream_id) {
            session.jitter_shield.record_client_stall();
        }
    }
}
