use axum::response::IntoResponse;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

/// Conflict resolution policy for multi-channel live streaming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ConflictPolicy {
    /// If a different live stream is currently active and being consumed by downstream clients,
    /// reject the new stream request with an error unless `force = true`.
    #[default]
    RejectIfActive,

    /// Always preempt existing streams (current behavior).
    Preempt,
}

/// Token representing granted access to an upstream live channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArbiterGrant {
    /// Stream identifier granted for consumption.
    pub stream_id: String,
    /// Indicates whether granting this stream preempted an existing active stream.
    pub is_preemption: bool,
    /// Total active subscribers currently sharing this stream.
    pub subscribers: usize,
    /// Identifier of the stream that was preempted, if any.
    pub previous_stream_id: Option<String>,
}

impl ArbiterGrant {
    /// Create a new grant token.
    pub fn new(
        stream_id: impl Into<String>,
        is_preemption: bool,
        subscribers: usize,
        previous_stream_id: Option<String>,
    ) -> Self {
        Self {
            stream_id: stream_id.into(),
            is_preemption,
            subscribers,
            previous_stream_id,
        }
    }

    /// Returns the target stream identifier.
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Returns true if this grant preempted another active stream.
    pub fn is_preemption(&self) -> bool {
        self.is_preemption
    }

    /// Alias for `is_preemption`.
    pub fn is_preempted(&self) -> bool {
        self.is_preemption
    }

    /// Number of downstream subscribers currently attached to this stream.
    pub fn subscribers(&self) -> usize {
        self.subscribers
    }

    /// The previous stream identifier that was preempted, if any.
    pub fn previous_stream_id(&self) -> Option<&str> {
        self.previous_stream_id.as_deref()
    }

    /// True if multiple subscribers share this active stream without preemption.
    pub fn is_shared(&self) -> bool {
        !self.is_preemption && self.subscribers > 1
    }
}

impl std::ops::Deref for ArbiterGrant {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.stream_id
    }
}

impl AsRef<str> for ArbiterGrant {
    fn as_ref(&self) -> &str {
        &self.stream_id
    }
}

/// Error returned when a requested stream cannot be granted due to tuner contention.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ConflictError {
    #[error(
        "Stream '{active_stream_id}' is currently active with {active_subscribers} subscriber(s)"
    )]
    StreamInUse {
        active_stream_id: String,
        active_subscribers: usize,
        started_at: Instant,
    },
}

impl ConflictError {
    /// Convert the conflict error into an Axum HTTP 409 Conflict response.
    ///
    /// The response payload contains:
    /// ```json
    /// {
    ///   "error": "tuner_busy",
    ///   "active_stream_id": "...",
    ///   "subscribers": N,
    ///   "hint": "Pass ?force=1 to preempt"
    /// }
    /// ```
    pub fn to_response(&self) -> axum::response::Response {
        match self {
            Self::StreamInUse {
                active_stream_id,
                active_subscribers,
                ..
            } => {
                let status = axum::http::StatusCode::CONFLICT;
                let body = serde_json::json!({
                    "error": "tuner_busy",
                    "active_stream_id": active_stream_id,
                    "subscribers": active_subscribers,
                    "hint": "Pass ?force=1 to preempt",
                });
                (status, axum::Json(body)).into_response()
            }
        }
    }

    /// Active stream identifier currently holding the tuner.
    pub fn active_stream_id(&self) -> &str {
        match self {
            Self::StreamInUse {
                active_stream_id, ..
            } => active_stream_id,
        }
    }

    /// Active subscriber count of the holding stream.
    pub fn active_subscribers(&self) -> usize {
        match self {
            Self::StreamInUse {
                active_subscribers, ..
            } => *active_subscribers,
        }
    }

    /// Monotonic timestamp when the holding stream was started.
    pub fn started_at(&self) -> Instant {
        match self {
            Self::StreamInUse { started_at, .. } => *started_at,
        }
    }
}

impl IntoResponse for ConflictError {
    fn into_response(self) -> axum::response::Response {
        self.to_response()
    }
}

#[derive(Debug)]
struct ArbiterInner {
    active_stream_id: Option<String>,
    active_subscribers: usize,
    started_at: Option<Instant>,
    policy: ConflictPolicy,
}

/// Thread-safe multi-channel arbiter managing single-tuner access and conflict policies.
#[derive(Debug)]
pub struct ChannelArbiter {
    state: RwLock<ArbiterInner>,
}

/// Alias for ChannelArbiter.
pub type StreamArbiter = ChannelArbiter;

impl ChannelArbiter {
    /// Construct a new channel arbiter with the given conflict policy.
    pub fn new(policy: ConflictPolicy) -> Self {
        Self {
            state: RwLock::new(ArbiterInner {
                active_stream_id: None,
                active_subscribers: 0,
                started_at: None,
                policy,
            }),
        }
    }

    /// Currently configured conflict policy.
    pub fn policy(&self) -> ConflictPolicy {
        self.state.read().policy
    }

    /// Reconfigure conflict policy at runtime.
    pub fn set_policy(&self, policy: ConflictPolicy) {
        self.state.write().policy = policy;
    }

    /// Identifier of the currently active live stream, if any.
    pub fn active_stream(&self) -> Option<String> {
        self.state.read().active_stream_id.clone()
    }

    /// Number of active downstream subscribers consuming the active stream.
    pub fn active_subscribers(&self) -> usize {
        self.state.read().active_subscribers
    }

    /// Timestamp when the current active stream began playing.
    pub fn started_at(&self) -> Option<Instant> {
        self.state.read().started_at
    }

    /// Returns true if a live stream is currently active and has one or more subscribers.
    pub fn is_in_use(&self) -> bool {
        let state = self.state.read();
        state.active_stream_id.is_some() && state.active_subscribers > 0
    }

    /// Request access to `target_stream_id` under the current conflict policy.
    ///
    /// - If no active stream: grants access, marks `target_stream_id` as active.
    /// - If same stream as active: grants access (shares single upstream connection).
    /// - If different stream:
    ///   - If `RejectIfActive` and `!force` and active subscribers > 0:
    ///     Returns `ConflictError::StreamInUse`.
    ///   - If `force == true` or policy is `Preempt`: grants access and signals preemption.
    pub fn request_stream(
        &self,
        target_stream_id: &str,
        force: bool,
    ) -> Result<ArbiterGrant, ConflictError> {
        let mut state = self.state.write();

        match &state.active_stream_id {
            None => {
                // No active stream: grant access, mark target_stream_id as active
                state.active_stream_id = Some(target_stream_id.to_string());
                state.active_subscribers = 1;
                state.started_at = Some(Instant::now());

                Ok(ArbiterGrant {
                    stream_id: target_stream_id.to_string(),
                    is_preemption: false,
                    subscribers: 1,
                    previous_stream_id: None,
                })
            }
            Some(current_id) if current_id == target_stream_id => {
                // Same stream as active: share single upstream connection
                state.active_subscribers += 1;

                Ok(ArbiterGrant {
                    stream_id: target_stream_id.to_string(),
                    is_preemption: false,
                    subscribers: state.active_subscribers,
                    previous_stream_id: None,
                })
            }
            Some(current_id) => {
                // Contention: different stream requested
                if state.policy == ConflictPolicy::RejectIfActive
                    && !force
                    && state.active_subscribers > 0
                {
                    let started_at = state.started_at.unwrap_or_else(Instant::now);
                    Err(ConflictError::StreamInUse {
                        active_stream_id: current_id.clone(),
                        active_subscribers: state.active_subscribers,
                        started_at,
                    })
                } else {
                    let was_preempted = state.active_subscribers > 0;
                    let previous_stream_id = Some(current_id.clone());

                    state.active_stream_id = Some(target_stream_id.to_string());
                    state.active_subscribers = 1;
                    state.started_at = Some(Instant::now());

                    Ok(ArbiterGrant {
                        stream_id: target_stream_id.to_string(),
                        is_preemption: was_preempted
                            || force
                            || state.policy == ConflictPolicy::Preempt,
                        subscribers: 1,
                        previous_stream_id,
                    })
                }
            }
        }
    }

    /// Asynchronous wrapper for `request_stream`.
    pub async fn request_stream_async(
        &self,
        target_stream_id: &str,
        force: bool,
    ) -> Result<ArbiterGrant, ConflictError> {
        self.request_stream(target_stream_id, force)
    }

    /// Release one downstream subscriber for the given stream.
    /// Returns the remaining active subscriber count.
    pub fn release_subscriber(&self, stream_id: &str) -> usize {
        let mut state = self.state.write();
        if state.active_stream_id.as_deref() == Some(stream_id) {
            state.active_subscribers = state.active_subscribers.saturating_sub(1);
            state.active_subscribers
        } else {
            0
        }
    }

    /// Explicitly release and clear an active stream session.
    pub fn release_stream(&self, stream_id: &str) {
        let mut state = self.state.write();
        if state.active_stream_id.as_deref() == Some(stream_id) {
            state.active_stream_id = None;
            state.active_subscribers = 0;
            state.started_at = None;
        }
    }

    /// Reset arbiter state to idle.
    pub fn reset(&self) {
        let mut state = self.state.write();
        state.active_stream_id = None;
        state.active_subscribers = 0;
        state.started_at = None;
    }

    /// Request a stream and return an RAII guard that automatically releases
    /// the subscriber when dropped.
    pub fn acquire_guard(
        self: &Arc<Self>,
        target_stream_id: &str,
        force: bool,
    ) -> Result<(ArbiterGrant, ArbiterSubscriberGuard), ConflictError> {
        let grant = self.request_stream(target_stream_id, force)?;
        let guard = ArbiterSubscriberGuard::new(Arc::clone(self), target_stream_id.to_string());
        Ok((grant, guard))
    }
}

impl Default for ChannelArbiter {
    fn default() -> Self {
        Self::new(ConflictPolicy::RejectIfActive)
    }
}

/// RAII subscriber guard that automatically decrements the active subscriber count on drop.
#[derive(Debug)]
pub struct ArbiterSubscriberGuard {
    arbiter: Arc<ChannelArbiter>,
    stream_id: String,
    active: bool,
}

impl ArbiterSubscriberGuard {
    /// Create a new subscriber guard.
    pub fn new(arbiter: Arc<ChannelArbiter>, stream_id: String) -> Self {
        Self {
            arbiter,
            stream_id,
            active: true,
        }
    }

    /// The stream identifier guarded.
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Disarm the guard so it will not decrement on drop.
    pub fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for ArbiterSubscriberGuard {
    fn drop(&mut self) {
        if self.active {
            self.arbiter.release_subscriber(&self.stream_id);
        }
    }
}
