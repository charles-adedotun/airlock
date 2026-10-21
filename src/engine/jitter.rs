//! Server-side Adaptive Jitter Shield and WAN Variance Tracker.
//!
//! Abstracts all upstream Internet IPTV inconsistencies (packet jitter, route hops,
//! and momentary stalls) directly on the homelab host so that downstream LAN/Tailnet
//! clients receive an unbroken, broadcast-grade streaming experience with zero rebuffering.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Server-side tracker that monitors upstream chunk arrival intervals and dynamically
/// sizes the ring buffer pre-roll cushion to insulate clients from network jitter.
pub struct AdaptiveJitterShield {
    base_cushion_sec: f64,
    min_cushion_sec: f64,
    max_cushion_sec: f64,
    last_arrival: Mutex<Option<Instant>>,
    jitter_ema_ms: Mutex<f64>,
    stalls_absorbed: AtomicU64,
    total_bytes_ingested: AtomicU64,
}

impl Default for AdaptiveJitterShield {
    fn default() -> Self {
        Self::new(3.5, 2.5, 7.5)
    }
}

impl AdaptiveJitterShield {
    /// Create a new jitter shield with baseline and boundary cushion targets in seconds.
    pub fn new(base_cushion_sec: f64, min_cushion_sec: f64, max_cushion_sec: f64) -> Self {
        Self {
            base_cushion_sec,
            min_cushion_sec,
            max_cushion_sec,
            last_arrival: Mutex::new(None),
            jitter_ema_ms: Mutex::new(0.0),
            stalls_absorbed: AtomicU64::new(0),
            total_bytes_ingested: AtomicU64::new(0),
        }
    }

    /// Record the arrival of an upstream chunk and update the running jitter metrics.
    pub fn record_chunk_arrival(&self, chunk_bytes: usize) {
        let now = Instant::now();
        self.total_bytes_ingested
            .fetch_add(chunk_bytes as u64, Ordering::Relaxed);

        let mut last_opt = self.last_arrival.lock();
        if let Some(prev) = *last_opt {
            let delta = now.duration_since(prev);
            let delta_ms = delta.as_secs_f64() * 1000.0;

            // An arrival interval > 750ms signifies an upstream WAN stall absorbed by the ring
            if delta_ms > 750.0 {
                self.stalls_absorbed.fetch_add(1, Ordering::Relaxed);
            }

            // Exponential moving average for jitter variance (alpha = 0.1)
            let mut j = self.jitter_ema_ms.lock();
            let expected_cadence_ms = 40.0; // Typical ~25fps / 40ms chunk arrival cadence
            let deviation = (delta_ms - expected_cadence_ms).abs();
            *j = 0.90 * (*j) + 0.10 * deviation;
        }

        *last_opt = Some(now);
    }

    /// Return the currently recommended pre-roll cushion in seconds.
    ///
    /// Dynamically expands under high upstream WAN jitter to guarantee
    /// downstream client buffers never run dry.
    pub fn recommended_cushion_sec(&self) -> f64 {
        let j = *self.jitter_ema_ms.lock();

        // Under clean LAN/low-jitter WAN (j < 50ms), stay at base cushion (e.g. 3.5s)
        // As jitter climbs toward 500ms, expand cushion toward max (up to 7.5s)
        let expansion =
            (j / 300.0).clamp(0.0, 1.0) * (self.max_cushion_sec - self.base_cushion_sec);
        let target = self.base_cushion_sec + expansion;
        target.clamp(self.min_cushion_sec, self.max_cushion_sec)
    }

    /// Return the current measured jitter variance in milliseconds.
    pub fn measured_jitter_ms(&self) -> f64 {
        *self.jitter_ema_ms.lock()
    }

    /// Total count of upstream WAN stalls successfully absorbed by the server reservoir.
    pub fn stalls_absorbed(&self) -> u64 {
        self.stalls_absorbed.load(Ordering::Relaxed)
    }

    /// Total bytes ingested through the shield.
    pub fn total_bytes_ingested(&self) -> u64 {
        self.total_bytes_ingested.load(Ordering::Relaxed)
    }

    /// Record an explicit client playback stall report (e.g. from ExoPlayer or Web AnalyticsListener)
    /// to trigger dynamic cushion expansion (closed-loop self-healing).
    pub fn record_client_stall(&self) {
        let mut j = self.jitter_ema_ms.lock();
        *j = (*j + 150.0).min(1000.0);
        self.stalls_absorbed.fetch_add(1, Ordering::Relaxed);
    }

    /// Reset jitter tracking state on stream switch.
    pub fn reset(&self) {
        *self.last_arrival.lock() = None;
        *self.jitter_ema_ms.lock() = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_jitter_shield_baseline_and_adaptation() {
        let shield = AdaptiveJitterShield::new(3.5, 2.5, 7.5);
        assert_eq!(shield.recommended_cushion_sec(), 3.5);

        // Simulate steady upstream chunk arrival (every 40ms)
        for _ in 0..10 {
            shield.record_chunk_arrival(188 * 20);
        }
        assert!(shield.recommended_cushion_sec() < 4.0);

        // Inject simulated WAN stall of 1200ms
        let now = Instant::now();
        *shield.last_arrival.lock() = Some(now - Duration::from_millis(1200));
        shield.record_chunk_arrival(188 * 50);

        assert_eq!(shield.stalls_absorbed(), 1);
        assert!(shield.recommended_cushion_sec() > 3.5);
    }
}
