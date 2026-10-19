//! Adaptive playback slew-rate controller for live stream jitter recovery.
//!
//! Provides dynamic catch-up calculations ($1.05\times - 1.08\times$) after upstream WAN
//! stalls or jitter events to restore razor-edge live sports latency (1.5s–2.5s) without
//! audible pitch distortion or video judder.

/// Playback rate decision computed by the [`AdaptiveSlewController`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SlewAction {
    /// Playback is synchronized within the acceptable live target window.
    Normal { rate: f32 },
    /// Playhead has drifted behind the live edge (e.g. after network recovery).
    /// Gradually speeds up playback using audio pitch-preserving time stretching.
    CatchUp {
        rate: f32,
        delay_sec: f32,
        target_latency_sec: f32,
    },
    /// Playhead is dangerously close to the live edge (< min_latency), risking buffer underrun.
    /// Slightly decelerates playback to allow the safe cushion to rebuild.
    SlowDown { rate: f32, current_lead_sec: f32 },
    /// Delay is beyond the recoverable threshold (> max_recoverable_lag_sec).
    /// Recommends an instantaneous jump to the newest keyframe at the live edge.
    SeekToLive { lag_sec: f32 },
}

/// Adaptive controller computing optimal playback speeds based on current buffer lag.
#[derive(Debug, Clone)]
pub struct AdaptiveSlewController {
    /// Ideal target latency behind broadcast live edge (default: 2.0s).
    pub target_latency_sec: f32,
    /// Minimum safe buffer lead before slowing down to prevent starvation (default: 1.2s).
    pub min_latency_sec: f32,
    /// Upper bound of normal latency tolerance before catch-up activates (default: 2.5s).
    pub max_normal_latency_sec: f32,
    /// Maximum catch-up slew rate (default: 1.08x, threshold of imperceptible pitch shift).
    pub max_slew_rate: f32,
    /// Minimum slow-down slew rate (default: 0.95x).
    pub min_slew_rate: f32,
    /// Maximum lag in seconds before abandoning slew catchup in favor of an instant jump (default: 25.0s).
    pub max_recoverable_lag_sec: f32,
}

impl Default for AdaptiveSlewController {
    fn default() -> Self {
        Self {
            target_latency_sec: 2.0,
            min_latency_sec: 1.2,
            max_normal_latency_sec: 2.5,
            max_slew_rate: 1.08,
            min_slew_rate: 0.95,
            max_recoverable_lag_sec: 25.0,
        }
    }
}

impl AdaptiveSlewController {
    /// Create a controller configured with specific sports latency parameters.
    pub fn new(target_latency_sec: f32, max_slew_rate: f32) -> Self {
        Self {
            target_latency_sec,
            min_latency_sec: (target_latency_sec * 0.6).max(0.8),
            max_normal_latency_sec: (target_latency_sec * 1.25).max(1.8),
            max_slew_rate,
            ..Default::default()
        }
    }

    /// Calculate the optimal playback rate and recommended action for the given measured latency.
    pub fn calculate_rate(&self, current_latency_sec: f32) -> SlewAction {
        if current_latency_sec > self.max_recoverable_lag_sec {
            return SlewAction::SeekToLive {
                lag_sec: current_latency_sec,
            };
        }

        if current_latency_sec > self.max_normal_latency_sec {
            let lag_delta = current_latency_sec - self.target_latency_sec;
            // Scale rate proportionally between 1.05x and max_slew_rate (1.08x)
            // A 10-second lag achieves max slew rate
            let progress = (lag_delta / 10.0).clamp(0.0, 1.0);
            let min_catchup = 1.05;
            let max_catchup = self.max_slew_rate.max(min_catchup);
            let rate = min_catchup + progress * (max_catchup - min_catchup);
            let rounded_rate = (rate * 1000.0).round() / 1000.0;

            return SlewAction::CatchUp {
                rate: rounded_rate,
                delay_sec: current_latency_sec,
                target_latency_sec: self.target_latency_sec,
            };
        }

        if current_latency_sec < self.min_latency_sec {
            let deficit = self.min_latency_sec - current_latency_sec;
            let progress = (deficit / self.min_latency_sec).clamp(0.0, 1.0);
            let rate = 1.0 - progress * (1.0 - self.min_slew_rate);
            let rounded_rate = (rate * 1000.0).round() / 1000.0;

            return SlewAction::SlowDown {
                rate: rounded_rate,
                current_lead_sec: current_latency_sec,
            };
        }

        SlewAction::Normal { rate: 1.0 }
    }

    /// Estimate the time in seconds needed to catch up to the target latency at the given rate.
    pub fn estimated_catchup_time_sec(&self, current_latency_sec: f32, rate: f32) -> Option<f32> {
        if rate <= 1.0 || current_latency_sec <= self.target_latency_sec {
            return None;
        }

        let lag_to_close = current_latency_sec - self.target_latency_sec;
        let speed_advantage = rate - 1.0;
        Some(lag_to_close / speed_advantage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_playback_within_window() {
        let controller = AdaptiveSlewController::default();
        let action = controller.calculate_rate(2.1);
        assert_eq!(action, SlewAction::Normal { rate: 1.0 });
    }

    #[test]
    fn test_catchup_rate_on_moderate_jitter_drift() {
        let controller = AdaptiveSlewController::default();
        // 6.0 seconds latency (e.g. after a 4s upstream stall)
        let action = controller.calculate_rate(6.0);
        match action {
            SlewAction::CatchUp {
                rate,
                delay_sec,
                target_latency_sec,
            } => {
                assert!((1.04..=1.08).contains(&rate), "Rate was {rate}");
                assert_eq!(delay_sec, 6.0);
                assert_eq!(target_latency_sec, 2.0);

                let est_time = controller
                    .estimated_catchup_time_sec(delay_sec, rate)
                    .unwrap();
                assert!(est_time > 0.0);
            }
            other => panic!("Expected CatchUp, got {other:?}"),
        }
    }

    #[test]
    fn test_slowdown_when_buffer_lead_too_thin() {
        let controller = AdaptiveSlewController::default();
        let action = controller.calculate_rate(0.6); // < min_latency (1.2s)
        match action {
            SlewAction::SlowDown {
                rate,
                current_lead_sec,
            } => {
                assert!((0.95..1.0).contains(&rate), "Rate was {rate}");
                assert_eq!(current_lead_sec, 0.6);
            }
            other => panic!("Expected SlowDown, got {other:?}"),
        }
    }

    #[test]
    fn test_seek_to_live_on_extreme_lag() {
        let controller = AdaptiveSlewController::default();
        let action = controller.calculate_rate(35.0); // > 25.0s max
        match action {
            SlewAction::SeekToLive { lag_sec } => {
                assert_eq!(lag_sec, 35.0);
            }
            other => panic!("Expected SeekToLive, got {other:?}"),
        }
    }
}
