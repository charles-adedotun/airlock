//! Cross-platform OS shutdown signal listener supporting both SIGINT (Ctrl+C)
//! and Unix SIGTERM (systemctl stop/restart).

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;

/// Awaits either SIGINT (Ctrl+C) or SIGTERM (systemd shutdown).
pub async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %err, "Failed to listen for Ctrl+C signal");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::error!(error = %err, "Failed to register SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received SIGINT (Ctrl+C), commencing graceful shutdown...");
        },
        _ = terminate => {
            info!("Received SIGTERM (systemd terminate), commencing graceful shutdown...");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_future_constructible() {
        // Verify that the shutdown future can be created and selected without panicking
        tokio::select! {
            _ = wait_for_shutdown_signal() => {},
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {},
        }
    }
}
