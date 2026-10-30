use outpost::{Config, Outpost};
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false)
        .init();
    let outpost = Outpost::bind(Config::from_env()).await?;
    tracing::info!(
        "listening: HTTP on {}, TURN on {} (UDP) and {} (TCP)",
        outpost.web_addr(),
        outpost.udp_addr(),
        outpost.tcp_addr()
    );
    outpost.run(terminated()).await
}

/// Docker stops the container with SIGTERM; Ctrl-C does the same when run by hand.
async fn terminated() {
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("shutting down");
}
