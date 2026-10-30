//! The HTTP side: a page saying what outpost is, health and the release marker.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use tokio::net::UdpSocket;

use crate::stun::{self, Message};

struct Shared {
    revision: String,
    probe: SocketAddr,
    probe_timeout: Duration,
}

/// The HTTP routes. `/healthz` asks `probe`, the TURN port's UDP listener, for a Binding and is
/// healthy only when it answers within `probe_timeout`.
pub fn app(revision: String, probe: SocketAddr, probe_timeout: Duration) -> Router {
    let shared = Shared {
        revision,
        probe,
        probe_timeout,
    };
    Router::new()
        .route("/", get(|| async { Html(include_str!("index.html")) }))
        .route("/healthz", get(healthz))
        .route("/release.json", get(release))
        .with_state(Arc::new(shared))
}

async fn healthz(State(shared): State<Arc<Shared>>) -> Response {
    let answered = tokio::time::timeout(shared.probe_timeout, binding_answered(shared.probe)).await;
    if matches!(answered, Ok(Ok(true))) {
        "ok".into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "the TURN port does not answer",
        )
            .into_response()
    }
}

async fn binding_answered(target: SocketAddr) -> std::io::Result<bool> {
    let any = match target {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = UdpSocket::bind(any).await?;
    socket.connect(target).await?;
    let transaction = rand::random();
    socket.send(&stun::binding_request(transaction)).await?;
    let mut datagram = [0; 512];
    loop {
        let size = socket.recv(&mut datagram).await?;
        if let Some(message) = Message::parse(&datagram[..size])
            && message.transaction == transaction
        {
            return Ok(message.is_binding_success());
        }
    }
}

async fn release(State(shared): State<Arc<Shared>>) -> Response {
    let body = serde_json::json!({ "revision": shared.revision }).to_string();
    let headers = [
        (header::CONTENT_TYPE, "application/json"),
        (header::CACHE_CONTROL, "no-cache"),
    ];
    (headers, body).into_response()
}
