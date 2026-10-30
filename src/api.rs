//! The internal HTTP API, for the service that hands players their way to outpost (PLAN.md
//! D2). Its port is never published or routed by Caddy, so only containers on the same network
//! reach it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::relay::RoomRefusal;
use crate::turn::Shared;

struct Api {
    network: Shared,
    /// The TURN URLs players are given, as an `RTCIceServer` takes them.
    urls: Vec<String>,
}

/// The routes: only `POST /rooms`.
pub fn app(network: Shared, public_ip: Ipv4Addr, udp: SocketAddr, tcp: SocketAddr) -> Router {
    let urls = vec![
        format!("turn:{public_ip}:{}?transport=udp", udp.port()),
        format!("turn:{public_ip}:{}?transport=tcp", tcp.port()),
    ];
    Router::new()
        .route("/rooms", post(open_room))
        .with_state(Arc::new(Api { network, urls }))
}

/// Opens a room and answers it as an `RTCIceServer`: `{urls, username, credential}`, for both
/// of its players.
async fn open_room(State(api): State<Arc<Api>>) -> Response {
    let opened = api.network.relay.lock().unwrap().open_room(Instant::now());
    match opened {
        Ok(room) => {
            let body = serde_json::json!({
                "urls": api.urls,
                "username": room.username,
                "credential": room.password,
            });
            let headers = [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ];
            (headers, body.to_string()).into_response()
        }
        // When to ask again: a room can be opened every second, and rooms close within minutes
        // of no longer being used.
        Err(RoomRefusal::TooSoon) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            "rooms are being opened too fast",
        )
            .into_response(),
        Err(RoomRefusal::Full) => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "60")],
            "too many rooms are open",
        )
            .into_response(),
    }
}
