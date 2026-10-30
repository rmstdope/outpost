//! outpost: a TURN relay for NESER network play that relays only between the two players of a
//! room. PLAN.md describes where it is going; so far it is a STUN server that also hands out
//! TURN allocations.

mod relay;
pub mod stun;
mod turn;
mod web;

use std::future::{Future, IntoFuture};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, UdpSocket};

pub use relay::Credentials;
pub use web::app;

#[derive(Clone, Debug)]
pub struct Config {
    /// Source commit served from `/release.json`.
    pub revision: String,
    /// Where the HTTP side listens.
    pub web: SocketAddr,
    /// Where the TURN port listens, on both UDP and TCP.
    pub turn: SocketAddr,
    /// How long `/healthz` waits for the TURN port to answer.
    pub probe_timeout: Duration,
    /// The IPv4 address players reach the TURN port at, given as the address of their relayed
    /// connections.
    pub public_ip: Ipv4Addr,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            revision: "unknown".to_string(),
            web: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)),
            turn: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 3478)),
            probe_timeout: Duration::from_secs(1),
            public_ip: Ipv4Addr::LOCALHOST,
        }
    }
}

impl Config {
    /// The defaults, with `OUTPOST_REVISION` and `OUTPOST_PUBLIC_IP` applied.
    pub fn from_env() -> Result<Self, String> {
        let mut config = Config::default();
        if let Ok(revision) = std::env::var("OUTPOST_REVISION") {
            config.revision = revision;
        }
        if let Ok(ip) = std::env::var("OUTPOST_PUBLIC_IP") {
            config.public_ip = ip
                .parse()
                .map_err(|_| format!("OUTPOST_PUBLIC_IP is not an IPv4 address: {ip}"))?;
        }
        Ok(config)
    }
}

/// Every listener, bound and ready to serve.
pub struct Outpost {
    revision: String,
    probe_timeout: Duration,
    web: TcpListener,
    udp: UdpSocket,
    tcp: TcpListener,
    relay: turn::Shared,
    public_ip: Ipv4Addr,
}

impl Outpost {
    pub async fn bind(config: Config) -> io::Result<Outpost> {
        Ok(Outpost {
            web: TcpListener::bind(config.web).await?,
            udp: UdpSocket::bind(config.turn).await?,
            tcp: TcpListener::bind(config.turn).await?,
            revision: config.revision,
            probe_timeout: config.probe_timeout,
            relay: Arc::new(Mutex::new(relay::Relay::new(
                config.public_ip,
                Instant::now(),
            ))),
            public_ip: config.public_ip,
        })
    }

    /// The address relayed addresses are given on.
    pub fn public_ip(&self) -> Ipv4Addr {
        self.public_ip
    }

    /// Opens a room and returns the credentials both of its players log in with.
    pub fn open_room(&self) -> Credentials {
        self.relay.lock().unwrap().open_room()
    }

    pub fn web_addr(&self) -> SocketAddr {
        self.web
            .local_addr()
            .expect("a bound listener has an address")
    }

    pub fn udp_addr(&self) -> SocketAddr {
        self.udp
            .local_addr()
            .expect("a bound socket has an address")
    }

    pub fn tcp_addr(&self) -> SocketAddr {
        self.tcp
            .local_addr()
            .expect("a bound listener has an address")
    }

    /// Serves until `shutdown` completes. Nothing is waited for: a relayed game cannot be handed
    /// over to another process anyway.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let app = app(self.revision.clone(), self.probe(), self.probe_timeout);
        tokio::select! {
            result = axum::serve(self.web, app).into_future() => result,
            result = turn::serve_udp(self.udp, self.relay.clone()) => result,
            result = turn::serve_tcp(self.tcp, self.relay.clone()) => result,
            result = turn::sweep(self.relay) => result,
            () = shutdown => Ok(()),
        }
    }

    /// The UDP listener as this process can reach it.
    fn probe(&self) -> SocketAddr {
        let mut address = self.udp_addr();
        if address.ip().is_unspecified() {
            address.set_ip(match address {
                SocketAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                SocketAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
            });
        }
        address
    }
}
