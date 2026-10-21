//! The gRPC server the daemon connects to (OpenSnitch's UI is the server).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request, Response, Status, Streaming};

use crate::hub::Hub;
use crate::pb::ui_server::{Ui, UiServer};
use crate::pb::{Alert, ClientConfig, Connection, MsgResponse, Notification, NotificationReply, PingReply, PingRequest, Rule};

pub const DEFAULT_SOCKET: &str = "/tmp/osui.sock";
const DAEMON_CONFIG: &str = "/etc/opensnitchd/default-config.json";

pub struct UiService {
    hub: Arc<Hub>,
}

#[tonic::async_trait]
impl Ui for UiService {
    async fn ping(&self, req: Request<PingRequest>) -> Result<Response<PingReply>, Status> {
        let req = req.into_inner();
        self.hub.on_ping(req.stats.as_ref());
        Ok(Response::new(PingReply { id: req.id }))
    }

    async fn ask_rule(&self, req: Request<Connection>) -> Result<Response<Rule>, Status> {
        let conn = req.into_inner();
        let what = format!(
            "{} -> {}:{}",
            conn.process_path,
            if conn.dst_host.is_empty() { &conn.dst_ip } else { &conn.dst_host },
            conn.dst_port
        );
        let rule = self.hub.ask(conn).await;
        eprintln!("snitchling: ask {what} => {} {} ({})", rule.action, rule.duration, rule.name);
        Ok(Response::new(rule))
    }

    async fn subscribe(&self, req: Request<ClientConfig>) -> Result<Response<ClientConfig>, Status> {
        let cfg = req.into_inner();
        self.hub.on_subscribe(&cfg);
        // Returned as-is: we don't override the daemon's DefaultAction.
        Ok(Response::new(cfg))
    }

    type NotificationsStream = ReceiverStream<Result<Notification, Status>>;

    async fn notifications(
        &self,
        req: Request<Streaming<NotificationReply>>,
    ) -> Result<Response<Self::NotificationsStream>, Status> {
        let mut replies = req.into_inner();
        let (tx, rx) = mpsc::channel(32);
        let generation = self.hub.attach(tx);
        let hub = self.hub.clone();
        tokio::spawn(async move {
            while let Ok(Some(reply)) = replies.message().await {
                hub.on_reply(reply);
            }
            hub.detach(generation);
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn post_alert(&self, req: Request<Alert>) -> Result<Response<MsgResponse>, Status> {
        self.hub.on_alert(&req.into_inner());
        Ok(Response::new(MsgResponse { id: 0 }))
    }
}

/// The UI socket the daemon is configured to dial, if it's a unix socket.
pub fn daemon_socket() -> PathBuf {
    std::fs::read_to_string(DAEMON_CONFIG)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.pointer("/Server/Address")?.as_str()?.strip_prefix("unix://").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

/// Binds the socket, refusing to steal it from another live UI.
pub async fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    if path.exists() {
        if UnixStream::connect(path).await.is_ok() {
            bail!(
                "another UI is already listening on {} (is opensnitch-ui running?)",
                path.display()
            );
        }
        std::fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))?;
    }
    UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))
}

pub async fn serve(hub: Arc<Hub>, listener: UnixListener, shutdown: impl Future<Output = ()>) -> anyhow::Result<()> {
    let path = listener.local_addr().ok().and_then(|a| a.as_pathname().map(Path::to_path_buf));
    let result = tonic::transport::Server::builder()
        .add_service(UiServer::new(UiService { hub }))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), shutdown)
        .await;
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
    result.context("gRPC server")
}
