//! Plays opensnitchd against a snitchling running on a private socket, so the
//! GUI can be tried without touching the real firewall:
//!
//!   snitchling --socket /tmp/sl-test.sock --show-rules &
//!   cargo run --example fake_daemon -- /tmp/sl-test.sock [--asks N] [--rules N] [--secs N]

use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Endpoint, Uri};

use snitchling::pb::ui_client::UiClient;
use snitchling::pb::{ClientConfig, Connection, NotificationReply, Operator, PingRequest, Rule, Statistics};

fn arg(name: &str, default: u64) -> u64 {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1)?.parse().ok())
        .unwrap_or(default)
}

fn sample_rule(i: u64) -> Rule {
    let (operand, data) = match i % 4 {
        0 => ("process.path", format!("/usr/bin/app{i}")),
        1 => ("dest.host", format!("service{i}.example.com")),
        2 => ("dest.port", format!("{}", 1000 + i)),
        _ => ("user.id", "1000".to_string()),
    };
    Rule {
        name: format!("{:03}-allow-always-simple-{}", i, data.replace(['/', '.'], "-")),
        enabled: !i.is_multiple_of(7),
        action: if i.is_multiple_of(5) { "deny" } else { "allow" }.into(),
        duration: "always".into(),
        operator: Some(Operator { r#type: "simple".into(), operand: operand.into(), data, ..Default::default() }),
        ..Default::default()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: fake_daemon SOCKET [--asks N] [--rules N] [--secs N]");
    let (asks, nrules, secs) = (arg("--asks", 1), arg("--rules", 130), arg("--secs", 30));

    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let p = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(p).await?)) }
        }))
        .await?;
    let mut ui = UiClient::new(channel);

    let cfg = ClientConfig {
        name: "fake-daemon".into(),
        version: "1.7.2".into(),
        is_firewall_running: true,
        config: r#"{"DefaultAction":"allow","DefaultDuration":"once"}"#.into(),
        rules: (0..nrules).map(sample_rule).collect(),
        ..Default::default()
    };
    ui.subscribe(cfg).await?;
    println!("subscribed with {nrules} rules");

    // Notifications: print what the UI asks for and say OK.
    let (tx, rx) = mpsc::channel(16);
    tx.send(NotificationReply::default()).await?;
    let mut incoming = ui.notifications(ReceiverStream::new(rx)).await?.into_inner();
    tokio::spawn(async move {
        while let Ok(Some(n)) = incoming.message().await {
            let names: Vec<_> = n.rules.iter().map(|r| format!("{} enabled={} action={}", r.name, r.enabled, r.action)).collect();
            println!("notification type={} {:?}", n.r#type, names);
            let _ = tx.send(NotificationReply { id: n.id, code: 0, data: String::new() }).await;
        }
    });

    let mut pinger = ui.clone();
    tokio::spawn(async move {
        for i in 0.. {
            let stats = Statistics {
                daemon_version: "1.7.2".into(),
                rules: nrules,
                connections: 1000 + i * 3,
                accepted: 990 + i * 3,
                dropped: 10,
                ..Default::default()
            };
            if pinger.ping(PingRequest { id: i, stats: Some(stats) }).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;
    for i in 0..asks {
        let conn = Connection {
            protocol: "tcp".into(),
            src_ip: "192.168.1.20".into(),
            src_port: 50000 + i as u32,
            dst_ip: "93.184.215.14".into(),
            dst_host: "www.example.com".into(),
            dst_port: 443,
            user_id: 1000,
            process_id: 31337,
            process_path: "/usr/bin/curl".into(),
            process_cwd: "/home/user".into(),
            process_args: vec!["curl".into(), "-s".into(), "https://www.example.com/".into()],
            ..Default::default()
        };
        let mut c = ui.clone();
        tokio::spawn(async move {
            match c.ask_rule(conn).await {
                Ok(r) => {
                    let r = r.into_inner();
                    println!("ask #{i} answered: {} {} {} {:?}", r.name, r.action, r.duration, r.operator.map(|o| o.data));
                }
                Err(e) => println!("ask #{i} failed: {e}"),
            }
        });
    }
    tokio::time::sleep(Duration::from_secs(secs)).await;
    println!("fake daemon done");
    Ok(())
}
