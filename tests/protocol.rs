//! Plays the daemon against snitchling's gRPC server over a real unix socket.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};

use snitchling::hub::{self, Hub, PromptRequest};
use snitchling::pb::ui_client::UiClient;
use snitchling::pb::{
    self, ClientConfig, Connection, Notification, NotificationReply, NotificationReplyCode, Operator, PingRequest, Rule,
    Statistics,
};
use snitchling::rules::{Action, Choice, Target};
use snitchling::service;

struct Fixture {
    hub: Arc<Hub>,
    client: UiClient<Channel>,
    _dir: tempfile::TempDir,
    path: PathBuf,
}

async fn connect(path: &Path) -> UiClient<Channel> {
    let path = path.to_path_buf();
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let p = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(p).await?)) }
        }))
        .await
        .unwrap();
    UiClient::new(channel)
}

/// Starts the server; `prompter` gets the prompt channel (None: auto-allow).
async fn start(timeout: Duration, prompter: Option<Box<dyn FnOnce(mpsc::Receiver<PromptRequest>)>>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("osui.sock");
    let (hub, prompts) = Hub::new(timeout);
    match prompter {
        Some(p) => p(prompts),
        None => hub::auto_answer(prompts, |_| Choice::simple(Action::Allow, "once", Target::Executable)),
    }
    let listener = service::bind(&path).await.unwrap();
    tokio::spawn(service::serve(hub.clone(), listener, std::future::pending()));
    let client = connect(&path).await;
    Fixture { hub, client, _dir: dir, path }
}

fn rule(name: &str, data: &str) -> Rule {
    Rule {
        name: name.into(),
        enabled: true,
        action: "allow".into(),
        duration: "always".into(),
        operator: Some(Operator {
            r#type: "simple".into(),
            operand: "process.path".into(),
            data: data.into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn daemon_config(default_action: &str) -> ClientConfig {
    ClientConfig {
        name: "testhost".into(),
        version: "6.1.0-generic".into(),
        is_firewall_running: true,
        config: format!(r#"{{"DefaultAction":"{default_action}","DefaultDuration":"once"}}"#),
        rules: vec![rule("r1", "/usr/bin/one"), rule("protected", "/usr/bin/two")],
        ..Default::default()
    }
}

fn conn(path: &str, host: &str) -> Connection {
    Connection {
        protocol: "tcp".into(),
        dst_ip: "10.0.0.1".into(),
        dst_host: host.into(),
        dst_port: 443,
        user_id: 1000,
        process_id: 77,
        process_path: path.into(),
        process_args: vec![path.into()],
        ..Default::default()
    }
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition never became true");
}

/// A fake daemon on the Notifications stream: records what it gets, replies
/// OK except for deleting the rule called "protected".
async fn open_notifications(client: &mut UiClient<Channel>) -> (Arc<Mutex<Vec<Notification>>>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(16);
    tx.send(NotificationReply { id: 0, code: 0, data: String::new() }).await.unwrap();
    let mut incoming = client.notifications(ReceiverStream::new(rx)).await.unwrap().into_inner();
    let seen = Arc::new(Mutex::new(vec![]));
    let seen2 = seen.clone();
    let daemon = tokio::spawn(async move {
        while let Ok(Some(n)) = incoming.message().await {
            let refuse = n.r#type == pb::Action::DeleteRule as i32 && n.rules.iter().any(|r| r.name == "protected");
            let reply = NotificationReply {
                id: n.id,
                code: if refuse { NotificationReplyCode::Error as i32 } else { 0 },
                data: if refuse { "rule is protected".into() } else { String::new() },
            };
            seen2.lock().unwrap().push(n);
            if tx.send(reply).await.is_err() {
                break;
            }
        }
    });
    (seen, daemon)
}

#[tokio::test]
async fn subscribe_and_ping_update_state() {
    let mut f = start(Duration::from_secs(5), None).await;
    let cfg = daemon_config("deny");
    let back = f.client.subscribe(cfg.clone()).await.unwrap().into_inner();
    assert_eq!(back, cfg, "Subscribe must hand the daemon its config back unchanged");

    let s = f.hub.snapshot();
    assert!(s.connected && s.interception);
    assert_eq!(s.daemon_version, "", "Subscribe's version is the kernel's, not the daemon's");
    assert_eq!(s.default_action, Some(Action::Deny));
    assert_eq!(s.rules.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["protected", "r1"]);

    let stats = Statistics { daemon_version: "1.7.2".into(), connections: 10, accepted: 7, dropped: 3, ..Default::default() };
    let pong = f.client.ping(PingRequest { id: 99, stats: Some(stats) }).await.unwrap().into_inner();
    assert_eq!(pong.id, 99);
    let s = f.hub.snapshot();
    assert_eq!((s.connections, s.accepted, s.dropped), (10, 7, 3));
    assert_eq!(s.daemon_version, "1.7.2");
}

#[tokio::test]
async fn ask_rule_returns_the_users_choice() {
    let prompter: Box<dyn FnOnce(_)> = Box::new(|rx| {
        hub::auto_answer(rx, |req| {
            assert_eq!(req.conn.dst_host, "api.example.com");
            Choice::simple(Action::Deny, "always", Target::Domain)
        })
    });
    let mut f = start(Duration::from_secs(5), Some(prompter)).await;
    f.client.subscribe(daemon_config("allow")).await.unwrap();

    let rule = f.client.ask_rule(conn("/usr/bin/curl", "api.example.com")).await.unwrap().into_inner();
    assert_eq!((rule.action.as_str(), rule.duration.as_str()), ("deny", "always"));
    let op = rule.operator.unwrap();
    assert_eq!((op.r#type.as_str(), op.data.as_str()), ("regexp", r"^(|.*\.)example\.com$"));
    assert!(f.hub.snapshot().rules.iter().any(|r| r.name == rule.name), "non-once rules are tracked");
}

#[tokio::test]
async fn unanswered_prompt_applies_the_daemon_default_once() {
    // prompter drops every request without answering
    let prompter: Box<dyn FnOnce(_)> = Box::new(|mut rx: mpsc::Receiver<PromptRequest>| {
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
    });
    let mut f = start(Duration::from_secs(5), Some(prompter)).await;
    f.client.subscribe(daemon_config("deny")).await.unwrap();
    let rule = f.client.ask_rule(conn("/usr/bin/wget", "example.org")).await.unwrap().into_inner();
    assert_eq!((rule.action.as_str(), rule.duration.as_str()), ("deny", "once"));
    assert_eq!(rule.operator.unwrap().data, "/usr/bin/wget");
    assert_eq!(f.hub.snapshot().rules.len(), 2, "once rules are not added");
}

#[tokio::test]
async fn prompter_that_never_answers_times_out() {
    let held = Arc::new(Mutex::new(vec![]));
    let held2 = held.clone();
    let prompter: Box<dyn FnOnce(_)> = Box::new(move |mut rx: mpsc::Receiver<PromptRequest>| {
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                held2.lock().unwrap().push(req); // keep it, never reply
            }
        });
    });
    let mut f = start(Duration::ZERO, Some(prompter)).await;
    f.client.subscribe(daemon_config("allow")).await.unwrap();
    let t = std::time::Instant::now();
    let rule = f.client.ask_rule(conn("/usr/bin/nc", "example.net")).await.unwrap().into_inner();
    assert_eq!((rule.action.as_str(), rule.duration.as_str()), ("allow", "once"));
    assert!(t.elapsed() < Duration::from_secs(10));
    assert_eq!(held.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn queued_prompt_covered_by_an_earlier_answer_is_not_shown() {
    let shown = Arc::new(AtomicUsize::new(0));
    let shown2 = shown.clone();
    let prompter: Box<dyn FnOnce(_)> = Box::new(move |rx| {
        hub::auto_answer(rx, move |_| {
            shown2.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100)); // user thinking; the second ask queues up
            Choice::simple(Action::Allow, "until restart", Target::Executable)
        })
    });
    let f = start(Duration::from_secs(5), Some(prompter)).await;
    let mut c1 = f.client.clone();
    let mut c2 = f.client.clone();
    c1.subscribe(daemon_config("deny")).await.unwrap();
    let (a, b) = tokio::join!(
        c1.ask_rule(conn("/usr/bin/firefox", "a.example.com")),
        c2.ask_rule(conn("/usr/bin/firefox", "b.example.com")),
    );
    let (a, b) = (a.unwrap().into_inner(), b.unwrap().into_inner());
    assert_eq!(shown.load(Ordering::SeqCst), 1, "second connection should reuse the first answer");
    assert_eq!(a.name, b.name);
    assert_eq!(b.action, "allow");
}

#[tokio::test]
async fn rule_commands_round_trip_through_notifications() {
    let mut f = start(Duration::from_secs(5), None).await;
    f.client.subscribe(daemon_config("allow")).await.unwrap();
    let (seen, _keep) = open_notifications(&mut f.client).await;
    wait_for(|| f.hub.snapshot().connected).await;

    f.hub.set_rule_enabled("r1", false).await.unwrap();
    {
        let n = seen.lock().unwrap();
        assert_eq!(n[0].r#type, pb::Action::DisableRule as i32);
        assert_eq!(n[0].rules[0].name, "r1");
        assert!(!n[0].rules[0].enabled);
    }
    assert!(!f.hub.snapshot().rules.iter().find(|r| r.name == "r1").unwrap().enabled);

    let err = f.hub.delete_rule("protected").await.unwrap_err();
    assert!(err.to_string().contains("rule is protected"), "{err:#}");
    assert!(f.hub.snapshot().rules.iter().any(|r| r.name == "protected"), "refused delete keeps the rule");

    f.hub.delete_rule("r1").await.unwrap();
    assert!(!f.hub.snapshot().rules.iter().any(|r| r.name == "r1"));

    let mut edited = rule("protected", "/usr/bin/two");
    edited.action = "deny".into();
    f.hub.change_rule(edited).await.unwrap();
    assert_eq!(f.hub.snapshot().rules.iter().find(|r| r.name == "protected").unwrap().action, "deny");

    f.hub.set_interception(false).await.unwrap();
    assert!(!f.hub.snapshot().interception);

    let types: Vec<i32> = seen.lock().unwrap().iter().map(|n| n.r#type).collect();
    assert_eq!(
        types,
        [
            pb::Action::DisableRule as i32,
            pb::Action::DeleteRule as i32,
            pb::Action::DeleteRule as i32,
            pb::Action::ChangeRule as i32,
            pb::Action::DisableInterception as i32,
        ]
    );
}

#[tokio::test]
async fn daemon_going_away_marks_disconnected() {
    let mut f = start(Duration::from_secs(5), None).await;
    f.client.subscribe(daemon_config("allow")).await.unwrap();
    let (_seen, daemon) = open_notifications(&mut f.client).await;
    wait_for(|| f.hub.snapshot().connected).await;
    daemon.abort(); // the daemon process goes away: its stream and connection close
    drop(f.client);
    wait_for(|| !f.hub.snapshot().connected).await;
    let err = f.hub.set_interception(true).await.unwrap_err();
    assert!(err.to_string().contains("not connected"), "{err:#}");
}

#[tokio::test]
async fn bind_refuses_to_steal_a_live_socket_but_replaces_a_stale_one() {
    let f = start(Duration::from_secs(5), None).await;
    let err = service::bind(&f.path).await.unwrap_err();
    assert!(err.to_string().contains("already listening"), "{err:#}");

    let dir = tempfile::tempdir().unwrap();
    let stale = dir.path().join("stale.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap()); // leaves the file behind
    assert!(stale.exists());
    service::bind(&stale).await.unwrap();
}

#[tokio::test]
async fn hub_counts_connections_queued_behind_the_prompt() {
    let (gate_tx, mut gate_rx) = mpsc::unbounded_channel::<()>();
    let prompter: Box<dyn FnOnce(_)> = Box::new(move |mut rx: mpsc::Receiver<PromptRequest>| {
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                gate_rx.recv().await; // hold the prompt until released
                let _ = req.reply.send(Choice::simple(Action::Deny, "once", Target::Executable));
            }
        });
    });
    let f = start(Duration::from_secs(30), Some(prompter)).await;
    let mut c = f.client.clone();
    c.subscribe(daemon_config("allow")).await.unwrap();
    let asks: Vec<_> = (0..3)
        .map(|i| {
            let mut c = f.client.clone();
            tokio::spawn(async move { c.ask_rule(conn(&format!("/usr/bin/app{i}"), "x.example.com")).await })
        })
        .collect();
    wait_for(|| f.hub.waiting() == 2).await;
    for _ in 0..3 {
        gate_tx.send(()).unwrap();
    }
    for a in asks {
        assert_eq!(a.await.unwrap().unwrap().into_inner().action, "deny");
    }
    assert_eq!(f.hub.waiting(), 0);
}

#[tokio::test]
async fn daemon_hanging_up_mid_prompt_releases_the_ask() {
    let held = Arc::new(Mutex::new(vec![]));
    let held2 = held.clone();
    let prompter: Box<dyn FnOnce(_)> = Box::new(move |mut rx: mpsc::Receiver<PromptRequest>| {
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                held2.lock().unwrap().push(req); // on screen, unanswered
            }
        });
    });
    let f = start(Duration::from_secs(30), Some(prompter)).await;
    let mut c = f.client.clone();
    c.subscribe(daemon_config("allow")).await.unwrap();
    let ask = tokio::spawn(async move { c.ask_rule(conn("/usr/bin/curl", "example.com")).await });
    wait_for(|| held.lock().unwrap().len() == 1).await;
    ask.abort(); // the daemon gives up on the request
    wait_for(|| held.lock().unwrap()[0].reply.is_closed()).await; // the GUI can see it's moot
    assert_eq!(f.hub.waiting(), 0);
    let mut c = f.client.clone();
    let ask = tokio::spawn(async move { c.ask_rule(conn("/usr/bin/curl", "example.com")).await });
    wait_for(|| held.lock().unwrap().len() == 2).await; // the next ask isn't stuck behind it
    ask.abort();
}
