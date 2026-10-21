mod gui;
mod tray;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::signal::unix::{SignalKind, signal};

use snitchling::hub::{self, Hub};
use snitchling::rules::{self, Action, Choice, Target};
use snitchling::service;

const USAGE: &str = "\
snitchling — a small UI for the OpenSnitch daemon

usage: snitchling [options]

  --socket PATH            UI socket the daemon dials (default: from
                           /etc/opensnitchd/default-config.json, else /tmp/osui.sock)
  --timeout SECS           seconds before a prompt applies the default action (default 15)
  --default-duration D     preselected duration in prompts (default \"until restart\")
  --show-rules             open the rules window at start
  --headless               no windows or tray; answer prompts with --auto-answer
  --auto-answer ACTION     allow|deny|reject, once, for the executable (headless only;
                           default: the daemon's DefaultAction)
  -h, --help               this help
";

struct Opts {
    socket: PathBuf,
    timeout: Duration,
    default_duration: String,
    show_rules: bool,
    headless: bool,
    auto_answer: Option<Action>,
}

fn parse_args() -> anyhow::Result<Opts> {
    let mut o = Opts {
        socket: service::daemon_socket(),
        timeout: Duration::from_secs(15),
        default_duration: "until restart".into(),
        show_rules: false,
        headless: false,
        auto_answer: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = || args.next().with_context(|| format!("{a} needs a value"));
        match a.as_str() {
            "--socket" => o.socket = value()?.into(),
            "--timeout" => o.timeout = Duration::from_secs(value()?.parse().context("--timeout")?),
            "--default-duration" => {
                let d = value()?;
                if !rules::DURATIONS.contains(&d.as_str()) {
                    bail!("--default-duration must be one of: {}", rules::DURATIONS.join(", "));
                }
                o.default_duration = d;
            }
            "--show-rules" => o.show_rules = true,
            "--headless" => o.headless = true,
            "--auto-answer" => {
                let v = value()?;
                o.auto_answer = Some(Action::parse(&v).with_context(|| format!("unknown action {v}"))?);
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other => bail!("unknown option {other}\n\n{USAGE}"),
        }
    }
    if o.auto_answer.is_some() && !o.headless {
        bail!("--auto-answer only works with --headless");
    }
    Ok(o)
}

async fn terminated() {
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

fn main() -> anyhow::Result<()> {
    let opts = parse_args()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let (hub, prompts) = Hub::new(opts.timeout);
    let listener = rt.block_on(service::bind(&opts.socket))?;
    eprintln!("snitchling: listening on {}", opts.socket.display());

    if opts.headless {
        return rt.block_on(async {
            let fixed = opts.auto_answer;
            hub::auto_answer(prompts, move |req| {
                Choice::simple(fixed.unwrap_or(req.default_action), rules::ONCE, Target::Executable)
            });
            tokio::spawn(log_changes(hub.clone()));
            service::serve(hub, listener, terminated()).await
        });
    }

    // Wayland compositors pick the window icon from the .desktop file named
    // after the app id (packaging/snitchling.desktop).
    // (needs the backend up, but no window created yet)
    slint::BackendSelector::new().select()?;
    slint::set_xdg_app_id("snitchling")?;
    gui::init(hub.clone(), rt.handle().clone(), &opts.default_duration)?;

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = rt.spawn(service::serve(hub.clone(), listener, async {
        let _ = stop_rx.await;
    }));
    rt.spawn(async move {
        let mut prompts = prompts;
        while let Some(req) = prompts.recv().await {
            gui::post(move || gui::enqueue_prompt(req));
        }
    });
    rt.spawn({
        let hub = hub.clone();
        async move {
            let mut changes = hub.changes();
            while changes.changed().await.is_ok() {
                let snap = hub.snapshot();
                gui::post(move || gui::refresh(snap));
            }
        }
    });
    rt.spawn(log_changes(hub.clone()));
    rt.spawn(tray::run(hub.clone(), rt.handle().clone()));
    rt.spawn(async {
        terminated().await;
        let _ = slint::quit_event_loop();
    });

    if opts.show_rules {
        gui::show_rules();
    }
    slint::run_event_loop_until_quit()?;

    let _ = stop_tx.send(());
    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    });
    Ok(())
}

/// One line per connect/disconnect, for the journal.
async fn log_changes(hub: Arc<Hub>) {
    let mut changes = hub.changes();
    let mut was = false;
    while changes.changed().await.is_ok() {
        let s = hub.snapshot();
        if s.connected != was {
            if s.connected {
                eprintln!(
                    "snitchling: daemon connected, {} rules, interception {}",
                    s.rules.len(),
                    if s.interception { "on" } else { "off" }
                );
            } else {
                eprintln!("snitchling: daemon disconnected");
            }
            was = s.connected;
        }
    }
}
