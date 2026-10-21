//! Exercises every UI -> daemon command against the real opensnitchd, using a
//! throwaway "until restart" rule that matches nothing real.
//!
//! Stop the running UI first (it owns the socket), then:
//!   cargo run --example live_check [-- --toggle-interception]

use std::time::Duration;

use anyhow::{Context, bail};
use snitchling::hub::{self, Hub};
use snitchling::pb::{Operator, Rule};
use snitchling::rules::{Action, Choice, Target};
use snitchling::service;

const NAME: &str = "snitchling-selftest";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let toggle = std::env::args().any(|a| a == "--toggle-interception");
    let (hub, prompts) = Hub::new(Duration::from_secs(15));
    hub::auto_answer(prompts, |req| Choice::simple(req.default_action, "once", Target::Executable));
    let listener = service::bind(&service::daemon_socket()).await?;
    tokio::spawn(service::serve(hub.clone(), listener, std::future::pending()));

    println!("waiting for opensnitchd to connect…");
    let mut changes = hub.changes();
    tokio::time::timeout(Duration::from_secs(60), async {
        while !hub.snapshot().connected || hub.snapshot().daemon_version.is_empty() {
            changes.changed().await.ok();
        }
    })
    .await
    .context("daemon never connected")?;
    tokio::time::sleep(Duration::from_millis(500)).await; // let the Notifications stream open
    let s = hub.snapshot();
    println!("ok   connected: daemon {}, {} rules, interception {}", s.daemon_version, s.rules.len(), s.interception);

    let rule = Rule {
        created: 0,
        name: NAME.into(),
        description: "temporary rule created by snitchling's live check".into(),
        enabled: true,
        action: Action::Deny.as_str().into(),
        duration: "until restart".into(),
        operator: Some(Operator {
            r#type: "simple".into(),
            operand: "dest.host".into(),
            data: "snitchling-selftest.invalid".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    hub.change_rule(rule).await.context("CHANGE_RULE (add)")?;
    println!("ok   CHANGE_RULE added {NAME}");
    hub.set_rule_enabled(NAME, false).await.context("DISABLE_RULE")?;
    println!("ok   DISABLE_RULE");
    hub.set_rule_enabled(NAME, true).await.context("ENABLE_RULE")?;
    println!("ok   ENABLE_RULE");
    let mut edited = hub.snapshot().rules.into_iter().find(|r| r.name == NAME).context("rule vanished")?;
    edited.action = "reject".into();
    hub.change_rule(edited).await.context("CHANGE_RULE (edit)")?;
    println!("ok   CHANGE_RULE edited action -> reject");
    hub.delete_rule(NAME).await.context("DELETE_RULE")?;
    println!("ok   DELETE_RULE");
    if hub.snapshot().rules.iter().any(|r| r.name == NAME) {
        bail!("rule still listed after delete");
    }

    if toggle {
        let was = hub.snapshot().interception;
        hub.set_interception(!was).await.context("toggle interception")?;
        println!("ok   interception -> {}", !was);
        let restored = hub.set_interception(was).await;
        restored.context("RESTORING INTERCEPTION FAILED — re-enable it from the UI")?;
        println!("ok   interception -> {was} (restored)");
    }
    println!("all live checks passed");
    Ok(())
}
