//! Shared state between the gRPC service (daemon side) and the GUI/tray.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use tokio::sync::{mpsc, oneshot, watch};
use tonic::Status;

use crate::pb::{self, ClientConfig, Connection, Notification, NotificationReply, NotificationReplyCode, Rule};
use crate::rules::{self, Action, Choice};

/// How long to wait for the daemon to answer a notification.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ALERTS: usize = 50;

/// A connection waiting for the user's decision.
pub struct PromptRequest {
    pub conn: Connection,
    pub default_action: Action,
    pub timeout: Duration,
    pub reply: oneshot::Sender<Choice>,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub connected: bool,
    pub daemon_version: String,
    pub interception: bool,
    pub default_action: Option<Action>,
    pub rules: Vec<Rule>,
    pub connections: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub alerts: Vec<String>,
}

type Outbox = mpsc::Sender<Result<Notification, Status>>;

#[derive(Default)]
struct Inner {
    snap: Snapshot,
    outbox: Option<(u64, Outbox)>,
    pending: HashMap<u64, oneshot::Sender<NotificationReply>>,
    /// Rules answered in this session, used to settle queued prompts that the
    /// latest answer already covers.
    answered: Vec<Rule>,
}

pub struct Hub {
    inner: Mutex<Inner>,
    changed: watch::Sender<u64>,
    prompts: mpsc::Sender<PromptRequest>,
    prompt_timeout: Duration,
    /// One prompt at a time, like the stock UI.
    ask_lock: tokio::sync::Mutex<()>,
    /// Asks in flight, including the one on screen.
    asking: AtomicUsize,
    ids: AtomicU64,
}

impl Hub {
    pub fn new(prompt_timeout: Duration) -> (Arc<Hub>, mpsc::Receiver<PromptRequest>) {
        let (tx, rx) = mpsc::channel(64);
        let hub = Hub {
            inner: Mutex::default(),
            changed: watch::Sender::new(0),
            prompts: tx,
            prompt_timeout,
            ask_lock: tokio::sync::Mutex::new(()),
            asking: AtomicUsize::new(0),
            ids: AtomicU64::new(1),
        };
        (Arc::new(hub), rx)
    }

    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.inner.lock().unwrap().snap.clone()
    }

    fn update<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let r = f(&mut self.inner.lock().unwrap());
        self.changed.send_modify(|g| *g += 1);
        r
    }

    // ---- daemon -> UI ----

    pub fn on_subscribe(&self, cfg: &ClientConfig) {
        let default_action = serde_json::from_str::<serde_json::Value>(&cfg.config)
            .ok()
            .and_then(|v| v.get("DefaultAction")?.as_str().and_then(Action::parse));
        self.update(|i| {
            let s = &mut i.snap;
            s.connected = true;
            // cfg.version is the daemon's kernel version; the daemon's own
            // version arrives with the first Ping.
            s.interception = cfg.is_firewall_running;
            s.default_action = default_action;
            s.rules = cfg.rules.clone();
            s.rules.sort_by(|a, b| a.name.cmp(&b.name));
        });
    }

    pub fn on_ping(&self, stats: Option<&pb::Statistics>) {
        let Some(st) = stats else { return };
        let mut inner = self.inner.lock().unwrap();
        let s = &mut inner.snap;
        let changed = (s.connections, s.accepted, s.dropped) != (st.connections, st.accepted, st.dropped)
            || s.daemon_version != st.daemon_version;
        s.connections = st.connections;
        s.accepted = st.accepted;
        s.dropped = st.dropped;
        s.daemon_version.clone_from(&st.daemon_version);
        drop(inner);
        if changed {
            self.changed.send_modify(|g| *g += 1);
        }
    }

    pub fn on_alert(&self, alert: &pb::Alert) {
        let text = match &alert.data {
            Some(pb::alert::Data::Text(t)) => t.clone(),
            Some(other) => format!("{other:?}"),
            None => return,
        };
        self.update(|i| {
            let a = &mut i.snap.alerts;
            a.push(text);
            if a.len() > MAX_ALERTS {
                a.remove(0);
            }
        });
    }

    /// A Notifications stream opened; returns its generation for `detach`.
    pub fn attach(&self, outbox: Outbox) -> u64 {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        self.update(|i| {
            i.outbox = Some((id, outbox));
            i.snap.connected = true;
        });
        id
    }

    pub fn detach(&self, generation: u64) {
        self.update(|i| {
            if i.outbox.as_ref().is_some_and(|(g, _)| *g == generation) {
                i.outbox = None;
                i.pending.clear();
                i.snap.connected = false;
            }
        });
    }

    pub fn on_reply(&self, reply: NotificationReply) {
        if let Some(tx) = self.inner.lock().unwrap().pending.remove(&reply.id) {
            let _ = tx.send(reply);
        }
    }

    /// AskRule: hand the connection to the prompter and turn the answer into
    /// a rule. Always returns a rule; no answer means the default action, once.
    /// Connections queued behind the prompt currently on screen.
    pub fn waiting(&self) -> usize {
        self.asking.load(Ordering::Relaxed).saturating_sub(1)
    }

    pub async fn ask(&self, conn: Connection) -> Rule {
        // A guard, because the daemon may hang up and drop this future mid-ask.
        struct Asking<'a>(&'a AtomicUsize);
        impl Drop for Asking<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.asking.fetch_add(1, Ordering::Relaxed);
        let _asking = Asking(&self.asking);
        self.ask_one(conn).await
    }

    async fn ask_one(&self, conn: Connection) -> Rule {
        let _turn = self.ask_lock.lock().await;
        let default_action = self.snapshot().default_action.unwrap_or(Action::Allow);

        // An answer given while this one was queued may already cover it.
        let covered = self
            .inner
            .lock()
            .unwrap()
            .answered
            .iter()
            .rev()
            .find(|r| rules::matches(r, &conn))
            .cloned();
        if let Some(rule) = covered {
            return rule;
        }

        let (tx, rx) = oneshot::channel();
        let req = PromptRequest {
            conn: conn.clone(),
            default_action,
            timeout: self.prompt_timeout,
            reply: tx,
        };
        // The prompter owns the countdown; the margin is only a safety net.
        let choice = match self.prompts.send(req).await {
            Ok(()) => tokio::time::timeout(self.prompt_timeout + Duration::from_secs(3), rx)
                .await
                .ok()
                .and_then(Result::ok),
            Err(_) => None,
        }
        .unwrap_or_else(|| rules::default_choice(default_action));

        self.answer(&conn, &choice)
    }

    fn answer(&self, conn: &Connection, choice: &Choice) -> Rule {
        let mut inner = self.inner.lock().unwrap();
        let rule = {
            let snap = &inner.snap;
            let exists = |n: &str| snap.rules.iter().any(|r| r.name == n);
            rules::build_rule(conn, choice, exists)
        }
        .or_else(|| {
            // no executable path and no fallback: still answer the daemon
            rules::build_rule(conn, &Choice::simple(choice.action, rules::ONCE, rules::Target::Ip), |_| false)
        })
        .unwrap_or_else(|| Rule {
            name: "snitchling-default".into(),
            action: choice.action.as_str().into(),
            duration: rules::ONCE.into(),
            enabled: true,
            ..Default::default()
        });

        if rule.duration != rules::ONCE {
            // the daemon adds non-once rules itself; mirror that locally
            inner.snap.rules.push(rule.clone());
            inner.snap.rules.sort_by(|a, b| a.name.cmp(&b.name));
            inner.answered.push(rule.clone());
        }
        drop(inner);
        self.changed.send_modify(|g| *g += 1);
        rule
    }

    // ---- UI -> daemon ----

    async fn notify(&self, kind: pb::Action, rules: Vec<Rule>) -> anyhow::Result<()> {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        let outbox = {
            let mut inner = self.inner.lock().unwrap();
            let (_, outbox) = inner.outbox.clone().ok_or_else(|| anyhow!("daemon not connected"))?;
            inner.pending.insert(id, tx);
            outbox
        };
        let noti = Notification {
            id,
            r#type: kind as i32,
            rules,
            ..Default::default()
        };
        outbox.send(Ok(noti)).await.map_err(|_| anyhow!("daemon disconnected"))?;
        let reply = tokio::time::timeout(REPLY_TIMEOUT, rx)
            .await
            .context("daemon did not reply")?
            .map_err(|_| anyhow!("daemon disconnected"))?;
        if reply.code == NotificationReplyCode::Error as i32 {
            bail!("daemon refused: {}", reply.data);
        }
        Ok(())
    }

    fn rule(&self, name: &str) -> anyhow::Result<Rule> {
        let inner = self.inner.lock().unwrap();
        inner
            .snap
            .rules
            .iter()
            .find(|r| r.name == name)
            .cloned()
            .ok_or_else(|| anyhow!("no rule named {name}"))
    }

    fn store_rule(&self, rule: Rule) {
        self.update(|i| {
            let rules = &mut i.snap.rules;
            match rules.iter_mut().find(|r| r.name == rule.name) {
                Some(r) => *r = rule,
                None => {
                    rules.push(rule);
                    rules.sort_by(|a, b| a.name.cmp(&b.name));
                }
            }
        });
    }

    pub async fn set_rule_enabled(&self, name: &str, enabled: bool) -> anyhow::Result<()> {
        let mut rule = self.rule(name)?;
        rule.enabled = enabled;
        let kind = if enabled { pb::Action::EnableRule } else { pb::Action::DisableRule };
        self.notify(kind, vec![rule.clone()]).await?;
        self.store_rule(rule);
        Ok(())
    }

    /// Adds or replaces a rule (matched by name).
    pub async fn change_rule(&self, rule: Rule) -> anyhow::Result<()> {
        if rule.name.is_empty() {
            bail!("rule needs a name");
        }
        self.notify(pb::Action::ChangeRule, vec![rule.clone()]).await?;
        self.store_rule(rule);
        Ok(())
    }

    pub async fn delete_rule(&self, name: &str) -> anyhow::Result<()> {
        let rule = self.rule(name)?;
        self.notify(pb::Action::DeleteRule, vec![rule]).await?;
        self.update(|i| {
            i.snap.rules.retain(|r| r.name != name);
            i.answered.retain(|r| r.name != name);
        });
        Ok(())
    }

    pub async fn set_interception(&self, on: bool) -> anyhow::Result<()> {
        let kind = if on { pb::Action::EnableInterception } else { pb::Action::DisableInterception };
        self.notify(kind, vec![]).await?;
        self.update(|i| i.snap.interception = on);
        Ok(())
    }
}

/// Lets tests and headless mode answer prompts without a GUI.
pub fn auto_answer(mut rx: mpsc::Receiver<PromptRequest>, answer: impl Fn(&PromptRequest) -> Choice + Send + 'static) {
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let choice = answer(&req);
            let _ = req.reply.send(choice);
        }
    });
}
