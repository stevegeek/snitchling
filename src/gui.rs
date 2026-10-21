//! Slint windows. Everything here runs on the GUI (main) thread; other
//! threads reach it through `post`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use tokio::runtime::Handle;

use snitchling::hub::{Hub, PromptRequest, Snapshot};
use snitchling::pb::{Operator, Rule};
use snitchling::rules::{self, Action, Choice, DURATIONS, Target};

slint::include_modules!();

const OP_TYPES: &[&str] = &["simple", "regexp", "network", "lists"];
const OPERANDS: &[&str] = &[
    "process.path",
    "process.command",
    "process.id",
    "dest.host",
    "dest.ip",
    "dest.port",
    "dest.network",
    "user.id",
    "protocol",
    "iface.out",
];

struct Current {
    reply: tokio::sync::oneshot::Sender<Choice>,
    targets: Vec<Target>,
    default_action: Action,
    deadline: Instant,
    timer: slint::Timer,
}

struct Edit {
    rule: Rule,
    operands: Vec<String>,
}

struct Gui {
    hub: Arc<Hub>,
    rt: Handle,
    default_duration: usize,
    prompt: PromptWindow,
    queue: VecDeque<PromptRequest>,
    current: Option<Current>,
    rules: Option<RulesWindow>,
    snap: Snapshot,
    edit: Option<Edit>,
}

thread_local! {
    static GUI: RefCell<Option<Gui>> = const { RefCell::new(None) };
}

fn with_gui<R>(f: impl FnOnce(&mut Gui) -> R) -> Option<R> {
    GUI.with(|g| g.borrow_mut().as_mut().map(f))
}

/// Runs `f` on the GUI thread.
pub fn post(f: impl FnOnce() + Send + 'static) {
    if let Err(e) = slint::invoke_from_event_loop(f) {
        eprintln!("snitchling: GUI is gone: {e}");
    }
}

fn strings(items: impl IntoIterator<Item = impl Into<SharedString>>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(items.into_iter().map(Into::into).collect::<Vec<_>>()))
}

pub fn init(hub: Arc<Hub>, rt: Handle, default_duration: &str) -> anyhow::Result<()> {
    // Creating the prompt window up front also initialises the Slint backend,
    // which `invoke_from_event_loop` needs. It stays hidden until asked.
    let prompt = PromptWindow::new()?;
    prompt.set_durations(strings(DURATIONS.iter().copied()));
    prompt.on_decide(|action| {
        let action = Action::parse(&action).unwrap_or(Action::Deny);
        with_gui(|g| g.decide(action));
    });
    prompt.window().on_close_requested(|| {
        with_gui(|g| g.expire());
        slint::CloseRequestResponse::HideWindow
    });
    let default_duration = DURATIONS.iter().position(|d| *d == default_duration).unwrap_or(7);
    GUI.with(|g| {
        *g.borrow_mut() = Some(Gui {
            snap: hub.snapshot(),
            hub,
            rt,
            default_duration,
            prompt,
            queue: VecDeque::new(),
            current: None,
            rules: None,
            edit: None,
        })
    });
    Ok(())
}

pub fn enqueue_prompt(req: PromptRequest) {
    with_gui(|g| {
        g.queue.push_back(req);
        if g.current.is_none() {
            g.show_next();
        } else {
            g.tick();
        }
    });
}

pub fn refresh(snap: Snapshot) {
    with_gui(|g| {
        g.snap = snap;
        g.refresh_rules();
    });
}

pub fn show_rules() {
    with_gui(|g| {
        if let Err(e) = g.open_rules() {
            eprintln!("snitchling: opening rules window: {e}");
        }
    });
}

fn app_name(path: &str) -> String {
    path.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("Unknown process").to_string()
}

impl Gui {
    // ---- prompt ----

    fn show_next(&mut self) {
        while let Some(req) = self.queue.pop_front() {
            if req.reply.is_closed() {
                continue; // the daemon side already gave up on it
            }
            let c = &req.conn;
            let options = Target::options(c);
            let dest = if c.dst_host.is_empty() {
                c.dst_ip.clone()
            } else {
                format!("{} ({})", c.dst_host, c.dst_ip)
            };
            let p = &self.prompt;
            p.set_app_name(app_name(&c.process_path).into());
            p.set_summary(
                format!("wants to connect to {dest} on {} port {}", c.protocol.to_uppercase(), c.dst_port).into(),
            );
            p.set_exe(c.process_path.clone().into());
            p.set_cmdline(c.process_args.join(" ").into());
            p.set_details(format!("PID {} · UID {} · {}", c.process_id, c.user_id, c.process_cwd).into());
            p.set_targets(strings(options.iter().map(|(_, l)| l.as_str())));
            p.set_target_index(0);
            p.set_duration_index(self.default_duration as i32);
            p.set_also_exe(false);
            p.set_also_port(false);
            p.set_also_user(false);

            let timer = slint::Timer::default();
            timer.start(slint::TimerMode::Repeated, Duration::from_millis(250), || {
                with_gui(|g| g.tick());
            });
            self.current = Some(Current {
                reply: req.reply,
                targets: options.into_iter().map(|(t, _)| t).collect(),
                default_action: req.default_action,
                deadline: Instant::now() + req.timeout,
                timer,
            });
            self.tick();
            if let Err(e) = self.prompt.show() {
                eprintln!("snitchling: showing prompt: {e}");
            }
            return;
        }
        let _ = self.prompt.hide();
    }

    fn tick(&mut self) {
        let Some(cur) = &self.current else { return };
        if cur.reply.is_closed() {
            // the daemon stopped waiting for this one
            if let Some(cur) = self.current.take() {
                cur.timer.stop();
            }
            self.show_next();
            return;
        }
        let left = cur.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            self.expire();
            return;
        }
        let mut text = format!("{} automatically in {}s", cur.default_action.as_str(), left.as_secs() + 1);
        let waiting = self.queue.len() + self.hub.waiting();
        if waiting > 0 {
            text += &format!(" · {waiting} more waiting");
        }
        self.prompt.set_countdown(text.into());
    }

    fn decide(&mut self, action: Action) {
        let Some(cur) = &self.current else { return };
        let p = &self.prompt;
        let target = usize::try_from(p.get_target_index())
            .ok()
            .and_then(|i| cur.targets.get(i).copied())
            .unwrap_or(Target::Executable);
        let duration = usize::try_from(p.get_duration_index())
            .ok()
            .and_then(|i| DURATIONS.get(i))
            .unwrap_or(&rules::ONCE);
        let choice = Choice {
            action,
            duration: duration.to_string(),
            target,
            also_executable: p.get_also_exe(),
            also_port: p.get_also_port(),
            also_user: p.get_also_user(),
        };
        self.finish(choice);
    }

    /// Nobody answered: apply the default action, once.
    fn expire(&mut self) {
        let Some(cur) = &self.current else { return };
        let choice = rules::default_choice(cur.default_action);
        self.finish(choice);
    }

    fn finish(&mut self, choice: Choice) {
        if let Some(cur) = self.current.take() {
            cur.timer.stop();
            let _ = cur.reply.send(choice);
        }
        self.show_next();
    }

    // ---- rules window ----

    fn open_rules(&mut self) -> anyhow::Result<()> {
        if let Some(w) = &self.rules {
            return Ok(w.show()?);
        }
        let w = RulesWindow::new()?;
        w.set_actions(strings(Action::ALL.iter().map(|a| a.as_str())));
        w.set_durations(strings(DURATIONS.iter().copied()));
        w.set_op_types(strings(OP_TYPES.iter().copied()));

        w.on_filter_edited(|_| {
            with_gui(|g| g.refresh_rules());
        });
        w.on_set_interception(|on| {
            with_gui(|g| {
                let hub = g.hub.clone();
                let what = if on { "Enable interception" } else { "Disable interception" };
                g.run(what, async move { hub.set_interception(on).await });
            });
        });
        w.on_set_enabled(|name, on| {
            with_gui(|g| {
                let hub = g.hub.clone();
                let what = format!("{} {name}", if on { "Enable" } else { "Disable" });
                g.run(&what, async move { hub.set_rule_enabled(&name, on).await });
            });
        });
        w.on_delete(|name| {
            with_gui(|g| {
                let hub = g.hub.clone();
                g.run(&format!("Delete {name}"), async move { hub.delete_rule(&name).await });
            });
        });
        w.on_edit(|name| {
            with_gui(|g| g.start_edit(&name));
        });
        w.on_save_edit(|| {
            with_gui(|g| g.save_edit());
        });
        w.window().on_close_requested(|| {
            // drop the window (and its buffers) once it's hidden
            slint::Timer::single_shot(Duration::ZERO, || {
                with_gui(|g| {
                    g.rules = None;
                    g.edit = None;
                });
            });
            slint::CloseRequestResponse::HideWindow
        });
        self.rules = Some(w);
        self.refresh_rules();
        self.rules.as_ref().unwrap().show()?;
        Ok(())
    }

    fn refresh_rules(&mut self) {
        let Some(w) = &self.rules else { return };
        let s = &self.snap;
        let status = if s.connected {
            format!(
                "opensnitchd {} · {} rules · {} connections, {} dropped",
                s.daemon_version,
                s.rules.len(),
                s.connections,
                s.dropped
            )
        } else {
            "Waiting for the daemon to connect…".to_string()
        };
        w.set_status(status.into());
        w.set_connected(s.connected);
        w.set_interception(s.interception);

        let filter = w.get_filter().to_lowercase();
        let rows: Vec<RuleRow> = s
            .rules
            .iter()
            .map(|r| (r, rules::describe(r.operator.as_ref())))
            .filter(|(r, cond)| {
                filter.is_empty()
                    || r.name.to_lowercase().contains(&filter)
                    || r.action.contains(&filter)
                    || cond.to_lowercase().contains(&filter)
            })
            .map(|(r, cond)| RuleRow {
                name: r.name.clone().into(),
                action: r.action.clone().into(),
                duration: r.duration.clone().into(),
                condition: cond.into(),
                enabled: r.enabled,
            })
            .collect();
        w.set_rules(ModelRc::from(Rc::new(VecModel::from(rows))));
    }

    fn set_message(&self, msg: String) {
        if let Some(w) = &self.rules {
            w.set_message(msg.into());
        }
    }

    /// Runs a daemon command off the GUI thread and reports how it went.
    fn run(&self, what: &str, fut: impl Future<Output = anyhow::Result<()>> + Send + 'static) {
        let what = what.to_string();
        self.set_message(format!("{what}…"));
        self.rt.spawn(async move {
            let msg = match fut.await {
                Ok(()) => format!("{what}: done"),
                Err(e) => format!("{what} failed: {e:#}"),
            };
            post(move || {
                with_gui(|g| {
                    g.set_message(msg);
                    // re-sync widgets (e.g. a switch flipped on a failed command)
                    g.snap = g.hub.snapshot();
                    g.refresh_rules();
                    if let Some(w) = &g.rules {
                        w.set_pending_delete(SharedString::new());
                    }
                });
            });
        });
    }

    fn start_edit(&mut self, name: &str) {
        let Some(w) = &self.rules else { return };
        let Some(rule) = self.snap.rules.iter().find(|r| r.name == name).cloned() else { return };
        let op = rule.operator.clone().unwrap_or_default();
        let mut operands: Vec<String> = OPERANDS.iter().map(|s| s.to_string()).collect();
        if !op.operand.is_empty() && !operands.contains(&op.operand) {
            operands.push(op.operand.clone());
        }
        let idx = |list: &[&str], v: &str| list.iter().position(|x| *x == v).unwrap_or(0) as i32;
        w.set_edit_name(rule.name.clone().into());
        w.set_edit_is_list(op.r#type == "list");
        w.set_edit_condition(rules::describe(Some(&op)).into());
        w.set_edit_action(idx(&Action::ALL.map(|a| a.as_str()), &rule.action));
        w.set_edit_duration(idx(DURATIONS, &rule.duration));
        w.set_edit_type(idx(OP_TYPES, &op.r#type));
        w.set_edit_operand(operands.iter().position(|o| *o == op.operand).unwrap_or(0) as i32);
        w.set_operands(strings(operands.iter().map(String::as_str)));
        w.set_edit_data(op.data.clone().into());
        w.set_editing(true);
        self.edit = Some(Edit { rule, operands });
    }

    fn save_edit(&mut self) {
        let (Some(w), Some(edit)) = (&self.rules, self.edit.take()) else { return };
        let mut rule = edit.rule;
        let pick = |list: &[&str], i: i32| list.get(i as usize).map(|s| s.to_string());
        if let Some(a) = Action::ALL.get(w.get_edit_action() as usize) {
            rule.action = a.as_str().into();
        }
        if let Some(d) = pick(DURATIONS, w.get_edit_duration()) {
            rule.duration = d;
        }
        let is_list = rule.operator.as_ref().is_some_and(|o| o.r#type == "list");
        if !is_list {
            let data = w.get_edit_data().to_string();
            if data.trim().is_empty() {
                self.set_message("A rule needs something to match on".into());
                self.edit = Some(Edit { rule, operands: edit.operands });
                return;
            }
            let op = rule.operator.get_or_insert_with(Operator::default);
            if let Some(t) = pick(OP_TYPES, w.get_edit_type()) {
                op.r#type = t;
            }
            if let Some(o) = edit.operands.get(w.get_edit_operand() as usize) {
                op.operand = o.clone();
            }
            op.data = data;
        }
        w.set_editing(false);
        let hub = self.hub.clone();
        let what = format!("Save {}", rule.name);
        self.run(&what, async move { hub.change_rule(rule).await });
    }
}
