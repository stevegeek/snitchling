//! StatusNotifierItem tray icon (KDE, and anything else speaking SNI).

use std::sync::Arc;

use ksni::menu::{CheckmarkItem, StandardItem};
use ksni::{MenuItem, ToolTip, Tray, TrayMethods};
use tokio::runtime::Handle;

use snitchling::hub::{Hub, Snapshot};

use crate::gui;

pub struct SnitchTray {
    hub: Arc<Hub>,
    rt: Handle,
    connected: bool,
    interception: bool,
    status: String,
}

impl SnitchTray {
    fn apply(&mut self, s: &Snapshot) {
        self.connected = s.connected;
        self.interception = s.interception;
        self.status = if !s.connected {
            "Daemon not connected".into()
        } else if s.interception {
            format!("Protecting · {} rules", s.rules.len())
        } else {
            "Interception disabled".into()
        };
    }
}

impl Tray for SnitchTray {
    fn id(&self) -> String {
        "snitchling".into()
    }

    fn title(&self) -> String {
        "snitchling".into()
    }

    fn icon_name(&self) -> String {
        match (self.connected, self.interception) {
            (true, true) => "security-high",
            (true, false) => "security-low",
            (false, _) => "security-medium",
        }
        .into()
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            title: "snitchling".into(),
            description: self.status.clone(),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        gui::post(gui::show_rules);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: self.status.clone(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "Interception enabled".into(),
                enabled: self.connected,
                checked: self.interception,
                activate: Box::new(|t: &mut Self| {
                    let hub = t.hub.clone();
                    let on = !t.interception;
                    t.rt.spawn(async move {
                        if let Err(e) = hub.set_interception(on).await {
                            eprintln!("snitchling: toggling interception: {e:#}");
                        }
                    });
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Rules…".into(),
                icon_name: "view-list-details".into(),
                activate: Box::new(|_: &mut Self| gui::post(gui::show_rules)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_: &mut Self| {
                    let _ = slint::quit_event_loop();
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Shows the tray icon and keeps it in sync with the hub.
pub async fn run(hub: Arc<Hub>, rt: Handle) {
    let mut tray = SnitchTray {
        hub: hub.clone(),
        rt,
        connected: false,
        interception: false,
        status: String::new(),
    };
    tray.apply(&hub.snapshot());
    let handle = match tray.spawn().await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("snitchling: no tray icon ({e}); use --show-rules to manage rules");
            return;
        }
    };
    let mut changes = hub.changes();
    while changes.changed().await.is_ok() {
        let s = hub.snapshot();
        if handle.update(|t| t.apply(&s)).await.is_none() {
            break;
        }
    }
}
