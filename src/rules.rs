//! Turning a prompt answer into an OpenSnitch rule, mirroring what the stock
//! UI sends so rules made by either UI look the same on disk.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::pb::{Connection, Operator, Rule};

pub const DURATIONS: &[&str] = &[
    "once",
    "30s",
    "5m",
    "15m",
    "30m",
    "1h",
    "12h",
    "until restart",
    "always",
];

pub const ONCE: &str = "once";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Reject,
}

impl Action {
    pub const ALL: [Action; 3] = [Action::Allow, Action::Deny, Action::Reject];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Reject => "reject",
        }
    }

    pub fn parse(s: &str) -> Option<Action> {
        match s.to_ascii_lowercase().as_str() {
            "allow" | "accept" => Some(Action::Allow),
            "deny" | "drop" => Some(Action::Deny),
            "reject" => Some(Action::Reject),
            _ => None,
        }
    }
}

/// What the rule matches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Executable,
    Command,
    Host,
    Domain,
    Ip,
    Port,
    User,
}

impl Target {
    pub const ALL: [Target; 7] = [
        Target::Executable,
        Target::Command,
        Target::Host,
        Target::Domain,
        Target::Ip,
        Target::Port,
        Target::User,
    ];

    /// Targets that make sense for this connection, with a label for the prompt.
    pub fn options(conn: &Connection) -> Vec<(Target, String)> {
        Target::ALL
            .iter()
            .filter_map(|&t| {
                let label = match t {
                    Target::Executable if !conn.process_path.is_empty() => {
                        format!("this executable ({})", conn.process_path)
                    }
                    Target::Command if !conn.process_args.is_empty() => {
                        format!("this command line ({})", conn.process_args.join(" "))
                    }
                    Target::Host if !conn.dst_host.is_empty() => format!("host {}", conn.dst_host),
                    Target::Domain if !conn.dst_host.is_empty() => {
                        format!("domain *.{}", parent_domain(&conn.dst_host))
                    }
                    Target::Ip if !conn.dst_ip.is_empty() => format!("IP {}", conn.dst_ip),
                    Target::Port => format!("port {}", conn.dst_port),
                    Target::User => format!("user ID {}", conn.user_id),
                    _ => return None,
                };
                Some((t, label))
            })
            .collect()
    }
}

/// The user's answer to a prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub action: Action,
    pub duration: String,
    pub target: Target,
    /// Extra conditions ANDed onto the target.
    pub also_executable: bool,
    pub also_port: bool,
    pub also_user: bool,
}

impl Choice {
    pub fn simple(action: Action, duration: &str, target: Target) -> Choice {
        Choice {
            action,
            duration: duration.to_string(),
            target,
            also_executable: false,
            also_port: false,
            also_user: false,
        }
    }
}

/// What the daemon gets when nobody answers: the default action, once, for
/// this executable.
pub fn default_choice(default_action: Action) -> Choice {
    Choice::simple(default_action, ONCE, Target::Executable)
}

fn op(kind: &str, operand: &str, data: impl Into<String>) -> Operator {
    Operator {
        r#type: kind.to_string(),
        operand: operand.to_string(),
        data: data.into(),
        sensitive: false,
        list: vec![],
    }
}

/// "www.example.com" -> "example.com"; two-label hosts are kept as they are.
pub fn parent_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() > 2 {
        labels[1..].join(".")
    } else {
        labels.join(".")
    }
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn target_operator(target: Target, conn: &Connection) -> Option<Operator> {
    let o = match target {
        Target::Executable => op("simple", "process.path", conn.process_path.clone()),
        Target::Command => {
            if conn.process_args.is_empty() || conn.process_args[0].is_empty() {
                return target_operator(Target::Executable, conn);
            }
            op("simple", "process.command", conn.process_args.join(" "))
        }
        Target::Host => op("simple", "dest.host", conn.dst_host.clone()),
        Target::Domain => op(
            "regexp",
            "dest.host",
            format!(r"^(|.*\.){}$", regex_escape(&parent_domain(&conn.dst_host))),
        ),
        Target::Ip => op("simple", "dest.ip", conn.dst_ip.clone()),
        Target::Port => op("simple", "dest.port", conn.dst_port.to_string()),
        Target::User => op("simple", "user.id", conn.user_id.to_string()),
    };
    if o.data.is_empty() {
        // e.g. no hostname resolved: fall back to something that exists
        return match target {
            Target::Host | Target::Domain => target_operator(Target::Ip, conn),
            Target::Executable => None,
            _ => target_operator(Target::Executable, conn),
        };
    }
    Some(o)
}

/// Lowercase, with runs of anything that isn't [a-z0-9] collapsed to '-'.
pub fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds the rule for an answer. `exists` says whether a rule name is taken,
/// so the new rule doesn't overwrite an unrelated one.
pub fn build_rule(conn: &Connection, choice: &Choice, exists: impl Fn(&str) -> bool) -> Option<Rule> {
    let primary = target_operator(choice.target, conn)?;
    let mut conds = vec![primary.clone()];
    let mut name_extra = vec![];

    let mut add = |o: Option<Operator>| {
        if let Some(o) = o
            && !conds.iter().any(|c| c.operand == o.operand)
        {
            name_extra.push(o.data.clone());
            conds.push(o);
        }
    };
    if choice.also_executable {
        add(target_operator(Target::Executable, conn));
    }
    if choice.also_port {
        add(target_operator(Target::Port, conn));
    }
    if choice.also_user {
        add(target_operator(Target::User, conn));
    }
    // A command line that doesn't start with an absolute path (or runs from
    // /proc/self/fd) can be faked, so pin it to the binary too.
    if primary.operand == "process.command" {
        let first = conn.process_args.first().map(String::as_str).unwrap_or("");
        if !first.starts_with('/') || first.starts_with("/proc") {
            add(target_operator(Target::Executable, conn));
        }
    }

    let is_list = conds.len() > 1;
    let kind = if is_list { "list" } else { "simple" };
    let mut name = slugify(&format!(
        "{} {} {} {}",
        choice.action.as_str(),
        choice.duration,
        kind,
        primary.data
    ));
    for extra in &name_extra {
        name = slugify(&format!("{name} {extra}"));
    }
    name.truncate(128);
    let name = unique_name(&name, exists);

    let operator = if is_list {
        let json: Vec<serde_json::Value> = conds
            .iter()
            .map(|c| serde_json::json!({"type": c.r#type, "operand": c.operand, "data": c.data}))
            .collect();
        Operator {
            r#type: "list".into(),
            operand: "list".into(),
            data: serde_json::Value::Array(json).to_string(),
            sensitive: false,
            list: conds,
        }
    } else {
        primary
    };

    Some(Rule {
        created: now_secs(),
        name,
        description: String::new(),
        enabled: true,
        precedence: false,
        nolog: false,
        action: choice.action.as_str().to_string(),
        duration: choice.duration.clone(),
        operator: Some(operator),
    })
}

pub fn unique_name(base: &str, exists: impl Fn(&str) -> bool) -> String {
    if !exists(base) {
        return base.to_string();
    }
    (1..)
        .map(|i| format!("{base}-{i}"))
        .find(|n| !exists(n))
        .expect("unbounded range")
}

/// Whether a rule we created would match this connection. Only understands
/// the operators snitchling itself generates; anything else is "no".
pub fn matches(rule: &Rule, conn: &Connection) -> bool {
    rule.enabled && rule.operator.as_ref().is_some_and(|o| op_matches(o, conn))
}

fn op_matches(o: &Operator, conn: &Connection) -> bool {
    match o.r#type.as_str() {
        "list" => !o.list.is_empty() && o.list.iter().all(|c| op_matches(c, conn)),
        "simple" => {
            let value = match o.operand.as_str() {
                "process.path" => conn.process_path.clone(),
                "process.command" => conn.process_args.join(" "),
                "dest.host" => conn.dst_host.clone(),
                "dest.ip" => conn.dst_ip.clone(),
                "dest.port" => conn.dst_port.to_string(),
                "user.id" => conn.user_id.to_string(),
                _ => return false,
            };
            if o.sensitive {
                value == o.data
            } else {
                value.eq_ignore_ascii_case(&o.data)
            }
        }
        "regexp" if o.operand == "dest.host" => {
            // only the ^(|.*\.)domain$ form built above
            let Some(domain) = o.data.strip_prefix(r"^(|.*\.)").and_then(|d| d.strip_suffix('$')) else {
                return false;
            };
            let domain = domain.replace('\\', "").to_ascii_lowercase();
            let host = conn.dst_host.to_ascii_lowercase();
            host == domain || host.ends_with(&format!(".{domain}"))
        }
        _ => false,
    }
}

/// One-line description of a rule's condition for the rules list.
pub fn describe(o: Option<&Operator>) -> String {
    let Some(o) = o else { return String::new() };
    match o.r#type.as_str() {
        "list" if !o.list.is_empty() => o
            .list
            .iter()
            .map(|c| describe(Some(c)))
            .collect::<Vec<_>>()
            .join("  AND  "),
        "regexp" => format!("{} ~ {}", o.operand, o.data),
        "network" => format!("{} in {}", o.operand, o.data),
        "lists" => format!("{} from {}", o.operand, o.data),
        _ => format!("{} = {}", o.operand, o.data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn curl() -> Connection {
        Connection {
            protocol: "tcp".into(),
            dst_ip: "93.184.215.14".into(),
            dst_host: "www.example.com".into(),
            dst_port: 443,
            user_id: 1000,
            process_id: 4242,
            process_path: "/usr/bin/curl".into(),
            process_args: vec!["curl".into(), "https://www.example.com".into()],
            ..Default::default()
        }
    }

    fn none(_: &str) -> bool {
        false
    }

    #[test]
    fn executable_rule_matches_stock_ui_shape() {
        let r = build_rule(&curl(), &Choice::simple(Action::Allow, "always", Target::Executable), none).unwrap();
        assert_eq!(r.name, "allow-always-simple-usr-bin-curl");
        assert_eq!(r.action, "allow");
        assert_eq!(r.duration, "always");
        assert!(r.enabled);
        let o = r.operator.unwrap();
        assert_eq!((o.r#type.as_str(), o.operand.as_str(), o.data.as_str()), ("simple", "process.path", "/usr/bin/curl"));
    }

    #[test]
    fn domain_rule_is_a_suffix_regexp() {
        let r = build_rule(&curl(), &Choice::simple(Action::Deny, "1h", Target::Domain), none).unwrap();
        let o = r.operator.as_ref().unwrap();
        assert_eq!(o.r#type, "regexp");
        assert_eq!(o.operand, "dest.host");
        assert_eq!(o.data, r"^(|.*\.)example\.com$");
        assert!(matches(&r, &curl()));
        let mut other = curl();
        other.dst_host = "api.example.com".into();
        assert!(matches(&r, &other));
        other.dst_host = "notexample.com".into();
        assert!(!matches(&r, &other));
    }

    #[test]
    fn extra_conditions_make_a_list_rule() {
        let mut c = Choice::simple(Action::Allow, "until restart", Target::Host);
        c.also_executable = true;
        c.also_port = true;
        let r = build_rule(&curl(), &c, none).unwrap();
        let o = r.operator.as_ref().unwrap();
        assert_eq!((o.r#type.as_str(), o.operand.as_str()), ("list", "list"));
        let operands: Vec<_> = o.list.iter().map(|c| c.operand.as_str()).collect();
        assert_eq!(operands, ["dest.host", "process.path", "dest.port"]);
        let json: serde_json::Value = serde_json::from_str(&o.data).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 3);
        assert_eq!(json[2]["data"], "443");
        assert_eq!(r.name, "allow-until-restart-list-www-example-com-usr-bin-curl-443");
        assert!(matches(&r, &curl()));
        let mut wget = curl();
        wget.process_path = "/usr/bin/wget".into();
        assert!(!matches(&r, &wget));
    }

    #[test]
    fn extra_condition_equal_to_target_is_not_duplicated() {
        let mut c = Choice::simple(Action::Allow, "once", Target::Port);
        c.also_port = true;
        let r = build_rule(&curl(), &c, none).unwrap();
        assert_eq!(r.operator.unwrap().r#type, "simple");
    }

    #[test]
    fn relative_command_line_is_pinned_to_the_binary() {
        let r = build_rule(&curl(), &Choice::simple(Action::Allow, "always", Target::Command), none).unwrap();
        let o = r.operator.unwrap();
        assert_eq!(o.r#type, "list");
        assert_eq!(o.list[0].data, "curl https://www.example.com");
        assert_eq!(o.list[1].operand, "process.path");
    }

    #[test]
    fn missing_host_falls_back_to_ip() {
        let mut conn = curl();
        conn.dst_host.clear();
        let r = build_rule(&conn, &Choice::simple(Action::Deny, "once", Target::Host), none).unwrap();
        let o = r.operator.unwrap();
        assert_eq!((o.operand.as_str(), o.data.as_str()), ("dest.ip", "93.184.215.14"));
        assert!(!Target::options(&conn).iter().any(|(t, _)| *t == Target::Host));
    }

    #[test]
    fn names_are_made_unique() {
        let taken = ["allow-always-simple-usr-bin-curl", "allow-always-simple-usr-bin-curl-1"];
        let r = build_rule(&curl(), &Choice::simple(Action::Allow, "always", Target::Executable), |n| taken.contains(&n)).unwrap();
        assert_eq!(r.name, "allow-always-simple-usr-bin-curl-2");
    }

    #[test]
    fn default_choice_is_once_for_the_executable() {
        let r = build_rule(&curl(), &default_choice(Action::Deny), none).unwrap();
        assert_eq!((r.action.as_str(), r.duration.as_str()), ("deny", "once"));
        assert_eq!(r.operator.unwrap().operand, "process.path");
    }

    #[test]
    fn slugify_and_parent_domain() {
        assert_eq!(slugify("Allow 30m  /usr/bin/Foo_bar"), "allow-30m-usr-bin-foo-bar");
        assert_eq!(parent_domain("a.b.example.com"), "b.example.com");
        assert_eq!(parent_domain("example.com"), "example.com");
    }

    #[test]
    fn describe_list() {
        let mut c = Choice::simple(Action::Allow, "once", Target::Host);
        c.also_port = true;
        let r = build_rule(&curl(), &c, none).unwrap();
        assert_eq!(describe(r.operator.as_ref()), "dest.host = www.example.com  AND  dest.port = 443");
    }
}
