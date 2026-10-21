# snitchling

A small, fast replacement for the OpenSnitch **UI**. The OpenSnitch daemon
(`opensnitchd`) keeps doing the actual firewalling; snitchling is just what it
talks to: the connection prompt, the rules list and a tray icon.

The stock Python/Qt UI can grow to gigabytes of memory over days of uptime;
snitchling idles at ~25–35 MB.

## What it does

- **Prompt** when an unknown connection appears: process, destination, command
  line, PID/UID/cwd. Allow / Deny / Reject, matched by executable, command line,
  host, domain (`*.example.com`), IP, port or user — optionally ANDed with "this
  executable / port / user" — for once, 30s … 12h, until restart, or always.
  No answer within the timeout (default 15s) applies the daemon's
  `DefaultAction`, once, like the stock UI. Prompts queue one at a time, and
  connections an earlier answer already covers are settled without asking again.
- **Rules window**: filter, enable/disable, edit (action, duration, condition
  of single-condition rules), delete (click twice), and an interception switch.
- **Tray icon** (StatusNotifierItem): status, interception toggle, Rules…, Quit.

Rules it creates have the same shape and names as the stock UI's, so you can
switch back and forth. Not included (v1): connection log/statistics views,
system firewall editor, remote nodes.

## How it fits

OpenSnitch's UI is a gRPC **server**; the daemon dials it at the address in
`/etc/opensnitchd/default-config.json` (`unix:///tmp/osui.sock`).
snitchling implements that service (`proto/ui.proto`, from opensnitch v1.7.2):

| RPC | snitchling |
|---|---|
| `Subscribe` | records daemon version, rules, interception state; returns the config unchanged |
| `Ping` | updates stats |
| `AskRule` | shows the prompt, returns the rule (the daemon persists `always` rules itself) |
| `Notifications` | stream used to send ENABLE/DISABLE/CHANGE/DELETE_RULE and interception toggles |
| `PostAlert` | kept as recent alerts |

The daemon's Go gRPC client sends the socket path (`/tmp/osui.sock`) as the
HTTP/2 `:authority`, which the stock `h2` crate rejects with
`RST_STREAM PROTOCOL_ERROR`. `vendor/h2` is h2 0.4.20 with that one check
relaxed (search for "snitchling patch"), wired in via `[patch.crates-io]`.
Re-apply it if h2 is bumped.

Code: `src/rules.rs` (answer → rule), `src/hub.rs` (state + commands),
`src/service.rs` (gRPC server), `src/gui.rs` + `ui/app.slint` (Slint windows),
`src/tray.rs` (ksni tray).

## Build

```sh
cargo build --release      # target/release/snitchling
```

## Switch from the stock UI

Only one UI can own the socket; snitchling refuses to start while another is
listening. The daemon keeps enforcing your rules while no UI is connected
(unknown connections get its `DefaultAction`).

```sh
pkill -f opensnitch-ui
./target/release/snitchling            # add --show-rules to open the rules window
```

Back to the stock UI: quit snitchling from the tray, then run `opensnitch-ui &`.

Install for your user (binary in `~/.local/bin`, icon, menu entry):

```sh
./install.sh
```

To autostart it instead of the stock UI, disable "OpenSnitch" in System
Settings → Autostart and add snitchling:

```sh
install -Dm644 packaging/snitchling.desktop ~/.config/autostart/snitchling.desktop
```

Options: `snitchling --help`.

## Testing

```sh
cargo test                 # rule building + a fake daemon over a real unix socket
```

Try the GUI without touching the real firewall (private socket + fake daemon):

```sh
./target/release/snitchling --socket /tmp/sl-test.sock --show-rules &
cargo run --release --example fake_daemon -- /tmp/sl-test.sock --asks 2
```

Check every rule command against the real daemon (stop the running UI first;
uses a throwaway `until restart` rule that matches nothing):

```sh
cargo run --release --example live_check            # add --toggle-interception to flip it off and back on
```

## Credits

`proto/ui.proto` is OpenSnitch's UI protocol definition, copied unchanged from
[evilsocket/opensnitch](https://github.com/evilsocket/opensnitch) v1.7.2
(GPL-3.0). `vendor/h2` is the [h2](https://github.com/hyperium/h2) crate (MIT)
with the one change described above.
