# RDP11 — tiny AnyDesk-style remote desktop (prototype)

Two Python programs and one web page. No encryption yet — the whole stream is
plaintext — so only use it between machines you control until TLS is added.

```
agent.py (Windows, controlled machine)        server.py (Alpine 77.83.198.200)
  captures primary screen -> JPEG frames  --TCP:9000-->  registry + relay
  injects mouse/keyboard input            <--TCP:9000--              |
                                                                       | WebSocket
browser (viewer machine, any OS)  <---- http://77.83.198.200:8080 -----
  canvas + mouse/keyboard capture
```

Only the *controlled* machine runs software. The viewer just opens the web page.

## 1. Server (Alpine, 77.83.198.200)

```sh
apk add python3 py3-pip
mkdir -p /opt/rdp11/static
# copy server.py, server_config.json, requirements-server.txt to /opt/rdp11
# copy static/index.html to /opt/rdp11/static/
cd /opt/rdp11
pip install --break-system-packages -r requirements-server.txt
python3 server.py
```

Config lives in `server_config.json` (`password`, `http_port`, `agent_port`).
Change the password — the default is committed here and therefore public.

Open both ports to the internet (cloud firewall and/or iptables):

```sh
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
```

To keep it running across reboots/crashes, save this as `/etc/init.d/rdp11`
(adjust `command` if you used a venv), then `chmod +x /etc/init.d/rdp11`,
`rc-update add rdp11 default`, `rc-service rdp11 start`:

```sh
#!/sbin/openrc-run
name="rdp11"
description="RDP11 remote desktop relay"
supervisor=supervise-daemon
directory="/opt/rdp11"
command="/usr/bin/python3"
command_args="/opt/rdp11/server.py"
output_log="/var/log/rdp11.log"
error_log="/var/log/rdp11.log"
```

## 2. Agent (each controlled Windows machine)

Install Python 3 from python.org, then:

```bat
py -3 -m pip install -r requirements-agent.txt
py -3 agent.py 85.206.170.117
```

The server address can be given as a command-line argument (as above), with an
optional `-p/--port` to override the agent port and `--pass` to specify a custom
password for the session (e.g. `py -3 agent.py 77.83.198.200 -p 9000 --pass MySecret123`).
Without arguments the agent falls back to `agent_config.json`.

The console prints the machine's **session ID** (a stable 9-digit number derived
from the machine GUID — it survives restarts). The agent reconnects
automatically; let Windows Firewall allow it when prompted.

Ctrl+C, Ctrl+Break, and closing the console window all exit the agent
immediately — a Windows console-control handler shuts the sockets down and
terminates without waiting for timeouts.

For unattended startup, create a Task Scheduler job (Basic Task → at log on →
`py -3 C:\path\agent.py 77.83.198.200`).

## 3. Viewing

Browse to `http://77.83.198.200:8080`, enter the remote machine's session ID
and the password, click **Connect**. Mouse and keyboard work on the remote
desktop; F5/F11/F12 stay with your own browser. "Fullscreen" is in the top bar.

## Protocol notes

- Agent TCP framing: `1-byte type | 4-byte big-endian length | payload`
  (type 1 = JSON, type 2 = JPEG frame). Heartbeat ping every 15 s keeps the
  agents' NAT mappings alive and detects dead peers; the server drops agents
  that stay silent for 90 s.
- Browser WebSocket: text frames are JSON control/input messages, binary
  frames are raw JPEG.
- Session IDs are checked to belong to a registered agent, the password is
  compared constant-time, and failed viewer logins are rate-limited to 5 per
  minute per IP. One viewer at a time per machine — a second viewer takes over.

## Known limitations (by design, for now)

- **No encryption**: screen contents, keystrokes, and the password cross the
  internet in plaintext. Adding TLS (a domain + Let's Encrypt, `wss://` for
  browsers, `ssl.SSLContext` around the agent socket) is the next step — don't
  invent custom crypto, and don't point this at real client machines before
  then.
- UAC prompts and the Windows lock screen can neither be seen nor controlled
  (fixing that means installing the agent as a service, like AnyDesk does).
- Primary monitor only; no clipboard sync, no file transfer.
- Browser can't intercept reserved shortcuts (Ctrl+Alt+Del, Ctrl+T/W/N);
  IME/dead-key input is ignored.
- The Flask dev server and the in-memory registry mean: single process, single
  box, a handful of sessions. Move to gunicorn+gevent or asyncio only when it
  actually grows.
- If you later package `agent.py` into an exe with PyInstaller, expect
  antivirus false positives — remote-control binaries look like malware to
  heuristics. Code-signing or an allowlist is the fix.
