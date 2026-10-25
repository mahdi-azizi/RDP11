# RDP11 — Hybrid TCP + UDP Remote Desktop (AnyDesk / RDP Architecture)

This folder contains the **Hybrid TCP + UDP** implementation of RDP11:

```
agent.py (Windows, controlled machine)            server.py (Alpine / Linux)
  - Control & input (reliable)      --TCP:9000-->   registry, auth, input relay
  - Video stream (low-latency)      --UDP:9001-->   UDP chunk reassembly
                                                               |
                                                               | WebSocket
browser (viewer machine, any OS)    <---- http://<server>:8080 -
  canvas + mouse/keyboard capture
```

### Why Hybrid TCP + UDP?
- **UDP for Video**: Screen JPEG frames are sliced into MTU-safe datagrams (~1,280 bytes). If a packet drops on a congested link, stale frames are discarded immediately without **Head-of-Line blocking** or latency accumulation.
- **TCP for Control & Input**: Agent registration, heartbeat keepalive, and mouse/keyboard events stay 100% reliable on TCP so keystrokes and mouse clicks never drop or get stuck.
- **WebSocket to Browser**: Complete reassembled frames are sent over WebSocket `/ws` and rendered using `requestAnimationFrame` with zero frame buffering.

---

## 1. Server Setup (Alpine / Linux)

### Requirements
```sh
pip install -r requirements-server.txt
```

### Firewall / Ports
Open both TCP and UDP ports on your cloud firewall / iptables:
```sh
# HTTP viewer & WebSocket
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
# Agent TCP control channel
iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
# Agent UDP video streaming channel
iptables -A INPUT -p udp --dport 9001 -j ACCEPT
```

### Configuration (`server_config.json`)
```json
{
  "password": "p@ssW0RdDD!!!",
  "http_port": 8080,
  "agent_port": 9000,
  "udp_port": 9001
}
```

### Start Server
```sh
python3 server.py
```

---

## 2. Agent Setup (Windows Controlled Machine)

### Requirements
```bat
py -3 -m pip install -r requirements-agent.txt
```

### Configuration (`agent_config.json`)
```json
{
  "server": "77.83.198.200",
  "agent_port": 9000,
  "udp_port": 9001,
  "password": "p@ssW0RdDD!!!",
  "fps": 30
}
```

### Start Agent
```bat
py -3 agent.py 77.83.198.200
```

### Command-Line Arguments
All configuration parameters can be overridden at runtime:
```bat
py -3 agent.py 77.83.198.200 -p 9000 -u 9001 --pass MySecretPass123 --fps 30
```
- `server`: Remote server IP address or hostname.
- `-p / --port`: TCP control port (default: `9000`).
- `-u / --udp-port`: UDP video streaming port (default: `9001`).
- `--pass / --password`: Password for remote viewers.
- `--fps`: Target frame rate (e.g. `15`, `30`, `60`, `120`).

---

## 3. Viewing in Browser

1. Open your browser and go to `http://<server-ip>:8080`.
2. Enter the agent's **9-digit Session ID** shown in the agent's console.
3. Enter the session password.
4. Click **Connect**.
