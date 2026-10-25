#!/usr/bin/env python3
"""RDP11 Hybrid TCP + UDP relay server - runs on the public Alpine machine.

One process, three roles:
  TCP :agent_port  -> Agents register & receive reliable mouse/keyboard input
  UDP :udp_port    -> Agents stream video frames with zero head-of-line blocking
  HTTP :http_port  -> Serves the browser viewer and its WebSocket (/ws)

Protocol details:
  Agent TCP: framed JSON messages (register, ping/pong, start/stop, input)
  Agent UDP: framed datagrams: [2B magic | 4B sid | 4B frame_id | 2B chunk_idx | 2B total_chunks | payload]
  Browser WebSocket: text frames are JSON control/input, binary frames are raw JPEG

Run single-process only: the session registry is in memory.
"""

import json
import logging
import queue
import socket
import struct
import threading
import time
from pathlib import Path
from secrets import compare_digest

from flask import Flask, request, send_from_directory
from flask_sock import Sock

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "server_config.json"
DEFAULT_CONFIG = {
    "password": "p@ssW0RdDD!!!",
    "http_port": 8080,
    "agent_port": 9000,
    "udp_port": 9001
}

# TCP control framing
TYPE_MSG = 1
TYPE_FRAME = 2
HEADER = struct.Struct(">BI")
MAX_PAYLOAD = 8 * 1024 * 1024

# UDP video framing
UDP_MAGIC = b"RF"
UDP_HEADER = struct.Struct(">2sIIHH")  # magic(2B), sid(4B), frame_id(4B), chunk_idx(2B), total_chunks(2B)

AUTH_WINDOW = 60.0      # seconds
AUTH_MAX_FAILS = 5      # wrong passwords per window per viewer IP

log = logging.getLogger("rdp11-udp-server")


def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        log.warning("created %s with defaults - change the password!", CONFIG_PATH.name)
        return dict(DEFAULT_CONFIG)
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


CONFIG = load_config()

app = Flask(__name__, static_folder=None)
sock = Sock(app)

REG_LOCK = threading.Lock()
AGENTS = {}  # session id -> Agent

AUTH_LOCK = threading.Lock()
AUTH_FAILS = {}  # viewer ip -> [failure timestamps]


def configure_socket(sock_obj):
    """Enable TCP keepalive and low latency."""
    sock_obj.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        try:
            sock_obj.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 3000, 1000))
        except OSError:
            pass
    elif hasattr(socket, "TCP_KEEPIDLE"):
        try:
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5)
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            sock_obj.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except OSError:
            pass


class FrameAssembler:
    """Reassembles chunked UDP datagrams into complete JPEG video frames.
    Drops older partial frames as soon as chunks from a newer frame arrive,
    ensuring zero buffering latency.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.current_frame_id = -1
        self.chunks = {}
        self.total_chunks = 0
        self.last_update = 0.0

    def add_chunk(self, frame_id, chunk_idx, total_chunks, payload):
        with self.lock:
            # Ignore stale chunks from older frames
            if frame_id < self.current_frame_id:
                if self.current_frame_id - frame_id < 0x7FFFFFFF:
                    return None

            # New frame started -> discard incomplete older frame immediately
            if frame_id > self.current_frame_id:
                self.current_frame_id = frame_id
                self.chunks.clear()
                self.total_chunks = total_chunks
                self.last_update = time.time()

            self.chunks[chunk_idx] = payload
            self.last_update = time.time()

            # Check if all chunks have arrived
            if len(self.chunks) == self.total_chunks:
                assembled = bytearray()
                for i in range(self.total_chunks):
                    chunk = self.chunks.get(i)
                    if chunk is None:
                        return None
                    assembled.extend(chunk)
                self.chunks.clear()
                return bytes(assembled)
            return None


class Agent:
    def __init__(self, sid, conn, addr, password=None):
        self.sid = sid
        self.conn = conn
        self.addr = addr
        self.password = password
        self.send_lock = threading.Lock()
        self.viewer = None  # mailbox Queue of the attached viewer, or None
        self.alive = True

    def send_msg(self, obj):
        data = json.dumps(obj).encode("utf-8")
        with self.send_lock:
            self.conn.sendall(HEADER.pack(TYPE_MSG, len(data)) + data)

    def close(self):
        self.alive = False
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.conn.close()
        except OSError:
            pass


class Viewer:
    """Wraps the WebSocket so reader and sender threads can send safely."""

    def __init__(self, ws):
        self.ws = ws
        self.lock = threading.Lock()

    def send(self, data):
        with self.lock:
            self.ws.send(data)


def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return bytes(buf)


def recv_packet(conn):
    ptype, length = HEADER.unpack(recv_exact(conn, HEADER.size))
    if length > MAX_PAYLOAD:
        raise ConnectionError(f"payload too large: {length}")
    payload = recv_exact(conn, length) if length else b""
    return ptype, payload


def push_frame(mailbox, data):
    """Non-blocking frame hand-off to viewer; drops oldest frame immediately."""
    try:
        mailbox.put_nowait(("frame", data))
    except queue.Full:
        try:
            mailbox.get_nowait()
        except queue.Empty:
            pass
        try:
            mailbox.put_nowait(("frame", data))
        except queue.Full:
            pass


def unbind_viewer(agent, reason):
    mailbox = agent.viewer
    if mailbox is not None:
        agent.viewer = None
        try:
            mailbox.put_nowait(("close", reason))
        except queue.Full:
            pass


def too_many_failures(ip):
    now = time.time()
    with AUTH_LOCK:
        fails = [t for t in AUTH_FAILS.get(ip, []) if now - t < AUTH_WINDOW]
        AUTH_FAILS[ip] = fails
        return len(fails) >= AUTH_MAX_FAILS


def record_failure(ip):
    with AUTH_LOCK:
        AUTH_FAILS.setdefault(ip, []).append(time.time())


# ---------------------------------------------------------------- agents side (TCP Control)

def agent_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", CONFIG["agent_port"]))
    srv.listen(16)
    log.info("listening for agent control on tcp/%d", CONFIG["agent_port"])
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_agent, args=(conn, addr), daemon=True).start()


def handle_agent(conn, addr):
    agent = None
    sid = None
    try:
        configure_socket(conn)
        conn.settimeout(15)  # agents ping every 3 s; 15 s timeout detects dead connection promptly
        ptype, payload = recv_packet(conn)
        if ptype != TYPE_MSG:
            raise ConnectionError("first packet must be a register message")
        reg = json.loads(payload)
        if reg.get("cmd") != "register":
            raise ConnectionError("expected register command")
        sid = int(reg["id"])
        if not 100000000 <= sid <= 999999999:
            raise ConnectionError(f"invalid session id {sid}")
        agent_password = reg.get("password") or CONFIG.get("password")
        agent = Agent(sid, conn, addr, password=agent_password)
        has_viewer = False
        with REG_LOCK:
            old = AGENTS.get(sid)
            AGENTS[sid] = agent
            if old is not None and old.viewer is not None:
                # Seamlessly transfer the active viewer to the new connection
                agent.viewer = old.viewer
                old.viewer = None
                has_viewer = True
        if old is not None:
            log.info("agent %d re-registered from %s, dropping previous connection", sid, addr[0])
            old.close()

        # Send register_ok along with assigned UDP port for video streaming
        agent.send_msg({
            "resp": "register_ok",
            "id": sid,
            "udp_port": CONFIG.get("udp_port", 9001)
        })
        log.info("agent %d registered from %s (UDP video port %d)",
                 sid, addr[0], CONFIG.get("udp_port", 9001))

        if has_viewer:
            log.info("agent %d preserved active viewer session, resuming stream", sid)
            try:
                agent.send_msg({"cmd": "start"})
            except OSError:
                pass

        while True:
            ptype, payload = recv_packet(conn)
            if ptype == TYPE_FRAME:
                # Fallback support for TCP video frames
                mailbox = agent.viewer
                if mailbox is not None:
                    push_frame(mailbox, payload)
            elif ptype == TYPE_MSG:
                msg = json.loads(payload)
                if msg.get("cmd") == "ping":
                    agent.send_msg({"resp": "pong"})
                else:
                    log.debug("agent %d sent unknown message: %r", sid, msg)
    except (ConnectionError, socket.timeout, TimeoutError, OSError, ValueError,
            json.JSONDecodeError) as exc:
        if agent is not None:
            log.info("agent %d connection ended: %s", sid, exc)
        else:
            log.info("agent handshake from %s failed: %s", addr[0], exc)
    finally:
        if agent is not None:
            should_unbind = False
            with REG_LOCK:
                if AGENTS.get(sid) is agent:
                    del AGENTS[sid]
                    should_unbind = True
            if should_unbind:
                unbind_viewer(agent, "agent disconnected")
        try:
            conn.close()
        except OSError:
            pass


# ---------------------------------------------------------------- agents side (UDP Video)

def udp_listener():
    """High-throughput UDP listener receiving video frame datagrams."""
    udp_port = CONFIG.get("udp_port", 9001)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        # 2 MB receive buffer to accommodate high frame rate bursts
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    except OSError:
        pass
    sock.bind(("0.0.0.0", udp_port))
    log.info("listening for agent video on udp/%d", udp_port)

    assemblers = {}  # sid -> FrameAssembler

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            if len(data) < UDP_HEADER.size:
                continue
            magic, sid, frame_id, chunk_idx, total_chunks = UDP_HEADER.unpack(data[:UDP_HEADER.size])
            if magic != UDP_MAGIC:
                continue
            payload = data[UDP_HEADER.size:]

            with REG_LOCK:
                agent = AGENTS.get(sid)
                if agent is None or not agent.alive or agent.viewer is None:
                    continue
                mailbox = agent.viewer

            assembler = assemblers.get(sid)
            if assembler is None:
                assembler = FrameAssembler()
                assemblers[sid] = assembler

            frame = assembler.add_chunk(frame_id, chunk_idx, total_chunks, payload)
            if frame is not None:
                push_frame(mailbox, frame)
        except Exception as exc:
            log.debug("UDP receive error: %s", exc)


# --------------------------------------------------------------- viewers side

def sanitize_input(msg):
    """Coerce viewer input to a small, typed whitelist before relaying."""
    typ = msg.get("type")
    out = {"type": typ}
    try:
        if typ == "move":
            out["x"] = int(msg["x"])
            out["y"] = int(msg["y"])
        elif typ == "btn":
            out["button"] = int(msg["button"])
            out["down"] = bool(msg["down"])
            out["x"] = int(msg["x"])
            out["y"] = int(msg["y"])
        elif typ == "wheel":
            out["amount"] = int(msg["amount"])
        elif typ == "key":
            out["key"] = str(msg["key"])[:32]
            out["code"] = str(msg.get("code", ""))[:32]
            out["down"] = bool(msg["down"])
        elif typ == "release_all":
            pass
        else:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    if typ == "move" and not (0 <= out["x"] <= 100000 and 0 <= out["y"] <= 100000):
        return None
    return out


def viewer_sender(viewer, mailbox):
    while True:
        item = mailbox.get()
        if item[0] == "close":
            try:
                viewer.ws.close()
            except Exception:
                pass
            return
        try:
            viewer.send(item[1])
        except Exception:
            return


def handle_viewer(viewer, ip):
    mailbox = None
    sid = None
    try:
        msg = viewer.ws.receive()
        if msg is None:
            return
        req = json.loads(msg)
        if req.get("cmd") != "auth":
            viewer.send(json.dumps({"resp": "error", "error": "expected auth first"}))
            return
        sid = int(req.get("id", 0))

        if too_many_failures(ip):
            viewer.send(json.dumps(
                {"resp": "auth_fail", "error": "too many attempts, wait a minute"}))
            return
        with REG_LOCK:
            agent = AGENTS.get(sid)
        if agent is None or not agent.alive:
            viewer.send(json.dumps(
                {"resp": "auth_fail", "error": "no agent online with that ID"}))
            return
        expected_pw = agent.password if getattr(agent, "password", None) is not None else CONFIG["password"]
        if not compare_digest(str(expected_pw).encode(),
                              str(req.get("password", "")).encode()):
            record_failure(ip)
            log.warning("viewer %s: wrong password for agent %d", ip, sid)
            viewer.send(json.dumps({"resp": "auth_fail", "error": "wrong password"}))
            return

        mailbox = queue.Queue(maxsize=1)  # maxsize=1 eliminates queued video lag
        with REG_LOCK:
            if not agent.alive or AGENTS.get(sid) is not agent:
                viewer.send(json.dumps(
                    {"resp": "auth_fail", "error": "agent just went offline"}))
                return
            prev = agent.viewer
            agent.viewer = mailbox
        if prev is not None:
            try:
                prev.put_nowait(("close", "another viewer took over this session"))
            except queue.Full:
                pass

        viewer.send(json.dumps({"resp": "auth_ok", "id": sid}))
        agent.send_msg({"cmd": "start"})
        log.info("viewer %s attached to agent %d", ip, sid)

        threading.Thread(target=viewer_sender, args=(viewer, mailbox),
                         daemon=True).start()
        while True:
            msg = viewer.ws.receive()
            if msg is None:
                break
            data = json.loads(msg)
            cmd = data.get("cmd")
            if cmd == "input":
                clean = sanitize_input(data)
                if clean is not None:
                    with REG_LOCK:
                        cur_agent = AGENTS.get(sid)
                    if cur_agent is not None and cur_agent.alive:
                        try:
                            cur_agent.send_msg({"cmd": "input", **clean})
                        except OSError:
                            pass
            elif cmd == "ping":
                viewer.send(json.dumps({"resp": "pong"}))
    except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as exc:
        log.info("viewer %s: %s", ip, exc)
    finally:
        if mailbox is not None and sid is not None:
            stop = False
            cur_agent = None
            with REG_LOCK:
                cur_agent = AGENTS.get(sid)
                if cur_agent is not None and cur_agent.viewer is mailbox:
                    cur_agent.viewer = None
                    stop = True
            if stop and cur_agent is not None and cur_agent.alive:
                try:
                    cur_agent.send_msg({"cmd": "stop"})
                except OSError:
                    pass
            try:
                mailbox.put_nowait(("close", "viewer loop ended"))
            except queue.Full:
                pass


@sock.route("/ws")
def ws_endpoint(ws):
    handle_viewer(Viewer(ws), request.remote_addr or "?")


# ------------------------------------------------------------------ http side

@app.route("/")
def index():
    return send_from_directory(HERE / "static", "index.html")


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    if CONFIG.get("password") == DEFAULT_CONFIG["password"]:
        log.warning("running with the default password - edit server_config.json!")

    # Start TCP agent listener
    threading.Thread(target=agent_listener, daemon=True, name="tcp-agent-listener").start()

    # Start UDP agent video listener
    threading.Thread(target=udp_listener, daemon=True, name="udp-video-listener").start()

    log.info("RDP11 server up: viewers http://<this-host>:%d  control tcp/%d  video udp/%d",
             CONFIG["http_port"], CONFIG["agent_port"], CONFIG.get("udp_port", 9001))
    app.run(host="0.0.0.0", port=CONFIG["http_port"], threaded=True)


if __name__ == "__main__":
    main()
