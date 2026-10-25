#!/usr/bin/env python3
"""RDP11 agent - runs on the controlled Windows machine.

Registers with the relay server, prints its session ID, then waits for a
viewer: streams JPEG frames of the primary screen and injects mouse/keyboard
input it receives. Reconnects automatically until stopped.
Resilient against network changes, VPN connections, and IP changes.
"""

import argparse
import hashlib
import io
import json
import logging
import os
import platform
import socket
import struct
import sys
import threading
import time
import uuid
from pathlib import Path

import mss
import pyautogui
from PIL import Image, ImageChops

pyautogui.FAILSAFE = False  # a remote session must not die on corner hits
pyautogui.PAUSE = 0         # remove PyAutoGUI's default 100ms artificial sleep!

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "agent_config.json"
DEFAULT_CONFIG = {"server": "77.83.198.200", "agent_port": 9000, "password": "p@ssW0RdDD!!!", "fps": 30}

TYPE_MSG = 1
TYPE_FRAME = 2
HEADER = struct.Struct(">BI")
MAX_PAYLOAD = 8 * 1024 * 1024

SPECIAL_KEYS = {
    "Escape": "esc", "Enter": "enter", "Tab": "tab", "Backspace": "backspace",
    "Delete": "delete", "Insert": "insert", "Home": "home", "End": "end",
    "PageUp": "pageup", "PageDown": "pagedown", "Space": "space",
    "ArrowUp": "up", "ArrowDown": "down", "ArrowLeft": "left", "ArrowRight": "right",
    "ControlLeft": "ctrlleft", "ControlRight": "ctrlright",
    "ShiftLeft": "shiftleft", "ShiftRight": "shiftright",
    "AltLeft": "altleft", "AltRight": "altright",
    "MetaLeft": "winleft", "MetaRight": "winright",
    "CapsLock": "capslock", "NumLock": "numlock",
    "PrintScreen": "printscreen", "ScrollLock": "scrolllock", "Pause": "pause",
    "ContextMenu": "menu",
}

log = logging.getLogger("rdp11-agent")


def load_config():
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
        log.warning("created %s with defaults - edit the server address if needed!",
                    CONFIG_PATH.name)
        return dict(DEFAULT_CONFIG)
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def enable_dpi_awareness():
    """Without this, captures and coordinates are scaled/virtualized on Windows."""
    if sys.platform != "win32":
        return
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except OSError:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except OSError:
            pass


def configure_socket(sock):
    """Enable keepalive and disable Nagle to detect broken connections fast."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if hasattr(socket, "SIO_KEEPALIVE_VALS"):
        # Windows: on=1, keepalivetime=3000ms, keepaliveinterval=1000ms
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 3000, 1000))
        except OSError:
            pass
    elif hasattr(socket, "TCP_KEEPIDLE"):
        # Linux
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 3)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except OSError:
            pass


def session_id():
    """Stable 9-digit ID derived from the machine identity, like AnyDesk's ID."""
    try:
        if sys.platform == "win32":
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Cryptography") as key:
                material, _ = winreg.QueryValueEx(key, "MachineGuid")
        else:
            material = f"{platform.node()}:{os.getlogin()}"
    except OSError:
        material = platform.node() or str(uuid.getnode())
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return 100000000 + int(digest[:16], 16) % 900000000


def recv_exact(conn, n, deadline=None, stop_event=None):
    buf = bytearray()
    while len(buf) < n:
        if stop_event is not None and stop_event.is_set():
            raise ConnectionError("client stopped")
        if deadline is not None and time.time() > deadline:
            raise TimeoutError("connection timed out (no data from server)")
        try:
            chunk = conn.recv(n - len(buf))
        except (TimeoutError, socket.timeout):
            continue
        if not chunk:
            raise ConnectionError("server closed connection")
        buf += chunk
    return bytes(buf)


def recv_packet(conn, timeout=None, stop_event=None):
    deadline = (time.time() + timeout) if timeout else None
    header = recv_exact(conn, HEADER.size, deadline=deadline, stop_event=stop_event)
    ptype, length = HEADER.unpack(header)
    if length > MAX_PAYLOAD:
        raise ConnectionError(f"payload too large: {length}")
    payload = recv_exact(conn, length, deadline=deadline, stop_event=stop_event) if length else b""
    return ptype, payload


def map_key(code, key):
    if code in SPECIAL_KEYS:
        return SPECIAL_KEYS[code]
    if key in SPECIAL_KEYS:
        return SPECIAL_KEYS[key]
    if code.startswith("F") and code[1:].isdigit() and 1 <= int(code[1:]) <= 12:
        return code.lower()
    if len(key) == 1:
        return key
    return None  # IME/dead keys and unmapped keys are ignored


class ScreenStreamer:
    MAX_WIDTH = 1920     # px; standard 1080p is unscaled; 2K/4K downscaled
    JPEG_QUALITY = 55
    DEFAULT_FPS = 30

    def __init__(self, fps=30, quality=55, max_width=1920):
        self.sct = mss.mss()
        self.prev = None
        self.scale_x = 1.0
        self.scale_y = 1.0
        self.fps = fps
        self.quality = quality
        self.max_width = max_width

    def reset(self):
        """Force the next frame out even if the screen looks unchanged."""
        self.prev = None

    def grab_jpeg(self):
        mon = self.sct.monitors[1]  # primary monitor only, for now
        raw = self.sct.grab(mon)
        img = Image.frombytes("RGB", raw.size, raw.rgb)
        if img.width > self.max_width:
            height = round(img.height * self.max_width / img.width)
            img = img.resize((self.max_width, height), Image.NEAREST)
        if self.prev is not None and self.prev.size == img.size:
            if ImageChops.difference(self.prev, img).getbbox() is None:
                return None  # screen unchanged - skip encode and send
        self.prev = img
        self.scale_x = mon["width"] / img.width
        self.scale_y = mon["height"] / img.height
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=self.quality, subsampling=2)
        return buf.getvalue()


class AgentClient:
    HEARTBEAT_INTERVAL = 3.0   # send ping every 3 seconds
    HEARTBEAT_TIMEOUT = 8.0    # drop & reconnect if no response in 8 seconds
    SOCKET_SLICE = 1.5         # recv slice timeout for watchdog & graceful exit
    CONNECT_TIMEOUT = 5.0      # socket connect timeout
    RECONNECT_MIN = 1.0
    RECONNECT_MAX = 6.0

    def __init__(self, cfg):
        self.cfg = cfg
        self.sid = session_id()
        self.password = str(cfg.get("password", "p@ssW0RdDD!!!"))
        self.fps = max(1, int(cfg.get("fps", 30)))
        self.sock = None
        self.send_lock = threading.Lock()
        self.active = threading.Event()  # a viewer is attached
        self.stop = threading.Event()    # set on Ctrl+C for instant exit
        self.streamer = None
        self.last_rx = 0.0

    def run(self):
        threading.Thread(target=self.capture_loop, daemon=True, name="agent-capture").start()
        backoff = self.RECONNECT_MIN
        while not self.stop.is_set():
            started = time.time()
            connected_ok = False
            try:
                self.session()
                connected_ok = True
                if not self.stop.is_set():
                    log.info("disconnected from server")
            except Exception as exc:
                if not self.stop.is_set():
                    log.warning("connection failed: %s", exc)

            if self.stop.is_set():
                break

            # If connected successfully or session lasted > 8s, reset backoff
            if connected_ok or (time.time() - started > 8.0):
                backoff = self.RECONNECT_MIN
            else:
                backoff = min(backoff * 1.5, self.RECONNECT_MAX)

            deadline = time.time() + backoff
            while not self.stop.is_set() and time.time() < deadline:
                time.sleep(0.2)

    def abort_session(self, sock=None):
        """Immediately interrupt blocking socket calls on all threads."""
        self.active.clear()
        target = sock or self.sock
        if target is not None:
            try:
                target.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                target.close()
            except OSError:
                pass
        if sock is None or self.sock is sock:
            self.sock = None

    def shutdown(self):
        """Kick the worker thread out of any blocking socket call."""
        self.stop.set()
        self.abort_session()

    def session(self):
        log.debug("connecting to %s:%d...", self.cfg["server"], self.cfg["agent_port"])
        sock = socket.create_connection(
            (self.cfg["server"], self.cfg["agent_port"]), timeout=self.CONNECT_TIMEOUT)
        configure_socket(sock)
        sock.settimeout(self.SOCKET_SLICE)
        self.sock = sock
        self.last_rx = time.time()
        self.send_msg(sock, {"cmd": "register", "id": self.sid, "password": self.password})
        log.info("connected to %s:%d (session %d)",
                 self.cfg["server"], self.cfg["agent_port"], self.sid)

        hb_thread = threading.Thread(
            target=self.heartbeat, args=(sock,), daemon=True, name="agent-hb")
        hb_thread.start()
        try:
            self.reader(sock)
        finally:
            self.abort_session(sock)

    def send_msg(self, sock, obj):
        data = json.dumps(obj).encode("utf-8")
        packet = HEADER.pack(TYPE_MSG, len(data)) + data
        acquired = self.send_lock.acquire(timeout=2.0)
        if not acquired:
            raise ConnectionError("send_lock timeout")
        try:
            if self.sock is not sock or self.stop.is_set():
                raise ConnectionError("socket closed or superseded")
            sock.sendall(packet)
        finally:
            self.send_lock.release()

    def send_frame(self, sock, data):
        packet = HEADER.pack(TYPE_FRAME, len(data)) + data
        acquired = self.send_lock.acquire(timeout=2.0)
        if not acquired:
            raise ConnectionError("send_lock timeout")
        try:
            if self.sock is not sock or self.stop.is_set():
                raise ConnectionError("socket closed or superseded")
            sock.sendall(packet)
        finally:
            self.send_lock.release()

    def heartbeat(self, sock):
        while self.sock is sock and not self.stop.is_set():
            steps = int(self.HEARTBEAT_INTERVAL / 0.25)
            for _ in range(steps):
                if self.sock is not sock or self.stop.is_set():
                    return
                time.sleep(0.25)
            if self.sock is not sock or self.stop.is_set():
                return
            try:
                self.send_msg(sock, {"cmd": "ping"})
            except (OSError, ConnectionError) as exc:
                log.debug("heartbeat ping failed: %s", exc)
                self.abort_session(sock)
                return

    def reader(self, sock):
        while self.sock is sock and not self.stop.is_set():
            try:
                ptype, payload = recv_packet(
                    sock, timeout=self.HEARTBEAT_TIMEOUT, stop_event=self.stop)
            except (TimeoutError, ConnectionError) as exc:
                if not self.stop.is_set():
                    log.warning("connection dropped (%s), reconnecting...", exc)
                break
            self.last_rx = time.time()
            if ptype != TYPE_MSG:
                continue
            msg = json.loads(payload)
            cmd = msg.get("cmd")
            if cmd == "start":
                if self.streamer is not None:
                    self.streamer.reset()
                self.active.set()
                log.info("viewer attached - streaming started")
            elif cmd == "stop":
                self.active.clear()
                log.info("viewer detached - streaming stopped")
            elif cmd == "input":
                self.handle_input(msg)
            elif msg.get("resp") == "register_ok":
                log.info("server accepted registration as session %d", msg.get("id"))
            elif msg.get("resp") == "pong":
                pass

    def capture_loop(self):
        interval = 1.0 / self.fps
        while not self.stop.is_set():
            if not self.active.wait(timeout=0.5):
                continue
            if self.streamer is None:
                try:
                    self.streamer = ScreenStreamer(fps=self.fps)
                except Exception as exc:
                    log.error("screen capture unavailable: %s", exc)
                    time.sleep(1.0)
                    continue
            started = time.time()
            try:
                jpeg = self.streamer.grab_jpeg()
            except Exception as exc:
                log.warning("capture failed: %s", exc)
                time.sleep(0.1)
                continue
            if jpeg is not None:
                sock = self.sock
                if sock is not None and self.active.is_set():
                    try:
                        self.send_frame(sock, jpeg)
                    except (OSError, ConnectionError) as exc:
                        log.warning("frame send failed, aborting session: %s", exc)
                        self.abort_session(sock)
            delay = interval - (time.time() - started)
            if delay > 0:
                time.sleep(delay)

    def handle_input(self, msg):
        if not self.active.is_set():
            return
        streamer = self.streamer
        if streamer is None:
            return
        try:
            typ = msg.get("type")
            if typ == "move":
                target_x = round(msg["x"] * streamer.scale_x)
                target_y = round(msg["y"] * streamer.scale_y)
                if sys.platform == "win32":
                    import ctypes
                    ctypes.windll.user32.SetCursorPos(target_x, target_y)
                else:
                    pyautogui.moveTo(target_x, target_y)
            elif typ == "btn":
                button = {0: "left", 1: "middle", 2: "right"}.get(msg["button"])
                if button is None:
                    return
                x = round(msg["x"] * streamer.scale_x)
                y = round(msg["y"] * streamer.scale_y)
                if msg["down"]:
                    pyautogui.mouseDown(x, y, button=button)
                else:
                    pyautogui.mouseUp(x, y, button=button)
            elif typ == "wheel":
                pyautogui.scroll(msg["amount"])
            elif typ == "key":
                name = map_key(msg.get("code", ""), msg.get("key", ""))
                if name:
                    if msg["down"]:
                        pyautogui.keyDown(name)
                    else:
                        pyautogui.keyUp(name)
            elif typ == "release_all":
                for name in ("ctrlleft", "ctrlright", "shiftleft", "shiftright",
                             "altleft", "altright", "winleft", "winright"):
                    try:
                        pyautogui.keyUp(name)
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("input %r failed: %s", msg.get("type"), exc)


def install_exit_handler(client, worker):
    """Windows console control handler: runs the instant the OS delivers
    Ctrl+C / Ctrl+Break / window-close, even if every Python thread is
    blocked in a socket or sleep call (where KeyboardInterrupt can't land).
    Keep the returned reference alive for the process lifetime.
    """
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    def handle(event_type):
        log.info("console event %d - exiting", event_type)
        client.shutdown()
        worker.join(timeout=1.0)
        os._exit(0)  # deterministic immediate exit, no interpreter teardown

    handler_ref = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)(handle)
    if not ctypes.windll.kernel32.SetConsoleCtrlHandler(handler_ref, True):
        log.warning("could not install console control handler")
    return handler_ref


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    enable_dpi_awareness()
    cfg = load_config()

    parser = argparse.ArgumentParser(
        description="RDP11 agent - registers with the relay server and shares "
                    "this machine's screen with authorized viewers.")
    parser.add_argument("server", nargs="?",
                        help="relay server address, e.g. 77.83.198.200 "
                             "(overrides agent_config.json)")
    parser.add_argument("-p", "--port", type=int,
                        help="agent TCP port (overrides agent_config.json)")
    parser.add_argument("--pass", "--password", dest="password",
                        help="session password for remote viewers (overrides agent_config.json)")
    parser.add_argument("--fps", type=int,
                        help="target streaming FPS, e.g. 30, 60, or 120 (overrides agent_config.json, default: 30)")
    args = parser.parse_args()
    if args.server:
        cfg["server"] = args.server
    if args.port:
        cfg["agent_port"] = args.port
    if args.password is not None:
        cfg["password"] = args.password
    if args.fps is not None:
        cfg["fps"] = args.fps

    client = AgentClient(cfg)
    log.info("RDP11 agent starting - session ID %d (server %s:%d, %d FPS, password %s)",
             client.sid, cfg["server"], cfg["agent_port"], client.fps, client.password)
    worker = threading.Thread(target=client.run, daemon=True, name="agent-worker")
    worker.start()
    handler_ref = install_exit_handler(client, worker)
    try:
        while worker.is_alive():
            worker.join(timeout=0.25)
    except KeyboardInterrupt:
        log.info("Ctrl+C - shutting down")
        client.shutdown()
        worker.join(timeout=1.5)
    log.info("agent stopped")


if __name__ == "__main__":
    main()
