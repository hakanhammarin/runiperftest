#!/usr/bin/env python3
"""
Windows session collector.

Two collection modes (selected automatically):
1. Windows Firewall log parser  – tails %SYSTEMROOT%\System32\LogFiles\Firewall\pfirewall.log
2. Netstat fallback             – parses `netstat -ano` output

Mode 1 is preferred (zero-syscall overhead, just log tail).
Enable firewall logging:  netsh advfirewall set allprofiles logging droppedconnections enable
                          netsh advfirewall set allprofiles logging allowedconnections enable
"""

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agents.common.mqtt_client import AgentMQTTClient

log = logging.getLogger(__name__)

FIREWALL_LOG = Path(os.environ.get(
    "FIREWALL_LOG",
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
))


# ---------------------------------------------------------------------------
# Firewall log tail
# ---------------------------------------------------------------------------

def _parse_log_line(line: str) -> dict | None:
    """
    Expected format:
    date time action protocol src-ip dst-ip src-port dst-port ...
    2024-01-01 12:00:01 ALLOW TCP 192.168.1.5 8.8.8.8 54321 443 ...
    """
    if line.startswith("#") or not line.strip():
        return None
    parts = line.split()
    if len(parts) < 8:
        return None
    # date time action proto src dst sport dport
    _, _, action, proto, src_ip, dst_ip, src_port, dst_port = parts[:8]
    proto = proto.lower()
    if proto not in ("tcp", "udp"):
        return None
    try:
        return {
            "protocol":  proto,
            "src_ip":    src_ip,
            "src_port":  int(src_port),
            "dst_ip":    dst_ip,
            "dst_port":  int(dst_port),
            "state":     "LOGGED",
            "direction": "out" if action.upper() == "SEND" else "in",
            "os":        "windows",
        }
    except ValueError:
        return None


def tail_firewall_log(client: AgentMQTTClient, seen: set):
    """Open firewall log and tail new lines."""
    if not FIREWALL_LOG.exists():
        raise FileNotFoundError(f"Firewall log not found: {FIREWALL_LOG}")

    log.info("Tailing firewall log: %s", FIREWALL_LOG)
    with FIREWALL_LOG.open(encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            session = _parse_log_line(line)
            if session:
                key = (session["protocol"], session["src_ip"], session["src_port"],
                       session["dst_ip"], session["dst_port"])
                if key not in seen:
                    client.publish_session(session)
                    seen.add(key)
                    if len(seen) > 20_000:
                        seen.clear()


# ---------------------------------------------------------------------------
# Netstat fallback
# ---------------------------------------------------------------------------

def _parse_netstat_line(line: str) -> dict | None:
    """
    Parses lines like:
    TCP    192.168.1.5:54321    8.8.8.8:443    ESTABLISHED    1234
    UDP    0.0.0.0:5353         *:*                           4321
    """
    parts = line.split()
    if not parts:
        return None
    proto = parts[0].lower()
    if proto not in ("tcp", "udp"):
        return None

    try:
        local  = parts[1]
        remote = parts[2]
        state  = parts[3] if proto == "tcp" and len(parts) > 3 else ""

        def split_addr(addr: str):
            if addr.startswith("["):  # IPv6 [::1]:port
                ip   = addr[1:addr.index("]")]
                port = int(addr.split("]:")[-1])
            elif ":" in addr:
                ip, port_s = addr.rsplit(":", 1)
                port = int(port_s) if port_s != "*" else 0
            else:
                return None, 0
            return ip, port

        src_ip, src_port = split_addr(local)
        dst_ip, dst_port = split_addr(remote)
        if dst_ip in (None, "*", "") or dst_ip == "0.0.0.0":
            return None
        if state in ("LISTENING", "LISTEN"):
            return None

        return {
            "protocol":  proto,
            "src_ip":    src_ip,
            "src_port":  src_port,
            "dst_ip":    dst_ip,
            "dst_port":  dst_port,
            "state":     state,
            "direction": "out",
            "os":        "windows",
        }
    except (ValueError, IndexError):
        return None


def poll_netstat(client: AgentMQTTClient, seen: set, interval: int):
    log.info("Using netstat fallback (poll every %ss)", interval)
    while True:
        try:
            out = subprocess.check_output(
                ["netstat", "-ano"], text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            for line in out.splitlines():
                session = _parse_netstat_line(line)
                if session:
                    key = (session["protocol"], session["src_ip"], session["src_port"],
                           session["dst_ip"], session["dst_port"])
                    if key not in seen:
                        client.publish_session(session)
                        seen.add(key)
            if len(seen) > 20_000:
                seen.clear()
            client.publish_status("windows")
        except Exception as exc:
            log.error("netstat error: %s", exc)
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(mqtt_host: str, mqtt_port: int, interval: int,
        mqtt_user: str = "", mqtt_pass: str = ""):
    client = AgentMQTTClient(mqtt_host, mqtt_port, mqtt_user, mqtt_pass)
    client.connect()
    seen: set = set()

    try:
        # Try firewall log first
        tail_firewall_log(client, seen)
    except FileNotFoundError as exc:
        log.warning("%s – falling back to netstat", exc)
        poll_netstat(client, seen, interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Windows session collector")
    p.add_argument("--mqtt-host", default=os.getenv("MQTT_HOST", "localhost"))
    p.add_argument("--mqtt-port", type=int, default=int(os.getenv("MQTT_PORT", "1883")))
    p.add_argument("--mqtt-user", default=os.getenv("MQTT_USER", ""))
    p.add_argument("--mqtt-pass", default=os.getenv("MQTT_PASS", ""))
    p.add_argument("--interval",  type=int, default=int(os.getenv("POLL_INTERVAL", "60")))
    args = p.parse_args()
    run(args.mqtt_host, args.mqtt_port, args.interval, args.mqtt_user, args.mqtt_pass)
