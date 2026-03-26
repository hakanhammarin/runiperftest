#!/usr/bin/env python3
"""
Linux session collector.

Reads /proc/net/tcp and /proc/net/udp directly – no subprocesses,
minimal CPU/memory footprint.  Reports new and changed 5-tuples to MQTT.
"""

import argparse
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agents.common.mqtt_client import AgentMQTTClient

log = logging.getLogger(__name__)

# /proc/net/tcp states
TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

# States we care about (skip LISTEN-only entries unless configured)
REPORT_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT",
                 "FIN_WAIT1", "FIN_WAIT2"}


def _hex_to_ip(hex_str: str) -> str:
    """Convert little-endian hex IP to dotted notation."""
    packed = bytes.fromhex(hex_str)
    return socket.inet_ntoa(struct.pack(">I", struct.unpack("<I", packed)[0]))


def _hex_to_ip6(hex_str: str) -> str:
    """Convert hex IPv6 address from /proc/net/tcp6."""
    parts = [hex_str[i:i+8] for i in range(0, 32, 8)]
    packed = b"".join(bytes.fromhex(p)[::-1] for p in parts)
    return socket.inet_ntop(socket.AF_INET6, packed)


def _parse_proc_net(path: str, proto: str) -> Iterator[dict]:
    is_ipv6 = "6" in path
    try:
        with open(path) as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local_addr, local_port  = parts[1].split(":")
                remote_addr, remote_port = parts[2].split(":")
                state_hex = parts[3]

                if is_ipv6:
                    local_ip  = _hex_to_ip6(local_addr)
                    remote_ip = _hex_to_ip6(remote_addr)
                else:
                    local_ip  = _hex_to_ip(local_addr)
                    remote_ip = _hex_to_ip(remote_addr)

                local_p  = int(local_port, 16)
                remote_p = int(remote_port, 16)

                # Skip unconnected UDP (remote = 0.0.0.0:0)
                if proto == "udp" and remote_ip in ("0.0.0.0", "::"):
                    continue

                state = TCP_STATES.get(state_hex.upper(), state_hex)
                if proto == "tcp" and state not in REPORT_STATES:
                    continue

                yield {
                    "protocol":  proto,
                    "src_ip":    local_ip,
                    "src_port":  local_p,
                    "dst_ip":    remote_ip,
                    "dst_port":  remote_p,
                    "state":     state,
                    "direction": "out",
                }
    except FileNotFoundError:
        pass


def collect_sessions() -> list[dict]:
    sessions = []
    for path, proto in [
        ("/proc/net/tcp",  "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp",  "udp"),
        ("/proc/net/udp6", "udp"),
    ]:
        sessions.extend(_parse_proc_net(path, proto))
    return sessions


def run(mqtt_host: str, mqtt_port: int, interval: int,
        mqtt_user: str = "", mqtt_pass: str = ""):
    client = AgentMQTTClient(mqtt_host, mqtt_port, mqtt_user, mqtt_pass)
    client.connect()

    seen: set[tuple] = set()

    while True:
        try:
            sessions = collect_sessions()
            for s in sessions:
                key = (s["protocol"], s["src_ip"], s["src_port"],
                       s["dst_ip"], s["dst_port"])
                if key not in seen:
                    s["os"] = "linux"
                    client.publish_session(s)
                    seen.add(key)

            client.publish_status("linux")
            # Prune seen set periodically to allow re-reporting
            if len(seen) > 10_000:
                seen.clear()
        except Exception as exc:
            log.error("Collector error: %s", exc)

        time.sleep(interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Linux session collector")
    p.add_argument("--mqtt-host", default=os.getenv("MQTT_HOST", "localhost"))
    p.add_argument("--mqtt-port", type=int, default=int(os.getenv("MQTT_PORT", "1883")))
    p.add_argument("--mqtt-user", default=os.getenv("MQTT_USER", ""))
    p.add_argument("--mqtt-pass", default=os.getenv("MQTT_PASS", ""))
    p.add_argument("--interval",  type=int, default=int(os.getenv("POLL_INTERVAL", "30")),
                   help="Poll interval in seconds (default 30)")
    args = p.parse_args()
    run(args.mqtt_host, args.mqtt_port, args.interval, args.mqtt_user, args.mqtt_pass)
