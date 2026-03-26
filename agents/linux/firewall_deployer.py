#!/usr/bin/env python3
"""
Linux firewall deployer.

Subscribes to netmon/rules/deploy/<hostname> and netmon/rules/revoke/<hostname>.
Applies rules using firewall-cmd (firewalld) and tracks deployed GUIDs in a
local JSON ledger so rules survive restarts.
"""

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agents.common.mqtt_client import AgentMQTTClient

log = logging.getLogger(__name__)

LEDGER_PATH = Path(os.getenv("LEDGER_PATH", "/var/lib/netmon/deployed_rules.json"))


# ---------------------------------------------------------------------------
# Ledger helpers
# ---------------------------------------------------------------------------

def _load_ledger() -> dict:
    try:
        return json.loads(LEDGER_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_ledger(ledger: dict):
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    LEDGER_PATH.write_text(json.dumps(ledger, indent=2))


# ---------------------------------------------------------------------------
# firewall-cmd helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.returncode, result.stdout + result.stderr
    except Exception as exc:
        return 1, str(exc)


def _proto_flag(proto: str) -> list[str]:
    p = proto.lower()
    if p in ("tcp", "udp"):
        return ["--protocol", p]
    return []


def _build_rich_rule(rule: dict) -> str:
    """Build a firewalld rich rule string from the rule dict."""
    direction = rule.get("direction", "out").lower()
    action    = rule.get("action", "allow").lower()
    protocol  = rule.get("protocol", "tcp").lower()
    src_ip    = rule.get("src_ip", "")
    src_port  = str(rule.get("src_port", ""))
    dst_ip    = rule.get("dst_ip", "")
    dst_port  = str(rule.get("dst_port", ""))

    parts = ["rule"]

    if direction == "in":
        if src_ip and src_ip != "*":
            parts.append(f'source address="{src_ip}"')
        if dst_ip and dst_ip != "*":
            parts.append(f'destination address="{dst_ip}"')
    else:  # out
        if src_ip and src_ip != "*":
            parts.append(f'source address="{src_ip}"')
        if dst_ip and dst_ip != "*":
            parts.append(f'destination address="{dst_ip}"')

    if protocol in ("tcp", "udp"):
        port_part = f'port port="{dst_port}" protocol="{protocol}"' if dst_port else ""
        if port_part:
            parts.append(port_part)

    fw_action = "accept" if action in ("allow", "accept") else "drop"
    parts.append(fw_action)
    return " ".join(parts)


def deploy_rule(rule: dict) -> bool:
    guid       = rule.get("guid", "")
    rich_rule  = _build_rich_rule(rule)
    ledger     = _load_ledger()

    if guid in ledger:
        log.info("Rule %s already deployed – skipping", guid)
        return True

    rc, out = _run(["firewall-cmd", "--permanent", f"--add-rich-rule={rich_rule}"])
    if rc != 0:
        log.error("firewall-cmd add failed: %s", out)
        return False

    rc, out = _run(["firewall-cmd", "--reload"])
    if rc != 0:
        log.warning("firewall-cmd reload warning: %s", out)

    ledger[guid] = {"rich_rule": rich_rule, "rule": rule}
    _save_ledger(ledger)
    log.info("Deployed rule %s: %s", guid, rich_rule)
    return True


def revoke_rule(guid: str) -> bool:
    ledger = _load_ledger()
    if guid not in ledger:
        log.warning("Rule %s not in ledger – cannot revoke", guid)
        return False

    rich_rule = ledger[guid]["rich_rule"]
    rc, out = _run(["firewall-cmd", "--permanent", f"--remove-rich-rule={rich_rule}"])
    if rc != 0:
        log.error("firewall-cmd remove failed: %s", out)
        return False

    _run(["firewall-cmd", "--reload"])
    del ledger[guid]
    _save_ledger(ledger)
    log.info("Revoked rule %s", guid)
    return True


# ---------------------------------------------------------------------------
# MQTT callback
# ---------------------------------------------------------------------------

def _on_rule(action: str, payload: dict):
    if action == "deploy":
        ok = deploy_rule(payload)
        log.info("Deploy result: %s", "ok" if ok else "failed")
    elif action == "revoke":
        guid = payload.get("guid", "")
        ok = revoke_rule(guid)
        log.info("Revoke result: %s", "ok" if ok else "failed")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(mqtt_host: str, mqtt_port: int, mqtt_user: str = "", mqtt_pass: str = ""):
    client = AgentMQTTClient(mqtt_host, mqtt_port, mqtt_user, mqtt_pass)
    client.connect()
    client.subscribe_deploy(_on_rule)
    client.publish_status("linux")
    log.info("Firewall deployer listening for rules…")
    try:
        while True:
            time.sleep(30)
            client.publish_status("linux")
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Linux firewall deployer")
    p.add_argument("--mqtt-host", default=os.getenv("MQTT_HOST", "localhost"))
    p.add_argument("--mqtt-port", type=int, default=int(os.getenv("MQTT_PORT", "1883")))
    p.add_argument("--mqtt-user", default=os.getenv("MQTT_USER", ""))
    p.add_argument("--mqtt-pass", default=os.getenv("MQTT_PASS", ""))
    args = p.parse_args()
    run(args.mqtt_host, args.mqtt_port, args.mqtt_user, args.mqtt_pass)
