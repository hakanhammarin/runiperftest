#!/usr/bin/env python3
"""
Windows firewall deployer.

Subscribes to netmon/rules/deploy/<hostname> and netmon/rules/revoke/<hostname>.

Deploy strategy:
  1. Generate an LGPO text file per rule (registry-based firewall policy)
  2. Compile to .pol with:   lgpo.exe /r out.pol /q /t in.txt
  3. Apply with:             lgpo.exe /m out.pol
  4. Track GUIDs in a local JSON ledger

Each rule is stored as a registry value under:
  HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules\{GUID}

LGPO text file format:
  Computer
  SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules
  {GUID}
  SZ:<rule-string>
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agents.common.mqtt_client import AgentMQTTClient

log = logging.getLogger(__name__)

LEDGER_PATH = Path(os.getenv("LEDGER_PATH",
    r"C:\ProgramData\NetMon\deployed_rules.json"))
LGPO_EXE    = Path(os.getenv("LGPO_EXE", r"C:\Windows\System32\lgpo.exe"))
WORK_DIR    = Path(os.getenv("WORK_DIR", r"C:\ProgramData\NetMon\rules"))


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
# LGPO / firewall rule building
# ---------------------------------------------------------------------------

_PROTO_MAP = {"tcp": "6", "udp": "17", "any": "*"}


def _build_rule_string(rule: dict) -> str:
    """
    Build the Windows Firewall rule value string.
    Format: v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|
            LPort=*|RPort=443|RA4=8.8.8.8|Name=Rule|Desc=...|
    """
    guid      = rule["guid"]
    direction = "In"  if rule.get("direction", "out").lower() == "in"  else "Out"
    action    = "Allow" if rule.get("action", "allow").lower() == "allow" else "Block"
    protocol  = _PROTO_MAP.get(rule.get("protocol", "tcp").lower(), "6")
    src_port  = rule.get("src_port", "*") or "*"
    dst_port  = rule.get("dst_port", "*") or "*"
    src_ip    = rule.get("src_ip",   "*") or "*"
    dst_ip    = rule.get("dst_ip",   "*") or "*"
    name      = rule.get("name", f"NetMon-{guid[:8]}")

    parts = [
        "v2.31",
        f"Action={action}",
        "Active=TRUE",
        f"Dir={direction}",
    ]
    if protocol != "*":
        parts.append(f"Protocol={protocol}")
    if src_ip != "*":
        parts.append(f"LA4={src_ip}")
    if dst_ip != "*":
        parts.append(f"RA4={dst_ip}")
    if src_port != "*":
        parts.append(f"LPort={src_port}")
    if dst_port != "*":
        parts.append(f"RPort={dst_port}")
    parts.append(f"Name={name}")
    parts.append(f"Desc=NetMon managed rule {guid}")
    parts.append("")  # trailing |
    return "|".join(parts)


def _write_lgpo_text(guid: str, rule_string: str, path: Path):
    """Write LGPO text file for a single rule."""
    content = (
        "Computer\n"
        "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules\n"
        f"{{{guid}}}\n"
        f"SZ:{rule_string}\n"
    )
    path.write_text(content, encoding="utf-8")


def _remove_lgpo_text(guid: str, path: Path):
    """Write LGPO text to DELETE a rule registry value."""
    content = (
        "Computer\n"
        "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules\n"
        f"{{{guid}}}\n"
        "DELETEVALUE\n"
    )
    path.write_text(content, encoding="utf-8")


def _apply_lgpo(txt_file: Path, pol_file: Path) -> tuple[bool, str]:
    """Compile txt → pol then apply with lgpo.exe."""
    if not LGPO_EXE.exists():
        return False, f"lgpo.exe not found at {LGPO_EXE}"

    # Compile
    r = subprocess.run(
        [str(LGPO_EXE), "/r", str(pol_file), "/q", "/t", str(txt_file)],
        capture_output=True, text=True, timeout=30
    )
    if r.returncode != 0:
        return False, f"lgpo compile: {r.stdout}{r.stderr}"

    # Apply
    r = subprocess.run(
        [str(LGPO_EXE), "/m", str(pol_file)],
        capture_output=True, text=True, timeout=30
    )
    if r.returncode != 0:
        return False, f"lgpo apply: {r.stdout}{r.stderr}"

    return True, "ok"


# ---------------------------------------------------------------------------
# Deploy / revoke
# ---------------------------------------------------------------------------

def deploy_rule(rule: dict) -> bool:
    guid = rule.get("guid", str(uuid.uuid4()).upper())
    ledger = _load_ledger()

    if guid in ledger:
        log.info("Rule %s already deployed", guid)
        return True

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    txt_file = WORK_DIR / f"{guid}.txt"
    pol_file = WORK_DIR / f"{guid}.pol"

    rule_string = _build_rule_string(rule)
    _write_lgpo_text(guid, rule_string, txt_file)

    ok, msg = _apply_lgpo(txt_file, pol_file)
    if not ok:
        log.error("Failed to deploy rule %s: %s", guid, msg)
        return False

    ledger[guid] = {"rule_string": rule_string, "rule": rule}
    _save_ledger(ledger)
    log.info("Deployed rule %s", guid)
    return True


def revoke_rule(guid: str) -> bool:
    ledger = _load_ledger()
    if guid not in ledger:
        log.warning("Rule %s not in ledger", guid)
        return False

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    txt_file = WORK_DIR / f"{guid}_del.txt"
    pol_file = WORK_DIR / f"{guid}_del.pol"

    _remove_lgpo_text(guid, txt_file)
    ok, msg = _apply_lgpo(txt_file, pol_file)
    if not ok:
        log.error("Failed to revoke rule %s: %s", guid, msg)
        return False

    del ledger[guid]
    _save_ledger(ledger)
    log.info("Revoked rule %s", guid)
    return True


# ---------------------------------------------------------------------------
# MQTT callback & main
# ---------------------------------------------------------------------------

def _on_rule(action: str, payload: dict):
    if action == "deploy":
        deploy_rule(payload)
    elif action == "revoke":
        revoke_rule(payload.get("guid", ""))


def run(mqtt_host: str, mqtt_port: int, mqtt_user: str = "", mqtt_pass: str = ""):
    client = AgentMQTTClient(mqtt_host, mqtt_port, mqtt_user, mqtt_pass)
    client.connect()
    client.subscribe_deploy(_on_rule)
    client.publish_status("windows")
    log.info("Windows firewall deployer listening…")
    try:
        while True:
            time.sleep(30)
            client.publish_status("windows")
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(description="Windows firewall deployer")
    p.add_argument("--mqtt-host", default=os.getenv("MQTT_HOST", "localhost"))
    p.add_argument("--mqtt-port", type=int, default=int(os.getenv("MQTT_PORT", "1883")))
    p.add_argument("--mqtt-user", default=os.getenv("MQTT_USER", ""))
    p.add_argument("--mqtt-pass", default=os.getenv("MQTT_PASS", ""))
    args = p.parse_args()
    run(args.mqtt_host, args.mqtt_port, args.mqtt_user, args.mqtt_pass)
