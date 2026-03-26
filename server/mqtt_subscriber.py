"""
MQTT subscriber that runs as a background thread.
Receives session reports from agents and stores them in the database.
Also publishes firewall rule deploy/revoke orders.
"""

import json
import logging
import threading
import uuid
from datetime import datetime

import paho.mqtt.client as mqtt

from server import config
from server.database import SessionLocal, Session, Host, FirewallRule

log = logging.getLogger(__name__)

_client: mqtt.Client = None
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Publish helpers (called from web layer)
# ---------------------------------------------------------------------------

def publish_deploy(hostname: str, rule: dict):
    """Send a firewall rule deploy order to a specific host."""
    if _client is None:
        log.warning("MQTT client not initialised – cannot publish deploy")
        return
    topic = f"{config.TOPIC_DEPLOY}/{hostname}"
    _client.publish(topic, json.dumps(rule), qos=1, retain=False)
    log.info("Published deploy to %s: %s", topic, rule.get("guid"))


def publish_revoke(hostname: str, guid: str):
    """Send a firewall rule revoke order to a specific host."""
    if _client is None:
        log.warning("MQTT client not initialised – cannot publish revoke")
        return
    topic = f"{config.TOPIC_REVOKE}/{hostname}"
    _client.publish(topic, json.dumps({"guid": guid}), qos=1, retain=False)
    log.info("Published revoke to %s: guid=%s", topic, guid)


# ---------------------------------------------------------------------------
# Internal MQTT callbacks
# ---------------------------------------------------------------------------

def _on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        log.info("Connected to MQTT broker")
        client.subscribe(f"{config.TOPIC_SESSIONS}/#", qos=0)
        client.subscribe(f"{config.TOPIC_STATUS}/#", qos=0)
    else:
        log.error("MQTT connect failed, rc=%s", rc)


def _on_message(client, userdata, msg):
    topic = msg.topic
    try:
        payload = json.loads(msg.payload.decode())
    except Exception as exc:
        log.warning("Bad payload on %s: %s", topic, exc)
        return

    if topic.startswith(config.TOPIC_SESSIONS + "/"):
        _handle_session(payload)
    elif topic.startswith(config.TOPIC_STATUS + "/"):
        _handle_status(payload)


def _handle_status(payload: dict):
    hostname = payload.get("hostname", "").strip()
    os_type  = payload.get("os", "linux").strip()
    ip       = payload.get("ip", "")
    if not hostname:
        return
    db = SessionLocal()
    try:
        host = db.query(Host).filter(Host.hostname == hostname).first()
        if host:
            host.last_seen = datetime.utcnow()
            host.online    = True
            if ip:
                host.ip = ip
        else:
            db.add(Host(hostname=hostname, os_type=os_type, ip=ip,
                        last_seen=datetime.utcnow(), online=True))
        db.commit()
    except Exception as exc:
        db.rollback()
        log.error("DB error in _handle_status: %s", exc)
    finally:
        db.close()


def _handle_session(payload: dict):
    hostname = payload.get("hostname", "").strip()
    os_type  = payload.get("os", "linux").strip()
    protocol = payload.get("protocol", "tcp").lower().strip()
    src_ip   = payload.get("src_ip", "").strip()
    src_port = int(payload.get("src_port", 0))
    dst_ip   = payload.get("dst_ip", "").strip()
    dst_port = int(payload.get("dst_port", 0))
    state    = payload.get("state", "")
    process  = payload.get("process", "")
    direction = payload.get("direction", "out")

    if not (hostname and src_ip and dst_ip):
        return

    db = SessionLocal()
    try:
        # Upsert host
        host = db.query(Host).filter(Host.hostname == hostname).first()
        if host:
            host.last_seen = datetime.utcnow()
            host.online    = True
        else:
            db.add(Host(hostname=hostname, os_type=os_type,
                        last_seen=datetime.utcnow(), online=True))
            db.flush()

        # Upsert session tuple
        existing = db.query(Session).filter(
            Session.hostname == hostname,
            Session.protocol == protocol,
            Session.src_ip   == src_ip,
            Session.src_port == src_port,
            Session.dst_ip   == dst_ip,
            Session.dst_port == dst_port,
        ).first()

        if existing:
            existing.last_seen  = datetime.utcnow()
            existing.hit_count += 1
            if state:
                existing.state = state
        else:
            db.add(Session(
                hostname=hostname, protocol=protocol,
                src_ip=src_ip, src_port=src_port,
                dst_ip=dst_ip, dst_port=dst_port,
                direction=direction, state=state, process=process,
                first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
            ))
        db.commit()
    except Exception as exc:
        db.rollback()
        log.error("DB error in _handle_session: %s", exc)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Start / stop
# ---------------------------------------------------------------------------

def start():
    global _client
    with _lock:
        if _client is not None:
            return
        _client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                              client_id=f"netmon-server-{uuid.uuid4().hex[:8]}")
        if config.MQTT_USER:
            _client.username_pw_set(config.MQTT_USER, config.MQTT_PASS)
        _client.on_connect = _on_connect
        _client.on_message = _on_message
        _client.connect_async(config.MQTT_HOST, config.MQTT_PORT, keepalive=60)
        _client.loop_start()
        log.info("MQTT subscriber started → %s:%s", config.MQTT_HOST, config.MQTT_PORT)


def stop():
    global _client
    with _lock:
        if _client:
            _client.loop_stop()
            _client.disconnect()
            _client = None
