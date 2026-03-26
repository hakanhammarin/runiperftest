"""
Shared MQTT publish helper used by both Windows and Linux agents.
"""

import json
import logging
import socket
import time
import uuid

import paho.mqtt.client as mqtt

log = logging.getLogger(__name__)


class AgentMQTTClient:
    """Thin wrapper around paho that reconnects automatically."""

    def __init__(self, host: str, port: int, user: str = "", password: str = "",
                 client_id: str = None):
        self.host     = host
        self.port     = port
        self.hostname = socket.gethostname()
        self._client  = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id or f"netmon-agent-{uuid.uuid4().hex[:8]}"
        )
        if user:
            self._client.username_pw_set(user, password)
        self._client.on_connect    = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._connected = False

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self._connected = True
            log.info("MQTT connected to %s:%s", self.host, self.port)
        else:
            log.error("MQTT connect error rc=%s", rc)

    def _on_disconnect(self, client, userdata, rc, properties=None, reasoncode=None):
        self._connected = False
        log.warning("MQTT disconnected rc=%s", rc)

    def connect(self):
        self._client.connect_async(self.host, self.port, keepalive=60)
        self._client.loop_start()
        # Wait up to 5 s for connection
        for _ in range(50):
            if self._connected:
                return
            time.sleep(0.1)
        log.warning("MQTT not connected after 5 s – will retry in background")

    def publish_session(self, session: dict):
        session.setdefault("hostname", self.hostname)
        topic = f"netmon/sessions/{self.hostname}"
        self._client.publish(topic, json.dumps(session), qos=0)

    def publish_status(self, os_type: str, ip: str = ""):
        payload = {"hostname": self.hostname, "os": os_type, "ip": ip}
        self._client.publish(f"netmon/status/{self.hostname}", json.dumps(payload), qos=0)

    def subscribe_deploy(self, callback):
        """Subscribe to inbound firewall deploy/revoke orders."""
        topic_deploy = f"netmon/rules/deploy/{self.hostname}"
        topic_revoke = f"netmon/rules/revoke/{self.hostname}"
        self._client.subscribe([(topic_deploy, 1), (topic_revoke, 1)])
        self._client.message_callback_add(topic_deploy,
            lambda c, u, m: callback("deploy", json.loads(m.payload.decode())))
        self._client.message_callback_add(topic_revoke,
            lambda c, u, m: callback("revoke", json.loads(m.payload.decode())))

    def disconnect(self):
        self._client.loop_stop()
        self._client.disconnect()
