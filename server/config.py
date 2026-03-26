import os

MQTT_HOST = os.getenv("MQTT_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_USER = os.getenv("MQTT_USER", "")
MQTT_PASS = os.getenv("MQTT_PASS", "")

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./netmon.db")

WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", "8000"))
SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")

# MQTT topic prefixes
TOPIC_SESSIONS = "netmon/sessions"        # agents publish here
TOPIC_DEPLOY   = "netmon/rules/deploy"    # server publishes deploy orders
TOPIC_REVOKE   = "netmon/rules/revoke"    # server publishes revoke orders
TOPIC_STATUS   = "netmon/status"          # agent heartbeats

# How many seconds before a duplicate session tuple is re-reported
SESSION_DEDUP_WINDOW = int(os.getenv("SESSION_DEDUP_WINDOW", "300"))
