# NetMon – Network Session Firewall Management

Lightweight, MQTT-backed system to collect TCP/UDP sessions from Windows and
Linux hosts, review them centrally through a web UI, and distribute approved
firewall rules back to each host automatically.

---

## Architecture

```
 Windows Host                Linux Host
 +-----------------+         +-----------------+
 | session_collect |         | session_collect |
 | (firewall log   |         | (/proc/net/tcp  |
 |  or netstat)    |         |  /proc/net/udp) |
 | firewall_deploy |         | firewall_deploy |
 | (LGPO + .pol)   |         | (firewall-cmd)  |
 +------+----------+         +--------+--------+
        |  MQTT publish sessions       |
        v                              v
   +-------------------------------------+
   |      MQTT Broker (Mosquitto)        |
   +------------------+------------------+
                      |
            +---------v----------+
            |   NetMon Server    |
            |  +-------------+  |
            |  | MQTT sub    |  |  Subscribe sessions
            |  | SQLite DB   |  |  Store 5-tuples
            |  | FastAPI UI  |  |  Review + approve
            |  +-------------+  |
            +---------+---------+
                      |  MQTT publish deploy/revoke
            +---------v----------+
            |  MQTT Broker       |  -> agents receive and apply rules
            +--------------------+
```

## MQTT Topics

| Topic                         | Direction       | Description                |
|------------------------------|-----------------|----------------------------|
| `netmon/sessions/{hostname}` | Agent -> Server | Observed 5-tuple sessions  |
| `netmon/status/{hostname}`   | Agent -> Server | Agent heartbeat            |
| `netmon/rules/deploy/{host}` | Server -> Agent | Deploy a firewall rule     |
| `netmon/rules/revoke/{host}` | Server -> Agent | Revoke a deployed rule     |

## Quick Start (Docker)

```bash
cp .env.example .env
docker compose up -d
# Web UI: http://localhost:8000
```

## Server (bare metal)

```bash
pip install -r server/requirements.txt
python -m server.main
```

## Linux Agent

```bash
pip install -r agents/linux/requirements.txt

# Collector (no root required)
MQTT_HOST=<server> python agents/linux/session_collector.py

# Deployer (run as root for firewall-cmd)
MQTT_HOST=<server> python agents/linux/firewall_deployer.py

# Install as systemd services:
sudo MQTT_HOST=<server> bash agents/linux/install.sh
```

## Windows Agent

### Requirements
- Python 3.10+
- `paho-mqtt`  (`pip install paho-mqtt`)
- `lgpo.exe` in `C:\Windows\System32\` (from Microsoft Security Compliance Toolkit)

### Enable Firewall Logging (run as Administrator)

```powershell
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging maxfilesize 4096
```

### Install as Windows services

```powershell
# Run PowerShell as Administrator
.\agents\windows\install.ps1 -MqttHost <server-ip>

# With NSSM for better service control:
.\agents\windows\install.ps1 -MqttHost <server-ip> -NssmPath C:\tools\nssm.exe
```

### Run manually

```powershell
$env:MQTT_HOST = "<server>"
python agents\windows\session_collector.py
python agents\windows\firewall_deployer.py
```

## Workflow

1. Agents start and publish observed TCP/UDP sessions to MQTT.
2. Server deduplicates by 5-tuple per host and stores in SQLite.
3. Operator opens web UI -> **Sessions** -> reviews pending entries.
4. Click **Allow**: choose direction (in/out) and action (allow/deny).
5. Server creates a `FirewallRule` with a unique GUID and publishes a deploy order.
6. The agent on the target host applies the rule:
   - **Windows**: generates LGPO text -> compiles to `.pol` -> applies with `lgpo.exe`
   - **Linux**: adds a `firewall-cmd` permanent rich rule
7. To revoke: **Firewall Rules** -> **Revoke** -> MQTT revoke order sent to agent.

## Windows LGPO Rule Details

Rules land in the registry at:

```
HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules\{GUID}
```

Each `.pol` file is saved to `C:\ProgramData\NetMon\rules\{GUID}.pol` for audit.
The GUID is unique per rule and is used for targeted revocation.

## Linux firewalld Rule Details

Rules are added as permanent firewalld rich rules to the default zone.
A local ledger at `/var/lib/netmon/deployed_rules.json` tracks GUIDs for revocation.

## Configuration

All settings via environment variables or `.env` file:

| Variable         | Default               | Description                   |
|-----------------|-----------------------|-------------------------------|
| `MQTT_HOST`     | `localhost`           | MQTT broker host              |
| `MQTT_PORT`     | `1883`                | MQTT broker port              |
| `MQTT_USER`     | *(empty)*             | MQTT username                 |
| `MQTT_PASS`     | *(empty)*             | MQTT password                 |
| `DATABASE_URL`  | `sqlite:///netmon.db` | SQLAlchemy database URL       |
| `WEB_PORT`      | `8000`                | Web UI port                   |
| `SECRET_KEY`    | *(change me)*         | Session secret key            |
| `POLL_INTERVAL` | `30`                  | Agent poll interval (seconds) |
