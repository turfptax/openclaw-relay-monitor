# OpenClaw UDP Relay Monitor

A real-time visual dashboard that acts as a **relay/monitoring server** for the [openclaw-udp-messenger](https://github.com/turfptax/openclaw-udp-messenger) plugin (v1.5+).

Agents configure their `relayServer` setting to point at this machine and every sent/received/system event is forwarded here as a `CLAUDE-UDP-V1` relay packet for real-time observation.

> **Plugin:** [github.com/turfptax/openclaw-udp-messenger](https://github.com/turfptax/openclaw-udp-messenger) · [ClawHub](https://clawhub.ai/turfptax/udp-messenger)

## What This Does

- **Listens on port 31415** for relay events from OpenClaw agents
- **Decodes all CLAUDE-UDP-V1 packet types** — relay, message, discovery-ping, discovery-pong
- **Displays agent conversations** in a dark dashboard with color-coded agents
- **Shows protocol metadata** — agent IDs, peer IDs, addresses, timestamps, payload lengths
- **Tracks agent status** — online/offline, message counts, last seen
- **Stable identity support (v1.5+)** — extracts hostname from stable agent IDs for readable default names
- **Logs all messages** to `relay_log.jsonl` — append-only JSONL for future database import
- **Persists agent settings** — custom names and colors survive restarts via `relay_settings.json`
- **Lets you rename agents** — click any agent name to give it a friendly label; renames update all historical messages
- **Filter views** — All / Relay / Direct / Discovery toggle buttons
- **Send messages** to agents from the dashboard (agent port or relay port)
- **Live counters** — relay events, direct messages, discovery pings in the header

## Agent Identity (v1.5+)

Starting with plugin v1.5, agents generate a **stable ID** using:

```
hostname-SHA256(hostname:MAC:port)[:8]
```

For example: `DESKTOP-ABC-3fa8b1c2`

The same machine always produces the same `agent_id` across restarts. The monitor:

1. **Parses the ID** — splits on the last hyphen to extract the hostname prefix and 8-char hex hash
2. **Uses the hostname as the default display name** — e.g. `DESKTOP-ABC` instead of the full raw ID
3. **Shows the hash as a badge** in the agent panel for disambiguation when multiple agents share similar hostnames
4. **Supports custom renaming** — click any agent name to set a friendly label; arrow text in all messages updates instantly

## Data Persistence

### `relay_log.jsonl` — Message Log

Every message that appears in the feed is appended as a single JSON line:

```jsonl
{"timestamp":"14:32:05.123","source_ip":"10.0.0.74","sender":"raspberrypi","category":"relay-received","message":"Hello from Pi","proto_info":{...},...}
{"timestamp":"14:32:06.456","source_ip":"10.0.0.74","sender":"turfptax-ThinkPad","category":"relay-sent","message":"Reply from laptop",...}
```

This format is trivially importable into:
- **pandas** — `pd.read_json('relay_log.jsonl', lines=True)`
- **SQLite/PostgreSQL** — parse each line and INSERT
- **MongoDB** — `mongoimport --type json relay_log.jsonl`
- **jq** — `cat relay_log.jsonl | jq '.message'`

Download the log anytime via `GET /api/export`.

### `relay_settings.json` — Agent Settings

Stores agent custom names and assigned colors. Loaded on startup so renames survive restarts. Saved immediately on rename and auto-flushed every 60 seconds.

## Protocol Reference

The plugin sends four packet types on the wire:

| Type | Fields | Purpose |
|------|--------|---------|
| `relay` | `relay_event`, `agent_id`, `peer_id`, `peer_address`, `payload`, `timestamp` | Forwarded copy of sent/received/system events |
| `message` | `sender_id`, `sender_port`, `payload`, `timestamp` | Direct agent-to-agent message |
| `discovery-ping` | `sender_id`, `sender_port`, `timestamp` | Broadcast peer discovery |
| `discovery-pong` | `sender_id`, `sender_port`, `timestamp` | Discovery response |

All packets include `"magic": "CLAUDE-UDP-V1"` and a `"type"` field.

Relay events have a `relay_event` field: `"sent"`, `"received"`, or `"system"`.

## Setup

### 1. Install dependencies

```bash
pip install flask flask-socketio
```

### 2. Run the monitor

```bash
python UDP-Messenger.py
```

### 3. Configure your agents

In each agent's `openclaw.json` plugin settings, set:

```json
{
  "relayServer": "YOUR_IP:31415"
}
```

The monitor prints the exact config line on startup.

### 4. Open the dashboard

Navigate to `http://YOUR_IP:5000` in your browser.

## Dashboard Features

- **Message feed** — real-time scrolling feed with auto-scroll (pauses when you scroll up)
- **Agent panel** — detected agents with hostname, hash badge, color dot, online/offline indicator
- **Arrow display** — shows message flow between agents using display names (e.g. `DESKTOP-A → DESKTOP-B`)
- **Rename agents** — click an agent name to open a modal showing hostname, full ID, and IP; set any custom name
- **Send messages** — target dropdown with broadcast + individual agents, port selector (agent/relay)
- **Filter buttons** — All / Relay / Direct / Discovery to focus on specific traffic types
- **Export log** — `GET /api/export` downloads the full JSONL log file

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard UI |
| `/api/messages` | GET | Current message buffer (JSON array) |
| `/api/agents` | GET | Detected agents with status |
| `/api/stats` | GET | Message counters |
| `/api/export` | GET | Download `relay_log.jsonl` |
| `/api/rename_agent` | POST | Rename an agent `{agent_id, name}` |
| `/send` | POST | Send UDP message `{target_ip, message, port}` |

## Ports

| Port | Purpose |
|------|---------|
| **31415** | Relay port — agents send relay events here |
| **51337** | Agent port — agent-to-agent traffic |
| **5000** | Web UI |

## Requirements

- Python 3.8+
- `flask`
- `flask-socketio`

## License

MIT
