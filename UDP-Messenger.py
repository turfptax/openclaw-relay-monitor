"""
OpenClaw UDP Relay Monitor
==========================
Visual relay/monitoring dashboard for the openclaw-udp-messenger plugin v1.5+.
  https://github.com/turfptax/openclaw-udp-messenger
  https://clawhub.ai/turfptax/udp-messenger

Agents set  relayServer: "THIS_IP:31415"  in their openclaw.json and every
sent/received/system event is forwarded here for real-time observation by a
human operator.

Agent identity (v1.5+):
  Agents generate a stable ID:  hostname-SHA256(hostname:MAC:port)[:8]
  The same machine always produces the same agent_id across restarts.
  This monitor extracts the hostname prefix for a readable default name
  and shows the full hash for disambiguation.

Protocol — four packet types:
  discovery-ping  {magic, type, sender_id, sender_port, timestamp}
  discovery-pong  {magic, type, sender_id, sender_port, timestamp}
  message         {magic, type, sender_id, sender_port, payload, timestamp}
  relay           {magic, type, relay_event, agent_id, peer_id,
                   peer_address, payload, timestamp}

Relay events:  "sent" | "received" | "system"
All packets carry  magic: "CLAUDE-UDP-V1".

Persistence:
  relay_log.jsonl     — append-only log of every message (one JSON per line)
  relay_settings.json — agent custom names and colors, survives restarts
"""

import os
import socket
import threading
import json
import time
import sys
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_socketio import SocketIO

# =============================================================================
# Configuration
# =============================================================================
RELAY_PORT   = 31415        # Default relay port — agents send events here
AGENT_PORT   = 51337        # Agent-to-agent port (for sending from the UI)
WEB_PORT     = 5000
MAX_MESSAGES = 500
BIND_ADDRESS = '0.0.0.0'

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
LOG_FILE      = os.path.join(BASE_DIR, 'relay_log.jsonl')
SETTINGS_FILE = os.path.join(BASE_DIR, 'relay_settings.json')

STALE_AGENT_HOURS = 24      # Prune agents not seen in this many hours

# =============================================================================
# State  (all guarded by _lock)
# =============================================================================
_lock = threading.RLock()

MESSAGES      = []
AGENTS        = {}           # keyed by agent_id string
AGENT_COUNTER = 0
START_TIME    = time.time()
STATS         = {'relay': 0, 'discovery': 0, 'message': 0, 'unknown': 0}

AGENT_COLORS = [
    '#00d4ff', '#ff6b6b', '#51cf66', '#ffd43b', '#cc5de8',
    '#ff922b', '#20c997', '#e599f7', '#74c0fc', '#f06595',
]

_running   = True            # Listener shutdown flag
_send_sock = None            # Reusable send socket

app = Flask(__name__)
app.config['SECRET_KEY'] = 'openclaw-relay-monitor'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

# =============================================================================
# Helpers — network interface discovery
# =============================================================================
def get_all_interfaces():
    """Return a list of IPv4 interfaces: [{name, ip, broadcast, netmask}].
    Uses socket/OS methods for cross-platform support (Windows, Linux, macOS).
    """
    interfaces = []
    seen_ips = set()

    # ── Method 1: netifaces (most reliable if installed) ─────────
    try:
        import netifaces
        for iface_name in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface_name)
            for info in addrs.get(netifaces.AF_INET, []):
                ip = info.get('addr', '')
                if ip and ip != '127.0.0.1' and ip not in seen_ips:
                    seen_ips.add(ip)
                    broadcast = info.get('broadcast', '')
                    if not broadcast:
                        parts = ip.split('.')
                        parts[3] = '255'
                        broadcast = '.'.join(parts)
                    interfaces.append({
                        'name': iface_name,
                        'ip': ip,
                        'broadcast': broadcast,
                        'netmask': info.get('netmask', '255.255.255.0'),
                    })
        if interfaces:
            return interfaces
    except ImportError:
        pass

    # ── Method 2: psutil (common on many systems) ────────────────
    try:
        import psutil
        for iface_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                    ip = addr.address
                    if ip in seen_ips or ip.startswith('169.254.'):
                        continue   # skip link-local / APIPA
                    seen_ips.add(ip)
                    broadcast = addr.broadcast or ''
                    if not broadcast:
                        parts = ip.split('.')
                        parts[3] = '255'
                        broadcast = '.'.join(parts)
                    interfaces.append({
                        'name': iface_name,
                        'ip': ip,
                        'broadcast': broadcast,
                        'netmask': addr.netmask or '255.255.255.0',
                    })
        if interfaces:
            return interfaces
    except ImportError:
        pass

    # ── Method 3: socket.getaddrinfo fallback ────────────────────
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and ip != '127.0.0.1' and ip not in seen_ips:
                seen_ips.add(ip)
                parts = ip.split('.')
                parts[3] = '255'
                interfaces.append({
                    'name': f'if-{len(interfaces)}',
                    'ip': ip,
                    'broadcast': '.'.join(parts),
                    'netmask': '255.255.255.0',
                })
    except Exception:
        pass

    # ── Method 4: UDP connect trick (always gets at least one) ───
    if not interfaces:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
            s.close()
            if ip and ip != '127.0.0.1':
                parts = ip.split('.')
                parts[3] = '255'
                interfaces.append({
                    'name': 'default',
                    'ip': ip,
                    'broadcast': '.'.join(parts),
                    'netmask': '255.255.255.0',
                })
        except Exception:
            pass

    # ── Last resort ──────────────────────────────────────────────
    if not interfaces:
        interfaces.append({
            'name': 'loopback',
            'ip': '127.0.0.1',
            'broadcast': '255.255.255.255',
            'netmask': '255.0.0.0',
        })

    return interfaces

INTERFACES   = get_all_interfaces()
LOCAL_IP     = INTERFACES[0]['ip']          # primary IP (for display)
BROADCAST_IP = INTERFACES[0]['broadcast']   # primary broadcast

def parse_agent_id(agent_id):
    """
    Split a stable agent_id like 'DESKTOP-ABC-3fa8b1c2' into
    (hostname, hash).  If there's no hash suffix return (agent_id, '').
    The plugin format is:  hostname-<8hex>
    We split on the *last* hyphen so hostnames with hyphens are preserved.
    """
    if not agent_id:
        return ('', '')
    idx = agent_id.rfind('-')
    if idx > 0 and len(agent_id) - idx - 1 == 8:
        suffix = agent_id[idx + 1:]
        if all(c in '0123456789abcdefABCDEF' for c in suffix):
            return (agent_id[:idx], suffix)
    return (agent_id, '')

# =============================================================================
# Persistence — JSONL log  +  settings
# =============================================================================
_saved_settings = {}   # loaded at startup, keyed by agent_id

def _load_settings():
    """Load relay_settings.json if it exists.  Returns dict."""
    global _saved_settings
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
            _saved_settings = data.get('agents', {})
            print(f"  Settings loaded: {len(_saved_settings)} agent(s)")
    except Exception as e:
        print(f"  Warning: could not load settings: {e}", file=sys.stderr)
        _saved_settings = {}

def _save_settings():
    """Persist agent custom names and colors to relay_settings.json."""
    with _lock:
        agents_data = {}
        for aid, a in AGENTS.items():
            if a.get('custom_name') or a.get('color'):
                agents_data[aid] = {
                    'custom_name': a.get('custom_name'),
                    'color':       a.get('color', ''),
                    'hostname':    a.get('hostname', ''),
                }
    try:
        tmp = SETTINGS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump({
                'agents':   agents_data,
                'saved_at': datetime.now().isoformat(),
            }, f, indent=2)
        os.replace(tmp, SETTINGS_FILE)
    except Exception as e:
        print(f"  Warning: could not save settings: {e}", file=sys.stderr)

def _log_message(msg_entry):
    """Append one message to the JSONL log.  Never raises."""
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(msg_entry, default=str) + '\n')
    except Exception:
        pass   # logging failure must not kill the listener

def _settings_flush_loop():
    """Background thread: save settings every 60 seconds."""
    while _running:
        time.sleep(60)
        _save_settings()

# =============================================================================
# Protocol decoder
# =============================================================================
def decode_packet(raw):
    """
    Returns (info_dict | None, display_text, category).
    Categories: relay-sent, relay-received, relay-system,
                discovery, message, unknown
    """
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None, raw, 'unknown'

    if not isinstance(obj, dict) or obj.get('magic') != 'CLAUDE-UDP-V1':
        return None, raw, 'unknown'

    msg_type = obj.get('type', 'unknown')

    # ── Relay ────────────────────────────────────────────
    if msg_type == 'relay':
        relay_event = obj.get('relay_event', 'unknown')
        agent_id    = obj.get('agent_id', '???')
        peer_id     = obj.get('peer_id', '')
        peer_addr   = obj.get('peer_address', '')
        payload     = obj.get('payload', '')
        ts          = obj.get('timestamp')

        info = {
            'protocol': 'CLAUDE-UDP-V1', 'msg_type': 'relay',
            'relay_event': relay_event,
            'agent_id': agent_id, 'peer_id': peer_id,
            'peer_address': peer_addr,
        }
        _add_ts(info, ts)
        if payload:
            info['payload_length'] = len(payload)

        if relay_event == 'sent':
            info['from_id'] = agent_id
            info['to_id']   = peer_id or peer_addr
            info['speaker'] = agent_id       # the agent spoke
            display  = payload or f'[SENT to {peer_id or peer_addr}]'
            category = 'relay-sent'
        elif relay_event == 'received':
            info['from_id'] = peer_id or peer_addr
            info['to_id']   = agent_id
            info['speaker'] = peer_id or peer_addr  # the *peer* spoke
            display  = payload or f'[RECEIVED from {peer_id or peer_addr}]'
            category = 'relay-received'
        else:
            info['from_id'] = agent_id
            info['to_id']   = ''
            info['speaker'] = agent_id
            display  = payload or f'[SYSTEM] {relay_event}'
            category = 'relay-system'
        return info, display, category

    # ── Discovery ────────────────────────────────────────
    if msg_type in ('discovery-ping', 'discovery-pong'):
        sender_id   = obj.get('sender_id', '???')
        sender_port = obj.get('sender_port', '?')
        ts          = obj.get('timestamp')
        info = {
            'protocol': 'CLAUDE-UDP-V1', 'msg_type': msg_type,
            'sender_id': sender_id, 'sender_port': sender_port,
            'speaker': sender_id,
        }
        _add_ts(info, ts)
        label = 'PING' if msg_type == 'discovery-ping' else 'PONG'
        display = f'[{label}] {sender_id} (port {sender_port})'
        return info, display, 'discovery'

    # ── Direct message ───────────────────────────────────
    if msg_type == 'message':
        sender_id   = obj.get('sender_id', '???')
        sender_port = obj.get('sender_port', '?')
        payload     = obj.get('payload', '')
        ts          = obj.get('timestamp')
        info = {
            'protocol': 'CLAUDE-UDP-V1', 'msg_type': 'message',
            'sender_id': sender_id, 'sender_port': sender_port,
            'speaker': sender_id,
        }
        _add_ts(info, ts)
        if payload:
            info['payload_length'] = len(payload)
        return info, payload, 'message'

    return None, raw, 'unknown'

def _add_ts(info, ts):
    if ts:
        try:
            info['protocol_time'] = datetime.fromtimestamp(
                ts / 1000).strftime('%H:%M:%S.%f')[:-3]
        except Exception:
            info['protocol_time'] = str(ts)

# =============================================================================
# Agent registry
# =============================================================================
def register_agent(agent_id, ip=None, count=True):
    """Register or update an agent.  Returns the agent dict or None.
    Set count=False when registering a peer reference (don't bump msg count).
    """
    global AGENT_COUNTER
    if not agent_id:
        return None

    with _lock:
        if agent_id not in AGENTS:
            hostname, hashsuffix = parse_agent_id(agent_id)
            # Restore saved settings if available
            saved = _saved_settings.get(agent_id, {})
            color = saved.get('color') or AGENT_COLORS[AGENT_COUNTER % len(AGENT_COLORS)]
            AGENT_COUNTER += 1
            AGENTS[agent_id] = {
                'agent_id':      agent_id,
                'hostname':      hostname,
                'hash':          hashsuffix,
                'name':          hostname or agent_id,
                'custom_name':   saved.get('custom_name'),
                'color':         color,
                'last_seen':     time.time(),
                'message_count': 0,
                'ip':            ip or '',
            }

        a = AGENTS[agent_id]
        if ip:
            a['ip'] = ip
        a['last_seen'] = time.time()
        if count:
            a['message_count'] += 1
        return a

def dname(agent):
    """Display name for an agent dict."""
    if agent is None:
        return 'Unknown'
    return agent.get('custom_name') or agent['name']

def dname_for_id(agent_id):
    """Display name looked up by agent_id string."""
    with _lock:
        a = AGENTS.get(agent_id)
    if a:
        return dname(a)
    hostname, _ = parse_agent_id(agent_id)
    return hostname or agent_id

def acolor(agent):
    return agent['color'] if agent else '#6e7681'

def _cleanup_stale_agents():
    """Background thread: prune agents not seen in STALE_AGENT_HOURS."""
    while _running:
        time.sleep(3600)
        cutoff = time.time() - STALE_AGENT_HOURS * 3600
        with _lock:
            stale = [aid for aid, a in AGENTS.items()
                     if a['last_seen'] < cutoff]
            for aid in stale:
                del AGENTS[aid]
        if stale:
            print(f"  Pruned {len(stale)} stale agent(s)")
            socketio.emit('agents_update', get_agents_list())

# =============================================================================
# Listener
# =============================================================================
def udp_listener():
    global _running
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except Exception:
        pass
    sock.bind((BIND_ADDRESS, RELAY_PORT))
    sock.settimeout(1.0)
    print(f"  Relay listener on {BIND_ADDRESS}:{RELAY_PORT}")

    try:
        while _running:
            # ── Receive ──────────────────────────────────
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                print(f"  Socket error: {e}", file=sys.stderr)
                break

            try:
                raw         = data.decode('utf-8', errors='replace')
                source_ip   = addr[0]
                source_port = addr[1]
                now         = datetime.now()
                timestamp   = now.strftime('%H:%M:%S.') + f'{now.microsecond // 1000:03d}'

                info, display_text, category = decode_packet(raw)

                # ── Register agents ──────────────────────
                if info:
                    primary_id = info.get('agent_id') or info.get('sender_id') or source_ip
                else:
                    primary_id = source_ip
                agent = register_agent(primary_id, source_ip)

                # Register peer (seen in relay) without bumping its count
                peer_id = info.get('peer_id') if info else None
                if peer_id:
                    register_agent(peer_id, count=False)

                # ── Determine speaker (who said the message) ──
                speaker_id = (info.get('speaker') if info else None) or primary_id
                speaker_agent = AGENTS.get(speaker_id)

                # ── Build arrow string ───────────────────
                arrow = ''
                if info and 'from_id' in info:
                    fn = dname_for_id(info['from_id'])
                    tn = dname_for_id(info['to_id']) if info.get('to_id') else ''
                    if tn:
                        arrow = f'{fn}  →  {tn}'
                    else:
                        arrow = fn

                # ── Stats ────────────────────────────────
                with _lock:
                    if category.startswith('relay'):
                        STATS['relay'] += 1
                    elif category == 'discovery':
                        STATS['discovery'] += 1
                    elif category == 'message':
                        STATS['message'] += 1
                    else:
                        STATS['unknown'] += 1

                msg_entry = {
                    'timestamp':   timestamp,
                    'source_ip':   source_ip,
                    'source_port': source_port,
                    'sender':      dname(speaker_agent) if speaker_agent else dname_for_id(speaker_id),
                    'sender_id':   speaker_id,
                    'color':       acolor(speaker_agent) if speaker_agent else '#6e7681',
                    'message':     display_text,
                    'raw_message': raw,
                    'is_json':     info is None and _is_json(raw),
                    'is_protocol': info is not None,
                    'proto_info':  info,
                    'category':    category,
                    'arrow':       arrow,
                }

                with _lock:
                    MESSAGES.append(msg_entry)
                    if len(MESSAGES) > MAX_MESSAGES:
                        MESSAGES.pop(0)

                _log_message(msg_entry)
                socketio.emit('new_message', msg_entry)
                socketio.emit('agents_update', get_agents_list())
                socketio.emit('stats_update', STATS)

            except Exception as e:
                print(f"  Packet processing error: {e}", file=sys.stderr)

    finally:
        sock.close()
        print("  Relay listener stopped")

def _is_json(s):
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, ValueError):
        return False

# =============================================================================
# Send (monitor UI → agents)
# =============================================================================
def _init_send_socket():
    global _send_sock
    _send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

def send_udp_message(target_ip, message, port=AGENT_PORT, bind_ip=None):
    try:
        # If a specific interface is requested, create a bound socket
        if bind_ip:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((bind_ip, 0))
            sock.sendto(message.encode('utf-8'), (target_ip, port))
            sock.close()
        else:
            _send_sock.sendto(message.encode('utf-8'), (target_ip, port))

        now = datetime.now()
        timestamp = now.strftime('%H:%M:%S.') + f'{now.microsecond // 1000:03d}'
        msg_entry = {
            'timestamp': timestamp, 'source_ip': bind_ip or LOCAL_IP,
            'source_port': port, 'sender': 'Monitor', 'sender_id': '_monitor_',
            'color': '#ffffff',
            'message': message, 'raw_message': message,
            'is_json': _is_json(message), 'is_protocol': False,
            'proto_info': None, 'category': 'monitor-out', 'arrow': '',
        }

        with _lock:
            MESSAGES.append(msg_entry)
            if len(MESSAGES) > MAX_MESSAGES:
                MESSAGES.pop(0)

        _log_message(msg_entry)
        socketio.emit('new_message', msg_entry)
        return True
    except Exception as e:
        print(f"  Send error: {e}", file=sys.stderr)
        return False

# =============================================================================
# Agent list & rename
# =============================================================================
def get_agents_list():
    now = time.time()
    out = []
    with _lock:
        for aid, a in AGENTS.items():
            out.append({
                'agent_id':      aid,
                'hostname':      a.get('hostname', ''),
                'hash':          a.get('hash', ''),
                'ip':            a.get('ip', ''),
                'name':          dname(a),
                'default_name':  a['name'],
                'custom_name':   a.get('custom_name') or '',
                'color':         a['color'],
                'online':        (now - a['last_seen']) < 60,
                'last_seen':     datetime.fromtimestamp(a['last_seen']).strftime('%H:%M:%S'),
                'message_count': a['message_count'],
            })
    return out

def _update_messages_for_agent(agent_id):
    """Update sender labels and arrows for all messages involving agent_id."""
    dn = dname_for_id(agent_id)
    with _lock:
        for msg in MESSAGES:
            pi = msg.get('proto_info')
            if not pi:
                continue
            # Update sender label if this agent is the speaker
            if msg.get('sender_id') == agent_id:
                msg['sender'] = dn
            # Rebuild arrow if either end matches
            if 'from_id' in pi and agent_id in (pi.get('from_id'), pi.get('to_id', '')):
                fn = dname_for_id(pi['from_id'])
                tn = dname_for_id(pi['to_id']) if pi.get('to_id') else ''
                msg['arrow'] = f'{fn}  →  {tn}' if tn else fn

# =============================================================================
# Routes
# =============================================================================
_cached_html = None

@app.route('/')
def index():
    global _cached_html
    if _cached_html is None:
        _cached_html = render_template_string(HTML_TEMPLATE,
            local_ip=LOCAL_IP, broadcast_ip=BROADCAST_IP,
            relay_port=RELAY_PORT, agent_port=AGENT_PORT,
            interfaces=INTERFACES)
    return _cached_html

@app.route('/api/messages')
def api_messages():
    with _lock:
        return jsonify(list(MESSAGES))

@app.route('/api/agents')
def api_agents():
    return jsonify(get_agents_list())

@app.route('/api/stats')
def api_stats():
    with _lock:
        return jsonify(dict(STATS))

@app.route('/api/interfaces')
def api_interfaces():
    return jsonify(INTERFACES)

@app.route('/api/export')
def api_export():
    """Download the full JSONL log file."""
    if os.path.exists(LOG_FILE):
        return send_file(LOG_FILE, mimetype='application/x-ndjson',
                         as_attachment=True,
                         download_name='relay_log.jsonl')
    return jsonify({'error': 'No log file yet'}), 404

@app.route('/send', methods=['POST'])
def handle_send():
    data = request.json or {}
    target  = data.get('target_ip', BROADCAST_IP)
    message = data.get('message', '')
    bind_ip = data.get('bind_ip', None)    # interface IP to send from
    # Validate port
    try:
        port = int(data.get('port', AGENT_PORT))
        if not (1 <= port <= 65535):
            return jsonify({'success': False, 'error': 'Invalid port'})
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'Invalid port'})
    if not message:
        return jsonify({'success': False, 'error': 'Empty message'})
    return jsonify({'success': send_udp_message(target, message, port, bind_ip)})

@app.route('/api/rename_agent', methods=['POST'])
def rename_agent():
    data     = request.json or {}
    agent_id = data.get('agent_id', '')
    new_name = data.get('name', '').strip()

    with _lock:
        if agent_id not in AGENTS:
            return jsonify({'success': False, 'error': 'Agent not found'})
        AGENTS[agent_id]['custom_name'] = new_name or None

    _update_messages_for_agent(agent_id)
    _save_settings()

    dn = dname_for_id(agent_id)
    socketio.emit('agents_update', get_agents_list())
    with _lock:
        socketio.emit('full_refresh', list(MESSAGES))
    return jsonify({'success': True, 'name': dn})

@socketio.on('connect')
def handle_connect():
    socketio.emit('agents_update', get_agents_list())
    with _lock:
        socketio.emit('stats_update', dict(STATS))

# =============================================================================
# HTML
# =============================================================================
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenClaw Relay Monitor</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.4/socket.io.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg0:#0d1117;--bg1:#161b22;--bg2:#1c2333;
  --bg-sent:#0e2a1f;--bg-recv:#1a1c2e;--bg-disc:#1a1a2e;--bg-sys:#2a1a1a;--bg-mon:#1a2a1a;
  --bdr:#30363d;--t1:#e6edf3;--t2:#8b949e;--t3:#6e7681;
  --acc:#00d4ff;--acc2:rgba(0,212,255,.15);
  --grn:#3fb950;--red:#f85149;--org:#d29922;--pur:#bc8cff;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg0);color:var(--t1);height:100vh;overflow:hidden;display:flex;flex-direction:column}

/* Header */
.hdr{background:var(--bg1);border-bottom:1px solid var(--bdr);padding:10px 20px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.hdr-l{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.hdr h1{font-size:16px;font-weight:600;color:var(--acc)}
.hb{font-size:10px;padding:2px 8px;border-radius:10px;font-weight:500;font-family:'SF Mono','Cascadia Code',Consolas,monospace}
.hb-p{background:rgba(188,140,255,.15);color:var(--pur)}
.hb-i{background:var(--acc2);color:var(--acc)}
.hb-r{background:rgba(210,153,34,.15);color:var(--org)}
.hb-a{background:rgba(63,185,80,.15);color:var(--grn)}
.hdr-r{display:flex;align-items:center;gap:14px}
.dot{width:8px;height:8px;background:var(--grn);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.st,.up{font-size:11px;color:var(--t2);font-family:monospace}
.st span{font-weight:700}
.st-r span{color:var(--acc)}.st-m span{color:var(--grn)}.st-d span{color:var(--pur)}

/* Layout */
.main{display:flex;flex:1;overflow:hidden}
.feed-p{flex:1;display:flex;flex-direction:column;border-right:1px solid var(--bdr)}
.fbar{padding:8px 16px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--t3);background:var(--bg1);border-bottom:1px solid var(--bdr);display:flex;justify-content:space-between;align-items:center}
.fctl{display:flex;gap:6px;align-items:center}
.fb{font-size:9px;padding:2px 7px;border-radius:6px;border:1px solid var(--bdr);background:0;color:var(--t3);cursor:pointer;transition:.2s}
.fb.on{border-color:var(--acc);color:var(--acc);background:var(--acc2)}
.si{font-size:9px;padding:2px 7px;border-radius:6px;background:var(--acc2);color:var(--acc);display:none;cursor:pointer}
.si.vis{display:inline-block}

.feed{flex:1;overflow-y:auto;padding:10px 14px;scroll-behavior:smooth}
.feed::-webkit-scrollbar{width:5px}
.feed::-webkit-scrollbar-track{background:0}
.feed::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:3px}

/* Messages */
.m{padding:8px 12px;margin-bottom:5px;border-radius:7px;border-left:3px solid var(--bdr);animation:fi .25s ease}
.m.rs{background:var(--bg-sent);border-left-color:var(--grn)}
.m.rr{background:var(--bg-recv);border-left-color:var(--acc)}
.m.ry{background:var(--bg-sys);border-left-color:var(--org)}
.m.di{background:var(--bg-disc);border-left-color:var(--pur);opacity:.75}
.m.dm{background:var(--bg2);border-left-color:var(--acc)}
.m.mo{background:var(--bg-mon);border-left-color:#fff}
.m.un{background:var(--bg2);border-left-color:var(--t3)}
.m.hid{display:none}
@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

.mh{display:flex;align-items:center;gap:6px;margin-bottom:4px;flex-wrap:wrap}
.ab{font-size:10px;font-weight:700;padding:1px 7px;border-radius:4px}
.ar{font-size:10px;color:var(--t2);font-family:monospace;white-space:nowrap}
.cb{font-size:8px;padding:1px 5px;border-radius:3px;font-weight:700;text-transform:uppercase}
.cb-s{background:rgba(63,185,80,.15);color:var(--grn)}
.cb-r{background:var(--acc2);color:var(--acc)}
.cb-y{background:rgba(210,153,34,.15);color:var(--org)}
.cb-p{background:rgba(188,140,255,.15);color:var(--pur)}
.cb-m{background:rgba(0,212,255,.1);color:var(--acc)}
.cb-o{background:rgba(255,255,255,.1);color:#fff}
.cb-u{background:rgba(110,118,129,.15);color:var(--t3)}
.mt{font-size:10px;color:var(--t3);margin-left:auto;font-family:monospace}
.ms{font-size:10px;color:var(--t3);font-family:monospace}

.mb{font-size:13px;line-height:1.5;color:var(--t1);word-break:break-word;white-space:pre-wrap}
.mb.jb{font-family:'SF Mono','Cascadia Code',Consolas,monospace;font-size:11px;background:rgba(0,0,0,.25);padding:6px 10px;border-radius:5px;margin-top:4px;max-height:250px;overflow-y:auto}

.pb{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px;padding:5px 8px;background:rgba(0,0,0,.2);border-radius:5px;font-family:monospace;font-size:10px}
.pt{padding:1px 5px;border-radius:3px;background:rgba(255,255,255,.06);color:var(--t2)}
.pt .l{color:var(--t3);margin-right:3px}
.pt .v{color:var(--t1)}

.es{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--t3);gap:10px}
.es .ic{font-size:42px;opacity:.3}

/* Side */
.sp{width:340px;flex-shrink:0;display:flex;flex-direction:column;background:var(--bg1);overflow:hidden}
.ps{border-bottom:1px solid var(--bdr)}
.ptl{padding:8px 14px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--t3);background:var(--bg2)}

.al{padding:6px;max-height:300px;overflow-y:auto}
.arow{display:flex;align-items:center;gap:8px;padding:7px 8px;border-radius:6px;transition:.15s}
.arow:hover{background:var(--bg2)}
.adot{width:9px;height:9px;border-radius:50%;flex-shrink:0;position:relative}
.adot.on::after{content:'';position:absolute;inset:-3px;border-radius:50%;border:2px solid currentColor;opacity:.3;animation:pulse 2s infinite}
.ai{flex:1;min-width:0}
.anr{display:flex;align-items:center;gap:5px}
.anm{font-size:12px;font-weight:600;cursor:pointer}.anm:hover{text-decoration:underline}
.ahash{font-size:8px;padding:1px 4px;border-radius:3px;background:rgba(188,140,255,.12);color:var(--pur);font-family:monospace}
.aip{font-size:10px;color:var(--t3);font-family:monospace}
.ast{text-align:right;font-size:10px;color:var(--t3)}
.na{padding:16px;text-align:center;color:var(--t3);font-size:12px}

/* Modal */
.mo-ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.mo-ov.act{display:flex}
.mo-box{background:var(--bg1);border:1px solid var(--bdr);border-radius:12px;padding:20px;width:360px}
.mo-box h3{font-size:15px;margin-bottom:14px;color:var(--acc)}
.mo-box label{font-size:11px;color:var(--t2);display:block;margin-bottom:5px}
.mo-box .detail{font-size:10px;color:var(--t3);margin-bottom:4px;font-family:monospace;word-break:break-all}
.mo-box input[type=text]{width:100%;padding:8px 12px;background:var(--bg2);color:var(--t1);border:1px solid var(--bdr);border-radius:6px;font-size:13px;outline:0;margin-bottom:14px}
.mo-box input:focus{border-color:var(--acc)}
.mo-act{display:flex;gap:6px;justify-content:flex-end}
.mo-act button{padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:none}
.bc{background:var(--bg2);color:var(--t2)}
.bs{background:var(--acc);color:#000}
.br{background:0;color:var(--t3);border:1px solid var(--bdr)!important}

/* Send */
.ss{padding:10px 14px;flex-shrink:0;margin-top:auto;border-top:1px solid var(--bdr)}
.ssel,.spsel{width:100%;padding:7px 10px;background:var(--bg2);color:var(--t1);border:1px solid var(--bdr);border-radius:6px;font-size:12px;margin-bottom:6px;outline:0}
.ssel:focus,.spsel:focus{border-color:var(--acc)}
option{background:var(--bg1);color:var(--t1)}
.srow{display:flex;gap:6px}
.sinp{flex:1;padding:8px 12px;background:var(--bg2);color:var(--t1);border:1px solid var(--bdr);border-radius:6px;font-size:13px;outline:0}
.sinp:focus{border-color:var(--acc)}
.sinp::placeholder{color:var(--t3)}
.sbtn{padding:8px 16px;background:var(--acc);color:#000;border:none;border-radius:6px;font-weight:600;font-size:12px;cursor:pointer;white-space:nowrap}
.sbtn:hover{opacity:.85}.sbtn:disabled{opacity:.4;cursor:not-allowed}
.sst{font-size:10px;margin-top:4px;height:14px;color:var(--grn)}

.pref{padding:8px 14px;font-size:10px;color:var(--t3);border-top:1px solid var(--bdr);text-align:center}
.pref a{color:var(--pur);text-decoration:none}.pref a:hover{text-decoration:underline}

@media(max-width:800px){.main{flex-direction:column}.sp{width:100%;max-height:40vh}.feed-p{border-right:none;border-bottom:1px solid var(--bdr)}}
</style>
</head>
<body>

<!-- Rename modal -->
<div class="mo-ov" id="rmMod">
  <div class="mo-box">
    <h3>Rename Agent</h3>
    <label>Hostname: <span id="rmHost" style="color:var(--t1)"></span></label>
    <div class="detail" id="rmFullId"></div>
    <div class="detail" id="rmIpLine"></div>
    <label style="margin-top:10px">Display name:</label>
    <input type="text" id="rmIn" placeholder="Enter name..." autocomplete="off">
    <input type="hidden" id="rmAid">
    <div class="mo-act">
      <button class="br" id="rmRst">Reset</button>
      <button class="bc" id="rmCan">Cancel</button>
      <button class="bs" id="rmSav">Save</button>
    </div>
  </div>
</div>

<!-- Header -->
<div class="hdr">
  <div class="hdr-l">
    <div class="dot"></div>
    <h1>OpenClaw Relay Monitor</h1>
    <span class="hb hb-p">CLAUDE-UDP-V1</span>
    {% for iface in interfaces %}<span class="hb hb-i" title="{{ iface.name }}">{{ iface.ip }}</span>{% endfor %}
    <span class="hb hb-r">relay :{{ relay_port }}</span>
    <span class="hb hb-a">agent :{{ agent_port }}</span>
  </div>
  <div class="hdr-r">
    <span class="st st-r">relay: <span id="sR">0</span></span>
    <span class="st st-m">msg: <span id="sM">0</span></span>
    <span class="st st-d">disc: <span id="sD">0</span></span>
    <span class="up" id="up">00:00:00</span>
  </div>
</div>

<!-- Main -->
<div class="main">
  <div class="feed-p">
    <div class="fbar">
      <span>Message Feed</span>
      <div class="fctl">
        <button class="fb on" data-f="all" onclick="sf('all')">All</button>
        <button class="fb" data-f="relay" onclick="sf('relay')">Relay</button>
        <button class="fb" data-f="messages" onclick="sf('messages')">Direct</button>
        <button class="fb" data-f="discovery" onclick="sf('discovery')">Discovery</button>
        <span class="si" id="si">&#x2193; New</span>
      </div>
    </div>
    <div class="feed" id="feed">
      <div class="es" id="es">
        <div class="ic">&#x1F4E1;</div>
        <p>Waiting for relay traffic on port {{ relay_port }}...</p>
        <p style="font-size:11px">Configure agents:  relayServer: "{{ local_ip }}:{{ relay_port }}"{% if interfaces|length > 1 %}  ({{ interfaces|length }} interfaces detected){% endif %}</p>
      </div>
    </div>
  </div>

  <div class="sp">
    <div class="ps">
      <div class="ptl">Detected Agents &mdash; click to rename</div>
      <div class="al" id="aList"><div class="na">No agents detected yet</div></div>
    </div>

    <div class="ss">
      <div class="ptl" style="margin:-10px -14px 10px -14px;padding:8px 14px">Send to Agent</div>
      <select class="ssel" id="sIface">
        {% for iface in interfaces %}<option value="{{ iface.ip }}" data-bc="{{ iface.broadcast }}">{{ iface.name }} — {{ iface.ip }}{% if iface.broadcast %} (bc: {{ iface.broadcast }}){% endif %}</option>{% endfor %}
      </select>
      <select class="ssel" id="sTgt"><option value="{{ broadcast_ip }}">Broadcast ({{ broadcast_ip }})</option></select>
      <select class="spsel" id="sPrt">
        <option value="{{ agent_port }}">Agent port :{{ agent_port }}</option>
        <option value="{{ relay_port }}">Relay port :{{ relay_port }}</option>
      </select>
      <div class="srow">
        <input type="text" class="sinp" id="sIn" placeholder="Type a message..." autocomplete="off">
        <button class="sbtn" id="sBtn">Send</button>
      </div>
      <div class="sst" id="sSt"></div>
    </div>

    <div class="pref">
      Plugin: <a href="https://github.com/turfptax/openclaw-udp-messenger" target="_blank">openclaw-udp-messenger</a>
      &middot; <a href="https://clawhub.ai/turfptax/udp-messenger" target="_blank">ClawHub</a>
      &middot; v1.5
    </div>
  </div>
</div>

<script>
const io_s = io();
const feed = document.getElementById('feed');
const es   = document.getElementById('es');
const aList = document.getElementById('aList');
const sIface = document.getElementById('sIface');
const sTgt = document.getElementById('sTgt');
const sPrt = document.getElementById('sPrt');
const sIn  = document.getElementById('sIn');
const sBtn = document.getElementById('sBtn');
const sSt  = document.getElementById('sSt');
const si   = document.getElementById('si');
let BC     = '{{ broadcast_ip }}';
let mc = 0, aScr = true, filt = 'all', cAgents = [];

/* Interface selector — update broadcast address when interface changes */
sIface.addEventListener('change',function(){
  const opt=sIface.options[sIface.selectedIndex];
  BC=opt.dataset.bc||'255.255.255.255';
  rebuildTargets();
});
function rebuildTargets(){
  const cv=sTgt.value;
  sTgt.innerHTML='<option value="'+BC+'">Broadcast ('+BC+')</option>';
  cAgents.forEach(a=>{
    if(a.ip){const o=document.createElement('option');o.value=a.ip;o.textContent=a.name+' ('+a.ip+')';sTgt.appendChild(o)}
  });
  if(cv){sTgt.value=cv;if(!sTgt.value)sTgt.value=BC}
}

/* Uptime */
const t0 = Date.now();
setInterval(()=>{const s=Math.floor((Date.now()-t0)/1e3);document.getElementById('up').textContent=
  String(Math.floor(s/3600)).padStart(2,'0')+':'+String(Math.floor(s%3600/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0')},1e3);

/* Scroll */
feed.addEventListener('scroll',()=>{const b=feed.scrollHeight-feed.scrollTop-feed.clientHeight<60;aScr=b;si.classList.toggle('vis',!b)});
si.addEventListener('click',()=>{feed.scrollTop=feed.scrollHeight;aScr=true;si.classList.remove('vis')});

/* Filter */
function sf(f){filt=f;document.querySelectorAll('.fb').forEach(b=>b.classList.toggle('on',b.dataset.f===f));
  document.querySelectorAll('.m').forEach(el=>{const c=el.dataset.c;
    if(f==='all')el.classList.remove('hid');
    else if(f==='relay')el.classList.toggle('hid',!c.startsWith('relay'));
    else if(f==='messages')el.classList.toggle('hid',c!=='message'&&c!=='monitor-out');
    else if(f==='discovery')el.classList.toggle('hid',c!=='discovery');
  })}

/* Category badge */
function cb(cat,pi){
  if(cat==='relay-sent')return'<span class="cb cb-s">SENT</span>';
  if(cat==='relay-received')return'<span class="cb cb-r">RECV</span>';
  if(cat==='relay-system')return'<span class="cb cb-y">SYSTEM</span>';
  if(cat==='discovery'){const t=pi&&pi.msg_type==='discovery-pong'?'PONG':'PING';return'<span class="cb cb-p">'+t+'</span>'}
  if(cat==='message')return'<span class="cb cb-m">MSG</span>';
  if(cat==='monitor-out')return'<span class="cb cb-o">MONITOR</span>';
  return'<span class="cb cb-u">???</span>'}

function render(msg){
  if(es&&es.parentNode)es.remove();
  const d=document.createElement('div');
  const cc={'relay-sent':'rs','relay-received':'rr','relay-system':'ry',discovery:'di',message:'dm','monitor-out':'mo',unknown:'un'};
  d.className='m '+(cc[msg.category]||'un');
  d.dataset.c=msg.category;

  const pi=msg.proto_info;
  let arH='';
  if(msg.arrow)arH='<span class="ar">'+esc(msg.arrow)+'</span>';

  let body;
  if(msg.is_json&&!msg.is_protocol){
    try{body='<div class="mb jb">'+esc(JSON.stringify(JSON.parse(msg.message),null,2))+'</div>'}
    catch(e){body='<div class="mb">'+esc(msg.message)+'</div>'}
  }else body='<div class="mb">'+esc(msg.message)+'</div>';

  let pb='';
  if(pi){let t='';
    if(pi.agent_id)t+=pt('agent',pi.agent_id);
    if(pi.sender_id)t+=pt('sender',pi.sender_id);
    if(pi.peer_id)t+=pt('peer',pi.peer_id);
    if(pi.peer_address)t+=pt('addr',pi.peer_address);
    if(pi.protocol_time)t+=pt('time',pi.protocol_time);
    if(pi.sender_port)t+=pt('port',pi.sender_port);
    if(pi.payload_length!==undefined)t+=pt('len',pi.payload_length+' chars');
    if(pi.relay_event)t+=pt('event',pi.relay_event);
    if(t)pb='<div class="pb">'+t+'</div>'}

  d.innerHTML='<div class="mh">'+
    '<span class="ab" style="background:'+msg.color+'22;color:'+msg.color+'">'+esc(msg.sender)+'</span>'+
    cb(msg.category,pi)+arH+
    '<span class="ms">'+esc(msg.source_ip)+':'+msg.source_port+'</span>'+
    '<span class="mt">'+esc(msg.timestamp)+'</span></div>'+body+pb;

  feed.appendChild(d);mc++;
  const c=msg.category;
  if(filt==='relay'&&!c.startsWith('relay'))d.classList.add('hid');
  else if(filt==='messages'&&c!=='message'&&c!=='monitor-out')d.classList.add('hid');
  else if(filt==='discovery'&&c!=='discovery')d.classList.add('hid');
  if(aScr)feed.scrollTop=feed.scrollHeight;
}
function pt(l,v){return'<span class="pt"><span class="l">'+l+':</span><span class="v">'+esc(String(v))+'</span></span>'}
function esc(s){if(s==null)return'';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}

/* Agents — delegated click handler (XSS safe) */
aList.addEventListener('click',function(e){
  const nm=e.target.closest('.anm');
  if(nm&&nm.dataset.aid)oR(nm.dataset.aid);
});

function uA(agents){
  cAgents=agents;
  if(!agents.length){aList.innerHTML='<div class="na">No agents detected yet</div>';rebuildTargets();return}
  aList.innerHTML='';
  agents.forEach(a=>{
    const r=document.createElement('div');r.className='arow';
    let hh='';
    if(a.hash)hh='<span class="ahash" title="'+esc(a.agent_id)+'">'+esc(a.hash)+'</span>';
    r.innerHTML=
      '<div class="adot'+(a.online?' on':'')+'" style="background:'+a.color+';color:'+a.color+'"></div>'+
      '<div class="ai"><div class="anr">'+
        '<span class="anm" data-aid="'+esc(a.agent_id)+'" style="color:'+a.color+'" title="Click to rename">'+esc(a.name)+'</span>'+hh+
      '</div><div class="aip">'+(a.ip?esc(a.ip):'no IP')+'</div></div>'+
      '<div class="ast"><div>'+a.message_count+' msgs</div><div>'+(a.online?'online':a.last_seen)+'</div></div>';
    aList.appendChild(r);
  });
  rebuildTargets();
}

/* Stats */
io_s.on('stats_update',s=>{document.getElementById('sR').textContent=s.relay||0;document.getElementById('sM').textContent=s.message||0;document.getElementById('sD').textContent=s.discovery||0});

/* Rename */
function oR(aid){
  const a=cAgents.find(x=>x.agent_id===aid);if(!a)return;
  document.getElementById('rmHost').textContent=a.hostname||a.agent_id;
  document.getElementById('rmFullId').textContent='ID: '+a.agent_id;
  document.getElementById('rmIpLine').textContent=a.ip?'IP: '+a.ip:'';
  document.getElementById('rmIn').value=a.custom_name||'';
  document.getElementById('rmAid').value=a.agent_id;
  document.getElementById('rmMod').classList.add('act');
  setTimeout(()=>document.getElementById('rmIn').focus(),100);
}
document.getElementById('rmCan').addEventListener('click',()=>document.getElementById('rmMod').classList.remove('act'));
document.getElementById('rmMod').addEventListener('click',e=>{if(e.target.id==='rmMod')e.target.classList.remove('act')});
document.getElementById('rmSav').addEventListener('click',dR);
document.getElementById('rmIn').addEventListener('keydown',e=>{if(e.key==='Enter')dR();if(e.key==='Escape')document.getElementById('rmMod').classList.remove('act')});
document.getElementById('rmRst').addEventListener('click',()=>{document.getElementById('rmIn').value='';dR()});
function dR(){fetch('/api/rename_agent',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({agent_id:document.getElementById('rmAid').value,name:document.getElementById('rmIn').value.trim()})
}).then(r=>r.json()).then(d=>{if(d.success)document.getElementById('rmMod').classList.remove('act')})}

io_s.on('full_refresh',m=>{feed.innerHTML='';mc=0;m.forEach(render)});
io_s.on('new_message',render);
io_s.on('agents_update',uA);

/* Send */
function snd(){const m=sIn.value.trim();if(!m)return;sBtn.disabled=true;
  const bindIp=sIface.value;
  fetch('/send',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target_ip:sTgt.value,message:m,port:sPrt.value,bind_ip:bindIp})
  }).then(r=>r.json()).then(d=>{sSt.style.color=d.success?'var(--grn)':'var(--red)';
    sSt.textContent=d.success?'Sent via '+bindIp+' to '+sTgt.value+':'+sPrt.value:'Failed';
    if(d.success)sIn.value='';setTimeout(()=>sSt.textContent='',3e3)
  }).catch(()=>{sSt.style.color='var(--red)';sSt.textContent='Network error';
    setTimeout(()=>sSt.textContent='',3e3)}).finally(()=>sBtn.disabled=false)}
sBtn.addEventListener('click',snd);sIn.addEventListener('keydown',e=>{if(e.key==='Enter')snd()});

/* Init */
fetch('/api/messages').then(r=>r.json()).then(m=>m.forEach(render));
fetch('/api/agents').then(r=>r.json()).then(uA);
setInterval(()=>fetch('/api/agents').then(r=>r.json()).then(uA),1e4);
sIn.focus();
</script>
</body></html>
"""

# =============================================================================
# Main
# =============================================================================
if __name__ == '__main__':
    print(f"{'=' * 58}")
    print(f"  OpenClaw Relay Monitor")
    print(f"  Protocol:    CLAUDE-UDP-V1")
    print(f"  Plugin:      openclaw-udp-messenger v1.5")
    print(f"  Relay Port:  {RELAY_PORT}  (agents relay events here)")
    print(f"  Agent Port:  {AGENT_PORT}  (agent-to-agent)")
    print(f"  Web UI:      http://{LOCAL_IP}:{WEB_PORT}")
    print(f"  Log File:    {LOG_FILE}")
    print(f"  Settings:    {SETTINGS_FILE}")
    print(f"  ")
    print(f"  Network interfaces ({len(INTERFACES)}):")
    for iface in INTERFACES:
        print(f"    {iface['name']:20s}  {iface['ip']:15s}  bc: {iface['broadcast']}")
    print(f"  ")
    print(f"  Agent config:  relayServer: \"<YOUR_IP>:{RELAY_PORT}\"")
    for iface in INTERFACES:
        print(f"    {iface['name']:20s}  relayServer: \"{iface['ip']}:{RELAY_PORT}\"")
    print(f"  ")
    print(f"  GitHub:  https://github.com/turfptax/openclaw-udp-messenger")
    print(f"  ClawHub: https://clawhub.ai/turfptax/udp-messenger")
    print(f"{'=' * 58}")

    _load_settings()
    _init_send_socket()
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=_cleanup_stale_agents, daemon=True).start()
    threading.Thread(target=_settings_flush_loop, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=WEB_PORT,
                 debug=False, allow_unsafe_werkzeug=True)
