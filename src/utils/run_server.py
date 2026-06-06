#!/usr/bin/env python3
"""
CyberShield - Laptop Central Server
python run_server.py
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from data_layer.database.db_manager import Database
from presentation_layer.socket_manager import SocketManager

# Fixed database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'threats.db')

app = Flask(__name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'presentation_layer', 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'presentation_layer', 'static'))
app.config['SECRET_KEY'] = 'cybershield-server-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

db = Database(DB_PATH)
sock = SocketManager()
sock.init_app(socketio)

API_KEY = "cybershield-secret-key"

# ============================================================
# RECEIVE ALERTS FROM PI
# ============================================================
@app.route('/api/remote_alert', methods=['POST'])
def receive():
    d = request.get_json()
    if d.get('api_key') != API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    aid = db.insert_alert(
        module=d.get('module','?'),
        detection_type=d.get('type','?'),
        confidence=d.get('confidence',0),
        source_ip=d.get('source_ip'),
        details=d.get('details',''),
        action_taken=d.get('action','detected'),
        is_blocked=1 if d.get('blocked_type') in ['IP','URL','EMAIL'] else 0
    )

    alert = {
        'id': aid,
        'module': d.get('module'),
        'type': d.get('type'),
        'confidence': d.get('confidence'),
        'severity': d.get('severity', 'medium'),
        'source_ip': d.get('source_ip'),
        'blocked': d.get('blocked_type') in ['IP','URL','EMAIL'],
        'blocked_type': d.get('blocked_type'),
        'blocked_target': d.get('blocked_target'),
        'phishing_url': d.get('phishing_url'),
        'phishing_domain': d.get('phishing_domain'),
        'pi_name': d.get('pi_name', ''),
        'timestamp': d.get('timestamp', datetime.now().isoformat())
    }
    sock.send_alert(alert)
    return jsonify({'success': True, 'alert_id': aid})

# ============================================================
# DASHBOARD API
# ============================================================
@app.route('/api/stats')
def stats():
    return jsonify(db.get_statistics(hours=720))

@app.route('/api/alerts')
def alerts():
    limit = request.args.get('limit', 1000, type=int)
    module = request.args.get('module', None)
    return jsonify(db.get_recent_alerts(limit=limit, module=module))

@app.route('/api/alert/<int:aid>')
def alert_detail(aid):
    a = db.get_detailed_alert(aid)
    return jsonify(a) if a else (jsonify({'error':'Not found'}), 404)

@app.route('/api/blocked_ips')
def blocked():
    return jsonify(db.get_blocked_ips())

@app.route('/api/timeline')
def timeline():
    h = request.args.get('hours', 24, type=int)
    return jsonify(db.get_statistics(hours=h).get('timeline', []))

@app.route('/api/top_threats')
def top():
    h = request.args.get('hours', 24, type=int)
    return jsonify(db.get_statistics(hours=h).get('by_type', []))

@app.route('/api/module_stats')
def modules():
    s = db.get_statistics(hours=720)
    mods = {}
    for item in s.get('by_module', []):
        mods[item['module']] = {'detections': item['count'], 'blocked': 0}
    return jsonify(mods)

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    data = request.get_json() or {}
    days = data.get('days', None)
    module = data.get('module', None)
    try:
        if days:
            db.cleanup_old_alerts(days=days)
            msg = f"Cleared alerts older than {days} days"
        elif module:
            import sqlite3
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM threats WHERE module = ?", (module,))
            conn.commit(); conn.close()
            msg = f"Cleared all {module} alerts"
        else:
            import sqlite3
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM threats")
            conn.execute("DELETE FROM urls")
            conn.execute("DELETE FROM email_threats")
            conn.execute("DELETE FROM app_layer_alerts")
            conn.execute("DELETE FROM flow_anomalies")
            conn.commit(); conn.close()
            msg = "Cleared ALL alerts"
        return jsonify({'success': True, 'message': msg})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health():
    return jsonify({'status':'running', 'timestamp':datetime.now().isoformat()})

@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-p','--port', default=5000, type=int)
    p.add_argument('-H','--host', default='0.0.0.0')
    args = p.parse_args()
    print(f"\n🛡️  CyberShield Server")
    print(f"   Dashboard: http://{args.host}:{args.port}")
    print(f"   API: http://{args.host}:{args.port}/api/remote_alert")
    print(f"   Database: {DB_PATH}")
    print(f"   Alerts stored: {db.get_statistics().get('total_alerts', 0)}\n")
    socketio.run(app, host=args.host, port=args.port, debug=False, allow_unsafe_werkzeug=True)