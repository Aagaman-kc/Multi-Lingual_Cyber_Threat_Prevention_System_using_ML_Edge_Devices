import logging
from datetime import datetime
from collections import deque

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SocketManager:
    """WebSocket manager for real-time dashboard updates"""

    def __init__(self, max_alerts_history=2000):
        self.socketio = None
        self.connected_clients = 0
        self.alert_history = deque(maxlen=max_alerts_history)
        self.live_stats = {
            'packets_processed': 0, 'urls_scanned': 0, 'emails_scanned': 0,
            'app_payloads_scanned': 0, 'flows_analyzed': 0,
            'threats_detected': 0, 'threats_blocked': 0,
            'active_blocks': 0, 'uptime': '0h 0m', 'last_update': None
        }
        self.module_stats = {
            'url': {'detections': 0, 'blocked': 0},
            'email': {'detections': 0, 'blocked': 0},
            'app_attack': {'detections': 0, 'blocked': 0},
            'dpi': {'detections': 0, 'blocked': 0}
        }
        self.threat_timeline = deque(maxlen=200)
        self.recent_blocks = deque(maxlen=100)

    def init_app(self, socketio):
        self.socketio = socketio
        self._register_handlers()

    def _register_handlers(self):
        @self.socketio.on('connect')
        def handle_connect():
            self.connected_clients += 1
            self.socketio.emit('catch_up', {
                'alerts': list(self.alert_history)[-100:],
                'stats': self.live_stats,
                'module_stats': self.module_stats,
                'recent_blocks': list(self.recent_blocks),
                'timeline': list(self.threat_timeline)
            })

        @self.socketio.on('disconnect')
        def handle_disconnect():
            self.connected_clients -= 1

    def send_alert(self, alert_data):
        alert_data['timestamp'] = alert_data.get('timestamp', datetime.now().isoformat())
        self.alert_history.append(alert_data)
        if self.socketio:
            self.socketio.emit('new_alert', alert_data)
        self._update_timeline(alert_data)
        module = alert_data.get('module', 'unknown')
        if module in self.module_stats:
            self.module_stats[module]['detections'] += 1
            if alert_data.get('blocked'):
                self.module_stats[module]['blocked'] += 1

    def update_stats(self, stats_dict):
        self.live_stats.update(stats_dict)
        self.live_stats['last_update'] = datetime.now().isoformat()
        if self.socketio:
            self.socketio.emit('stats_update', self.live_stats)

    def _update_timeline(self, alert_data):
        timestamp = alert_data.get('timestamp', datetime.now().isoformat())
        try:
            dt = datetime.fromisoformat(timestamp)
            hour_key = dt.strftime('%Y-%m-%d %H:00')
        except:
            hour_key = str(timestamp)[:13]
        for entry in self.threat_timeline:
            if entry['hour'] == hour_key:
                entry['count'] += 1
                return
        self.threat_timeline.append({'hour': hour_key, 'count': 1})