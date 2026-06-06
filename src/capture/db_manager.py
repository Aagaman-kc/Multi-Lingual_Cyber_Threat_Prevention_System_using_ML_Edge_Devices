import sqlite3
import json
import os
from datetime import datetime, timedelta
from threading import Lock

class Database:
    """Database manager for the Multi-Layer Cyber Threat Detection System"""
    
    def __init__(self, db_path='threats.db'):
        """
        Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.lock = Lock()  # Thread safety for concurrent access
        self._init_db()
    
    def _init_db(self):
        """Initialize database with schema"""
        schema_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            'schema.sql'
        )
        
        if os.path.exists(schema_path):
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
            
            with self.get_connection() as conn:
                conn.executescript(schema_sql)
                conn.commit()
        else:
            print(f"Warning: Schema file not found at {schema_path}")
            self._create_minimal_schema()
    
    def _create_minimal_schema(self):
        """Create minimal schema if schema.sql is missing"""
        with self.get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    module TEXT NOT NULL,
                    detection_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    details TEXT,
                    action_taken TEXT DEFAULT 'logged',
                    is_blocked INTEGER DEFAULT 0
                )
            ''')
            conn.commit()
    
    def get_connection(self):
        """Get a thread-safe database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent access
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    
    # ==================== THREAT ALERT METHODS ====================
    
    def insert_alert(self, module, detection_type, confidence, 
                    source_ip=None, destination_ip=None, 
                    details=None, action_taken='logged', is_blocked=0):
        """
        Insert a threat alert into the database
        
        Args:
            module: Detection module name ('url', 'email', 'app_attack', 'dpi')
            detection_type: Type of threat detected
            confidence: Detection confidence (0.0 to 1.0)
            source_ip: Source IP address
            destination_ip: Destination IP address
            details: Additional details (dict or string)
            action_taken: Action taken ('blocked', 'logged', 'alerted')
            is_blocked: Whether the threat was blocked (0 or 1)
        
        Returns:
            threat_id: ID of the inserted alert
        """
        if isinstance(details, dict):
            details = json.dumps(details)
        
        with self.lock:
            with self.get_connection() as conn:
                cursor = conn.execute('''
                    INSERT INTO threats 
                    (module, detection_type, confidence, source_ip, 
                     destination_ip, details, action_taken, is_blocked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (module, detection_type, confidence, source_ip,
                     destination_ip, details, action_taken, is_blocked))
                conn.commit()
                return cursor.lastrowid
    
    def insert_url_alert(self, threat_id, url, classification, confidence):
        """Insert URL-specific alert"""
        with self.lock:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO urls (threat_id, url, classification, confidence)
                    VALUES (?, ?, ?, ?)
                ''', (threat_id, url, classification, confidence))
                conn.commit()
    
    def insert_email_alert(self, threat_id, sender, subject, snippet, 
                          classification, confidence):
        """Insert email-specific alert"""
        with self.lock:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO email_threats 
                    (threat_id, sender, subject, snippet, classification, confidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (threat_id, sender, subject, snippet, classification, confidence))
                conn.commit()
    
    def insert_app_alert(self, threat_id, attack_type, payload_snippet, 
                        confidence, endpoint):
        """Insert application-layer alert"""
        with self.lock:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO app_layer_alerts 
                    (threat_id, attack_type, payload_snippet, confidence, endpoint)
                    VALUES (?, ?, ?, ?, ?)
                ''', (threat_id, attack_type, payload_snippet, confidence, endpoint))
                conn.commit()
    
    def insert_flow_anomaly(self, threat_id, anomaly_type, confidence,
                           flow_features, source_ip, destination_ip, protocol):
        """Insert flow anomaly alert"""
        if isinstance(flow_features, dict):
            flow_features = json.dumps(flow_features)
        
        with self.lock:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO flow_anomalies 
                    (threat_id, anomaly_type, confidence, flow_features,
                     source_ip, destination_ip, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (threat_id, anomaly_type, confidence, flow_features,
                     source_ip, destination_ip, protocol))
                conn.commit()
    
    # ==================== BLOCKED IP METHODS ====================
    
    def block_ip(self, ip_address, reason, duration_hours=None):
        """
        Block an IP address
        
        Args:
            ip_address: IP to block
            reason: Reason for blocking
            duration_hours: How long to block (None = permanent)
        """
        expires_at = None
        if duration_hours:
            expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        with self.lock:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO blocked_ips 
                    (ip_address, reason, expires_at, is_active)
                    VALUES (?, ?, ?, 1)
                ''', (ip_address, reason, expires_at.isoformat() if expires_at else None))
                conn.commit()
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        with self.lock:
            with self.get_connection() as conn:
                conn.execute('''
                    UPDATE blocked_ips SET is_active = 0 
                    WHERE ip_address = ?
                ''', (ip_address,))
                conn.commit()
    
    def is_ip_blocked(self, ip_address):
        """Check if an IP is currently blocked"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT 1 FROM blocked_ips 
                WHERE ip_address = ? 
                AND is_active = 1
                AND (expires_at IS NULL OR expires_at > datetime('now'))
            ''', (ip_address,))
            return cursor.fetchone() is not None
    
    def get_blocked_ips(self):
        """Get all currently blocked IPs"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM blocked_ips 
                WHERE is_active = 1
                AND (expires_at IS NULL OR expires_at > datetime('now'))
                ORDER BY blocked_at DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== DASHBOARD QUERY METHODS ====================
    
    def get_recent_alerts(self, limit=100, module=None):
        """
        Get recent threat alerts
        
        Args:
            limit: Maximum number of alerts to return
            module: Filter by module (None = all)
        """
        query = '''
            SELECT * FROM threats 
            WHERE 1=1
        '''
        params = []
        
        if module:
            query += ' AND module = ?'
            params.append(module)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def get_detailed_alert(self, threat_id):
        """Get full details of a specific alert"""
        with self.get_connection() as conn:
            # Main threat
            threat = conn.execute(
                'SELECT * FROM threats WHERE id = ?', 
                (threat_id,)
            ).fetchone()
            
            if not threat:
                return None
            
            result = dict(threat)
            
            # Module-specific details
            if result['module'] == 'url':
                url_detail = conn.execute(
                    'SELECT * FROM urls WHERE threat_id = ?', 
                    (threat_id,)
                ).fetchone()
                if url_detail:
                    result['url_details'] = dict(url_detail)
            
            elif result['module'] == 'email':
                email_detail = conn.execute(
                    'SELECT * FROM email_threats WHERE threat_id = ?', 
                    (threat_id,)
                ).fetchone()
                if email_detail:
                    result['email_details'] = dict(email_detail)
            
            elif result['module'] == 'app_attack':
                app_detail = conn.execute(
                    'SELECT * FROM app_layer_alerts WHERE threat_id = ?', 
                    (threat_id,)
                ).fetchone()
                if app_detail:
                    result['app_details'] = dict(app_detail)
            
            elif result['module'] == 'dpi':
                flow_detail = conn.execute(
                    'SELECT * FROM flow_anomalies WHERE threat_id = ?', 
                    (threat_id,)
                ).fetchone()
                if flow_detail:
                    result['flow_details'] = dict(flow_detail)
            
            return result
    
    def get_statistics(self, hours=24):
        """Get statistics for the dashboard"""
        with self.get_connection() as conn:
            # Total alerts
            total = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE timestamp > datetime('now', ? || ' hours')
            ''', (f'-{hours}',)).fetchone()[0]
            
            # Blocked threats
            blocked = conn.execute('''
                SELECT COUNT(*) FROM threats 
                WHERE is_blocked = 1
                AND timestamp > datetime('now', ? || ' hours')
            ''', (f'-{hours}',)).fetchone()[0]
            
            # Alerts by module
            by_module = conn.execute('''
                SELECT module, COUNT(*) as count 
                FROM threats 
                WHERE timestamp > datetime('now', ? || ' hours')
                GROUP BY module
            ''', (f'-{hours}',)).fetchall()
            
            # Alerts by type
            by_type = conn.execute('''
                SELECT detection_type, COUNT(*) as count 
                FROM threats 
                WHERE timestamp > datetime('now', ? || ' hours')
                GROUP BY detection_type
                ORDER BY count DESC
            ''', (f'-{hours}',)).fetchall()
            
            # Recent alerts timeline (last 24h, grouped by hour)
            timeline = conn.execute('''
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                    COUNT(*) as count
                FROM threats 
                WHERE timestamp > datetime('now', ? || ' hours')
                GROUP BY hour
                ORDER BY hour ASC
            ''', (f'-{hours}',)).fetchall()
            
            return {
                'total_alerts': total,
                'blocked_threats': blocked,
                'by_module': [dict(row) for row in by_module],
                'by_type': [dict(row) for row in by_type],
                'timeline': [dict(row) for row in timeline]
            }
    
    def cleanup_old_alerts(self, days=30):
        """Clean up alerts older than specified days"""
        with self.lock:
            with self.get_connection() as conn:
                conn.execute('''
                    DELETE FROM threats 
                    WHERE timestamp < datetime('now', ? || ' days')
                ''', (f'-{days}',))
                conn.commit()
    
    def close(self):
        """Close database connection (for cleanup)"""
        # SQLite connections are created per-query, so nothing to close
        pass


# ==================== USAGE EXAMPLE ====================
if __name__ == '__main__':
    # Test the database manager
    db = Database('test_threats.db')
    
    # Insert a test alert
    alert_id = db.insert_alert(
        module='url',
        detection_type='phishing',
        confidence=0.95,
        source_ip='192.168.1.100',
        destination_ip='10.0.0.1',
        details={'url': 'http://evil-phishing.com/login', 'method': 'GET'},
        action_taken='blocked',
        is_blocked=1
    )
    print(f"Inserted alert with ID: {alert_id}")
    
    # Block an IP
    db.block_ip('192.168.1.200', 'Multiple phishing attempts', duration_hours=24)
    print(f"IP blocked: {db.is_ip_blocked('192.168.1.200')}")
    
    # Get statistics
    stats = db.get_statistics(hours=24)
    print(f"Statistics: {stats}")
    
    # Clean up
    import os
    os.remove('test_threats.db')