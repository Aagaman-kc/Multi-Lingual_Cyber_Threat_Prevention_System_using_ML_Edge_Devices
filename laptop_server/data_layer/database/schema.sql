-- Multi-Layer Cyber Threat Detection System
-- Database Schema for SQLite

-- Threats table (main detection log)
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    module TEXT NOT NULL,              -- 'url', 'email', 'app_attack', 'dpi'
    detection_type TEXT NOT NULL,      -- 'phishing', 'sql_injection', 'xss', 'anomaly', etc.
    confidence REAL NOT NULL,         -- 0.0 to 1.0
    source_ip TEXT,                   -- Source IP address
    destination_ip TEXT,              -- Destination IP address
    details TEXT,                     -- JSON with full context
    action_taken TEXT DEFAULT 'logged', -- 'blocked', 'logged', 'alerted'
    is_blocked INTEGER DEFAULT 0     -- 0 = false, 1 = true
);

-- URLs table (for URL scanner detections)
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER,
    url TEXT NOT NULL,
    classification TEXT,             -- 'phishing', 'malware', 'defacement', 'benign'
    confidence REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

-- Email threats table
CREATE TABLE IF NOT EXISTS email_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER,
    sender TEXT,
    subject TEXT,
    snippet TEXT,
    classification TEXT,             -- 'phishing', 'legitimate'
    confidence REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

-- Application layer alerts
CREATE TABLE IF NOT EXISTS app_layer_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER,
    attack_type TEXT,                -- 'sql_injection', 'xss', 'command_injection', 'ssti', 'path_traversal'
    payload_snippet TEXT,
    confidence REAL,
    endpoint TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

-- Flow anomalies table (for DPI)
CREATE TABLE IF NOT EXISTS flow_anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER,
    anomaly_type TEXT,               -- 'c2_communication', 'beaconing', 'port_scanning', 'data_exfiltration', 'dos'
    confidence REAL,
    flow_features TEXT,              -- JSON with flow statistics
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);

-- Blocked IPs table (for prevention engine)
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    reason TEXT,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,            -- NULL = permanent block
    is_active INTEGER DEFAULT 1
);

-- Traffic statistics (for dashboard)
CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_packets INTEGER DEFAULT 0,
    total_connections INTEGER DEFAULT 0,
    blocked_connections INTEGER DEFAULT 0,
    alerts_generated INTEGER DEFAULT 0,
    http_requests INTEGER DEFAULT 0,
    dns_queries INTEGER DEFAULT 0,
    smtp_sessions INTEGER DEFAULT 0
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_module ON threats(module);
CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(detection_type);
CREATE INDEX IF NOT EXISTS idx_threats_blocked ON threats(is_blocked);
CREATE INDEX IF NOT EXISTS idx_urls_timestamp ON urls(timestamp);
CREATE INDEX IF NOT EXISTS idx_email_timestamp ON email_threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_app_timestamp ON app_layer_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON flow_anomalies(timestamp);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(is_active);