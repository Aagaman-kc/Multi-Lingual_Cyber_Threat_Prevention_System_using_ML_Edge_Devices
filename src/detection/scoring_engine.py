import logging
from datetime import datetime
from collections import defaultdict
import threading

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScoringEngine:
    """
    Risk Fusion Engine - Combines alerts from all 4 detection modules
    and makes final decision on threat severity and actions
    """
    
    def __init__(self):
        # Weight configuration for each module
        self.module_weights = {
            'url': 0.25,
            'email': 0.30,
            'app_attack': 0.30,
            'dpi': 0.15
        }
        
        # Confidence thresholds
        self.thresholds = {
            'critical': 0.90,
            'high': 0.75,
            'medium': 0.60,
            'low': 0.40
        }
        
        # Risk score multiplier for specific attack types
        # UPDATED: Matches labels from your ML models
        self.attack_severity = {
            # Critical attacks (score multiplier: 2.0)
            'c2_communication': 2.0,
            'data_exfiltration': 2.0,
            'ransomware': 2.0,
            'apt': 2.0,
            
            # High severity (score multiplier: 1.5)
            'phishing': 1.5,
            'malware': 1.5,
            'defacement': 1.5,
            'sql': 1.5,              # Your model returns 'sql'
            'sql_injection': 1.5,    # Backup label
            'cmdinj': 1.5,           # Your model returns 'cmdinj'
            'command_injection': 1.5, # Backup label
            'anomaly': 1.5,          # DPI detector returns 'anomaly'
            'dos_attack': 1.5,
            
            # Medium severity (score multiplier: 1.0)
            'xss': 1.0,
            'ssti': 1.0,
            'traversal': 1.0,        # Your model returns 'traversal'
            'path_traversal': 1.0,   # Backup label
            'beaconing': 1.0,
            'port_scanning': 1.0,
            'suspicious_dns': 1.0,
            
            # Low severity (score multiplier: 0.5)
            'suspicious': 0.5,
            'benign': 0.0,
            'normal': 0.0,
            'legitimate': 0.0
        }
        
        # Alert history for correlation
        self.alert_history = defaultdict(list)
        self.alert_lock = threading.Lock()
        
        # IP reputation tracking
        self.ip_reputation = defaultdict(lambda: {
            'score': 0,
            'alerts': [],
            'last_seen': None,
            'blocked': False
        })
        
        # Correlation rules
        self.correlation_rules = [
            {
                'name': 'Phishing with malicious URL',
                'conditions': ['email_phishing', 'url_phishing'],
                'timeframe': 300,
                'action': 'block',
                'multiplier': 2.0
            },
            {
                'name': 'Multiple attack types from same IP',
                'conditions': ['app_attack', 'dpi_anomaly'],
                'timeframe': 600,
                'action': 'block',
                'multiplier': 1.8
            },
            {
                'name': 'Repeated URL phishing attempts',
                'conditions': ['url_phishing', 'url_phishing'],
                'timeframe': 120,
                'action': 'block',
                'multiplier': 1.5
            }
        ]
    
    def evaluate_threat(self, detection_result, source_ip=None, context=None):
        """
        Evaluate a single detection result and calculate risk score
        
        Args:
            detection_result: Dict from any detector {label, confidence, module}
            source_ip: Source IP address
            context: Additional context data
        
        Returns:
            dict: Risk assessment with action recommendation
        """
        module = detection_result.get('module', 'unknown')
        label = detection_result.get('label', 'unknown')
        confidence = detection_result.get('confidence', 0.0)
        
        # Calculate base risk score
        base_score = self._calculate_base_score(module, label, confidence)
        
        # Apply attack severity multiplier
        severity_multiplier = self.attack_severity.get(label, 1.0)
        weighted_score = base_score * severity_multiplier
        
        # Apply module weight
        module_weight = self.module_weights.get(module, 0.2)
        final_score = weighted_score * module_weight
        
        # Adjust score based on IP reputation
        if source_ip:
            ip_rep = self.ip_reputation[source_ip]
            if ip_rep['score'] > 100:
                final_score *= 1.6
            elif ip_rep['score'] > 50:
                final_score *= 1.3
        
        # Determine severity level
        severity = self._determine_severity(final_score, confidence)
        
        # Determine recommended action
        action = self._determine_action(severity, final_score)
        
        # Update IP reputation
        if source_ip:
            self._update_ip_reputation(source_ip, label, final_score)
        
        # Store alert in history
        self._store_alert(source_ip, module, label, final_score)
        
        # Check for correlated threats
        correlation_result = self._check_correlations(source_ip, module, label)
        if correlation_result and correlation_result['score_boost'] > 0:
            final_score *= correlation_result['score_boost']
            severity = self._determine_severity(final_score, confidence)
            action = self._determine_action(severity, final_score)
        
        result = {
            'module': module,
            'label': label,
            'confidence': confidence,
            'raw_score': base_score,
            'final_score': final_score,
            'severity': severity,
            'action': action,
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat(),
            'correlated': correlation_result is not None,
            'correlation_details': correlation_result
        }
        
        logger.info(f"Threat evaluated: {label} | Score: {final_score:.2f} | "
                   f"Severity: {severity} | Action: {action}")
        
        return result
    
    def evaluate_multiple(self, detection_results, source_ip=None):
        """Evaluate multiple detection results for the same event"""
        if not detection_results:
            return None
        
        evaluations = []
        for result in detection_results:
            eval_result = self.evaluate_threat(result, source_ip)
            evaluations.append(eval_result)
        
        total_score = sum(eval['final_score'] for eval in evaluations)
        avg_confidence = sum(eval['confidence'] for eval in evaluations) / max(len(evaluations), 1)
        
        severity = self._determine_severity(total_score, avg_confidence)
        action = self._determine_action(severity, total_score)
        
        return {
            'total_score': total_score,
            'average_confidence': avg_confidence,
            'severity': severity,
            'action': action,
            'individual_evaluations': evaluations,
            'source_ip': source_ip,
            'detection_count': len(evaluations),
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_base_score(self, module, label, confidence):
        """Calculate base risk score from detection"""
        base = confidence * 10
        
        module_bonus = {
            'url': 0.5,
            'email': 0.3,
            'app_attack': 0.4,
            'dpi': 0.2
        }
        
        base += module_bonus.get(module, 0)
        return min(base, 10.0)
    
    def _determine_severity(self, score, confidence):
        """Determine severity level based on score and confidence"""
        if score >= 9.0 or confidence >= self.thresholds['critical']:
            return 'critical'
        elif score >= 7.0 or confidence >= self.thresholds['high']:
            return 'high'
        elif score >= 5.0 or confidence >= self.thresholds['medium']:
            return 'medium'
        elif score >= 3.0 or confidence >= self.thresholds['low']:
            return 'low'
        else:
            return 'info'
    
    def _determine_action(self, severity, score):
        """Determine recommended action based on severity"""
        actions = {
            'critical': 'block_immediately',
            'high': 'block_after_confirm',
            'medium': 'alert_and_log',
            'low': 'log_only',
            'info': 'log_only'
        }
        
        action = actions.get(severity, 'log_only')
        
        if score >= 9.5:
            action = 'block_immediately'
        
        return action
    
    def _update_ip_reputation(self, ip, label, score):
        """Update IP reputation based on detection"""
        if not ip:
            return
        
        rep = self.ip_reputation[ip]
        rep['score'] += score
        rep['alerts'].append({
            'label': label,
            'score': score,
            'timestamp': datetime.now().isoformat()
        })
        rep['last_seen'] = datetime.now().isoformat()
        
        if rep['score'] > 100 and not rep['blocked']:
            rep['blocked'] = True
            logger.warning(f"IP {ip} reached reputation threshold - recommend blocking")
    
    def _store_alert(self, source_ip, module, label, score):
        """Store alert in history for correlation"""
        with self.alert_lock:
            alert = {
                'source_ip': source_ip,
                'module': module,
                'label': label,
                'score': score,
                'timestamp': datetime.now()
            }
            self.alert_history[source_ip or 'unknown'].append(alert)
            
            if len(self.alert_history[source_ip or 'unknown']) > 100:
                self.alert_history[source_ip or 'unknown'] = \
                    self.alert_history[source_ip or 'unknown'][-100:]
    
    def _check_correlations(self, source_ip, module, label):
        """Check for correlated threats from same source"""
        if not source_ip or source_ip not in self.alert_history:
            return None
        
        alerts = self.alert_history[source_ip]
        if len(alerts) < 2:
            return None
        
        now = datetime.now()
        recent_alerts = []
        
        for alert in alerts:
            time_diff = (now - alert['timestamp']).total_seconds()
            if time_diff <= 600:
                recent_alerts.append(alert)
        
        if len(recent_alerts) < 2:
            return None
        
        for rule in self.correlation_rules:
            conditions_met = 0
            for condition in rule['conditions']:
                for alert in recent_alerts:
                    alert_type = f"{alert['module']}_{alert['label']}"
                    if condition == alert_type or alert_type.startswith(condition):
                        conditions_met += 1
                        break
            
            if conditions_met >= len(rule['conditions']):
                return {
                    'rule': rule['name'],
                    'score_boost': rule['multiplier'],
                    'action': rule['action'],
                    'related_alerts': len(recent_alerts)
                }
        
        return None
    
    def get_ip_reputation(self, ip):
        """Get reputation score for an IP"""
        if ip in self.ip_reputation:
            return self.ip_reputation[ip]
        return {'score': 0, 'alerts': [], 'blocked': False}
    
    def get_statistics(self):
        """Get scoring engine statistics"""
        with self.alert_lock:
            total_alerts = sum(len(alerts) for alerts in self.alert_history.values())
            unique_ips = len(self.alert_history)
            blocked_ips = sum(1 for rep in self.ip_reputation.values() if rep['blocked'])
            
            return {
                'total_alerts_processed': total_alerts,
                'unique_ips_tracked': unique_ips,
                'ips_recommended_block': blocked_ips,
                'alert_history_size': len(self.alert_history)
            }
    
    def reset_ip_reputation(self, ip):
        """Reset reputation for an IP"""
        if ip in self.ip_reputation:
            self.ip_reputation[ip] = {
                'score': 0,
                'alerts': [],
                'last_seen': None,
                'blocked': False
            }