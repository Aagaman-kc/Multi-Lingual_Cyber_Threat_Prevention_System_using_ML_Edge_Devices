import numpy as np
import pandas as pd
from collections import defaultdict
import logging
import math

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DPIFeatureExtractor:
    """
    Extract and engineer features for DPI anomaly detection
    Prepares flow data for Isolation Forest / Random Forest model
    """
    
    def __init__(self):
        # Feature names in the exact order expected by the model
        self.feature_names = [
            'duration',
            'packet_count',
            'byte_count',
            'pps',
            'bps',
            'avg_packet_size',
            'iat_mean',
            'iat_std',
            'iat_min',
            'iat_max',
            'payload_mean',
            'payload_std',
            'payload_min',
            'payload_max',
            'syn_ratio',
            'fin_ratio',
            'rst_ratio',
            'ack_ratio',
            'psh_ratio',
            'urg_ratio',
            'window_mean',
            'window_std',
            'entropy',
            'protocol',
            'port_ratio',
            'byte_ratio_direction',
            'packet_ratio_direction',
            'iat_variance_coefficient'
        ]
        
        # Statistical baselines (will be updated during operation)
        self.baselines = defaultdict(lambda: {'mean': 0, 'std': 0, 'count': 0})
        
        # Known malicious patterns
        self.malicious_patterns = {
            'c2_beaconing': {
                'description': 'Periodic communication pattern',
                'iat_std_threshold': 0.1,  # Very regular intervals
                'duration_threshold': 300   # Long duration
            },
            'port_scanning': {
                'description': 'Many connections to different ports',
                'packet_count_threshold': 100,
                'syn_ratio_threshold': 0.8
            },
            'data_exfiltration': {
                'description': 'Large outbound data transfer',
                'byte_count_threshold': 100000,
                'bps_threshold': 100000
            },
            'dos_attack': {
                'description': 'High packet rate',
                'pps_threshold': 1000,
                'packet_count_threshold': 10000
            }
        }
    
    def extract_features_from_flow(self, flow_data):
        """
        Extract features from flow metadata
        
        Args:
            flow_data: Flow data from FlowMetadataCollector
        
        Returns:
            dict: Extracted features for ML model
        """
        try:
            data = flow_data.get('data', flow_data)
            
            # Basic flow features (already extracted)
            features = data.copy()
            
            # Remove non-numeric fields for ML
            features.pop('src_ip', None)
            features.pop('dst_ip', None)
            features.pop('src_port', None)
            features.pop('dst_port', None)
            features.pop('type', None)
            
            # Add derived features
            features.update(self._calculate_derived_features(data))
            
            # Add statistical anomaly scores
            features.update(self._calculate_statistical_scores(features))
            
            # Ensure all required features are present
            for feature in self.feature_names:
                if feature not in features:
                    features[feature] = 0
            
            # Return only the features the model expects, in order
            ordered_features = {name: features.get(name, 0) for name in self.feature_names}
            
            return {
                'features': ordered_features,
                'metadata': {
                    'src_ip': data.get('src_ip'),
                    'dst_ip': data.get('dst_ip'),
                    'src_port': data.get('src_port'),
                    'dst_port': data.get('dst_port'),
                    'protocol': 'TCP' if data.get('protocol') == 1 else 'UDP'
                }
            }
        except Exception as e:
            logger.error(f"Error extracting DPI features: {e}")
            return None
    
    def _calculate_derived_features(self, data):
        """
        Calculate additional derived features
        
        Args:
            data: Raw flow data
        
        Returns:
            dict: Derived features
        """
        derived = {}
        
        try:
            # Port ratio (dst_port / src_port normalized)
            src_port = data.get('src_port', 0)
            dst_port = data.get('dst_port', 0)
            if src_port > 0 and dst_port > 0:
                derived['port_ratio'] = min(dst_port, src_port) / max(dst_port, src_port)
            else:
                derived['port_ratio'] = 0
            
            # PSH ratio
            packet_count = max(data.get('packet_count', 1), 1)
            psh_count = data.get('psh_count', 0)
            derived['psh_ratio'] = psh_count / packet_count
            
            # URG ratio
            urg_count = data.get('urg_count', 0)
            derived['urg_ratio'] = urg_count / packet_count
            
            # Directional byte ratio (placeholder - in production, use actual direction)
            derived['byte_ratio_direction'] = data.get('byte_count', 0) / max(packet_count, 1)
            
            # Directional packet ratio
            derived['packet_ratio_direction'] = 1.0  # Placeholder
            
            # Coefficient of variation for inter-arrival times
            iat_mean = data.get('iat_mean', 0)
            iat_std = data.get('iat_std', 0)
            if iat_mean > 0:
                derived['iat_variance_coefficient'] = iat_std / iat_mean
            else:
                derived['iat_variance_coefficient'] = 0
        
        except Exception as e:
            logger.error(f"Error calculating derived features: {e}")
        
        return derived
    
    def _calculate_statistical_scores(self, features):
        """
        Calculate statistical anomaly scores
        
        Args:
            features: Flow features
        
        Returns:
            dict: Statistical scores
        """
        scores = {}
        
        try:
            # Z-score based anomaly detection
            for feature_name in ['packet_count', 'byte_count', 'pps', 'bps', 'entropy']:
                if feature_name in features and features[feature_name] is not None:
                    z_score = self._calculate_z_score(feature_name, features[feature_name])
                    scores[f'{feature_name}_zscore'] = z_score
                else:
                    scores[f'{feature_name}_zscore'] = 0
        except Exception as e:
            logger.error(f"Error calculating statistical scores: {e}")
        
        return scores
    
    def _calculate_z_score(self, feature_name, value):
        """Calculate z-score for a feature"""
        baseline = self.baselines[feature_name]
        
        if baseline['count'] < 10:  # Not enough data for reliable baseline
            baseline['count'] += 1
            # Update running mean and std
            delta = value - baseline['mean']
            baseline['mean'] += delta / baseline['count']
            delta2 = value - baseline['mean']
            baseline['std'] = math.sqrt(
                ((baseline['count'] - 1) * baseline['std']**2 + delta * delta2) / baseline['count']
            ) if baseline['count'] > 1 else 0
            return 0
        
        if baseline['std'] == 0:
            return 0 if value == baseline['mean'] else 3  # Significant deviation
        
        return abs(value - baseline['mean']) / baseline['std']
    
    def check_malicious_patterns(self, flow_data):
        """
        Check flow against known malicious patterns
        
        Args:
            flow_data: Flow data dict
        
        Returns:
            list: Detected patterns
        """
        detected_patterns = []
        
        try:
            # Check for C2 beaconing (regular periodic communication)
            if (flow_data.get('iat_std', 1) < self.malicious_patterns['c2_beaconing']['iat_std_threshold'] and
                flow_data.get('duration', 0) > self.malicious_patterns['c2_beaconing']['duration_threshold']):
                detected_patterns.append('c2_beaconing')
            
            # Check for port scanning
            if (flow_data.get('packet_count', 0) > self.malicious_patterns['port_scanning']['packet_count_threshold'] and
                flow_data.get('syn_ratio', 0) > self.malicious_patterns['port_scanning']['syn_ratio_threshold']):
                detected_patterns.append('port_scanning')
            
            # Check for data exfiltration
            if (flow_data.get('byte_count', 0) > self.malicious_patterns['data_exfiltration']['byte_count_threshold'] and
                flow_data.get('bps', 0) > self.malicious_patterns['data_exfiltration']['bps_threshold']):
                detected_patterns.append('data_exfiltration')
            
            # Check for DoS attack
            if (flow_data.get('pps', 0) > self.malicious_patterns['dos_attack']['pps_threshold'] and
                flow_data.get('packet_count', 0) > self.malicious_patterns['dos_attack']['packet_count_threshold']):
                detected_patterns.append('dos_attack')
        
        except Exception as e:
            logger.error(f"Error checking malicious patterns: {e}")
        
        return detected_patterns
    
    def update_baselines(self, flow_features):
        """Update statistical baselines with new flow data"""
        for feature_name, value in flow_features.items():
            if isinstance(value, (int, float)) and feature_name in self.feature_names:
                self._calculate_z_score(feature_name, value)
    
    def get_feature_importance_hint(self):
        """
        Return expected feature importance order
        (Based on training data - adjust according to your model)
        """
        return {
            'high_importance': ['entropy', 'iat_std', 'pps', 'rst_ratio', 'bps'],
            'medium_importance': ['duration', 'packet_count', 'byte_count', 'syn_ratio', 'payload_std'],
            'low_importance': ['window_mean', 'window_std', 'port_ratio']
        }


if __name__ == '__main__':
    # Test feature extractor
    extractor = DPIFeatureExtractor()
    
    test_flow = {
        'data': {
            'duration': 120,
            'packet_count': 500,
            'byte_count': 50000,
            'pps': 50,
            'bps': 5000,
            'avg_packet_size': 100,
            'iat_mean': 0.02,
            'iat_std': 0.001,
            'iat_min': 0.01,
            'iat_max': 0.05,
            'payload_mean': 80,
            'payload_std': 20,
            'payload_min': 40,
            'payload_max': 1500,
            'syn_ratio': 0.1,
            'fin_ratio': 0.1,
            'rst_ratio': 0.0,
            'ack_ratio': 0.8,
            'psh_count': 200,
            'urg_count': 0,
            'window_mean': 65535,
            'window_std': 100,
            'entropy': 3.5,
            'protocol': 1,
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 45678,
            'dst_port': 443
        }
    }
    
    features = extractor.extract_features_from_flow(test_flow)
    print(f"Extracted {len(features['features'])} features")
    patterns = extractor.check_malicious_patterns(test_flow['data'])
    print(f"Detected patterns: {patterns}")