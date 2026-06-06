import joblib
import pandas as pd
import numpy as np


class DPIDetector:
    """
    DPI Flow-Based Anomaly Detector
    Uses Isolation Forest / Random Forest pipeline to detect network anomalies
    Handles feature padding for models trained with different feature counts
    """
    
    def __init__(self, pipeline_path):
        self.pipeline = joblib.load(pipeline_path)
        
        # Determine expected feature count from the pipeline
        try:
            self.n_features = self.pipeline.steps[0][1].n_features_in_
        except AttributeError:
            try:
                self.n_features = self.pipeline.steps[-1][1].n_features_in_
            except AttributeError:
                self.n_features = 194

    def predict(self, flow_features_dict):
        """
        Predict whether a flow is anomalous
        
        Args:
            flow_features_dict: Dictionary of flow features
        
        Returns:
            dict: {'label': 'anomaly' or 'normal', 'confidence': float, 'module': 'dpi'}
        """
        try:
            features = flow_features_dict.copy()
            
            # Pad with extra features if needed
            current_count = len(features)
            if current_count < self.n_features:
                for i in range(current_count, self.n_features):
                    features[f'feature_{i}'] = 0.0
            
            # Create DataFrame and trim
            df = pd.DataFrame([features])
            if df.shape[1] > self.n_features:
                df = df.iloc[:, :self.n_features]
            
            # Convert to numpy array
            X = df.values.astype(np.float64)
            
            # Predict
            pred = self.pipeline.predict(X)[0]
            proba = self.pipeline.predict_proba(X)[0].max()
            
            label = 'anomaly' if pred == 1 else 'normal'
            
            return {
                'label': label,
                'confidence': float(proba),
                'module': 'dpi'
            }
            
        except Exception as e:
            print(f"[DPI] Error: {e}")
            return self._fallback_predict(flow_features_dict)

    def _fallback_predict(self, flow_features_dict):
        """
        Fallback prediction using heuristics when ML model fails
        Detects: DoS, Port Scanning, C2 Beaconing, Data Exfiltration
        """
        pps = flow_features_dict.get('pps', 0)
        syn_ratio = flow_features_dict.get('syn_ratio', 0)
        byte_count = flow_features_dict.get('byte_count', 0)
        bps = flow_features_dict.get('bps', 0)
        entropy = flow_features_dict.get('entropy', 0)
        iat_std = flow_features_dict.get('iat_std', 0)
        iat_mean = flow_features_dict.get('iat_mean', 0.001)
        
        score = 0
        reasons = []
        
        # DoS/DDoS detection
        if pps > 5000:
            score += 4
            reasons.append(f'Extreme PPS: {pps:.0f}')
        elif pps > 500:
            score += 2
            reasons.append(f'High PPS: {pps:.0f}')
        elif pps > 100:
            score += 1
        
        # Port scanning detection
        if syn_ratio > 0.9:
            score += 4
            reasons.append(f'Port scan: SYN ratio {syn_ratio:.2f}')
        elif syn_ratio > 0.7:
            score += 2
            reasons.append(f'Suspicious SYN: {syn_ratio:.2f}')
        
        # Data exfiltration detection
        if bps > 1000000:
            score += 4
            reasons.append(f'Extreme BPS: {bps:.0f}')
        elif bps > 100000:
            score += 2
            reasons.append(f'High BPS: {bps:.0f}')
        
        if byte_count > 10000000:
            score += 3
            reasons.append(f'Large transfer: {byte_count:,} bytes')
        
        # C2 Beaconing detection
        if iat_mean > 0 and iat_std / max(iat_mean, 0.001) < 0.1 and iat_mean > 1:
            score += 3
            reasons.append(f'Beaconing: regular {iat_mean:.1f}s intervals')
        
        # Encrypted/obfuscated traffic
        if entropy > 7.5:
            score += 2
            reasons.append(f'High entropy: {entropy:.2f}')
        
        # Decision
        if score >= 6:
            label = 'anomaly'
            confidence = min(0.7 + (score * 0.04), 0.95)
        elif score >= 3:
            label = 'anomaly'
            confidence = 0.5 + (score * 0.05)
        else:
            label = 'normal'
            confidence = max(0.6, 0.9 - (score * 0.1))
        
        return {
            'label': label,
            'confidence': confidence,
            'module': 'dpi'
        }