from collections import defaultdict
import time
import math


class FlowMetadataCollector:
    """
    Collect flow-level metadata for DPI-based anomaly detection
    Extracts features needed for Isolation Forest / Random Forest models
    """
    
    def __init__(self, flow_timeout=60):
        self.flow_timeout = flow_timeout
        self.flows = defaultdict(self._create_flow)
        self.completed_flows = []
        self.stats = {
            'active_flows': 0,
            'completed_flows': 0,
            'total_packets_processed': 0
        }
    
    def _create_flow(self):
        return {
            'packets': [],
            'start_time': None,
            'last_packet_time': None,
            'byte_count': 0,
            'packet_count': 0,
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'ack_count': 0,
            'psh_count': 0,
            'urg_count': 0,
            'payload_sizes': [],
            'inter_arrival_times': [],
            'window_sizes': []
        }
    
    def process_packet(self, packet):
        """Process a packet and update flow statistics"""
        try:
            self.stats['total_packets_processed'] += 1
            
            if packet.haslayer('IP') and (packet.haslayer('TCP') or packet.haslayer('UDP')):
                proto = 'TCP' if packet.haslayer('TCP') else 'UDP'
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                src_port = packet[proto].sport
                dst_port = packet[proto].dport
                
                flow_key = (
                    min(src_ip, dst_ip),
                    max(src_ip, dst_ip),
                    min(src_port, dst_port),
                    max(src_port, dst_port),
                    proto
                )
                
                flow = self.flows[flow_key]
                
                if flow['start_time'] is None:
                    flow['start_time'] = packet.time
                    flow['protocol'] = proto
                    flow['src_ip'] = src_ip
                    flow['dst_ip'] = dst_ip
                    flow['src_port'] = src_port
                    flow['dst_port'] = dst_port
                
                if flow['last_packet_time'] is not None:
                    inter_arrival = packet.time - flow['last_packet_time']
                    flow['inter_arrival_times'].append(inter_arrival)
                
                flow['last_packet_time'] = packet.time
                flow['packet_count'] += 1
                
                if proto == 'TCP':
                    flags = packet['TCP'].flags
                    if flags & 0x02: flow['syn_count'] += 1
                    if flags & 0x01: flow['fin_count'] += 1
                    if flags & 0x04: flow['rst_count'] += 1
                    if flags & 0x10: flow['ack_count'] += 1
                    if flags & 0x08: flow['psh_count'] += 1
                    if flags & 0x20: flow['urg_count'] += 1
                    flow['window_sizes'].append(packet['TCP'].window)
                
                payload_size = len(packet.payload) if hasattr(packet, 'payload') else 0
                flow['byte_count'] += payload_size
                if payload_size > 0:
                    flow['payload_sizes'].append(payload_size)
                
                flow['packets'].append(packet.time)
                self._cleanup_old_flows()
                self.stats['active_flows'] = len(self.flows)
                
        except Exception as e:
            print(f"Error processing flow packet: {e}")
    
    def _cleanup_old_flows(self):
        """Remove flows that have timed out"""
        if not self.flows:
            return
        
        latest_time = max(
            flow['last_packet_time'] 
            for flow in self.flows.values() 
            if flow['last_packet_time'] is not None
        ) if self.flows else time.time()
        
        expired_flows = []
        for flow_key, flow in self.flows.items():
            if flow['last_packet_time'] is not None:
                if latest_time - flow['last_packet_time'] > self.flow_timeout:
                    expired_flows.append(flow_key)
        
        for flow_key in expired_flows:
            flow = self.flows.pop(flow_key)
            if flow['packet_count'] > 1:
                self.completed_flows.append(flow)
                self.stats['completed_flows'] += 1
    
    def get_flow_statistics(self):
        """Get current flow statistics for anomaly detection"""
        completed = []
        while self.completed_flows:
            flow = self.completed_flows.pop(0)
            completed.append(flow)
        
        if not completed:
            for flow_key, flow in list(self.flows.items())[:5]:
                if flow['packet_count'] >= 10:
                    completed.append(flow)
                    del self.flows[flow_key]
                    break
        
        if not completed:
            return None
        
        flow = completed[-1]
        features = self._extract_flow_features(flow)
        return features
    
    def _extract_flow_features(self, flow):
        """Extract features from a flow for ML model input - NUMERIC ONLY"""
        duration = (flow['last_packet_time'] - flow['start_time']) if flow['start_time'] and flow['last_packet_time'] else 0
        
        packet_count = flow['packet_count']
        byte_count = flow['byte_count']
        pps = packet_count / max(duration, 0.001)
        bps = byte_count / max(duration, 0.001)
        
        iat_list = flow['inter_arrival_times']
        if iat_list:
            iat_mean = sum(iat_list) / len(iat_list)
            iat_std = math.sqrt(sum((x - iat_mean) ** 2 for x in iat_list) / len(iat_list)) if len(iat_list) > 1 else 0
            iat_min = min(iat_list)
            iat_max = max(iat_list)
        else:
            iat_mean = iat_std = iat_min = iat_max = 0
        
        payload_sizes = flow['payload_sizes']
        if payload_sizes:
            payload_mean = sum(payload_sizes) / len(payload_sizes)
            payload_std = math.sqrt(sum((x - payload_mean) ** 2 for x in payload_sizes) / len(payload_sizes)) if len(payload_sizes) > 1 else 0
            payload_min = min(payload_sizes)
            payload_max = max(payload_sizes)
        else:
            payload_mean = payload_std = payload_min = payload_max = 0
        
        syn_ratio = flow['syn_count'] / max(packet_count, 1)
        fin_ratio = flow['fin_count'] / max(packet_count, 1)
        rst_ratio = flow['rst_count'] / max(packet_count, 1)
        ack_ratio = flow['ack_count'] / max(packet_count, 1)
        psh_ratio = flow['psh_count'] / max(packet_count, 1)
        urg_ratio = flow['urg_count'] / max(packet_count, 1)
        
        window_sizes = flow['window_sizes']
        if window_sizes:
            window_mean = sum(window_sizes) / len(window_sizes)
            window_std = math.sqrt(sum((x - window_mean) ** 2 for x in window_sizes) / len(window_sizes)) if len(window_sizes) > 1 else 0
        else:
            window_mean = window_std = 0
        
        entropy = self._calculate_entropy(payload_sizes)
        
        # RETURN ONLY FLOATS - NO STRINGS!
        return {
            'type': 'dpi',
            'data': {
                'duration': float(duration),
                'packet_count': float(packet_count),
                'byte_count': float(byte_count),
                'pps': float(pps),
                'bps': float(bps),
                'avg_packet_size': float(byte_count / max(packet_count, 1)),
                'iat_mean': float(iat_mean),
                'iat_std': float(iat_std),
                'iat_min': float(iat_min),
                'iat_max': float(iat_max),
                'payload_mean': float(payload_mean),
                'payload_std': float(payload_std),
                'payload_min': float(payload_min),
                'payload_max': float(payload_max),
                'syn_ratio': float(syn_ratio),
                'fin_ratio': float(fin_ratio),
                'rst_ratio': float(rst_ratio),
                'ack_ratio': float(ack_ratio),
                'psh_ratio': float(psh_ratio),
                'urg_ratio': float(urg_ratio),
                'window_mean': float(window_mean),
                'window_std': float(window_std),
                'entropy': float(entropy),
                'protocol': 1.0 if flow['protocol'] == 'TCP' else 0.0,
            },
            'metadata': {
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port']
            }
        }
    
    def _calculate_entropy(self, values):
        if not values:
            return 0
        value_counts = defaultdict(int)
        for value in values:
            value_counts[value] += 1
        entropy = 0
        total = len(values)
        for count in value_counts.values():
            prob = count / total
            entropy -= prob * math.log2(prob)
        return entropy
    
    def get_active_flow_count(self):
        return len(self.flows)