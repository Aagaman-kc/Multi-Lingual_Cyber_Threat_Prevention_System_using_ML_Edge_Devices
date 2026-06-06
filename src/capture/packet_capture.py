import scapy.all as scapy
from scapy.layers import http, dns
import threading
import queue
import time
from collections import defaultdict
import logging

from capture_layer.http_extractor import HTTPExtractor
from capture_layer.dns_extractor import DNSExtractor
from capture_layer.smtp_extractor import SMTPExtractor
from capture_layer.flow_metadata import FlowMetadataCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PacketCapture:
    """Main packet capture engine using Scapy"""
    
    def __init__(self, interface='eth0', promiscuous=True, packet_queue_size=10000):
        self.interface = interface
        self.promiscuous = promiscuous
        self.running = False
        
        self.packet_queue = queue.Queue(maxsize=packet_queue_size)
        
        self.http_extractor = HTTPExtractor()
        self.dns_extractor = DNSExtractor()
        self.smtp_extractor = SMTPExtractor()
        self.flow_collector = FlowMetadataCollector()
        
        self.callbacks = {
            'http_request': [],
            'http_response': [],
            'https_request': [],     # NEW: HTTPS SNI support
            'dns_query': [],
            'dns_response': [],
            'smtp_data': [],
            'flow_stats': [],
            'raw_packet': []
        }
        
        self.stats = {
            'total_packets': 0, 'http_packets': 0, 'https_packets': 0,
            'dns_packets': 0, 'smtp_packets': 0, 'tcp_packets': 0,
            'udp_packets': 0, 'icmp_packets': 0, 'other_packets': 0,
            'start_time': None, 'errors': 0
        }
        
        self.processor_thread = None
        self.flow_check_counter = 0  # Only check flows periodically
        
    def register_callback(self, event_type, callback):
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
            logger.info(f"Callback registered for {event_type}")
        else:
            logger.warning(f"Unknown event type: {event_type}")
    
    def start(self):
        if self.running:
            logger.warning("Capture is already running")
            return
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        self.processor_thread = threading.Thread(target=self._process_packets, daemon=True)
        self.processor_thread.start()
        logger.info("Packet processor thread started")
        
        capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        capture_thread.start()
        logger.info(f"Packet capture started on interface: {self.interface}")
    
    def stop(self):
        self.running = False
        logger.info("Packet capture stopped")
    
    def _capture_packets(self):
        """Main packet capture loop with error recovery"""
        while self.running:
            try:
                scapy.sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    promisc=self.promiscuous,
                    stop_filter=lambda x: not self.running
                )
            except PermissionError:
                logger.error("Permission denied! Run with sudo.")
                self.running = False
            except OSError as e:
                logger.error(f"Interface error: {e}")
                time.sleep(5)  # Wait before retry
            except Exception as e:
                logger.error(f"Capture error: {e}")
                self.stats['errors'] += 1
                if self.running:
                    time.sleep(1)  # Brief pause before retry
    
    def _packet_handler(self, packet):
        """Handle captured packet - add to processing queue"""
        try:
            if self.packet_queue.full():
                # Drop oldest packet to make room
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    pass
                logger.debug("Packet queue full, dropped oldest packet")
            
            self.packet_queue.put_nowait(packet)
            self.stats['total_packets'] += 1
            
            if packet.haslayer(scapy.TCP):
                self.stats['tcp_packets'] += 1
            elif packet.haslayer(scapy.UDP):
                self.stats['udp_packets'] += 1
            elif packet.haslayer(scapy.ICMP):
                self.stats['icmp_packets'] += 1
            else:
                self.stats['other_packets'] += 1
                
        except queue.Full:
            pass  # Queue full, packet dropped
        except Exception as e:
            logger.error(f"Error handling packet: {e}")
            self.stats['errors'] += 1
    
    def _process_packets(self):
        """Process packets from queue"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self._route_packet(packet)
                
                # Always collect flow metadata
                self.flow_collector.process_packet(packet)
                
                # Only check flow stats every 50 packets (reduce overhead)
                self.flow_check_counter += 1
                if self.flow_check_counter >= 50:
                    self.flow_check_counter = 0
                    flow_stats = self.flow_collector.get_flow_statistics()
                    if flow_stats:
                        self._trigger_callback('flow_stats', flow_stats)
                
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                self.stats['errors'] += 1
    
    def _route_packet(self, packet):
        """Route packet to appropriate extractor"""
        
        # HTTP detection (port 80)
        if packet.haslayer(http.HTTPRequest):
            self.stats['http_packets'] += 1
            extracted_data = self.http_extractor.extract_request(packet)
            if extracted_data:
                self._trigger_callback('http_request', extracted_data)
        
        elif packet.haslayer(http.HTTPResponse):
            extracted_data = self.http_extractor.extract_response(packet)
            if extracted_data:
                self._trigger_callback('http_response', extracted_data)
        
        # HTTPS detection (port 443) - Extract SNI
        elif (packet.haslayer(scapy.TCP) and 
              (packet[scapy.TCP].sport == 443 or packet[scapy.TCP].dport == 443)):
            self.stats['https_packets'] += 1
            extracted_data = self.http_extractor._extract_tls_sni(packet)
            if extracted_data:
                self._trigger_callback('https_request', extracted_data)
        
        # DNS detection (port 53)
        elif packet.haslayer(dns.DNS):
            self.stats['dns_packets'] += 1
            if packet.haslayer(dns.DNSQR):
                extracted_data = self.dns_extractor.extract_query(packet)
                if extracted_data:
                    self._trigger_callback('dns_query', extracted_data)
            
            if packet.haslayer(dns.DNSRR):
                extracted_data = self.dns_extractor.extract_response(packet)
                if extracted_data:
                    self._trigger_callback('dns_response', extracted_data)
        
        # SMTP detection by port
        elif (packet.haslayer(scapy.TCP) and 
              (packet[scapy.TCP].sport in [25, 587, 465, 2525] or 
               packet[scapy.TCP].dport in [25, 587, 465, 2525])):
            self.stats['smtp_packets'] += 1
            extracted_data = self.smtp_extractor.extract_data(packet)
            if extracted_data:
                self._trigger_callback('smtp_data', extracted_data)
        
        self._trigger_callback('raw_packet', packet)
    
    def _trigger_callback(self, event_type, data):
        """Trigger all registered callbacks for an event type"""
        if event_type in self.callbacks:
            for callback in self.callbacks[event_type]:
                try:
                    callback(data)
                except Exception as e:
                    logger.error(f"Callback error for {event_type}: {e}")
    
    def get_statistics(self):
        """Get current capture statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['uptime_seconds'] = time.time() - stats['start_time']
            if stats['uptime_seconds'] > 0:
                stats['packets_per_second'] = stats['total_packets'] / stats['uptime_seconds']
        return stats
    
    def reset_statistics(self):
        """Reset statistics counters"""
        self.stats = {
            'total_packets': 0, 'http_packets': 0, 'https_packets': 0,
            'dns_packets': 0, 'smtp_packets': 0, 'tcp_packets': 0,
            'udp_packets': 0, 'icmp_packets': 0, 'other_packets': 0,
            'start_time': time.time(), 'errors': 0
        }