import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RegexRules:
    """
    Rule-based detection for common web application attacks
    Complements the ML-based AppAttackDetector
    """
    
    def __init__(self):
        # SQL Injection patterns
        self.sql_injection_patterns = [
            r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"(?i)(\%22)|(\")",
            r"(?i)(\%3D)|(=)[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"(?i)((\%27)|(\'))\s*union\s*select",
            r"(?i)((\%27)|(\'))\s*union\s*all\s*select",
            r"(?i)((\%27)|(\'))\s*or\s*(\'|\%27)[^\n]*(\'|\%27)\s*=\s*(\'|\%27)",
            r"(?i)((\%27)|(\'))\s*and\s*(\'|\%27)[^\n]*(\'|\%27)\s*=\s*(\'|\%27)",
            r"(?i)((\%27)|(\'))\s*waitfor\s*delay",
            r"(?i)((\%27)|(\'))\s*benchmark\s*\(",
            r"(?i)sleep\s*\(\s*\d+\s*\)",
            r"(?i)information_schema",
            r"(?i)table_name",
            r"(?i)column_name",
            r"(?i)group_concat\s*\(",
            r"(?i)concat\s*\(",
            r"(?i)load_file\s*\(",
            r"(?i)outfile",
            r"(?i)dumpfile",
            r"(?i);\s*(drop|delete|update|insert|exec|execute)\s",
            r"(?i)/\*.*\*/",
            r"(?i)--\s",
            r"(?i)#",
        ]
        
        # XSS (Cross-Site Scripting) patterns
        self.xss_patterns = [
            r"(?i)<script[^>]*>.*?</script>",
            r"(?i)<script[^>]*>",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)onclick\s*=",
            r"(?i)onmouseover\s*=",
            r"(?i)onfocus\s*=",
            r"(?i)onblur\s*=",
            r"(?i)javascript\s*:",
            r"(?i)vbscript\s*:",
            r"(?i)\%3Cscript\%3E",
            r"(?i)\&lt;script\&gt;",
            r"(?i)\\x3cscript\\x3e",
            r"(?i)\\u003cscript\\u003e",
            r"(?i)<img[^>]+src\s*=\s*[\"'][^\"']*onerror",
            r"(?i)<iframe[^>]*>",
            r"(?i)<embed[^>]*>",
            r"(?i)<object[^>]*>",
            r"(?i)eval\s*\(",
            r"(?i)document\.cookie",
            r"(?i)document\.location",
            r"(?i)window\.location",
            r"(?i)alert\s*\(",
            r"(?i)prompt\s*\(",
            r"(?i)confirm\s*\(",
            r"(?i)autofocus\s*.*onfocus",
            r"(?i)<svg[^>]*onload",
            r"(?i)<marquee[^>]*onstart",
            r"(?i)<details[^>]*ontoggle",
        ]
        
        # Command Injection patterns
        self.command_injection_patterns = [
            r"(?i)[;&|]\s*(ls|pwd|id|whoami|cat|more|less|head|tail|grep|find)\b",
            r"(?i)[;&|]\s*(wget|curl|nc|netcat|telnet|ssh)\b",
            r"(?i)[;&|]\s*(chmod|chown|mkdir|rmdir|rm|mv|cp)\b",
            r"(?i)[;&|]\s*(ps|kill|service|systemctl)\b",
            r"(?i)[;&|]\s*(python|perl|ruby|php|bash|sh)\b",
            r"(?i)[;&|]\s*(whoami|sudo)\b",
            r"(?i)[;&|]\s*(dir|type|whoami|hostname|ipconfig|netstat|tasklist)\b",
            r"(?i)[;&|]\s*(powershell|cmd\.exe|wmic|reg)\b",
            r"(?i)\$\(.*\)",
            r"(?i)\`[^`]*\`",
            r"(?i)\$\{.*\}",
            r"(?i)\|\s*(bash|sh|zsh|ksh|csh)",
            r"(?i)>\s*/dev/null",
            r"(?i)2>&1",
            r"(?i)\\x[0-9a-f]{2}",
            r"(?i)\${IFS}",
            r"(?i)\<\(",
        ]
        
        # Path Traversal patterns
        self.path_traversal_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"\.\.\%2f",
            r"\.\.\%5c",
            r"\.\.%252f",
            r"\.\.%255c",
            r"\.%2e\/",
            r"%2e%2e\/",
            r"\/etc\/passwd",
            r"\/etc\/shadow",
            r"\/etc\/hosts",
            r"\/proc\/self\/environ",
            r"C:\\Windows\\System32",
            r"C:\\boot\.ini",
            r"\/var\/log\/",
            r"\.\.\u2215",
            r"\.\.\u2216",
            r"\.\.%c0%af",
            r"\.\.%c1%9c",
        ]
        
        # SSTI (Server-Side Template Injection) patterns
        self.ssti_patterns = [
            r"(?i)\{\{.*\}\}",
            r"(?i)\{\%.*\%\}",
            r"(?i)\$\{.*\}",
            r"(?i)\#\{.*\}",
            r"(?i)<\%=.*\%>",
            r"(?i)\{\{7\*7\}\}",
            r"(?i)\{\{config\}\}",
            r"(?i)\{\{self\}\}",
            r"(?i)\{\{request\}\}",
        ]
    
    def _contains_attack_patterns(self, text):
        """
        Quick check if text contains ANY attack patterns.
        Used by run_remote.py for fast pre-screening.
        
        Args:
            text: String to check
        
        Returns:
            bool: True if any attack pattern found
        """
        if not text:
            return False
        
        all_patterns = (
            self.sql_injection_patterns +
            self.xss_patterns +
            self.command_injection_patterns +
            self.path_traversal_patterns +
            self.ssti_patterns
        )
        
        for pattern in all_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def detect_attack(self, payload, attack_type=None):
        """
        Detect attacks using regex patterns
        
        Args:
            payload: String payload to check
            attack_type: Specific attack type to check (None = all)
        
        Returns:
            dict: Detection results
        """
        if not payload:
            return {'detected': False, 'matches': []}
        
        all_matches = []
        
        if attack_type is None or attack_type == 'sql_injection':
            sql_matches = self._check_patterns(payload, self.sql_injection_patterns)
            if sql_matches:
                all_matches.append({
                    'attack_type': 'sql_injection',
                    'matches': sql_matches,
                    'confidence': min(len(sql_matches) * 0.15, 0.95)
                })
        
        if attack_type is None or attack_type == 'xss':
            xss_matches = self._check_patterns(payload, self.xss_patterns)
            if xss_matches:
                all_matches.append({
                    'attack_type': 'xss',
                    'matches': xss_matches,
                    'confidence': min(len(xss_matches) * 0.15, 0.95)
                })
        
        if attack_type is None or attack_type == 'command_injection':
            cmd_matches = self._check_patterns(payload, self.command_injection_patterns)
            if cmd_matches:
                all_matches.append({
                    'attack_type': 'command_injection',
                    'matches': cmd_matches,
                    'confidence': min(len(cmd_matches) * 0.2, 0.95)
                })
        
        if attack_type is None or attack_type == 'path_traversal':
            path_matches = self._check_patterns(payload, self.path_traversal_patterns)
            if path_matches:
                all_matches.append({
                    'attack_type': 'path_traversal',
                    'matches': path_matches,
                    'confidence': min(len(path_matches) * 0.2, 0.95)
                })
        
        if attack_type is None or attack_type == 'ssti':
            ssti_matches = self._check_patterns(payload, self.ssti_patterns)
            if ssti_matches:
                all_matches.append({
                    'attack_type': 'ssti',
                    'matches': ssti_matches,
                    'confidence': min(len(ssti_matches) * 0.25, 0.95)
                })
        
        if all_matches:
            best_match = max(all_matches, key=lambda x: x['confidence'])
            return {
                'detected': True,
                'attack_type': best_match['attack_type'],
                'confidence': best_match['confidence'],
                'all_matches': all_matches
            }
        
        return {'detected': False, 'matches': []}
    
    def _check_patterns(self, text, patterns):
        """Check text against a list of regex patterns"""
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, text)
            if found:
                matches.append({
                    'pattern': pattern,
                    'matches': found[:5]
                })
        return matches
    
    def quick_scan(self, http_data):
        """
        Quick scan of HTTP data for obvious attacks
        
        Args:
            http_data: Dict from HTTPExtractor
        
        Returns:
            dict: Scan results
        """
        results = {
            'suspicious': False,
            'detected_attacks': [],
            'url_attacks': None,
            'body_attacks': None
        }
        
        if 'uri' in http_data:
            url_result = self.detect_attack(http_data['uri'])
            if url_result['detected']:
                results['suspicious'] = True
                results['detected_attacks'].append(url_result)
                results['url_attacks'] = url_result
        
        if 'query_params' in http_data:
            for param, values in http_data['query_params'].items():
                for value in values:
                    param_result = self.detect_attack(f"{param}={value}")
                    if param_result['detected']:
                        results['suspicious'] = True
                        results['detected_attacks'].append(param_result)
        
        if 'body' in http_data and http_data['body']:
            body_result = self.detect_attack(http_data['body'])
            if body_result['detected']:
                results['suspicious'] = True
                results['detected_attacks'].append(body_result)
                results['body_attacks'] = body_result
        
        return results