"""
Built-in vulnerability scanner - no external tools required
Detects common web vulnerabilities using HTTP requests
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Any
from loguru import logger


class BuiltinScanner:
    """Built-in vulnerability scanner using pure Python"""
    
    def __init__(self, config):
        self.config = config
        self.timeout = aiohttp.ClientTimeout(total=30)
    
    async def scan(self, hosts: List) -> List[Dict[str, Any]]:
        """Scan hosts for common vulnerabilities"""
        logger.info(f"Starting built-in vulnerability scan for {len(hosts)} targets")
        
        vulnerabilities = []
        
        for host in hosts:
            urls = self._extract_web_urls(host)
            
            for url in urls:
                try:
                    logger.info(f"Testing {url}")
                    
                    # Run all vulnerability checks
                    tasks = [
                        self._test_sql_injection(url),
                        self._test_xss(url),
                        self._test_directory_traversal(url),
                        self._test_security_headers(url),
                        self._test_sensitive_files(url),
                        self._test_http_methods(url),
                    ]
                    
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for result in results:
                        if result and not isinstance(result, Exception):
                            if isinstance(result, list):
                                vulnerabilities.extend(result)
                            else:
                                vulnerabilities.append(result)
                    
                except Exception as e:
                    logger.debug(f"Scan failed for {url}: {e}")
        
        logger.success(f"Built-in scan completed: {len(vulnerabilities)} vulnerabilities found")
        return vulnerabilities
    
    def _extract_web_urls(self, host) -> List[str]:
        """Extract web URLs from host"""
        urls = []
        
        if hasattr(host, 'open_ports'):
            for port_info in host.open_ports:
                port = port_info.get('port', 0)
                service = port_info.get('service', '').lower()
                
                if service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                    protocol = 'https' if port in [443, 8443] or service == 'https' else 'http'
                    ip = host.ip if hasattr(host, 'ip') else str(host)
                    if port in [80, 443]:
                        urls.append(f'{protocol}://{ip}')
                    else:
                        urls.append(f'{protocol}://{ip}:{port}')
        
        return urls
    
    async def _test_sql_injection(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Common SQL injection test payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]
        
        # Common vulnerable parameters
        test_paths = [
            '/index.php?id=1',
            '/product.php?id=1',
            '/page.php?id=1',
            '/article.php?id=1',
            '/user.php?id=1',
            '/item.php?id=1',
            '/cat.php?id=1',
        ]
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for path in test_paths:
                url = base_url + path
                
                try:
                    # Get baseline response
                    async with session.get(url, ssl=False) as resp:
                        baseline = await resp.text()
                        baseline_len = len(baseline)
                    
                    # Test payloads
                    for payload in sql_payloads:
                        test_url = url.replace('id=1', f'id={payload}')
                        
                        try:
                            async with session.get(test_url, ssl=False) as resp:
                                content = await resp.text()
                                
                                # Check for SQL error messages
                                sql_errors = [
                                    'sql syntax',
                                    'mysql_fetch',
                                    'mysql_num_rows',
                                    'mysqli',
                                    'sqlstate',
                                    'pg_query',
                                    'ora-',
                                    'microsoft sql',
                                    'odbc',
                                    'sqlite',
                                    'syntax error',
                                    'unclosed quotation',
                                ]
                                
                                content_lower = content.lower()
                                for error in sql_errors:
                                    if error in content_lower:
                                        vulnerabilities.append({
                                            'id': f'sqli-{hash(url)}',
                                            'name': 'SQL Injection',
                                            'severity': 'critical',
                                            'cvss_score': 9.8,
                                            'cve_id': 'CWE-89',
                                            'url': url,
                                            'description': f'SQL injection vulnerability detected. Error message: {error}',
                                            'payload': payload,
                                            'evidence': content[:200],
                                            'solution': 'Use parameterized queries and input validation',
                                            'tool': 'BuiltinScanner'
                                        })
                                        logger.warning(f"🚨 SQL Injection found: {url}")
                                        return vulnerabilities  # Found one, no need to test more
                                
                                # Check for significant response differences
                                if abs(len(content) - baseline_len) > baseline_len * 0.3:
                                    vulnerabilities.append({
                                        'id': f'sqli-blind-{hash(url)}',
                                        'name': 'Possible SQL Injection (Blind)',
                                        'severity': 'high',
                                        'cvss_score': 8.5,
                                        'cve_id': 'CWE-89',
                                        'url': url,
                                        'description': 'Possible blind SQL injection - response varies significantly',
                                        'payload': payload,
                                        'solution': 'Use parameterized queries and input validation',
                                        'tool': 'BuiltinScanner'
                                    })
                                    logger.warning(f"⚠️  Possible blind SQL injection: {url}")
                                    return vulnerabilities
                        
                        except:
                            continue
                
                except:
                    continue
        
        return vulnerabilities
    
    async def _test_xss(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
        ]
        
        test_paths = [
            '/search.php?q=test',
            '/index.php?search=test',
            '/search?q=test',
        ]
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for path in test_paths:
                url = base_url + path
                
                for payload in xss_payloads:
                    test_url = url.replace('test', payload)
                    
                    try:
                        async with session.get(test_url, ssl=False) as resp:
                            content = await resp.text()
                            
                            # Check if payload is reflected unescaped
                            if payload in content:
                                vulnerabilities.append({
                                    'id': f'xss-{hash(url)}',
                                    'name': 'Cross-Site Scripting (XSS)',
                                    'severity': 'high',
                                    'cvss_score': 7.5,
                                    'cve_id': 'CWE-79',
                                    'url': url,
                                    'description': 'Reflected XSS vulnerability detected',
                                    'payload': payload,
                                    'solution': 'Sanitize and encode user input',
                                    'tool': 'BuiltinScanner'
                                })
                                logger.warning(f"🚨 XSS found: {url}")
                                return vulnerabilities
                    except:
                        continue
        
        return vulnerabilities
    
    async def _test_directory_traversal(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
        ]
        
        test_paths = [
            '/file.php?file=test.txt',
            '/download.php?file=test.txt',
            '/include.php?page=home',
        ]
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for path in test_paths:
                url = base_url + path
                
                for payload in traversal_payloads:
                    test_url = url.replace('test.txt', payload).replace('home', payload)
                    
                    try:
                        async with session.get(test_url, ssl=False) as resp:
                            content = await resp.text()
                            
                            # Check for file disclosure indicators
                            if 'root:' in content or '[extensions]' in content.lower():
                                vulnerabilities.append({
                                    'id': f'lfi-{hash(url)}',
                                    'name': 'Directory Traversal / Local File Inclusion',
                                    'severity': 'high',
                                    'cvss_score': 8.0,
                                    'cve_id': 'CWE-22',
                                    'url': url,
                                    'description': 'Directory traversal vulnerability detected',
                                    'payload': payload,
                                    'solution': 'Validate and sanitize file paths',
                                    'tool': 'BuiltinScanner'
                                })
                                logger.warning(f"🚨 Directory traversal found: {url}")
                                return vulnerabilities
                    except:
                        continue
        
        return vulnerabilities
    
    async def _test_security_headers(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for missing security headers"""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(base_url, ssl=False) as resp:
                    headers = resp.headers
                    
                    # Check for missing security headers
                    missing_headers = []
                    
                    if 'X-Frame-Options' not in headers:
                        missing_headers.append('X-Frame-Options')
                    
                    if 'X-Content-Type-Options' not in headers:
                        missing_headers.append('X-Content-Type-Options')
                    
                    if 'X-XSS-Protection' not in headers:
                        missing_headers.append('X-XSS-Protection')
                    
                    if 'Strict-Transport-Security' not in headers and base_url.startswith('https'):
                        missing_headers.append('Strict-Transport-Security')
                    
                    if 'Content-Security-Policy' not in headers:
                        missing_headers.append('Content-Security-Policy')
                    
                    if missing_headers:
                        vulnerabilities.append({
                            'id': f'headers-{hash(base_url)}',
                            'name': 'Missing Security Headers',
                            'severity': 'medium',
                            'cvss_score': 5.0,
                            'cve_id': 'CWE-693',
                            'url': base_url,
                            'description': f'Missing security headers: {", ".join(missing_headers)}',
                            'solution': 'Add recommended security headers',
                            'tool': 'BuiltinScanner'
                        })
                        logger.info(f"ℹ️  Missing security headers: {base_url}")
        
        except:
            pass
        
        return vulnerabilities
    
    async def _test_sensitive_files(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for exposed sensitive files"""
        vulnerabilities = []
        
        sensitive_files = [
            '/.git/config',
            '/.env',
            '/phpinfo.php',
            '/admin/',
            '/backup.sql',
            '/config.php.bak',
            '/web.config',
        ]
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for file_path in sensitive_files:
                url = base_url + file_path
                
                try:
                    async with session.get(url, ssl=False) as resp:
                        if resp.status == 200:
                            vulnerabilities.append({
                                'id': f'exposure-{hash(url)}',
                                'name': 'Sensitive File Exposure',
                                'severity': 'medium',
                                'cvss_score': 6.0,
                                'cve_id': 'CWE-200',
                                'url': url,
                                'description': f'Sensitive file exposed: {file_path}',
                                'solution': 'Remove or restrict access to sensitive files',
                                'tool': 'BuiltinScanner'
                            })
                            logger.warning(f"⚠️  Sensitive file exposed: {url}")
                except:
                    continue
        
        return vulnerabilities
    
    async def _test_http_methods(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for dangerous HTTP methods"""
        vulnerabilities = []
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for method in dangerous_methods:
                try:
                    async with session.request(method, base_url, ssl=False) as resp:
                        if resp.status not in [405, 501]:  # Method not allowed
                            vulnerabilities.append({
                                'id': f'method-{method}-{hash(base_url)}',
                                'name': f'Dangerous HTTP Method Enabled: {method}',
                                'severity': 'low',
                                'cvss_score': 4.0,
                                'cve_id': 'CWE-16',
                                'url': base_url,
                                'description': f'HTTP {method} method is enabled',
                                'solution': 'Disable unnecessary HTTP methods',
                                'tool': 'BuiltinScanner'
                            })
                except:
                    continue
        
        return vulnerabilities
