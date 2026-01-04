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
        """Scan hosts for common vulnerabilities with enhanced detection"""
        logger.info(f"Starting ENHANCED built-in vulnerability scan for {len(hosts)} targets")
        
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
                        self._test_host_header_injection(url),
                        self._test_cache_poisoning(url),
                    ]
                    
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for result in results:
                        if result and not isinstance(result, Exception):
                            if isinstance(result, list):
                                vulnerabilities.extend(result)
                            else:
                                vulnerabilities.append(result)
                                
                except:
                    continue
        
        logger.success(f"ENHANCED built-in scan completed: {len(vulnerabilities)} vulnerabilities found")
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
                    
                    # Add both IP and hostname if available
                    targets = []
                    if hasattr(host, 'ip'):
                        targets.append(host.ip)
                    if hasattr(host, 'hostname') and host.hostname:
                        targets.append(host.hostname)
                    
                    # If neither IP nor hostname, use string representation
                    if not targets:
                        targets.append(str(host))
                    
                    for target in targets:
                        base_url = f'{protocol}://{target}'
                        if port not in [80, 443]:
                            base_url = f'{protocol}://{target}:{port}'
                        
                        # Add base URL
                        urls.append(base_url)
                        
                        # Add common web paths for more comprehensive testing
                        common_paths = [
                            '',  # Base path
                            '/index.php',
                            '/index.html',
                            '/home.php',
                            '/login.php',
                            '/register.php',
                            '/search.php',
                            '/contact.php',
                            '/about.php',
                            '/admin/index.php',
                            '/user/profile.php',
                            '/api/',
                            '/api/v1/',
                            '/api/users',
                            '/api/products',
                            '/dashboard/',
                            '/account/',
                            '/settings/',
                            '/upload/',
                            '/download/',
                        ]
                        
                        for path in common_paths:
                            if path:  # Don't duplicate the base URL
                                urls.append(f'{base_url}{path}')
        
        return urls
    
    async def _test_sql_injection(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Common SQL injection test payloads - expanded list
        sql_payloads = [
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
        ]
        
        # Common vulnerable parameters - expanded list
        test_paths = [
            '/index.php?id=1',
            '/product.php?id=1',
            '/page.php?id=1',
            '/article.php?id=1',
            '/user.php?id=1',
            '/item.php?id=1',
            '/cat.php?id=1',
            '/view.php?id=1',
            '/detail.php?id=1',
            '/profile.php?id=1',
            '/login.php?user=1',
            '/search.php?query=test',
            '/api/user?id=1',
            '/api/product?id=1',
            '/userinfo.php?uname=test',
            '/listproducts.php?cat=1',
            '/artists.php?artist=1',
            '/categories.php',
            '/search.php?test=test',

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
                                            'name': 'Error-Based SQL Injection',
                                            'severity': 'critical',
                                            'cvss_score': 9.8,
                                            'cve_id': 'CWE-89',
                                            'url': url,
                                            'description': f'Error-based SQL injection vulnerability detected. The application is vulnerable to SQL injection attacks that trigger database error messages, which can reveal sensitive information about the database structure and content.',
                                            'payload': payload,
                                            'evidence': content[:200],
                                            'solution': 'Use parameterized queries and input validation. Restrict database permissions. Avoid displaying raw database errors to users.',
                                            'tool': 'BuiltinScanner'
                                        })
                                        logger.warning(f"🚨 SQL Injection found: {url}")
                                        # Continue testing other payloads and paths
                                
                                # Check for significant response differences
                                if abs(len(content) - baseline_len) > baseline_len * 0.3:
                                    vulnerabilities.append({
                                        'id': f'sqli-blind-{hash(url)}',
                                        'name': 'Possible SQL Injection (Blind)',
                                        'severity': 'high',
                                        'cvss_score': 8.5,
                                        'cve_id': 'CWE-89',
                                        'url': url,
                                        'description': 'Possible blind SQL injection vulnerability detected. The application exhibits different response behaviors that could be exploited for blind SQL injection attacks.',
                                        'payload': payload,
                                        'solution': 'Use parameterized queries and consistent response handling. Implement proper input validation.',
                                        'tool': 'BuiltinScanner'
                                    })
                                    logger.warning(f"⚠️  Possible blind SQL injection: {url}")
                                    # Continue testing other payloads and paths
                        
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
            "javascript:alert('XSS')",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<marquee onstart=alert(1)>",
            "<details ontoggle=alert(1)>",
            "<audio src=x onerror=alert(1)>",
        ]
        
        test_paths = [
            '/search.php?q=test',
            '/index.php?search=test',
            '/search?q=test',
            '/search.php?query=test',
            '/search.php?term=test',
            '/find?q=test',
            '/lookup?name=test',
            '/profile?user=test',
            '/view?item=test',
            '/api/search?q=test',
            '/search.php?test=test',
            '/guestbook.php',

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
                                    'description': 'Reflected Cross-Site Scripting (XSS) vulnerability detected. The application reflects unsanitized user input directly back to the browser.',
                                    'payload': payload,
                                    'solution': 'Implement proper input sanitization and output encoding. Use Content Security Policy (CSP) headers.',
                                    'tool': 'BuiltinScanner'
                                })
                                logger.warning(f"🚨 XSS found: {url}")
                                # Continue testing other payloads and paths
                    except:
                        continue
        
        return vulnerabilities
    
    async def _test_directory_traversal(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\..\..\windows\win.ini',
            '....//....//....//etc/passwd',
            '../../../../../../../../etc/passwd',
            '..\..\..\..\..\..\..\windows\win.ini',
            '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
            '.././.././.././etc/passwd',
            '..\\..\\..\\windows\\win.ini',
        ]
        
        test_paths = [
            '/file.php?file=test.txt',
            '/download.php?file=test.txt',
            '/include.php?page=home',
            '/view.php?file=test.txt',
            '/read.php?doc=test.txt',
            '/load.php?path=home',
            '/get.php?filepath=test.txt',
            '/open.php?name=test.txt',
            '/retrieve.php?filename=test.txt',
            '/api/file?path=test.txt',
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
                                    'description': 'Directory traversal (path traversal) vulnerability detected. The application fails to properly validate user-supplied input used in file operations.',
                                    'payload': payload,
                                    'solution': 'Validate and sanitize all file paths. Use secure APIs that do not allow path traversal.',
                                    'tool': 'BuiltinScanner'
                                })
                                logger.warning(f"🚨 Directory traversal found: {url}")
                                # Continue testing other payloads and paths
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
            '/.htaccess',
            '/.htpasswd',
            '/config.php',
            '/database.php',
            '/db.php',
            '/wp-config.php',
            '/configuration.php',
            '/settings.php',
            '/appsettings.json',
            '/web.xml',
            '/robots.txt',
            '/sitemap.xml',
            '/composer.json',
            '/package.json',
            '/yarn.lock',
            '/Dockerfile',
            '/docker-compose.yml',
            '/README.md',
            '/license.txt',
            '/install.php',
            '/setup.php',
            '/install/index.php',
            '/install/setup.php',
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
    
    async def _test_host_header_injection(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for Host Header Injection vulnerabilities"""
        vulnerabilities = []
        
        headers = {
            'Host': 'evil.com'
        }
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(base_url, headers=headers, ssl=False) as resp:
                    content = await resp.text()
                    
                    # Check if our injected host appears in the response
                    if 'evil.com' in content:
                        vulnerabilities.append({
                            'id': f'host-header-{hash(base_url)}',
                            'name': 'Host Header Injection',
                            'severity': 'medium',
                            'cvss_score': 6.0,
                            'cve_id': 'CWE-20',
                            'url': base_url,
                            'description': 'Host Header Injection vulnerability detected. The application reflects the Host header in the response.',
                            'solution': 'Validate and sanitize the Host header. Use a whitelist of allowed hosts.',
                            'tool': 'BuiltinScanner-Pro'
                        })
                        logger.warning(f"🚨 Host Header Injection found: {base_url}")
        except:
            pass
        
        return vulnerabilities
    
    async def _test_cache_poisoning(self, base_url: str) -> List[Dict[str, Any]]:
        """Test for Web Cache Poisoning vulnerabilities"""
        vulnerabilities = []
        
        # Test with cache poisoning headers
        poison_headers = [
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Forwarded-Scheme': 'http'},
            {'X-Original-URL': '/poisoned'},
            {'X-Rewrite-URL': '/poisoned'}
        ]
        
        for headers in poison_headers:
            try:
                async with aiohttp.ClientSession(timeout=self.timeout) as session:
                    async with session.get(base_url, headers=headers, ssl=False) as resp:
                        # We're looking for signs of header reflection or unusual behavior
                        content = await resp.text()
                        response_headers = dict(resp.headers)
                        
                        # Check for header reflection
                        for key, value in headers.items():
                            if value in content or value in str(response_headers):
                                vulnerabilities.append({
                                    'id': f'cache-poison-{hash(base_url)}-{key}',
                                    'name': 'Web Cache Poisoning',
                                    'severity': 'medium',
                                    'cvss_score': 6.0,
                                    'cve_id': 'CWE-20',
                                    'url': base_url,
                                    'description': f'Potential Web Cache Poisoning vulnerability with header: {key}',
                                    'payload': f'{key}: {value}',
                                    'solution': 'Properly validate and sanitize all proxy headers. Implement strict header filtering.',
                                    'tool': 'BuiltinScanner-Pro'
                                })
                                logger.warning(f"🚨 Cache Poisoning vector found: {base_url} ({key})")
            except:
                continue
        
        return vulnerabilities
