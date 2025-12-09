"""
SQLMap SQL injection scanner
Automated SQL injection detection and exploitation
"""

import asyncio
import json
import subprocess
from typing import Dict, Any, List
from pathlib import Path
from loguru import logger


class SQLMapRunner:
    """SQLMap SQL injection scanner via subprocess"""
    
    def __init__(self, config):
        self.config = config
        self.sqlmap_path = getattr(config.tools, 'sqlmap_path', 'sqlmap')
        
    async def scan(self, hosts: List) -> List[Any]:
        """Run SQLMap on web targets"""
        logger.info(f"Starting SQLMap scan for {len(hosts)} targets")
        
        vulnerabilities = []
        
        for host in hosts:
            # Extract URLs with parameters
            urls = self._extract_urls_with_params(host)
            
            for url in urls:
                try:
                    logger.info(f"Testing {url} for SQL injection")
                    
                    # Run SQLMap
                    result = await self._run_sqlmap(url)
                    
                    if result['vulnerable']:
                        vulnerabilities.append({
                            'id': f"sqlmap-{hash(url)}",
                            'name': 'SQL Injection',
                            'severity': 'critical',
                            'cvss_score': 9.8,
                            'cve_id': 'CWE-89',
                            'url': url,
                            'description': f"SQL injection vulnerability found in {url}",
                            'injection_type': result.get('injection_type', 'Unknown'),
                            'dbms': result.get('dbms', 'Unknown'),
                            'payload': result.get('payload', ''),
                            'solution': 'Use parameterized queries and input validation'
                        })
                        
                        logger.warning(f"SQL injection found: {url}")
                    
                except Exception as e:
                    logger.error(f"SQLMap scan failed for {url}: {e}")
        
        logger.success(f"SQLMap scan completed: {len(vulnerabilities)} SQL injections found")
        return vulnerabilities
    
    def _extract_urls_with_params(self, host) -> List[str]:
        """Extract URLs with parameters from host"""
        urls = []
        
        # If host has discovered URLs with parameters
        if hasattr(host, 'urls'):
            for url in host.urls:
                if '?' in url:  # Has parameters
                    urls.append(url)
        
        # If host is a URL string
        elif isinstance(host, str) and 'http' in host:
            if '?' in host:
                urls.append(host)
        
        # Generate test URLs for common parameters
        if hasattr(host, 'ip'):
            base_urls = []
            for port_info in getattr(host, 'open_ports', []):
                port = port_info.get('port', 0)
                service = port_info.get('service', '').lower()
                
                if service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    base_urls.append(f'{protocol}://{host.ip}:{port}')
            
            # Add common vulnerable endpoints
            for base_url in base_urls:
                test_urls = [
                    f'{base_url}/index.php?id=1',
                    f'{base_url}/product.php?id=1',
                    f'{base_url}/page.php?id=1',
                    f'{base_url}/article.php?id=1',
                    f'{base_url}/user.php?id=1'
                ]
                urls.extend(test_urls)
        
        return urls[:10]  # Limit to 10 URLs per host
    
    async def _run_sqlmap(self, url: str) -> Dict[str, Any]:
        """Run SQLMap on a URL"""
        cmd = [
            self.sqlmap_path,
            '-u', url,
            '--batch',  # Never ask for user input
            '--random-agent',  # Use random user agent
            '--level=1',  # Test level (1-5)
            '--risk=1',  # Risk level (1-3)
            '--threads=5',  # Number of threads
            '--timeout=30',  # Timeout per request
            '--retries=2',  # Retries on connection timeout
            '--technique=BEUSTQ',  # All techniques
            '--output-dir=/tmp/sqlmap',  # Output directory
            '--flush-session',  # Flush session files
            '--fresh-queries',  # Ignore cached results
            '--answers=quit=N,follow=N',  # Auto-answer prompts
        ]
        
        try:
            # Run SQLMap
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=300  # 5 minute timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            # Parse output
            result = {
                'vulnerable': False,
                'injection_type': None,
                'dbms': None,
                'payload': None
            }
            
            # Check if vulnerable
            if 'is vulnerable' in output.lower() or 'injectable' in output.lower():
                result['vulnerable'] = True
                
                # Extract injection type
                if 'boolean-based blind' in output.lower():
                    result['injection_type'] = 'Boolean-based blind'
                elif 'time-based blind' in output.lower():
                    result['injection_type'] = 'Time-based blind'
                elif 'error-based' in output.lower():
                    result['injection_type'] = 'Error-based'
                elif 'union query' in output.lower():
                    result['injection_type'] = 'UNION query'
                elif 'stacked queries' in output.lower():
                    result['injection_type'] = 'Stacked queries'
                
                # Extract DBMS
                for dbms in ['MySQL', 'PostgreSQL', 'Oracle', 'MSSQL', 'SQLite', 'MongoDB']:
                    if dbms.lower() in output.lower():
                        result['dbms'] = dbms
                        break
                
                # Extract payload (simplified)
                if 'payload:' in output.lower():
                    lines = output.split('\n')
                    for i, line in enumerate(lines):
                        if 'payload:' in line.lower() and i + 1 < len(lines):
                            result['payload'] = lines[i + 1].strip()
                            break
            
            return result
            
        except asyncio.TimeoutError:
            logger.warning(f"SQLMap timeout for {url}")
            return {'vulnerable': False}
        except Exception as e:
            logger.error(f"SQLMap execution failed: {e}")
            return {'vulnerable': False}
