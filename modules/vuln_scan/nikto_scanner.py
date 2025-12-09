"""
Nikto web server scanner
Web server vulnerability and misconfiguration scanner
"""

import asyncio
import subprocess
import re
from typing import Dict, Any, List
from loguru import logger


class NiktoScanner:
    """Nikto web server scanner via subprocess"""
    
    def __init__(self, config):
        self.config = config
        self.nikto_path = getattr(config.tools, 'nikto_path', 'nikto')
        
    async def scan(self, hosts: List) -> List[Any]:
        """Run Nikto scan on web servers"""
        logger.info(f"Starting Nikto scan for {len(hosts)} targets")
        
        vulnerabilities = []
        
        for host in hosts:
            # Extract web URLs
            urls = self._extract_web_urls(host)
            
            for url in urls:
                try:
                    logger.info(f"Scanning {url} with Nikto")
                    
                    # Run Nikto
                    results = await self._run_nikto(url)
                    vulnerabilities.extend(results)
                    
                except Exception as e:
                    logger.error(f"Nikto scan failed for {url}: {e}")
        
        logger.success(f"Nikto scan completed: {len(vulnerabilities)} issues found")
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
                    urls.append(f'{protocol}://{ip}:{port}')
        else:
            # Assume it's a URL or domain
            url = str(host)
            if not url.startswith('http'):
                urls.append(f'http://{url}')
                urls.append(f'https://{url}')
            else:
                urls.append(url)
        
        return urls
    
    async def _run_nikto(self, url: str) -> List[Dict[str, Any]]:
        """Run Nikto on a URL"""
        cmd = [
            self.nikto_path,
            '-h', url,
            '-Format', 'csv',  # CSV output for easier parsing
            '-Tuning', '123456789abc',  # All tests
            '-timeout', '30',
            '-maxtime', '300',  # 5 minute max
            '-nointeractive'
        ]
        
        try:
            # Run Nikto
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=360  # 6 minute timeout
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            # Parse CSV output
            vulnerabilities = self._parse_nikto_output(output, url)
            
            return vulnerabilities
            
        except asyncio.TimeoutError:
            logger.warning(f"Nikto timeout for {url}")
            return []
        except FileNotFoundError:
            logger.error(f"Nikto not found at {self.nikto_path}")
            return []
        except Exception as e:
            logger.error(f"Nikto execution failed: {e}")
            return []
    
    def _parse_nikto_output(self, output: str, url: str) -> List[Dict[str, Any]]:
        """Parse Nikto CSV output"""
        vulnerabilities = []
        
        lines = output.split('\n')
        
        for line in lines:
            if not line.strip() or line.startswith('"host"'):
                continue
            
            try:
                # CSV format: "host","ip","port","vuln_id","method","uri","description","osvdb","refs"
                parts = line.split('","')
                
                if len(parts) >= 7:
                    # Clean quotes
                    parts = [p.strip('"') for p in parts]
                    
                    host = parts[0]
                    ip = parts[1]
                    port = parts[2]
                    vuln_id = parts[3]
                    method = parts[4]
                    uri = parts[5]
                    description = parts[6]
                    osvdb = parts[7] if len(parts) > 7 else ''
                    refs = parts[8] if len(parts) > 8 else ''
                    
                    # Determine severity from description
                    severity = self._determine_severity(description)
                    
                    vulnerabilities.append({
                        'id': f'nikto-{vuln_id}',
                        'name': f'Nikto Finding: {vuln_id}',
                        'severity': severity,
                        'cvss_score': self._severity_to_cvss(severity),
                        'url': f'{url}{uri}',
                        'method': method,
                        'description': description,
                        'osvdb': osvdb,
                        'references': refs.split(',') if refs else [],
                        'tool': 'Nikto'
                    })
            
            except Exception as e:
                logger.debug(f"Failed to parse Nikto line: {e}")
                continue
        
        return vulnerabilities
    
    def _determine_severity(self, description: str) -> str:
        """Determine severity from description"""
        desc_lower = description.lower()
        
        # Critical indicators
        if any(word in desc_lower for word in ['sql injection', 'remote code execution', 'rce', 'command injection']):
            return 'critical'
        
        # High indicators
        if any(word in desc_lower for word in ['xss', 'cross-site scripting', 'file inclusion', 'directory traversal', 'authentication bypass']):
            return 'high'
        
        # Medium indicators
        if any(word in desc_lower for word in ['disclosure', 'exposed', 'misconfiguration', 'outdated']):
            return 'medium'
        
        # Low indicators
        if any(word in desc_lower for word in ['information', 'banner', 'header', 'cookie']):
            return 'low'
        
        return 'info'
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity to CVSS score"""
        severity_map = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.5,
            'low': 3.5,
            'info': 0.0
        }
        return severity_map.get(severity, 0.0)
