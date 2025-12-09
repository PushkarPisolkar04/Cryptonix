"""
Nessus vulnerability scanner integration
Professional vulnerability scanning via Nessus REST API
"""

import asyncio
import time
from typing import Dict, Any, List, Optional
from loguru import logger

try:
    import aiohttp
    import ssl
except ImportError:
    aiohttp = None
    ssl = None


class NessusScanner:
    """Nessus vulnerability scanner integration via REST API"""
    
    def __init__(self, config):
        self.config = config
        self.base_url = getattr(config.tools, 'nessus_url', 'https://localhost:8834')
        self.access_key = getattr(config.tools, 'nessus_access_key', None)
        self.secret_key = getattr(config.tools, 'nessus_secret_key', None)
        self.verify_ssl = False  # Nessus often uses self-signed certs
        
    async def scan(self, hosts: List) -> List[Any]:
        """Run Nessus scan on target hosts"""
        if not self.access_key or not self.secret_key:
            logger.warning("Nessus API keys not configured, skipping scan")
            return []
        
        if not aiohttp:
            logger.error("aiohttp not installed, cannot use Nessus scanner")
            return []
        
        logger.info(f"Starting Nessus scan for {len(hosts)} hosts")
        
        try:
            # Create scan
            scan_id = await self._create_scan(hosts)
            if not scan_id:
                return []
            
            # Launch scan
            await self._launch_scan(scan_id)
            
            # Wait for completion
            await self._wait_for_completion(scan_id)
            
            # Get results
            vulnerabilities = await self._get_results(scan_id)
            
            logger.success(f"Nessus scan completed: {len(vulnerabilities)} vulnerabilities found")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Nessus scan failed: {e}")
            return []
    
    async def _create_scan(self, hosts: List) -> Optional[str]:
        """Create a new scan"""
        targets = ','.join([str(h.ip) if hasattr(h, 'ip') else str(h) for h in hosts])
        
        headers = {
            'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'uuid': 'ab4bacd2-05f6-425c-9d79-3ba3940ad1c24e51e1f403febe40',  # Basic Network Scan
            'settings': {
                'name': f'AutoPenTest Scan {int(time.time())}',
                'text_targets': targets,
                'enabled': False
            }
        }
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f'{self.base_url}/scans',
                json=payload,
                headers=headers,
                ssl=ssl_context
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    scan_id = data['scan']['id']
                    logger.info(f"Created Nessus scan: {scan_id}")
                    return str(scan_id)
                else:
                    logger.error(f"Failed to create scan: {resp.status}")
                    return None
    
    async def _launch_scan(self, scan_id: str):
        """Launch the scan"""
        headers = {
            'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}'
        }
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f'{self.base_url}/scans/{scan_id}/launch',
                headers=headers,
                ssl=ssl_context
            ) as resp:
                if resp.status == 200:
                    logger.info(f"Launched Nessus scan: {scan_id}")
                else:
                    logger.error(f"Failed to launch scan: {resp.status}")
    
    async def _wait_for_completion(self, scan_id: str, timeout: int = 3600):
        """Wait for scan to complete"""
        headers = {
            'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}'
        }
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.base_url}/scans/{scan_id}',
                    headers=headers,
                    ssl=ssl_context
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        status = data['info']['status']
                        
                        if status == 'completed':
                            logger.success("Nessus scan completed")
                            return
                        elif status in ['canceled', 'aborted']:
                            logger.warning(f"Nessus scan {status}")
                            return
                        
                        logger.info(f"Scan status: {status}")
            
            await asyncio.sleep(30)  # Check every 30 seconds
        
        logger.warning("Nessus scan timeout")
    
    async def _get_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get scan results"""
        headers = {
            'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}'
        }
        
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            # Get host list
            async with session.get(
                f'{self.base_url}/scans/{scan_id}',
                headers=headers,
                ssl=ssl_context
            ) as resp:
                if resp.status != 200:
                    return []
                
                data = await resp.json()
                hosts = data.get('hosts', [])
            
            # Get vulnerabilities for each host
            for host in hosts:
                host_id = host['host_id']
                
                async with session.get(
                    f'{self.base_url}/scans/{scan_id}/hosts/{host_id}',
                    headers=headers,
                    ssl=ssl_context
                ) as resp:
                    if resp.status == 200:
                        host_data = await resp.json()
                        
                        for vuln in host_data.get('vulnerabilities', []):
                            vulnerabilities.append({
                                'id': f"nessus-{vuln['plugin_id']}",
                                'name': vuln['plugin_name'],
                                'severity': self._map_severity(vuln['severity']),
                                'cvss_score': vuln.get('cvss_base_score', 0),
                                'cve_id': vuln.get('cve', None),
                                'host': host['hostname'],
                                'port': vuln.get('port', 0),
                                'description': vuln.get('plugin_output', ''),
                                'solution': vuln.get('solution', ''),
                                'references': vuln.get('see_also', [])
                            })
        
        return vulnerabilities
    
    def _map_severity(self, nessus_severity: int) -> str:
        """Map Nessus severity to standard levels"""
        severity_map = {
            0: 'info',
            1: 'low',
            2: 'medium',
            3: 'high',
            4: 'critical'
        }
        return severity_map.get(nessus_severity, 'info')
