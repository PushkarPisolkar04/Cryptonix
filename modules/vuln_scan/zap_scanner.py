"""
OWASP ZAP web application scanner
Automated web vulnerability scanning via ZAP API
"""

import asyncio
import time
from typing import Dict, Any, List
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None


class ZAPScanner:
    """OWASP ZAP web application scanner via API"""
    
    def __init__(self, config):
        self.config = config
        self.zap_host = getattr(config.tools, 'zap_host', '127.0.0.1')
        self.zap_port = getattr(config.tools, 'zap_port', 8080)
        self.api_key = getattr(config.tools, 'zap_api_key', None)
        self.base_url = f'http://{self.zap_host}:{self.zap_port}'
        
    async def scan(self, hosts: List) -> List[Any]:
        """Run ZAP scan on web applications"""
        if not aiohttp:
            logger.error("aiohttp not installed, cannot use ZAP scanner")
            return []
        
        logger.info(f"Starting OWASP ZAP scan for {len(hosts)} targets")
        
        vulnerabilities = []
        
        for host in hosts:
            # Extract web URLs from hosts
            urls = self._extract_web_urls(host)
            
            for url in urls:
                try:
                    logger.info(f"Scanning {url} with ZAP")
                    
                    # Spider the target
                    await self._spider(url)
                    
                    # Active scan
                    await self._active_scan(url)
                    
                    # Get alerts
                    alerts = await self._get_alerts(url)
                    vulnerabilities.extend(alerts)
                    
                except Exception as e:
                    logger.error(f"ZAP scan failed for {url}: {e}")
        
        logger.success(f"ZAP scan completed: {len(vulnerabilities)} vulnerabilities found")
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
    
    async def _spider(self, url: str):
        """Spider the target to discover pages"""
        params = {
            'apikey': self.api_key,
            'url': url,
            'maxChildren': '10',
            'recurse': 'true'
        }
        
        async with aiohttp.ClientSession() as session:
            # Start spider
            async with session.get(
                f'{self.base_url}/JSON/spider/action/scan/',
                params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    scan_id = data['scan']
                    logger.info(f"Started ZAP spider: {scan_id}")
                    
                    # Wait for spider to complete
                    await self._wait_for_spider(scan_id)
    
    async def _wait_for_spider(self, scan_id: str):
        """Wait for spider to complete"""
        params = {
            'apikey': self.api_key,
            'scanId': scan_id
        }
        
        while True:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.base_url}/JSON/spider/view/status/',
                    params=params
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        status = int(data['status'])
                        
                        if status >= 100:
                            logger.info("ZAP spider completed")
                            return
                        
                        logger.debug(f"Spider progress: {status}%")
            
            await asyncio.sleep(2)
    
    async def _active_scan(self, url: str):
        """Run active scan"""
        params = {
            'apikey': self.api_key,
            'url': url,
            'recurse': 'true',
            'inScopeOnly': 'false'
        }
        
        async with aiohttp.ClientSession() as session:
            # Start active scan
            async with session.get(
                f'{self.base_url}/JSON/ascan/action/scan/',
                params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    scan_id = data['scan']
                    logger.info(f"Started ZAP active scan: {scan_id}")
                    
                    # Wait for scan to complete
                    await self._wait_for_active_scan(scan_id)
    
    async def _wait_for_active_scan(self, scan_id: str):
        """Wait for active scan to complete"""
        params = {
            'apikey': self.api_key,
            'scanId': scan_id
        }
        
        while True:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'{self.base_url}/JSON/ascan/view/status/',
                    params=params
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        status = int(data['status'])
                        
                        if status >= 100:
                            logger.info("ZAP active scan completed")
                            return
                        
                        logger.debug(f"Active scan progress: {status}%")
            
            await asyncio.sleep(5)
    
    async def _get_alerts(self, url: str) -> List[Dict[str, Any]]:
        """Get scan alerts/vulnerabilities"""
        params = {
            'apikey': self.api_key,
            'baseurl': url
        }
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f'{self.base_url}/JSON/core/view/alerts/',
                params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    for alert in data.get('alerts', []):
                        vulnerabilities.append({
                            'id': f"zap-{alert['pluginId']}",
                            'name': alert['alert'],
                            'severity': alert['risk'].lower(),
                            'cvss_score': self._risk_to_cvss(alert['risk']),
                            'cve_id': alert.get('cweid', None),
                            'url': alert['url'],
                            'description': alert['description'],
                            'solution': alert.get('solution', ''),
                            'references': alert.get('reference', '').split('\n'),
                            'evidence': alert.get('evidence', ''),
                            'attack': alert.get('attack', '')
                        })
        
        return vulnerabilities
    
    def _risk_to_cvss(self, risk: str) -> float:
        """Convert ZAP risk to CVSS score"""
        risk_map = {
            'Informational': 0.0,
            'Low': 3.9,
            'Medium': 6.9,
            'High': 8.9,
            'Critical': 10.0
        }
        return risk_map.get(risk, 0.0)
