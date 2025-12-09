"""
Stage 2: Discovery & Enumeration
Active reconnaissance: port scanning, service detection, OS fingerprinting
"""

import asyncio
from typing import Dict, Any

from loguru import logger

from stages.base import BaseStage
from modules.discovery.nmap_scanner import NmapScanner
from modules.discovery.service_detector import ServiceDetector
from modules.discovery.cloud_assets import CloudAssetDiscovery
from modules.discovery.waf_detector import WAFDetector
from modules.discovery.ssl_analyzer import SSLAnalyzer
from core.models import Host


class DiscoveryStage(BaseStage):
    """Active discovery and enumeration"""
    
    @property
    def name(self) -> str:
        return "Discovery & Enumeration"
    
    @property
    def description(self) -> str:
        return "Active scanning: hosts, ports, services, OS detection, cloud assets"
    
    async def run(self) -> Dict[str, Any]:
        """Execute discovery"""
        
        target = self.scope.target
        osint_data = self.get_previous_stage_data('osint')
        
        # Expand target list with subdomains from OSINT
        targets = [target]
        if 'subdomains' in osint_data:
            targets.extend(osint_data['subdomains'][:50])  # Limit to top 50
        
        results = {
            'hosts': [],
            'total_hosts': 0,
            'total_open_ports': 0,
            'services': []
        }
        
        # Nmap scanning
        logger.info(f"🔍 Scanning {len(targets)} targets with Nmap...")
        nmap_scanner = NmapScanner(self.config, self.scope)
        scan_results = await nmap_scanner.scan_targets(targets)
        
        # Process scan results
        for scan_result in scan_results:
            host = Host(
                ip=scan_result['ip'],
                hostname=scan_result.get('hostname'),
                os=scan_result.get('os'),
                status=scan_result.get('status', 'up'),
                open_ports=scan_result.get('ports', []),
                services=scan_result.get('services', [])
            )
            results['hosts'].append(host)
        
        results['total_hosts'] = len(results['hosts'])
        results['total_open_ports'] = sum(len(h.open_ports) for h in results['hosts'])
        
        # Additional discovery tasks
        tasks = []
        
        # Cloud asset discovery
        logger.info("☁️ Discovering cloud assets...")
        cloud_module = CloudAssetDiscovery(self.config)
        tasks.append(self._discover_cloud_assets(cloud_module, target, results))
        
        # WAF detection for web services
        logger.info("🛡️ Detecting WAFs...")
        waf_module = WAFDetector(self.config)
        tasks.append(self._detect_wafs(waf_module, results))
        
        # SSL/TLS analysis
        logger.info("🔐 Analyzing SSL/TLS...")
        ssl_module = SSLAnalyzer(self.config)
        tasks.append(self._analyze_ssl(ssl_module, results))
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.success(f"✅ Discovered {results['total_hosts']} hosts")
        logger.success(f"✅ Found {results['total_open_ports']} open ports")
        
        return results
    
    async def _discover_cloud_assets(self, module, target, results):
        try:
            cloud_assets = await module.discover(target)
            results['cloud_assets'] = cloud_assets
        except Exception as e:
            logger.warning(f"Cloud asset discovery failed: {e}")
    
    async def _detect_wafs(self, module, results):
        try:
            for host in results['hosts']:
                waf_info = await module.detect(host)
                if waf_info:
                    host.services.append({'type': 'waf', 'info': waf_info})
        except Exception as e:
            logger.warning(f"WAF detection failed: {e}")
    
    async def _analyze_ssl(self, module, results):
        try:
            ssl_results = []
            for host in results['hosts']:
                for port in host.open_ports:
                    if port.get('service') in ['https', 'ssl', 'tls']:
                        ssl_info = await module.analyze(host.ip, port['port'])
                        ssl_results.append(ssl_info)
            results['ssl_analysis'] = ssl_results
        except Exception as e:
            logger.warning(f"SSL analysis failed: {e}")
