"""Nmap scanner wrapper"""

import nmap
import asyncio
from typing import List, Dict, Any
from loguru import logger


class NmapScanner:
    """Wrapper for python-nmap"""
    
    def __init__(self, config, scope):
        self.config = config
        self.scope = scope
        self.nm = nmap.PortScanner()
    
    async def scan_targets(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple targets"""
        results = []
        
        for target in targets:
            try:
                result = await self.scan_single(target)
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"Scan failed for {target}: {e}")
        
        return results
    
    async def scan_single(self, target: str) -> Dict[str, Any]:
        """Scan a single target"""
        logger.info(f"Scanning {target}...")
        
        # Build scan arguments
        args = self._build_scan_args()
        
        # Run scan in thread pool (nmap is blocking)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.nm.scan, target, '1-65535', args)
        
        # Parse results
        result = {
            'ip': target,
            'hostname': None,
            'status': 'down',
            'os': None,
            'ports': [],
            'services': []
        }
        
        for host in self.nm.all_hosts():
            result['status'] = self.nm[host].state()
            
            if 'hostnames' in self.nm[host]:
                hostnames = self.nm[host]['hostnames']
                if hostnames:
                    result['hostname'] = hostnames[0].get('name')
            
            # OS detection
            if 'osmatch' in self.nm[host]:
                matches = self.nm[host]['osmatch']
                if matches:
                    result['os'] = matches[0].get('name')
            
            # Ports and services
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    port_info = self.nm[host][proto][port]
                    
                    result['ports'].append({
                        'port': port,
                        'protocol': proto,
                        'state': port_info['state'],
                        'service': port_info.get('name', 'unknown')
                    })
                    
                    if port_info['state'] == 'open':
                        result['services'].append({
                            'port': port,
                            'name': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        })
        
        return result
    
    def _build_scan_args(self) -> str:
        """Build nmap scan arguments based on scope"""
        args = []
        
        if self.scope.stealth_mode:
            args.extend(['-sS', '-T2', '-f'])  # SYN scan, slow timing, fragment packets
        elif self.scope.aggressive_mode:
            args.extend(['-T4', '-A'])  # Aggressive timing and detection
        else:
            args.extend(['-sV', '-O', '-T3'])  # Service version, OS detection, normal timing
        
        return ' '.join(args)
