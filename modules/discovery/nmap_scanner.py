"""Nmap scanner wrapper"""

import nmap
import asyncio
import time
from typing import List, Dict, Any
from loguru import logger


class NmapScanner:
    """Wrapper for python-nmap"""
    
    def __init__(self, config, scope):
        self.config = config
        self.scope = scope
        self.nm = nmap.PortScanner()
    
    async def scan_targets(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Scan multiple targets with progress tracking"""
        results = []
        total = len(targets)
        start_time = time.time()
        
        # Estimate time per target based on mode
        if self.scope.aggressive_mode:
            est_per_target = 120  # 2 minutes per target (all ports)
        elif self.scope.stealth_mode:
            est_per_target = 60   # 1 minute per target (stealth)
        else:
            est_per_target = 30   # 30 seconds per target (normal)
        
        estimated_total = total * est_per_target
        logger.info(f"⏱️  Estimated scan time: {estimated_total // 60} minutes {estimated_total % 60} seconds")
        
        for idx, target in enumerate(targets, 1):
            try:
                target_start = time.time()
                result = await self.scan_single(target)
                target_elapsed = time.time() - target_start
                
                if result:
                    results.append(result)
                
                # Progress update
                elapsed = time.time() - start_time
                avg_time = elapsed / idx
                remaining = (total - idx) * avg_time
                
                logger.info(f"📊 Progress: {idx}/{total} targets | "
                          f"Elapsed: {int(elapsed)}s | "
                          f"Remaining: ~{int(remaining)}s | "
                          f"This target: {int(target_elapsed)}s")
                
            except Exception as e:
                logger.error(f"Scan failed for {target}: {e}")
        
        total_elapsed = time.time() - start_time
        logger.success(f"✅ Scan complete! Total time: {int(total_elapsed // 60)}m {int(total_elapsed % 60)}s")
        
        return results
    
    async def scan_single(self, target: str) -> Dict[str, Any]:
        """Scan a single target"""
        logger.info(f"Scanning {target}...")
        
        # Build scan arguments
        args = self._build_scan_args()
        
        # Determine port range based on mode
        if self.scope.aggressive_mode:
            ports = '1-65535'  # All ports (slow)
        else:
            ports = '1-1000'  # Top 1000 ports (fast)
        
        # Run scan in thread pool (nmap is blocking)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.nm.scan, target, ports, args)
        
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
