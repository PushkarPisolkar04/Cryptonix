"""Nmap scanner wrapper"""

import nmap
import socket

import asyncio
import time
from typing import List, Dict, Any
from loguru import logger
from urllib.parse import urlparse


class NmapScanner:
    """Wrapper for python-nmap"""
    
    def __init__(self, config, scope):
        self.config = config
        self.scope = scope
        try:
            self.nm = nmap.PortScanner()
            self.has_nmap = True
        except (nmap.PortScannerError, FileNotFoundError, Exception):
            logger.warning("⚠️  Nmap not found or failed to initialize. Using built-in Python scanner (slower, limited features).")
            self.nm = None
            self.has_nmap = False
    
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
        # Normalize target: accept URLs (http://...) as well as host/IP
        clean_target = self._normalize_target(target)

        # Build scan arguments
        args = self._build_scan_args()
        
        # Determine port range based on mode
        if self.scope.aggressive_mode:
            ports = '1-65535'  # All ports (slow)
        else:
            ports = '1-1000'  # Top 1000 ports (fast)
        
        if self.has_nmap:
            # Run scan in thread pool (nmap is blocking)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.nm.scan, clean_target, ports, args)
        else:
            # Use fallback scanner
            return await self._scan_socket_async(clean_target, ports)

        
        # Parse results
        result = {
            'ip': clean_target,
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

    def _normalize_target(self, target: str) -> str:
        """Return a hostname or IP extracted from a URL or host string."""
        if not target or not isinstance(target, str):
            return target

        # If it's a URL with scheme, parse netloc
        try:
            parsed = urlparse(target)
            if parsed.scheme and parsed.netloc:
                netloc = parsed.netloc
                if '@' in netloc:
                    netloc = netloc.split('@')[-1]
                # strip port if present
                if ':' in netloc:
                    return netloc.split(':')[0]
                return netloc
        except Exception:
            pass

        # If contains path but no scheme (e.g., example.com/path), split
        if '/' in target:
            try:
                return target.split('/')[0]
            except Exception:
                pass

        # If host:port, return host part
        if ':' in target:
            try:
                return target.split(':')[0]
            except Exception:
                pass

        return target
    
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

    async def _scan_socket_async(self, target: str, port_range: str) -> Dict[str, Any]:
        """Fallback scanner using Python sockets"""
        logger.info(f"Using fallback scanner for {target}...")
        
        result = {
            'ip': target,
            'hostname': target,
            'status': 'up',
            'os': 'Unknown (Scanner limitation)',
            'ports': [],
            'services': []
        }
        
        # Parse ports
        ports_to_scan = []
        if port_range == '1-65535':
            # Limit fallback scan to common ports to avoid taking forever
            ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
            logger.info("Fallback mode: Scanning top common ports only")
        elif '-' in port_range:
            start, end = map(int, port_range.split('-'))
            # Cap at top 100 for speed if range is large
            if end - start > 100:
                ports_to_scan = [p for p in range(start, start+100)]
            else:
                ports_to_scan = [p for p in range(start, end+1)]
        else:
             ports_to_scan = [int(p) for p in port_range.split(',')]

        async def check_port(ip, port):
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1.0)
                writer.close()
                await writer.wait_closed()
                return port, True
            except:
                return port, False

        tasks = [check_port(target, p) for p in ports_to_scan]
        results = await asyncio.gather(*tasks)
        
        for port, is_open in results:
            if is_open:
                service_name = socket.getservbyport(port, 'tcp') if port < 1024 else 'unknown'
                
                result['ports'].append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service_name
                })
                
                result['services'].append({
                    'port': port,
                    'name': service_name,
                    'product': 'Unknown',
                    'version': '',
                    'extrainfo': 'Socket Scan'
                })
                
        return result

