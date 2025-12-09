"""Enhanced service detection and fingerprinting"""
import asyncio
import socket
from typing import Dict, Any
from loguru import logger

class ServiceDetector:
    def __init__(self, config):
        self.config = config
    
    async def detect(self, host: str, port: int) -> Dict[str, Any]:
        logger.info(f"Detecting service on {host}:{port}")
        
        service_info = {
            'host': host,
            'port': port,
            'service': 'unknown',
            'version': None,
            'banner': None
        }
        
        try:
            # Try to grab banner
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            await loop.run_in_executor(None, sock.connect, (host, port))
            
            # Send probe
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            service_info['banner'] = banner[:200]
            
            # Identify service from banner
            if 'HTTP' in banner:
                service_info['service'] = 'http'
                if 'Apache' in banner:
                    service_info['version'] = 'Apache'
                elif 'nginx' in banner:
                    service_info['version'] = 'nginx'
            elif 'SSH' in banner:
                service_info['service'] = 'ssh'
            elif 'FTP' in banner:
                service_info['service'] = 'ftp'
            
            logger.success(f"Service detected: {service_info['service']}")
        except Exception as e:
            logger.debug(f"Service detection failed: {e}")
        
        return service_info
