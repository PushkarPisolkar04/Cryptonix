"""SSL/TLS configuration analysis"""
import asyncio
import ssl
import socket
from typing import Dict, Any
from loguru import logger

class SSLAnalyzer:
    def __init__(self, config):
        self.config = config
    
    async def analyze(self, host: str, port: int) -> Dict[str, Any]:
        logger.info(f"Analyzing SSL/TLS for {host}:{port}")
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            await loop.run_in_executor(None, sock.connect, (host, port))
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            cert = ssl_sock.getpeercert()
            cipher = ssl_sock.cipher()
            version = ssl_sock.version()
            
            ssl_sock.close()
            
            issues = []
            if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                issues.append(f'Weak protocol: {version}')
            
            if cipher and cipher[0] in ['RC4', 'DES', '3DES']:
                issues.append(f'Weak cipher: {cipher[0]}')
            
            return {
                'host': host,
                'port': port,
                'protocol': version,
                'cipher': cipher[0] if cipher else None,
                'cipher_bits': cipher[2] if cipher else None,
                'certificate': cert,
                'issues': issues,
                'secure': len(issues) == 0
            }
        except Exception as e:
            logger.debug(f"SSL analysis failed: {e}")
            return {'host': host, 'port': port, 'error': str(e)}
