"""Web Application Firewall detection"""
import asyncio
from typing import Dict, Any
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None

class WAFDetector:
    def __init__(self, config):
        self.config = config
        self.waf_signatures = {
            'cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'akamai': ['akamai', 'akamaighost'],
            'aws': ['x-amz', 'awselb'],
            'imperva': ['incap_ses', 'visid_incap'],
            'f5': ['bigip', 'f5'],
            'fortinet': ['fortigate', 'fortiweb'],
            'barracuda': ['barra'],
            'sucuri': ['sucuri', 'x-sucuri']
        }
    
    async def detect(self, host) -> Dict[str, Any]:
        if not aiohttp:
            return {}
        
        url = self._get_url(host)
        logger.info(f"Detecting WAF for {url}")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10, allow_redirects=False) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    
                    detected_wafs = []
                    for waf_name, signatures in self.waf_signatures.items():
                        for sig in signatures:
                            if any(sig.lower() in str(v).lower() for v in headers.values()):
                                detected_wafs.append(waf_name)
                                break
                    
                    if detected_wafs:
                        logger.warning(f"WAF detected: {', '.join(detected_wafs)}")
                        return {'detected': True, 'wafs': detected_wafs, 'headers': dict(headers)}
                    
                    return {'detected': False, 'wafs': [], 'headers': dict(headers)}
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
            return {}
    
    def _get_url(self, host) -> str:
        if isinstance(host, str):
            return f'http://{host}' if not host.startswith('http') else host
        return f'http://{host.ip}' if hasattr(host, 'ip') else str(host)
