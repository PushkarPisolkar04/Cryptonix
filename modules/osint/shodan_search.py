"""Shodan API integration"""

import asyncio
from typing import Dict, Any
from loguru import logger

try:
    import shodan
except ImportError:
    logger.warning("shodan library not installed")
    shodan = None


class ShodanSearch:
    """Shodan search integration"""
    
    def __init__(self, config):
        self.config = config
        self.api = None
        
        if shodan and config.apis.shodan_api_key:
            self.api = shodan.Shodan(config.apis.shodan_api_key)
    
    async def search(self, target: str) -> Dict[str, Any]:
        """Search Shodan for target"""
        if not self.api:
            logger.warning("Shodan API not configured")
            return {}
        
        try:
            # Run in thread pool (shodan is blocking)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self.api.host, target)
            
            return {
                'ip': result.get('ip_str'),
                'org': result.get('org'),
                'os': result.get('os'),
                'ports': result.get('ports', []),
                'vulns': result.get('vulns', []),
                'hostnames': result.get('hostnames', []),
                'services': result.get('data', [])
            }
            
        except shodan.APIError as e:
            logger.warning(f"Shodan search failed: {e}")
            return {}
        except Exception as e:
            logger.error(f"Shodan error: {e}")
            return {}
