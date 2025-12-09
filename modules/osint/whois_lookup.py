"""WHOIS lookup module"""

import asyncio
import whois
from typing import Dict, Any
from loguru import logger


class WhoisLookup:
    """WHOIS information gathering"""
    
    def __init__(self, config):
        self.config = config
    
    async def lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        try:
            # Run in thread pool (whois is blocking)
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            
            return {
                'domain': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'country': w.country
            }
            
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {}
