"""
Stage 1: OSINT - Open Source Intelligence Gathering
Passive reconnaissance without touching the target
"""

import asyncio
from typing import Dict, Any, List

from loguru import logger

from stages.base import BaseStage
from modules.osint.whois_lookup import WhoisLookup
from modules.osint.subdomain_enum import SubdomainEnumerator
from modules.osint.email_harvester import EmailHarvester
from modules.osint.shodan_search import ShodanSearch
from modules.osint.breach_checker import BreachChecker
from modules.osint.cert_transparency import CertTransparency
from modules.osint.social_media import SocialMediaFootprint


class OSINTStage(BaseStage):
    """OSINT and passive intelligence gathering"""
    
    @property
    def name(self) -> str:
        return "OSINT & Intelligence Gathering"
    
    @property
    def description(self) -> str:
        return "Passive reconnaissance: WHOIS, subdomains, emails, breaches, certificates"
    
    async def run(self) -> Dict[str, Any]:
        """Execute OSINT gathering"""
        
        target = self.scope.target
        results = {
            'target': target,
            'whois': {},
            'subdomains': [],
            'emails': [],
            'breached_credentials': [],
            'certificates': [],
            'shodan_data': {},
        }
        
        # Run all OSINT modules concurrently
        tasks = []
        
        # WHOIS lookup
        if self.config.tools.whois_enabled:
            logger.info("🔍 Performing WHOIS lookup...")
            whois_module = WhoisLookup(self.config)
            tasks.append(self._run_whois(whois_module, target, results))
        
        # Subdomain enumeration
        logger.info("🔍 Enumerating subdomains...")
        subdomain_module = SubdomainEnumerator(self.config)
        tasks.append(self._run_subdomain_enum(subdomain_module, target, results))
        
        # Email harvesting
        logger.info("🔍 Harvesting email addresses...")
        email_module = EmailHarvester(self.config)
        tasks.append(self._run_email_harvest(email_module, target, results))
        
        # Shodan search (if API key provided)
        if self.config.apis.shodan_api_key:
            logger.info("🔍 Searching Shodan...")
            shodan_module = ShodanSearch(self.config)
            tasks.append(self._run_shodan(shodan_module, target, results))
        
        # Breach checking
        if self.config.tools.hibp_enabled:
            logger.info("🔍 Checking breach databases...")
            breach_module = BreachChecker(self.config)
            tasks.append(self._run_breach_check(breach_module, target, results))
        
        # Certificate transparency
        logger.info("🔍 Searching certificate transparency logs...")
        cert_module = CertTransparency(self.config)
        tasks.append(self._run_cert_search(cert_module, target, results))
        
        # Social media footprint
        logger.info("🔍 Gathering social media intelligence...")
        social_module = SocialMediaFootprint(self.config)
        tasks.append(self._run_social_media(social_module, target, results))
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.success(f"OSINT gathering completed. Found {len(results['subdomains'])} subdomains and {len(results['emails'])} emails")
        return results
    
    async def _run_whois(self, module, target, results):
        try:
            results['whois'] = await module.lookup(target)
        except Exception as e:
            logger.warning(f"WHOIS lookup failed: {e}")
    
    async def _run_subdomain_enum(self, module, target, results):
        try:
            subdomains = await module.enumerate(target)
            results['subdomains'].extend(subdomains)
        except Exception as e:
            logger.warning(f"Subdomain enumeration failed: {e}")
    
    async def _run_email_harvest(self, module, target, results):
        try:
            emails = await module.harvest(target)
            results['emails'].extend(emails)
        except Exception as e:
            logger.warning(f"Email harvesting failed: {e}")
    
    async def _run_shodan(self, module, target, results):
        try:
            results['shodan_data'] = await module.search(target)
        except Exception as e:
            logger.warning(f"Shodan search failed: {e}")
    
    async def _run_breach_check(self, module, target, results):
        try:
            results['breached_credentials'] = await module.check(target)
        except Exception as e:
            logger.warning(f"Breach check failed: {e}")
    
    async def _run_cert_search(self, module, target, results):
        try:
            results['certificates'] = await module.search(target)
        except Exception as e:
            logger.warning(f"Certificate search failed: {e}")
    
    async def _run_social_media(self, module, target, results):
        try:
            results['social_media'] = await module.gather(target)
                    
            logger.success(f"Social media gathering completed")
        except Exception as e:
            logger.warning(f"Social media gathering failed: {e}")