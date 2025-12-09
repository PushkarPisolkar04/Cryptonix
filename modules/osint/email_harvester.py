"""
Email harvesting from various sources
"""

import asyncio
import re
from typing import Dict, Any, List, Set
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


class EmailHarvester:
    """Email harvesting using multiple sources"""
    
    def __init__(self, config):
        self.config = config
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    async def harvest(self, domain: str) -> List[Dict[str, Any]]:
        """Harvest emails associated with a domain"""
        logger.info(f"Starting email harvesting for {domain}")
        
        emails: Set[str] = set()
        email_details: List[Dict[str, Any]] = []
        
        tasks = [
            self._web_scraping(domain),
            self._search_engine_scraping(domain),
            self._pgp_search(domain),
            self._whois_emails(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                for email_info in result:
                    if isinstance(email_info, dict):
                        email = email_info.get('email', '').lower()
                        if email and email not in emails:
                            emails.add(email)
                            email_details.append(email_info)
                    elif isinstance(email_info, str):
                        email = email_info.lower()
                        if email and email not in emails:
                            emails.add(email)
                            email_details.append({'email': email, 'source': 'unknown'})
        
        logger.success(f"Harvested {len(email_details)} unique emails for {domain}")
        return email_details
    
    async def _web_scraping(self, domain: str) -> List[Dict[str, Any]]:
        """Scrape company website for emails"""
        found = []
        
        if not aiohttp:
            return found
        
        pages = [
            f"https://{domain}", f"https://{domain}/contact",
            f"https://{domain}/about", f"https://www.{domain}",
        ]
        
        async def scrape_page(url: str):
            emails = []
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {'User-Agent': self.user_agent}
                    async with session.get(url, headers=headers, 
                                         timeout=aiohttp.ClientTimeout(total=15), ssl=False) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            for email in self.email_pattern.findall(html):
                                if domain in email.lower():
                                    emails.append({'email': email.lower(), 'source': url})
            except:
                pass
            return emails
        
        tasks = [scrape_page(url) for url in pages]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                found.extend(result)
        
        return found
    
    async def _search_engine_scraping(self, domain: str) -> List[Dict[str, Any]]:
        """Search for emails via search engines"""
        found = []
        
        if not aiohttp:
            return found
        
        try:
            async with aiohttp.ClientSession() as session:
                query = f'"@{domain}" email'
                url = f"https://html.duckduckgo.com/html/?q={query}"
                headers = {'User-Agent': self.user_agent}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        for email in self.email_pattern.findall(html):
                            if domain in email.lower():
                                found.append({'email': email.lower(), 'source': 'search_engine'})
        except:
            pass
        
        return found
    
    async def _pgp_search(self, domain: str) -> List[Dict[str, Any]]:
        """Search PGP key servers for emails"""
        found = []
        
        if not aiohttp:
            return found
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://pgp.mit.edu/pks/lookup?search={domain}&op=index"
                headers = {'User-Agent': self.user_agent}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        for email in self.email_pattern.findall(html):
                            if domain in email.lower():
                                found.append({'email': email.lower(), 'source': 'pgp_keyserver'})
        except:
            pass
        
        return found
    
    async def _whois_emails(self, domain: str) -> List[Dict[str, Any]]:
        """Extract emails from WHOIS data"""
        found = []
        
        try:
            import whois
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            
            if w.emails:
                emails = w.emails if isinstance(w.emails, list) else [w.emails]
                for email in emails:
                    found.append({'email': email.lower(), 'source': 'whois', 'type': 'registrant'})
        except:
            pass
        
        return found
