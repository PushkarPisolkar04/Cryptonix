"""
Subdomain enumeration using multiple techniques
"""

import asyncio
import socket
import re
from typing import Dict, Any, List, Set
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import dns.resolver
    import dns.asyncresolver
except ImportError:
    dns = None


class SubdomainEnumerator:
    """Subdomain enumeration using multiple techniques"""
    
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 'ns',
        'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm', 'imap',
        'test', 'old', 'new', 'mobile', 'api', 'app', 'dev', 'staging',
        'admin', 'portal', 'blog', 'shop', 'store', 'secure', 'vpn',
        'remote', 'server', 'cloud', 'git', 'wiki', 'docs', 'support',
        'status', 'cdn', 'media', 'static', 'assets', 'img', 'video',
        'upload', 'download', 'files', 'backup', 'db', 'database', 'sql',
        'mysql', 'postgres', 'mongo', 'redis', 'cache', 'proxy', 'gateway',
        'web', 'web1', 'web2', 'app1', 'app2', 'api1', 'api2', 'beta', 'alpha',
        'demo', 'sandbox', 'qa', 'uat', 'prod', 'internal', 'intranet',
        'helpdesk', 'help', 'forum', 'sso', 'login', 'auth', 'oauth',
        'accounts', 'billing', 'pay', 'payment', 'checkout', 'order',
        'analytics', 'stats', 'monitor', 'grafana', 'prometheus', 'kibana',
        'jenkins', 'ci', 'build', 'deploy', 'docker', 'k8s', 'console',
        'panel', 'dashboard', 'mgmt', 'manage', 'exchange', 'owa', 'outlook',
        'office', 'sharepoint', 'calendar', 'drive', 'storage', 'share',
        'ldap', 'ad', 'dc', 'ns3', 'ns4', 'mx1', 'mx2', 'mail1', 'mail2'
    ]
    
    def __init__(self, config):
        self.config = config
        self.timeout = 30
    
    async def enumerate(self, domain: str) -> List[str]:
        """Enumerate subdomains using multiple methods"""
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        subdomains: Set[str] = set()
        tasks = [
            self._dns_bruteforce(domain),
            self._cert_transparency(domain),
            self._search_engines(domain),
            self._dns_records(domain),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                subdomains.update(result)
        
        valid_subdomains = await self._validate_subdomains(list(subdomains), domain)
        logger.success(f"Found {len(valid_subdomains)} valid subdomains for {domain}")
        return sorted(valid_subdomains)
    
    async def _dns_bruteforce(self, domain: str) -> List[str]:
        """Brute force common subdomains via DNS"""
        found = []
        
        if not dns:
            return found
        
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        async def check_subdomain(subdomain: str):
            fqdn = f"{subdomain}.{domain}"
            try:
                await resolver.resolve(fqdn, 'A')
                return fqdn
            except:
                return None
        
        batch_size = 50
        for i in range(0, len(self.COMMON_SUBDOMAINS), batch_size):
            batch = self.COMMON_SUBDOMAINS[i:i + batch_size]
            tasks = [check_subdomain(sub) for sub in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    found.append(result)
        
        return found
    
    async def _cert_transparency(self, domain: str) -> List[str]:
        """Search certificate transparency logs (crt.sh)"""
        found = []
        
        if not aiohttp:
            return found
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            names = name.replace('*.', '').split('\n')
                            for n in names:
                                n = n.strip().lower()
                                if n.endswith(domain) and n != domain:
                                    found.append(n)
        except Exception as e:
            logger.debug(f"CT search failed: {e}")
        
        return list(set(found))
    
    async def _search_engines(self, domain: str) -> List[str]:
        """Search for subdomains using APIs"""
        found = []
        
        if not aiohttp:
            return found
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if 'error' not in text.lower():
                            for line in text.split('\n'):
                                if ',' in line:
                                    subdomain = line.split(',')[0].strip()
                                    if subdomain and subdomain != domain:
                                        found.append(subdomain)
        except Exception as e:
            logger.debug(f"API search failed: {e}")
        
        return found
    
    async def _dns_records(self, domain: str) -> List[str]:
        """Check various DNS record types"""
        found = []
        
        if not dns:
            return found
        
        resolver = dns.asyncresolver.Resolver()
        record_types = ['MX', 'NS', 'TXT', 'SOA']
        
        for rtype in record_types:
            try:
                answers = await resolver.resolve(domain, rtype)
                for rdata in answers:
                    record_str = str(rdata)
                    matches = re.findall(r'[\w.-]+\.' + re.escape(domain), record_str)
                    found.extend(matches)
            except:
                pass
        
        return list(set(found))
    
    async def _validate_subdomains(self, subdomains: List[str], domain: str) -> List[str]:
        """Validate subdomains by DNS resolution"""
        valid = []
        
        if not dns:
            return subdomains
        
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        async def validate(subdomain: str) -> str:
            try:
                await resolver.resolve(subdomain, 'A')
                return subdomain
            except:
                return None
        
        batch_size = 100
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i:i + batch_size]
            tasks = [validate(sub) for sub in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    valid.append(result)
        
        return valid
