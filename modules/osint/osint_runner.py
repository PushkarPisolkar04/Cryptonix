"""
Comprehensive OSINT (Open Source Intelligence) gathering module
Stage 1: Pre-Assessment & Intelligence Gathering
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import requests
from urllib.parse import urlencode
from dataclasses import dataclass, asdict

from loguru import logger


@dataclass
class OSINTResult:
    """Result container for OSINT findings"""
    timestamp: str
    target: str
    subdomains: Set[str]
    emails: Set[str]
    breached_emails: Set[str]
    passwords: Set[str]
    certificates: List[Dict]
    social_profiles: List[Dict]
    paste_leaks: List[Dict]
    dns_records: Dict
    whois_info: Dict
    leaked_configs: List[Dict]

    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        result['subdomains'] = list(result['subdomains'])
        result['emails'] = list(result['emails'])
        result['breached_emails'] = list(result['breached_emails'])
        result['passwords'] = list(result['passwords'])
        return result


class OSINTRunner:
    """Main OSINT orchestrator"""

    def __init__(self, config: Dict):
        self.config = config
        self.shodan_api_key = config.get('shodan_api_key')
        self.hibp_api_key = config.get('hibp_api_key')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    async def gather_intelligence(self, target: str) -> OSINTResult:
        """Orchestrate all OSINT gathering tasks"""
        logger.info(f"Starting comprehensive OSINT for {target}")
        
        result = OSINTResult(
            timestamp=datetime.now().isoformat(),
            target=target,
            subdomains=set(),
            emails=set(),
            breached_emails=set(),
            passwords=set(),
            certificates=[],
            social_profiles=[],
            paste_leaks=[],
            dns_records={},
            whois_info={},
            leaked_configs=[]
        )

        # Run all tasks in parallel
        tasks = [
            self._whois_lookup(target),
            self._dns_enumeration(target),
            self._subdomain_enumeration(target),
            self._certificate_transparency(target),
            self._email_harvesting(target),
            self._breach_check(result.emails),
            self._social_media_footprinting(target),
            self._paste_site_monitoring(target),
            self._dark_web_search(target)
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Task {idx} failed: {res}")
                continue
            
            if idx == 0:  # WHOIS
                result.whois_info = res
            elif idx == 1:  # DNS
                result.dns_records = res
            elif idx == 2:  # Subdomains
                result.subdomains.update(res)
            elif idx == 3:  # Certificates
                result.certificates = res
            elif idx == 4:  # Emails
                result.emails.update(res)
            elif idx == 5:  # Breached emails
                breached, passwords = res
                result.breached_emails.update(breached)
                result.passwords.update(passwords)
            elif idx == 6:  # Social profiles
                result.social_profiles = res
            elif idx == 7:  # Paste leaks
                result.paste_leaks = res
            elif idx == 8:  # Dark web
                result.leaked_configs = res

        logger.success(f"OSINT gathering complete. Found {len(result.subdomains)} subdomains, {len(result.emails)} emails, {len(result.breached_emails)} breached accounts")
        return result

    async def _whois_lookup(self, target: str) -> Dict:
        """Get WHOIS information"""
        logger.info(f"Performing WHOIS lookup for {target}")
        try:
            import whois
            w = whois.whois(target)
            return {
                'registrar': str(w.registrar),
                'registrant': str(w.registrant),
                'created': str(w.creation_date),
                'expires': str(w.expiration_date),
                'updated': str(w.updated_date),
                'name_servers': w.name_servers if w.name_servers else [],
                'organization': str(w.org),
                'country': str(w.country)
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return {}

    async def _dns_enumeration(self, target: str) -> Dict:
        """Enumerate DNS records"""
        logger.info(f"Performing DNS enumeration for {target}")
        try:
            import dns.resolver
            dns_records = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    dns_records[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    pass
            
            return dns_records
        except Exception as e:
            logger.error(f"DNS enumeration failed: {e}")
            return {}

    async def _subdomain_enumeration(self, target: str) -> List[str]:
        """Enumerate subdomains via multiple methods"""
        logger.info(f"Enumerating subdomains for {target}")
        subdomains = set()

        # Method 1: Certificate Transparency
        subdomains.update(await self._crt_sh_enumeration(target))

        # Method 2: Shodan
        if self.shodan_api_key:
            subdomains.update(await self._shodan_subdomain_search(target))

        # Method 3: DNS brute force (common subdomains)
        subdomains.update(await self._dns_brute_force(target))

        logger.success(f"Found {len(subdomains)} subdomains")
        return list(subdomains)

    async def _crt_sh_enumeration(self, target: str) -> Set[str]:
        """Get subdomains from crt.sh (Certificate Transparency)"""
        try:
            url = f"https://crt.sh/?q=%25.{target}&output=json"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                certs = response.json()
                subdomains = set()
                for cert in certs:
                    names = cert.get('name_value', '').split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name and not name.startswith('*.'):
                            subdomains.add(name)
                return subdomains
        except Exception as e:
            logger.error(f"crt.sh enumeration failed: {e}")
        return set()

    async def _shodan_subdomain_search(self, target: str) -> Set[str]:
        """Search Shodan for subdomains"""
        try:
            url = "https://api.shodan.io/dns/domain/subdomains"
            params = {'domain': target, 'key': self.shodan_api_key}
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set([f"{sub}.{target}" for sub in data.get('subdomains', [])])
                return subdomains
        except Exception as e:
            logger.error(f"Shodan subdomain search failed: {e}")
        return set()

    async def _dns_brute_force(self, target: str) -> Set[str]:
        """Brute force common subdomains via DNS"""
        common_subdomains = [
            'www', 'mail', 'smtp', 'ftp', 'admin', 'vpn', 'api', 'cdn',
            'staging', 'test', 'dev', 'prod', 'db', 'internal', 'server',
            'portal', 'dashboard', 'git', 'jenkins', 'kibana', 'grafana',
            'prometheus', 'elasticsearch', 'backup', 'archive'
        ]
        
        subdomains = set()
        try:
            import dns.resolver
            for sub in common_subdomains:
                try:
                    domain = f"{sub}.{target}"
                    dns.resolver.resolve(domain, 'A')
                    subdomains.add(domain)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"DNS brute force failed: {e}")
        
        return subdomains

    async def _certificate_transparency(self, target: str) -> List[Dict]:
        """Get certificate information from CT logs"""
        try:
            url = f"https://crt.sh/?q={target}&output=json"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                certs = response.json()
                result = []
                for cert in certs[:10]:  # Limit to 10 most recent
                    result.append({
                        'id': cert.get('id'),
                        'logged_at': cert.get('entry_timestamp'),
                        'issuer': cert.get('issuer_name'),
                        'names': cert.get('name_value', '').split('\n')
                    })
                return result
        except Exception as e:
            logger.error(f"Certificate transparency lookup failed: {e}")
        return []

    async def _email_harvesting(self, target: str) -> Set[str]:
        """Harvest employee emails"""
        logger.info(f"Harvesting emails for {target}")
        emails = set()

        # Method 1: Google search operators
        emails.update(await self._google_email_search(target))

        # Method 2: LinkedIn scraping (basic)
        emails.update(await self._linkedin_search(target))

        logger.success(f"Found {len(emails)} email addresses")
        return emails

    async def _google_email_search(self, target: str) -> Set[str]:
        """Search Google for emails"""
        try:
            # Using public search operators
            search_queries = [
                f'site:{target} "@{target}"',
                f'site:linkedin.com "{target}"',
                f'inurl:"{target}" email OR contact',
            ]
            
            emails = set()
            for query in search_queries:
                url = "https://www.google.com/search"
                params = {'q': query}
                response = self.session.get(url, params=params, timeout=10)
                # Simple regex pattern matching in response
                import re
                pattern = r'[\w\.-]+@' + target.replace('.', r'\.')
                found = re.findall(pattern, response.text)
                emails.update(found)
            
            return emails
        except Exception as e:
            logger.error(f"Google email search failed: {e}")
        return set()

    async def _linkedin_search(self, target: str) -> Set[str]:
        """Basic LinkedIn search for company employees"""
        try:
            url = "https://www.linkedin.com/search/results/people/"
            params = {'keywords': target}
            response = self.session.get(url, params=params, timeout=10)
            
            emails = set()
            import re
            pattern = r'[\w\.-]+@[\w\.-]+'
            found = re.findall(pattern, response.text)
            emails.update([e for e in found if target in e or 'linkedin' not in e])
            
            return emails
        except Exception as e:
            logger.error(f"LinkedIn search failed: {e}")
        return set()

    async def _breach_check(self, emails: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Check HaveIBeenPwned for breached emails"""
        logger.info(f"Checking {len(emails)} emails against breach databases")
        breached_emails = set()
        passwords = set()

        if not self.hibp_api_key:
            logger.warning("HaveIBeenPwned API key not configured")
            return breached_emails, passwords

        for email in list(emails)[:50]:  # Limit to 50 to avoid rate limiting
            try:
                headers = {'User-Agent': 'Cryptonix', 'hibp-api-key': self.hibp_api_key}
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                response = self.session.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    breaches = response.json()
                    breached_emails.add(email)
                    # Log breach details
                    for breach in breaches:
                        logger.warning(f"  {email} found in: {breach.get('Title')}")
                
                await asyncio.sleep(1.5)  # Rate limiting
            except Exception as e:
                logger.debug(f"HIBP check failed for {email}: {e}")

        logger.success(f"Found {len(breached_emails)} breached emails")
        return breached_emails, passwords

    async def _social_media_footprinting(self, target: str) -> List[Dict]:
        """Footprint organization on social media"""
        logger.info(f"Performing social media footprinting for {target}")
        profiles = []

        platforms = {
            'LinkedIn': f"https://www.linkedin.com/company/{target.replace('.com', '')}",
            'Twitter': f"https://twitter.com/search?q={target}",
            'GitHub': f"https://github.com/search?q={target}",
            'Facebook': f"https://www.facebook.com/search/top/?q={target}",
            'Instagram': f"https://www.instagram.com/explore/tags/{target.split('.')[0]}/",
        }

        for platform, url in platforms.items():
            try:
                response = self.session.head(url, timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    profiles.append({
                        'platform': platform,
                        'url': url,
                        'found': True
                    })
                    logger.success(f"Found {platform} presence")
            except Exception as e:
                logger.debug(f"Social media check for {platform} failed: {e}")

        return profiles

    async def _paste_site_monitoring(self, target: str) -> List[Dict]:
        """Monitor paste sites for leaked data"""
        logger.info(f"Monitoring paste sites for {target} leaks")
        leaks = []

        paste_sites = [
            ('Pastebin', 'https://pastebin.com/search?q='),
            ('PasteBin', 'https://www.paste.ee/?s='),
        ]

        for site_name, base_url in paste_sites:
            try:
                url = f"{base_url}{target}"
                response = self.session.get(url, timeout=10)
                if response.status_code == 200 and len(response.text) > 100:
                    leaks.append({
                        'site': site_name,
                        'url': url,
                        'found': True,
                        'snippet': response.text[:200]
                    })
                    logger.warning(f"Potential leak found on {site_name}")
            except Exception as e:
                logger.debug(f"Paste site check failed: {e}")

        return leaks

    async def _dark_web_search(self, target: str) -> List[Dict]:
        """Placeholder for dark web monitoring"""
        logger.info(f"Checking dark web for {target} mentions")
        # This would require Tor connection and monitoring services
        # For now, return placeholder
        return [{
            'source': 'threat_intelligence_feed',
            'message': 'Dark web monitoring would require Tor infrastructure',
            'status': 'not_configured'
        }]

    def save_results(self, result: OSINTResult, output_path: str):
        """Save OSINT results to file"""
        output_file = Path(output_path) / f"osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        logger.success(f"OSINT results saved to {output_file}")
        return output_file
