"""
Passive Reconnaissance Module
Gathers information without directly connecting to target systems
"""

import asyncio
import aiohttp
import json
import re
from typing import Dict, List, Any
from urllib.parse import urlparse
from loguru import logger

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    whois = None

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    dns = None

try:
    from shodan import Shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    Shodan = None

try:
    from censys.search import CensysHosts
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False
    CensysHosts = None


class PassiveRecon:
    """Passive reconnaissance for gathering target information"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.shodan_api_key = self.config.get('shodan_api_key')
        self.censys_api_id = self.config.get('censys_api_id')
        self.censys_api_secret = self.config.get('censys_api_secret')
    
    async def gather_intelligence(self, target: str) -> Dict[str, Any]:
        """
        Gather passive intelligence about a target
        """
        logger.info(f"Starting passive reconnaissance for {target}")
        
        results = {
            'target': target,
            'domains': [],
            'subdomains': [],
            'dns_records': {},
            'whois_info': {},
            'certificates': [],
            'social_profiles': [],
            'leaks': [],
            'threat_intel': [],
            'technologies': []
        }
        
        # Run all passive recon tasks concurrently
        tasks = [
            self._gather_whois_info(target, results),
            self._gather_dns_info(target, results),
            self._gather_subdomains(target, results),
            self._gather_certificates(target, results),
            self._gather_threat_intel(target, results),
            self._gather_technologies(target, results)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.success(f"Passive reconnaissance completed for {target}")
        return results
    
    async def _gather_whois_info(self, target: str, results: Dict) -> None:
        """Gather WHOIS information"""
        if not WHOIS_AVAILABLE:
            return
            
        try:
            logger.info(f"Gathering WHOIS info for {target}")
            
            # Extract domain from URL or use as-is
            parsed = urlparse(target)
            domain = parsed.netloc if parsed.netloc else target
            
            if domain:
                whois_info = whois.whois(domain)
                results['whois_info'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date),
                    'name_servers': whois_info.name_servers,
                    'emails': whois_info.emails,
                    'org': whois_info.org
                }
                logger.info(f"WHOIS info gathered for {domain}")
        except Exception as e:
            logger.debug(f"WHOIS gathering failed for {target}: {e}")
    
    async def _gather_dns_info(self, target: str, results: Dict) -> None:
        """Gather DNS records"""
        if not DNS_AVAILABLE:
            return
            
        try:
            logger.info(f"Gathering DNS info for {target}")
            
            # Extract domain from URL or use as-is
            parsed = urlparse(target)
            domain = parsed.netloc if parsed.netloc else target
            
            if domain:
                dns_records = {}
                
                # Query common record types
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
                
                for record_type in record_types:
                    try:
                        answers = dns.resolver.resolve(domain, record_type)
                        dns_records[record_type] = [str(rdata) for rdata in answers]
                    except dns.exception.DNSException:
                        continue
                
                results['dns_records'] = dns_records
                logger.info(f"DNS info gathered for {domain}")
        except Exception as e:
            logger.debug(f"DNS gathering failed for {target}: {e}")
    
    async def _gather_subdomains(self, target: str, results: Dict) -> None:
        """Gather subdomains using passive methods"""
        try:
            logger.info(f"Gathering subdomains for {target}")
            
            # Extract domain from URL or use as-is
            parsed = urlparse(target)
            domain = parsed.netloc if parsed.netloc else target
            
            if not domain:
                return
            
            subdomains = set()
            
            # Method 1: Certificate transparency logs
            ct_subdomains = await self._query_cert_transparency(domain)
            subdomains.update(ct_subdomains)
            
            # Method 2: DNS dumpster (if available)
            # This would require scraping or API access
            
            # Method 3: VirusTotal (if API key available)
            vt_subdomains = await self._query_virustotal(domain)
            subdomains.update(vt_subdomains)
            
            results['subdomains'] = list(subdomains)
            logger.info(f"Found {len(subdomains)} subdomains for {domain}")
        except Exception as e:
            logger.debug(f"Subdomain gathering failed for {target}: {e}")
    
    async def _query_cert_transparency(self, domain: str) -> List[str]:
        """Query certificate transparency logs"""
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Query crt.sh for certificates
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if name and not name.startswith('*'):
                                subdomains.add(name)
        except Exception as e:
            logger.debug(f"Certificate transparency query failed: {e}")
        
        return list(subdomains)
    
    async def _query_virustotal(self, domain: str) -> List[str]:
        """Query VirusTotal for subdomains (requires API key)"""
        subdomains = []
        vt_api_key = self.config.get('virustotal_api_key')
        
        if not vt_api_key:
            return subdomains
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                headers = {'x-apikey': vt_api_key}
                url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        for item in data.get('data', []):
                            subdomains.append(item['id'])
        except Exception as e:
            logger.debug(f"VirusTotal query failed: {e}")
        
        return subdomains
    
    async def _gather_certificates(self, target: str, results: Dict) -> None:
        """Gather certificate information"""
        try:
            logger.info(f"Gathering certificate info for {target}")
            
            # Extract domain from URL or use as-is
            parsed = urlparse(target)
            domain = parsed.netloc if parsed.netloc else target
            
            if not domain:
                return
            
            certificates = []
            
            # Query crt.sh for recent certificates
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"https://crt.sh/?q={domain}&output=json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data[:10]:  # Limit to 10 most recent
                            cert_info = {
                                'issuer': entry.get('issuer_name', ''),
                                'subject': entry.get('common_name', ''),
                                'not_before': entry.get('not_before', ''),
                                'not_after': entry.get('not_after', ''),
                                'serial': entry.get('serial_number', '')
                            }
                            certificates.append(cert_info)
            
            results['certificates'] = certificates
            logger.info(f"Certificate info gathered for {domain}")
        except Exception as e:
            logger.debug(f"Certificate gathering failed for {target}: {e}")
    
    async def _gather_threat_intel(self, target: str, results: Dict) -> None:
        """Gather threat intelligence"""
        try:
            logger.info(f"Gathering threat intel for {target}")
            
            threat_info = []
            
            # Query threat intelligence sources
            # This is a simplified implementation
            
            # Check if Shodan API key is available
            if SHODAN_AVAILABLE and self.shodan_api_key:
                try:
                    api = Shodan(self.shodan_api_key)
                    # Extract IP or domain
                    parsed = urlparse(target)
                    query_target = parsed.netloc if parsed.netloc else target
                    
                    if query_target:
                        # Shodan host lookup
                        host_info = api.host(query_target)
                        threat_info.append({
                            'source': 'Shodan',
                            'info': host_info
                        })
                except Exception as e:
                    logger.debug(f"Shodan query failed: {e}")
            
            # Check if Censys credentials are available
            if CENSYS_AVAILABLE and self.censys_api_id and self.censys_api_secret:
                try:
                    censys_hosts = CensysHosts(self.censys_api_id, self.censys_api_secret)
                    # Extract IP or domain
                    parsed = urlparse(target)
                    query_target = parsed.netloc if parsed.netloc else target
                    
                    if query_target:
                        # Censys host lookup
                        host_info = censys_hosts.view(query_target)
                        threat_info.append({
                            'source': 'Censys',
                            'info': host_info
                        })
                except Exception as e:
                    logger.debug(f"Censys query failed: {e}")
            
            results['threat_intel'] = threat_info
            logger.info(f"Threat intel gathered for {target}")
        except Exception as e:
            logger.debug(f"Threat intel gathering failed for {target}: {e}")
    
    async def _gather_technologies(self, target: str, results: Dict) -> None:
        """Gather technology fingerprinting information"""
        try:
            logger.info(f"Gathering technology info for {target}")
            
            technologies = []
            
            # Extract domain/IP from URL
            parsed = urlparse(target)
            host = parsed.netloc if parsed.netloc else target
            
            if not host:
                return
            
            # Query Wappalyzer-like service or use built-in detection
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Check for common technologies by examining HTTP headers and content
                try:
                    async with session.get(f"http://{host}" if not parsed.scheme else target, ssl=False) as response:
                        headers = response.headers
                        content = await response.text()
                        
                        # Detect technologies based on headers and content
                        techs = self._detect_technologies(headers, content)
                        technologies.extend(techs)
                except:
                    pass
                
                # Try HTTPS if HTTP failed
                if not technologies:
                    try:
                        async with session.get(f"https://{host}", ssl=False) as response:
                            headers = response.headers
                            content = await response.text()
                            
                            # Detect technologies based on headers and content
                            techs = self._detect_technologies(headers, content)
                            technologies.extend(techs)
                    except:
                        pass
            
            results['technologies'] = technologies
            logger.info(f"Technology info gathered for {host}")
        except Exception as e:
            logger.debug(f"Technology gathering failed for {target}: {e}")
    
    def _detect_technologies(self, headers: Dict, content: str) -> List[Dict]:
        """Detect technologies based on headers and content"""
        technologies = []
        
        # Check server header
        server = headers.get('Server', '')
        if server:
            technologies.append({
                'name': 'Web Server',
                'version': server,
                'confidence': 'high'
            })
        
        # Check for common CMS/framework signatures
        cms_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-content'],
            'Joomla': ['/components/com_', '/administrator/', 'Joomla!'],
            'Drupal': ['/sites/all/', '/misc/drupal.js', 'Drupal.settings'],
            'Magento': ['/skin/frontend/', '/js/varien/', 'Mage.Cookies'],
        }
        
        for cms, signatures in cms_signatures.items():
            for signature in signatures:
                if signature in content:
                    technologies.append({
                        'name': cms,
                        'version': 'Unknown',
                        'confidence': 'medium'
                    })
                    break
        
        # Check for JavaScript libraries
        js_libs = {
            'jQuery': ['jquery.min.js', 'jQuery'],
            'Bootstrap': ['bootstrap.min.css', 'bootstrap'],
            'React': ['react-dom', 'ReactDOM'],
            'Vue.js': ['vue.min.js', 'new Vue'],
            'Angular': ['angular.min.js', 'ng-app']
        }
        
        for lib, signatures in js_libs.items():
            for signature in signatures:
                if signature in content:
                    technologies.append({
                        'name': lib,
                        'version': 'Unknown',
                        'confidence': 'medium'
                    })
                    break
        
        return technologies

# Example usage
if __name__ == "__main__":
    async def main():
        recon = PassiveRecon()
        results = await recon.gather_intelligence("example.com")
        print(json.dumps(results, indent=2))
    
    asyncio.run(main())