"""
Certificate Transparency log searching
"""

import asyncio
import ssl
import socket
from typing import List, Dict, Any, Set
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None


class CertTransparency:
    """Search Certificate Transparency logs for domain information"""
    
    def __init__(self, config):
        self.config = config
        self.censys_id = getattr(config.apis, 'censys_api_id', None) if hasattr(config, 'apis') else None
        self.censys_secret = getattr(config.apis, 'censys_api_secret', None) if hasattr(config, 'apis') else None
    
    async def search(self, domain: str) -> List[Dict[str, Any]]:
        """Search CT logs for certificates"""
        domain = domain.lower().strip()
        logger.info(f"Searching CT logs for {domain}")
        
        tasks = [
            self._search_crtsh(domain),
            self._search_certspotter(domain),
            self._get_live_cert(domain),
        ]
        
        if self.censys_id and self.censys_secret:
            tasks.append(self._search_censys(domain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        certificates = []
        seen = set()
        
        for result in results:
            if isinstance(result, list):
                for cert in result:
                    fp = cert.get('fingerprint', cert.get('serial', cert.get('id', '')))
                    if fp and fp not in seen:
                        seen.add(fp)
                        certificates.append(cert)
        
        logger.success(f"Found {len(certificates)} certificates for {domain}")
        return certificates
    
    async def _search_crtsh(self, domain: str) -> List[Dict[str, Any]]:
        """Search crt.sh CT logs"""
        certificates = []
        
        if not aiohttp:
            return certificates
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        seen = set()
                        for entry in data:
                            cert_id = entry.get('id')
                            if cert_id in seen:
                                continue
                            seen.add(cert_id)
                            
                            certificates.append({
                                'source': 'crt.sh',
                                'id': cert_id,
                                'serial': entry.get('serial_number'),
                                'issuer': entry.get('issuer_name'),
                                'common_name': entry.get('common_name'),
                                'name_value': entry.get('name_value'),
                                'not_before': entry.get('not_before'),
                                'not_after': entry.get('not_after'),
                            })
        except Exception as e:
            logger.debug(f"crt.sh search failed: {e}")
        
        return certificates
    
    async def _search_censys(self, domain: str) -> List[Dict[str, Any]]:
        """Search Censys.io for certificates"""
        certificates = []
        
        if not aiohttp:
            return certificates
        
        try:
            async with aiohttp.ClientSession() as session:
                url = "https://search.censys.io/api/v2/certificates/search"
                auth = aiohttp.BasicAuth(self.censys_id, self.censys_secret)
                payload = {"q": f"names: {domain}", "per_page": 100}
                
                async with session.post(url, json=payload, auth=auth, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for hit in data.get('result', {}).get('hits', []):
                            certificates.append({
                                'source': 'Censys',
                                'fingerprint': hit.get('fingerprint_sha256'),
                                'names': hit.get('names', []),
                            })
        except Exception as e:
            logger.debug(f"Censys search failed: {e}")
        
        return certificates
    
    async def _search_certspotter(self, domain: str) -> List[Dict[str, Any]]:
        """Search Cert Spotter API"""
        certificates = []
        
        if not aiohttp:
            return certificates
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            certificates.append({
                                'source': 'CertSpotter',
                                'id': entry.get('id'),
                                'dns_names': entry.get('dns_names', []),
                                'issuer': entry.get('issuer'),
                                'not_before': entry.get('not_before'),
                                'not_after': entry.get('not_after'),
                            })
        except Exception as e:
            logger.debug(f"CertSpotter search failed: {e}")
        
        return certificates
    
    async def _get_live_cert(self, domain: str) -> List[Dict[str, Any]]:
        """Get live certificate from domain"""
        certificates = []
        
        try:
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(None, self._fetch_ssl_cert, domain)
            if cert_info:
                certificates.append(cert_info)
        except Exception as e:
            logger.debug(f"Live cert fetch failed: {e}")
        
        return certificates
    
    def _fetch_ssl_cert(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Fetch SSL certificate from server"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    
                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        
                        san = []
                        for entry in cert.get('subjectAltName', []):
                            if entry[0] == 'DNS':
                                san.append(entry[1])
                        
                        return {
                            'source': 'Live',
                            'domain': domain,
                            'common_name': subject.get('commonName'),
                            'organization': subject.get('organizationName'),
                            'issuer_cn': issuer.get('commonName'),
                            'issuer_org': issuer.get('organizationName'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'serial': cert.get('serialNumber'),
                            'san': san,
                        }
        except Exception as e:
            logger.debug(f"SSL cert fetch error: {e}")
        
        return None
    
    async def get_subdomains_from_ct(self, domain: str) -> List[str]:
        """Extract unique subdomains from CT logs"""
        certificates = await self.search(domain)
        subdomains: Set[str] = set()
        
        for cert in certificates:
            name_value = cert.get('name_value', '')
            if name_value:
                for name in name_value.split('\n'):
                    name = name.strip().lower()
                    if name.endswith(domain) and '*' not in name:
                        subdomains.add(name)
            
            for name in cert.get('dns_names', []):
                name = name.lower()
                if name.endswith(domain) and '*' not in name:
                    subdomains.add(name)
            
            for name in cert.get('san', []):
                name = name.lower()
                if name.endswith(domain) and '*' not in name:
                    subdomains.add(name)
        
        return sorted(subdomains)
