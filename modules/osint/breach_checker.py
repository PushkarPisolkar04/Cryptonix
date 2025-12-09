"""
Breach data checking using various sources
"""

import asyncio
import hashlib
from typing import Dict, Any, List
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None


class BreachChecker:
    """Check for breached credentials and data leaks"""
    
    def __init__(self, config):
        self.config = config
        self.hibp_api_key = None
        if hasattr(config, 'apis') and hasattr(config.apis, 'haveibeenpwned_api_key'):
            self.hibp_api_key = config.apis.haveibeenpwned_api_key
        self.user_agent = 'AutoPenTest-Security-Scanner'
    
    async def check(self, target: str) -> List[Dict[str, Any]]:
        """Check domain/email for breaches"""
        logger.info(f"Checking breach databases for {target}")
        
        breaches = []
        is_email = '@' in target
        
        if is_email:
            breaches.extend(await self._check_email_breaches(target))
        else:
            breaches.extend(await self._check_domain_breaches(target))
        
        if is_email:
            breaches.extend(await self._check_paste_sites(target))
        
        logger.success(f"Found {len(breaches)} breach records")
        return breaches
    
    async def _check_email_breaches(self, email: str) -> List[Dict[str, Any]]:
        """Check email against HaveIBeenPwned"""
        breaches = []
        
        if not aiohttp or not self.hibp_api_key:
            logger.warning("HIBP API key not configured")
            return breaches
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'hibp-api-key': self.hibp_api_key, 'User-Agent': self.user_agent}
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for breach in data:
                            breaches.append({
                                'email': email,
                                'name': breach.get('Name', 'Unknown'),
                                'title': breach.get('Title', ''),
                                'domain': breach.get('Domain', ''),
                                'breach_date': breach.get('BreachDate', ''),
                                'pwn_count': breach.get('PwnCount', 0),
                                'data_classes': breach.get('DataClasses', []),
                                'is_verified': breach.get('IsVerified', False),
                                'source': 'haveibeenpwned'
                            })
        except Exception as e:
            logger.debug(f"HIBP check failed: {e}")
        
        return breaches
    
    async def _check_domain_breaches(self, domain: str) -> List[Dict[str, Any]]:
        """Check domain for breaches"""
        breaches = []
        
        if not aiohttp or not self.hibp_api_key:
            return breaches
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'hibp-api-key': self.hibp_api_key, 'User-Agent': self.user_agent}
                url = f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}"
                
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for breach in data:
                            breaches.append({
                                'domain': domain,
                                'name': breach.get('Name', 'Unknown'),
                                'breach_date': breach.get('BreachDate', ''),
                                'pwn_count': breach.get('PwnCount', 0),
                                'data_classes': breach.get('DataClasses', []),
                                'source': 'haveibeenpwned'
                            })
        except Exception as e:
            logger.debug(f"HIBP domain check failed: {e}")
        
        return breaches
    
    async def _check_paste_sites(self, email: str) -> List[Dict[str, Any]]:
        """Check paste sites for leaked data"""
        pastes = []
        
        if not aiohttp or not self.hibp_api_key:
            return pastes
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'hibp-api-key': self.hibp_api_key, 'User-Agent': self.user_agent}
                url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
                
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for paste in data:
                            pastes.append({
                                'email': email,
                                'source': paste.get('Source', 'Unknown'),
                                'paste_id': paste.get('Id', ''),
                                'title': paste.get('Title', ''),
                                'date': paste.get('Date', ''),
                                'type': 'paste'
                            })
        except Exception as e:
            logger.debug(f"Paste check failed: {e}")
        
        return pastes
    
    async def check_password_pwned(self, password: str) -> Dict[str, Any]:
        """Check if a password has been pwned using k-Anonymity"""
        if not aiohttp:
            return {'pwned': False, 'count': 0}
        
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            async with aiohttp.ClientSession() as session:
                url = f"https://api.pwnedpasswords.com/range/{prefix}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.split('\n'):
                            parts = line.strip().split(':')
                            if len(parts) == 2 and parts[0] == suffix:
                                return {'pwned': True, 'count': int(parts[1])}
        except:
            pass
        
        return {'pwned': False, 'count': 0}
