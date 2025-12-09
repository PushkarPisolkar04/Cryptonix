"""Cloud asset discovery (S3, Azure, GCS)"""
import asyncio
from typing import Dict, Any, List
from loguru import logger

try:
    import aiohttp
except ImportError:
    aiohttp = None

class CloudAssetDiscovery:
    def __init__(self, config):
        self.config = config
    
    async def discover(self, target: str) -> List[Dict[str, Any]]:
        logger.info(f"Discovering cloud assets for {target}")
        
        assets = []
        domain = target.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Generate bucket names
        bucket_names = self._generate_bucket_names(domain)
        
        # Check S3
        assets.extend(await self._check_s3_buckets(bucket_names))
        
        # Check Azure
        assets.extend(await self._check_azure_blobs(bucket_names))
        
        # Check GCS
        assets.extend(await self._check_gcs_buckets(bucket_names))
        
        logger.success(f"Found {len(assets)} cloud assets")
        return assets
    
    def _generate_bucket_names(self, domain: str) -> List[str]:
        base = domain.split('.')[0]
        return [
            base, f'{base}-backup', f'{base}-backups', f'{base}-data',
            f'{base}-files', f'{base}-uploads', f'{base}-assets',
            f'{base}-prod', f'{base}-dev', f'{base}-staging'
        ]
    
    async def _check_s3_buckets(self, names: List[str]) -> List[Dict[str, Any]]:
        if not aiohttp:
            return []
        
        found = []
        for name in names:
            try:
                url = f'https://{name}.s3.amazonaws.com'
                async with aiohttp.ClientSession() as session:
                    async with session.head(url, timeout=5) as resp:
                        if resp.status in [200, 403]:
                            found.append({'type': 's3', 'name': name, 'url': url, 'accessible': resp.status == 200})
            except:
                pass
        return found
    
    async def _check_azure_blobs(self, names: List[str]) -> List[Dict[str, Any]]:
        if not aiohttp:
            return []
        
        found = []
        for name in names:
            try:
                url = f'https://{name}.blob.core.windows.net'
                async with aiohttp.ClientSession() as session:
                    async with session.head(url, timeout=5) as resp:
                        if resp.status in [200, 403]:
                            found.append({'type': 'azure', 'name': name, 'url': url, 'accessible': resp.status == 200})
            except:
                pass
        return found
    
    async def _check_gcs_buckets(self, names: List[str]) -> List[Dict[str, Any]]:
        if not aiohttp:
            return []
        
        found = []
        for name in names:
            try:
                url = f'https://storage.googleapis.com/{name}'
                async with aiohttp.ClientSession() as session:
                    async with session.head(url, timeout=5) as resp:
                        if resp.status in [200, 403]:
                            found.append({'type': 'gcs', 'name': name, 'url': url, 'accessible': resp.status == 200})
            except:
                pass
        return found
