"""OpenVAS vulnerability scanner integration"""
import asyncio
from typing import Dict, Any, List
from loguru import logger

try:
    import aiohttp
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
except ImportError:
    aiohttp = None
    Gmp = None

class OpenVASScanner:
    def __init__(self, config):
        self.config = config
        self.socket_path = getattr(config.tools, 'openvas_socket', '/var/run/gvmd.sock')
        self.username = getattr(config.tools, 'openvas_user', 'admin')
        self.password = getattr(config.tools, 'openvas_password', None)
    
    async def scan(self, hosts: List) -> List[Any]:
        if not Gmp:
            logger.warning("python-gvm not installed, using fallback")
            return []
        
        logger.info(f"Starting OpenVAS scan for {len(hosts)} hosts")
        targets = ','.join([str(h.ip) if hasattr(h, 'ip') else str(h) for h in hosts])
        
        try:
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Create target
                target_response = gmp.create_target(name=f'AutoPenTest-{int(asyncio.get_event_loop().time())}', hosts=[targets])
                target_id = target_response.get('id')
                
                # Create and start task
                task_response = gmp.create_task(name=f'Scan-{target_id}', config_id='daba56c8-73ec-11df-a475-002264764cea', target_id=target_id)
                task_id = task_response.get('id')
                gmp.start_task(task_id)
                
                # Wait for completion
                await self._wait_for_task(gmp, task_id)
                
                # Get results
                results = gmp.get_results(task_id=task_id)
                return self._parse_results(results)
        except Exception as e:
            logger.error(f"OpenVAS scan failed: {e}")
            return []
    
    async def _wait_for_task(self, gmp, task_id: str):
        while True:
            status = gmp.get_task(task_id)
            if status.find('.//status').text == 'Done':
                return
            await asyncio.sleep(10)
    
    def _parse_results(self, results) -> List[Dict[str, Any]]:
        vulns = []
        for result in results.findall('.//result'):
            vulns.append({
                'id': f"openvas-{result.find('.//nvt').get('oid')}",
                'name': result.find('.//name').text,
                'severity': result.find('.//severity').text,
                'cvss_score': float(result.find('.//severity').text or 0),
                'description': result.find('.//description').text,
                'solution': result.find('.//solution').text
            })
        return vulns
