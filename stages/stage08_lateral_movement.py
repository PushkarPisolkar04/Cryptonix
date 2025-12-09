"""
Stage 8: Lateral Movement & Pivoting
Network propagation and internal reconnaissance
"""

from typing import Dict, Any
from loguru import logger
from stages.base import BaseStage
from modules.lateral.pass_the_hash import PassTheHashAttack
from modules.lateral.smb_relay import SMBRelayAttack
from modules.lateral.network_mapper import InternalNetworkMapper
from modules.lateral.pivot_manager import PivotManager


class LateralMovementStage(BaseStage):
    
    @property
    def name(self) -> str:
        return "Lateral Movement & Pivoting"
    
    @property
    def description(self) -> str:
        return "Internal network mapping, pass-the-hash, SMB relay, pivoting"
    
    async def run(self) -> Dict[str, Any]:
        if self.scope.dry_run:
            logger.warning("⚠️ Dry-run mode: Skipping lateral movement")
            return {'internal_hosts': [], 'dry_run': True}
        
        post_exploit_data = self.get_previous_stage_data('post_exploit')
        credentials = post_exploit_data.get('credentials', [])
        compromised_hosts = post_exploit_data.get('compromised_hosts', [])
        
        if not compromised_hosts:
            logger.warning("No compromised hosts for lateral movement")
            return {'internal_hosts': []}
        
        logger.info(f"🔄 Attempting lateral movement from {len(compromised_hosts)} hosts")
        
        # Map internal network from compromised hosts
        mapper = InternalNetworkMapper(self.config)
        internal_hosts = await mapper.map_from_compromised(compromised_hosts[0])
        
        # Setup pivots
        pivot_mgr = PivotManager(self.config)
        pivots = await pivot_mgr.setup_pivots(compromised_hosts)
        
        # Pass-the-hash attacks
        pth_attack = PassTheHashAttack(self.config)
        pth_results = []
        
        for cred in credentials:
            if cred.hash:
                result = await pth_attack.attempt(cred, internal_hosts)
                pth_results.append(result)
        
        # SMB relay attacks
        smb_relay = SMBRelayAttack(self.config)
        relay_results = await smb_relay.attempt(internal_hosts)
        
        results = {
            'internal_hosts': internal_hosts,
            'pivots': pivots,
            'pth_results': pth_results,
            'relay_results': relay_results,
            'newly_compromised': sum(1 for r in pth_results if r.get('success'))
        }
        
        logger.success(f"✅ Discovered {len(internal_hosts)} internal hosts")
        logger.success(f"✅ Compromised {results['newly_compromised']} additional hosts")
        
        return results
