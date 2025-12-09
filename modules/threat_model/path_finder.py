"""Attack path finding"""
import asyncio
from typing import Dict, Any, List
from loguru import logger

class AttackPathFinder:
    def __init__(self, config):
        self.config = config
    
    async def find_paths(self, attack_graph: Dict) -> List[Dict[str, Any]]:
        logger.info("Finding attack paths through network")
        
        paths = []
        nodes = attack_graph.get('nodes', [])
        edges = attack_graph.get('edges', [])
        
        # Find critical vulnerabilities
        vuln_nodes = [n for n in nodes if n.get('type') == 'vulnerability' and n.get('severity') in ['critical', 'high']]
        
        for vuln in vuln_nodes[:10]:
            path = {
                'target': vuln.get('label', 'Unknown'),
                'severity': vuln.get('severity', 'info'),
                'cvss': vuln.get('cvss', 0),
                'exploitability': self._calculate_exploitability(vuln),
                'impact': self._calculate_impact(vuln),
                'steps': [
                    {'phase': 'Reconnaissance', 'description': 'Gather information about target'},
                    {'phase': 'Initial Access', 'description': f"Exploit {vuln.get('label')}"},
                    {'phase': 'Execution', 'description': 'Execute malicious code'},
                    {'phase': 'Persistence', 'description': 'Establish foothold'},
                    {'phase': 'Privilege Escalation', 'description': 'Gain higher privileges'},
                    {'phase': 'Lateral Movement', 'description': 'Move to other systems'}
                ]
            }
            paths.append(path)
        
        logger.success(f"Found {len(paths)} attack paths")
        return paths
    
    def _calculate_exploitability(self, vuln: Dict) -> float:
        cvss = vuln.get('cvss', 0)
        return min(cvss / 10.0, 1.0)
    
    def _calculate_impact(self, vuln: Dict) -> float:
        severity_map = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.3, 'info': 0.1}
        return severity_map.get(vuln.get('severity', 'info'), 0.5)
