"""Attack graph generation"""
import asyncio
from typing import Dict, Any, List
from loguru import logger

class AttackGraphGenerator:
    def __init__(self, config):
        self.config = config
    
    async def generate(self, hosts: List, vulnerabilities: List) -> Dict[str, Any]:
        logger.info(f"Generating attack graph for {len(hosts)} hosts, {len(vulnerabilities)} vulns")
        
        graph = {
            'nodes': [],
            'edges': [],
            'attack_paths': []
        }
        
        # Create nodes for hosts
        for host in hosts:
            host_id = getattr(host, 'ip', str(host))
            graph['nodes'].append({
                'id': host_id,
                'type': 'host',
                'label': host_id,
                'os': getattr(host, 'os', 'unknown')
            })
        
        # Create nodes for vulnerabilities
        for vuln in vulnerabilities:
            vuln_id = getattr(vuln, 'id', str(hash(str(vuln))))
            graph['nodes'].append({
                'id': vuln_id,
                'type': 'vulnerability',
                'label': getattr(vuln, 'name', 'Unknown'),
                'severity': getattr(vuln, 'severity', 'info'),
                'cvss': getattr(vuln, 'cvss_score', 0)
            })
            
            # Create edges from host to vulnerability
            affected_host = getattr(vuln, 'host', None) or getattr(vuln, 'affected_service', None)
            if affected_host:
                graph['edges'].append({
                    'from': affected_host,
                    'to': vuln_id,
                    'type': 'has_vulnerability'
                })
        
        # Generate attack paths
        critical_vulns = [v for v in vulnerabilities if getattr(v, 'severity', 'info') in ['critical', 'high']]
        for vuln in critical_vulns[:10]:
            graph['attack_paths'].append({
                'vulnerability': getattr(vuln, 'name', 'Unknown'),
                'severity': getattr(vuln, 'severity', 'info'),
                'steps': ['Initial Access', 'Exploitation', 'Privilege Escalation', 'Lateral Movement']
            })
        
        logger.success(f"Generated attack graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
        return graph
