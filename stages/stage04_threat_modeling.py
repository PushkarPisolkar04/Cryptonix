"""
Stage 4: Threat Modeling & Attack Path Analysis
Analyze vulnerabilities and create attack graphs
"""

from typing import Dict, Any
from loguru import logger
from stages.base import BaseStage
from modules.threat_model.attack_graph import AttackGraphGenerator
from modules.threat_model.risk_scorer import RiskScorer
from modules.threat_model.path_finder import AttackPathFinder


class ThreatModelingStage(BaseStage):
    
    @property
    def name(self) -> str:
        return "Threat Modeling & Attack Path Analysis"
    
    @property
    def description(self) -> str:
        return "Generate attack graphs, calculate risk scores, identify attack paths"
    
    async def run(self) -> Dict[str, Any]:
        vuln_data = self.get_previous_stage_data('vuln_scan')
        discovery_data = self.get_previous_stage_data('discovery')
        
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        hosts = discovery_data.get('hosts', [])
        
        logger.info(f"🧠 Analyzing {len(vulnerabilities)} vulnerabilities across {len(hosts)} hosts")
        
        # Generate attack graph
        graph_gen = AttackGraphGenerator(self.config)
        attack_graph = await graph_gen.generate(hosts, vulnerabilities)
        
        # Calculate risk scores
        risk_scorer = RiskScorer(self.config)
        risk_analysis = await risk_scorer.analyze(vulnerabilities, hosts)
        
        # Find attack paths
        path_finder = AttackPathFinder(self.config)
        attack_paths = await path_finder.find_paths(attack_graph)
        
        results = {
            'attack_graph': attack_graph,
            'risk_analysis': risk_analysis,
            'attack_paths': attack_paths,
            'prioritized_targets': self._prioritize_targets(attack_paths, risk_analysis)
        }
        
        logger.success(f"✅ Identified {len(attack_paths)} potential attack paths")
        
        return results
    
    def _prioritize_targets(self, paths, risk_analysis):
        """Prioritize targets based on exploitability and impact"""
        targets = []
        for path in paths:
            score = path.get('exploitability', 0) * path.get('impact', 0)
            targets.append({
                'path': path,
                'priority_score': score
            })
        return sorted(targets, key=lambda x: x['priority_score'], reverse=True)
