"""
Stage 9: Impact Demonstration
Quantify business risk and demonstrate impact
"""

from typing import Dict, Any
from loguru import logger
from stages.base import BaseStage
from modules.impact.data_access_proof import DataAccessProof
from modules.impact.service_disruption import ServiceDisruptionSimulator
from modules.impact.financial_calculator import FinancialImpactCalculator
from modules.impact.compliance_mapper import ComplianceMapper


class ImpactDemonstrationStage(BaseStage):
    
    @property
    def name(self) -> str:
        return "Impact Demonstration"
    
    @property
    def description(self) -> str:
        return "Prove business risk: data access, service disruption, financial impact"
    
    async def run(self) -> Dict[str, Any]:
        # Gather all previous data
        post_exploit_data = self.get_previous_stage_data('post_exploit')
        lateral_data = self.get_previous_stage_data('lateral_movement')
        vuln_data = self.get_previous_stage_data('vuln_scan')
        
        compromised_hosts = post_exploit_data.get('compromised_hosts', [])
        credentials = post_exploit_data.get('credentials', [])
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        
        logger.info("📊 Calculating business impact...")
        
        # Demonstrate data access
        data_proof = DataAccessProof(self.config)
        data_access = await data_proof.demonstrate(compromised_hosts)
        
        # Calculate financial impact
        fin_calc = FinancialImpactCalculator(self.config)
        financial_impact = await fin_calc.calculate(
            compromised_hosts=len(compromised_hosts),
            credentials_exposed=len(credentials),
            vulnerabilities=vulnerabilities
        )
        
        # Map to compliance frameworks
        compliance = ComplianceMapper(self.config)
        compliance_violations = await compliance.map_violations(vulnerabilities)
        
        results = {
            'data_access_proof': data_access,
            'financial_impact': financial_impact,
            'compliance_violations': compliance_violations,
            'executive_summary': self._generate_exec_summary(
                financial_impact,
                len(compromised_hosts),
                len(vulnerabilities)
            )
        }
        
        logger.success(f"💰 Estimated financial impact: ${financial_impact.get('total_cost', 0):,.2f}")
        
        return results
    
    def _generate_exec_summary(self, financial, hosts, vulns):
        return {
            'total_cost': financial.get('total_cost', 0),
            'hosts_compromised': hosts,
            'critical_vulnerabilities': vulns,
            'risk_level': 'CRITICAL' if hosts > 0 else 'HIGH'
        }
