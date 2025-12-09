"""Compliance framework mapper"""
import asyncio
from typing import Dict, Any, List
from loguru import logger

class ComplianceMapper:
    def __init__(self, config):
        self.config = config
    
    async def map_violations(self, vulnerabilities: List) -> Dict[str, Any]:
        logger.info(f"Mapping {len(vulnerabilities)} vulnerabilities to compliance frameworks")
        
        violations = {
            'GDPR': [],
            'PCI-DSS': [],
            'HIPAA': [],
            'SOC2': [],
            'ISO27001': []
        }
        
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'info').lower()
            name = getattr(vuln, 'name', '').lower()
            
            # GDPR violations
            if 'data' in name or 'encryption' in name or severity in ['critical', 'high']:
                violations['GDPR'].append({
                    'article': 'Article 32',
                    'requirement': 'Security of processing',
                    'vulnerability': getattr(vuln, 'name', 'Unknown')
                })
            
            # PCI-DSS violations
            if 'sql' in name or 'xss' in name or 'authentication' in name:
                violations['PCI-DSS'].append({
                    'requirement': 'Requirement 6.5',
                    'description': 'Develop secure applications',
                    'vulnerability': getattr(vuln, 'name', 'Unknown')
                })
            
            # HIPAA violations
            if 'access' in name or 'authentication' in name:
                violations['HIPAA'].append({
                    'standard': '164.312(a)(1)',
                    'description': 'Access Control',
                    'vulnerability': getattr(vuln, 'name', 'Unknown')
                })
        
        total_violations = sum(len(v) for v in violations.values())
        logger.success(f"Compliance mapping complete: {total_violations} violations found")
        return violations
