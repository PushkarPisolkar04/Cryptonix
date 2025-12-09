"""Risk scoring engine"""
import asyncio
from typing import Dict, Any, List
from loguru import logger

class RiskScorer:
    def __init__(self, config):
        self.config = config
    
    async def analyze(self, vulnerabilities: List, hosts: List) -> Dict[str, Any]:
        logger.info(f"Analyzing risk for {len(vulnerabilities)} vulnerabilities")
        
        risk_analysis = {
            'overall_risk': 'medium',
            'risk_score': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'top_risks': []
        }
        
        for vuln in vulnerabilities:
            severity = getattr(vuln, 'severity', 'info').lower()
            cvss = getattr(vuln, 'cvss_score', 0)
            
            if severity == 'critical':
                risk_analysis['critical_count'] += 1
                risk_analysis['risk_score'] += 10
            elif severity == 'high':
                risk_analysis['high_count'] += 1
                risk_analysis['risk_score'] += 7
            elif severity == 'medium':
                risk_analysis['medium_count'] += 1
                risk_analysis['risk_score'] += 4
            elif severity == 'low':
                risk_analysis['low_count'] += 1
                risk_analysis['risk_score'] += 1
        
        # Determine overall risk
        if risk_analysis['critical_count'] > 0:
            risk_analysis['overall_risk'] = 'critical'
        elif risk_analysis['high_count'] > 5:
            risk_analysis['overall_risk'] = 'high'
        elif risk_analysis['high_count'] > 0:
            risk_analysis['overall_risk'] = 'medium'
        else:
            risk_analysis['overall_risk'] = 'low'
        
        # Top risks
        sorted_vulns = sorted(vulnerabilities, key=lambda v: getattr(v, 'cvss_score', 0), reverse=True)
        for vuln in sorted_vulns[:10]:
            risk_analysis['top_risks'].append({
                'name': getattr(vuln, 'name', 'Unknown'),
                'severity': getattr(vuln, 'severity', 'info'),
                'cvss': getattr(vuln, 'cvss_score', 0)
            })
        
        logger.success(f"Risk analysis complete: {risk_analysis['overall_risk']} risk")
        return risk_analysis
