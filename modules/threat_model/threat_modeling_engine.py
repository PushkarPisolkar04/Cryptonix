"""
Threat Modeling & Attack Path Analysis
Stage 4: The "brain" stage - generates attack graphs and risk scoring
"""

import json
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum

from loguru import logger


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Vulnerability:
    """Vulnerability representation"""
    id: str
    name: str
    severity: RiskLevel
    cvss_score: float
    type: str  # sql_injection, rce, auth_bypass, etc.
    affected_asset: str
    remediable: bool


@dataclass
class AttackPath:
    """Attack path from initial access to goal"""
    id: str
    name: str
    steps: List[str]
    required_vulns: List[str]
    success_likelihood: float  # 0-1
    impact: int  # 1-10
    entry_point: str
    goal: str
    privilege_escalation_required: bool


@dataclass
class ThreatModel:
    """Complete threat model"""
    timestamp: str
    target: str
    vulnerabilities: List[Vulnerability]
    attack_paths: List[AttackPath]
    risk_score: float
    privilege_escalation_opportunities: int
    lateral_movement_opportunities: int
    data_exfiltration_opportunities: int


class AttackGraphBuilder:
    """Builds attack graphs from vulnerabilities"""

    def __init__(self, config: Dict):
        self.config = config
        self.vulns: List[Vulnerability] = []
        self.assets: Dict[str, Dict] = {}  # Asset inventory

    def add_vulnerability(self, vuln: Vulnerability):
        """Add a vulnerability to the graph"""
        self.vulns.append(vuln)

    def add_asset(self, asset_id: str, asset_type: str, criticality: int):
        """Add an asset (server, database, etc.)"""
        self.assets[asset_id] = {
            'type': asset_type,
            'criticality': criticality,  # 1-5
            'vulns': []
        }

    def link_vuln_to_asset(self, vuln_id: str, asset_id: str):
        """Link vulnerability to asset"""
        if asset_id in self.assets:
            self.assets[asset_id]['vulns'].append(vuln_id)

    def build_attack_paths(self) -> List[AttackPath]:
        """Generate attack paths from vulnerabilities"""
        logger.info("Building attack paths from vulnerability graph")
        paths = []

        # Path 1: External RCE to full compromise
        if self._has_vuln_type('rce'):
            paths.append(AttackPath(
                id='path_001',
                name='Remote Code Execution → System Compromise',
                steps=[
                    'Identify web service with RCE vulnerability',
                    'Execute commands on target system',
                    'Establish persistent shell',
                    'Escalate privileges',
                    'Move laterally'
                ],
                required_vulns=['rce'],
                success_likelihood=0.85,
                impact=10,
                entry_point='web_service',
                goal='full_system_compromise',
                privilege_escalation_required=True
            ))

        # Path 2: SQL Injection → Data Theft
        if self._has_vuln_type('sql_injection'):
            paths.append(AttackPath(
                id='path_002',
                name='SQL Injection → Database Access → Data Theft',
                steps=[
                    'Identify web form with SQL injection',
                    'Extract database contents',
                    'Pivot to database server',
                    'Access sensitive data'
                ],
                required_vulns=['sql_injection'],
                success_likelihood=0.80,
                impact=8,
                entry_point='web_form',
                goal='data_exfiltration',
                privilege_escalation_required=False
            ))

        # Path 3: Auth Bypass → Account Takeover
        if self._has_vuln_type('auth_bypass'):
            paths.append(AttackPath(
                id='path_003',
                name='Authentication Bypass → Account Takeover',
                steps=[
                    'Identify authentication mechanism',
                    'Bypass authentication controls',
                    'Gain admin/privileged access',
                    'Modify data, create backdoors'
                ],
                required_vulns=['auth_bypass'],
                success_likelihood=0.75,
                impact=9,
                entry_point='login_form',
                goal='privilege_escalation',
                privilege_escalation_required=False
            ))

        # Path 4: Privilege Escalation → Domain Admin
        if self._has_vuln_type('privesc'):
            paths.append(AttackPath(
                id='path_004',
                name='Privilege Escalation → Domain Admin → Full Network Control',
                steps=[
                    'Gain low-privilege access',
                    'Identify privilege escalation vector',
                    'Elevate to admin/root',
                    'Compromise domain controller',
                    'Control entire network'
                ],
                required_vulns=['privesc'],
                success_likelihood=0.70,
                impact=10,
                entry_point='user_account',
                goal='domain_compromise',
                privilege_escalation_required=True
            ))

        # Path 5: Configuration Weakness → Lateral Movement
        if self._has_vuln_type('misconfiguration'):
            paths.append(AttackPath(
                id='path_005',
                name='Configuration Weakness → Lateral Movement → Network Control',
                steps=[
                    'Identify misconfigured service',
                    'Exploit weak default credentials',
                    'Move to internal network',
                    'Compromise internal services'
                ],
                required_vulns=['misconfiguration'],
                success_likelihood=0.65,
                impact=7,
                entry_point='network_service',
                goal='lateral_movement',
                privilege_escalation_required=False
            ))

        logger.success(f"Generated {len(paths)} attack paths")
        return paths

    def _has_vuln_type(self, vuln_type: str) -> bool:
        """Check if vulnerability type exists"""
        return any(v.type == vuln_type for v in self.vulns)

    def calculate_risk_scores(self, paths: List[AttackPath]) -> Dict[str, float]:
        """Calculate risk scores for each path"""
        scores = {}
        
        for path in paths:
            # Risk = Likelihood * Impact
            likelihood = path.success_likelihood
            impact = path.impact / 10.0
            cvss_component = self._calc_avg_cvss(path.required_vulns)
            
            # Composite score
            score = (likelihood * 0.4) + (impact * 0.4) + (cvss_component * 0.2)
            scores[path.id] = score * 100

        return scores

    def _calc_avg_cvss(self, vuln_ids: List[str]) -> float:
        """Calculate average CVSS score for vulnerabilities"""
        if not vuln_ids:
            return 0.0
        
        scores = [v.cvss_score for v in self.vulns if v.id in vuln_ids]
        return sum(scores) / len(scores) / 10.0 if scores else 0.0

    def find_privilege_escalation_paths(self) -> List[Dict]:
        """Identify privilege escalation chains"""
        logger.info("Analyzing privilege escalation opportunities")
        paths = []

        pe_vulns = [v for v in self.vulns if v.type == 'privesc']

        for vuln in pe_vulns:
            # Windows privilege escalation paths
            windows_paths = [
                'Unquoted service path',
                'Missing patches',
                'Weak file permissions',
                'Registry misconfiguration',
                'DLL hijacking',
                'Token impersonation',
                'UAC bypass'
            ]

            # Linux privilege escalation paths
            linux_paths = [
                'SUID binaries',
                'Kernel exploits',
                'Sudo misconfigurations',
                'Weak file permissions',
                'Cron job exploits',
                'Library injection'
            ]

            paths.extend([{
                'type': 'windows',
                'vulnerability': vuln.name,
                'methods': windows_paths,
                'severity': vuln.severity.name,
                'likelihood': self._estimate_likelihood(vuln)
            }])

        logger.success(f"Found {len(paths)} privilege escalation opportunities")
        return paths

    def find_lateral_movement_opportunities(self) -> List[Dict]:
        """Identify lateral movement opportunities"""
        logger.info("Analyzing lateral movement opportunities")
        opportunities = []

        # From current compromised asset, identify lateral movement vectors
        for asset_id, asset_info in self.assets.items():
            if asset_info['criticality'] > 2:  # Focus on important assets
                opportunity = {
                    'from_asset': asset_id,
                    'asset_type': asset_info['type'],
                    'vectors': [
                        'Pass-the-hash attacks',
                        'Kerberos ticket forgery',
                        'SMB relay attacks',
                        'DNS spoofing',
                        'ARP poisoning',
                        'MITM attacks',
                        'Credential harvesting'
                    ],
                    'target_assets': self._find_adjacent_assets(asset_id),
                    'ease_of_exploitation': 'medium'
                }
                opportunities.append(opportunity)

        logger.success(f"Found {len(opportunities)} lateral movement opportunities")
        return opportunities

    def _find_adjacent_assets(self, asset_id: str) -> List[str]:
        """Find adjacent/reachable assets"""
        # In a real scenario, this would traverse network topology
        return [a for a in self.assets.keys() if a != asset_id][:3]

    def _estimate_likelihood(self, vuln: Vulnerability) -> float:
        """Estimate exploitation likelihood"""
        # Based on CVSS and asset exposure
        base_likelihood = min(vuln.cvss_score / 10.0, 1.0)
        
        # Adjust based on asset criticality if linked
        for asset in self.assets.values():
            if vuln.id in asset['vulns']:
                base_likelihood *= (asset['criticality'] / 5.0)
        
        return min(base_likelihood, 1.0)


class ThreatModelingEngine:
    """Main threat modeling engine"""

    def __init__(self, config: Dict):
        self.config = config
        self.graph_builder = AttackGraphBuilder(config)

    async def generate_threat_model(
        self,
        target: str,
        vulnerabilities: List[Dict],
        assets: List[Dict]
    ) -> ThreatModel:
        """Generate complete threat model"""
        logger.info(f"Generating threat model for {target}")

        # Convert input vulns to Vulnerability objects
        vuln_objects = self._parse_vulnerabilities(vulnerabilities)
        for vuln in vuln_objects:
            self.graph_builder.add_vulnerability(vuln)

        # Add assets
        for asset in assets:
            self.graph_builder.add_asset(
                asset['id'],
                asset['type'],
                asset['criticality']
            )

        # Build attack paths
        attack_paths = self.graph_builder.build_attack_paths()

        # Calculate risk scores
        risk_scores = self.graph_builder.calculate_risk_scores(attack_paths)
        overall_risk = sum(risk_scores.values()) / len(risk_scores) if risk_scores else 0

        # Find privilege escalation paths
        pe_opportunities = self.graph_builder.find_privilege_escalation_paths()
        pe_count = len(pe_opportunities)

        # Find lateral movement opportunities
        lm_opportunities = self.graph_builder.find_lateral_movement_opportunities()
        lm_count = len(lm_opportunities)

        # Data exfiltration opportunities (assets with sensitive data + data access vuln)
        de_count = self._count_data_exfil_opportunities(vuln_objects, assets)

        threat_model = ThreatModel(
            timestamp=datetime.now().isoformat(),
            target=target,
            vulnerabilities=vuln_objects,
            attack_paths=attack_paths,
            risk_score=overall_risk,
            privilege_escalation_opportunities=pe_count,
            lateral_movement_opportunities=lm_count,
            data_exfiltration_opportunities=de_count
        )

        logger.success(f"Threat model generated. Overall risk score: {overall_risk:.2f}/100")
        return threat_model

    def _parse_vulnerabilities(self, vuln_data: List[Dict]) -> List[Vulnerability]:
        """Convert vulnerability data to Vulnerability objects"""
        vulns = []

        type_mapping = {
            'rce': 'Remote Code Execution',
            'sql_injection': 'SQL Injection',
            'xss': 'Cross-Site Scripting',
            'auth_bypass': 'Authentication Bypass',
            'privesc': 'Privilege Escalation',
            'misconfiguration': 'Misconfiguration',
            'weak_crypto': 'Weak Cryptography',
        }

        for vuln_dict in vuln_data:
            vuln_type = vuln_dict.get('type', 'unknown')
            severity = RiskLevel[vuln_dict.get('severity', 'MEDIUM')]

            vuln = Vulnerability(
                id=vuln_dict.get('id', f"vuln_{len(vulns)}"),
                name=type_mapping.get(vuln_type, vuln_dict.get('name', 'Unknown')),
                severity=severity,
                cvss_score=vuln_dict.get('cvss_score', 5.0),
                type=vuln_type,
                affected_asset=vuln_dict.get('asset', 'unknown'),
                remediable=not vuln_dict.get('zero_day', False)
            )
            vulns.append(vuln)

        return vulns

    def _count_data_exfil_opportunities(self, vulns: List[Vulnerability], assets: List[Dict]) -> int:
        """Count data exfiltration opportunities"""
        count = 0
        data_access_vulns = {v.id for v in vulns if v.type in ['sql_injection', 'auth_bypass']}
        
        for asset in assets:
            if asset.get('contains_sensitive_data', False):
                if asset.get('id') in [v.affected_asset for v in vulns]:
                    count += 1

        return count

    def save_threat_model(self, model: ThreatModel, output_path: str):
        """Save threat model to file"""
        output_file = Path(output_path) / f"threat_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Prepare data for JSON serialization
        data = {
            'timestamp': model.timestamp,
            'target': model.target,
            'vulnerabilities': [
                {
                    'id': v.id,
                    'name': v.name,
                    'severity': v.severity.name,
                    'cvss_score': v.cvss_score,
                    'type': v.type,
                    'affected_asset': v.affected_asset,
                    'remediable': v.remediable
                }
                for v in model.vulnerabilities
            ],
            'attack_paths': [
                {
                    'id': p.id,
                    'name': p.name,
                    'steps': p.steps,
                    'required_vulns': p.required_vulns,
                    'success_likelihood': p.success_likelihood,
                    'impact': p.impact,
                    'entry_point': p.entry_point,
                    'goal': p.goal,
                    'privilege_escalation_required': p.privilege_escalation_required
                }
                for p in model.attack_paths
            ],
            'risk_score': model.risk_score,
            'privilege_escalation_opportunities': model.privilege_escalation_opportunities,
            'lateral_movement_opportunities': model.lateral_movement_opportunities,
            'data_exfiltration_opportunities': model.data_exfiltration_opportunities
        }

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        logger.success(f"Threat model saved to {output_file}")
        return output_file

    def generate_attack_graph_visualization(self, model: ThreatModel) -> str:
        """Generate GraphViz representation of attack graph"""
        logger.info("Generating attack graph visualization")
        
        dot_graph = "digraph AttackGraph {\n"
        dot_graph += '  rankdir=LR;\n'
        dot_graph += '  node [shape=box];\n\n'

        # Add nodes for entry points
        entry_points = set(p.entry_point for p in model.attack_paths)
        for ep in entry_points:
            dot_graph += f'  "{ep}" [shape=ellipse, color=red, label="{ep}"];\n'

        # Add nodes for goals
        goals = set(p.goal for p in model.attack_paths)
        for goal in goals:
            dot_graph += f'  "{goal}" [shape=ellipse, color=darkred, label="{goal}"];\n'

        # Add edges for paths
        for path in model.attack_paths:
            dot_graph += f'  "{path.entry_point}" -> "{path.goal}" [label="{path.name}"];\n'

        dot_graph += "}\n"
        return dot_graph
