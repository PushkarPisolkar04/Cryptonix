"""
Advanced Reporting & Remediation Tracking Module
Stage 10: Multi-format reports, remediation prioritization, compliance mapping, integrations
"""

import json
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum

from loguru import logger


class ReportFormat(Enum):
    """Supported report formats"""
    HTML = 'html'
    PDF = 'pdf'
    JSON = 'json'
    MARKDOWN = 'markdown'
    SARIF = 'sarif'
    EXCEL = 'excel'


@dataclass
class Remediation:
    """Remediation action item"""
    id: str
    title: str
    description: str
    affected_systems: List[str]
    severity: str  # Critical, High, Medium, Low
    effort_hours: int
    estimated_cost: int
    priority: int  # 1-10
    due_date: str
    responsible_team: str
    success_criteria: List[str]


@dataclass
class RemediationPlan:
    """Overall remediation roadmap"""
    total_findings: int
    critical_findings: int
    estimated_total_hours: int
    estimated_total_cost: int
    implementation_weeks: int
    remediation_items: List[Remediation]
    quick_wins: List[Remediation]  # Can be fixed within 1 week


@dataclass
class TestingStrategy:
    """Retest strategy and scheduling"""
    initial_test_date: str
    retest_schedule: List[Dict]  # [{date: '', focus_areas: []}]
    success_criteria: List[str]
    regression_test_plan: str


@dataclass
class ComplianceMapping:
    """Mapping to compliance frameworks"""
    framework: str  # NIST, ISO27001, PCI-DSS, GDPR, HIPAA
    control_id: str
    control_name: str
    violations: List[str]
    required_evidence: List[str]
    remediation_deadline: str


@dataclass
class FindingSummary:
    """Summary of findings for reporting"""
    total_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    unique_issues: int
    remediable_count: int


@dataclass
class ExecutiveReportData:
    """Data for executive report"""
    assessment_date: str
    target: str
    summary: FindingSummary
    key_risks: List[str]
    financial_impact_million: float
    remediation_timeline_weeks: int
    board_approved_scope: bool


class HTMLReportGenerator:
    """Generate HTML reports"""

    async def generate_html(
        self,
        findings: Dict,
        target: str,
        output_path: str
    ) -> str:
        """Generate HTML report"""
        logger.info("Generating HTML report")

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report - {target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #d32f2f; }}
                .critical {{ color: red; font-weight: bold; }}
                .high {{ color: orange; font-weight: bold; }}
                .medium {{ color: #ff9800; }}
                .low {{ color: green; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Security Assessment Report</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Date:</strong> {datetime.now().isoformat()}</p>
            
            <h2>Executive Summary</h2>
            <p>This report details findings from the security assessment.</p>
            
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Remediation</th>
                </tr>
        """

        # Add findings
        for finding in findings.get('vulnerabilities', []):
            severity_class = finding.get('severity', 'low').lower()
            html_content += f"""
                <tr>
                    <td>{finding.get('id', 'N/A')}</td>
                    <td>{finding.get('title', 'N/A')}</td>
                    <td class="{severity_class}">{finding.get('severity', 'N/A')}</td>
                    <td>{finding.get('description', 'N/A')[:100]}...</td>
                    <td>{finding.get('remediation', 'N/A')}</td>
                </tr>
            """

        html_content += """
            </table>
            
            <h2>Remediation Plan</h2>
            <p>See detailed remediation recommendations below.</p>
            
            <footer>
                <p>This report is confidential and intended for authorized personnel only.</p>
            </footer>
        </body>
        </html>
        """

        output_file = Path(output_path) / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            f.write(html_content)

        logger.success(f"HTML report generated: {output_file}")
        return str(output_file)


class PDFReportGenerator:
    """Generate PDF reports"""

    async def generate_pdf(
        self,
        findings: Dict,
        target: str,
        output_path: str
    ) -> str:
        """Generate PDF report"""
        logger.info("Generating PDF report")

        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib import colors
            from datetime import datetime

            output_file = Path(output_path) / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            output_file.parent.mkdir(parents=True, exist_ok=True)

            doc = SimpleDocTemplate(str(output_file), pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()

            # Title
            title = Paragraph(f"Security Assessment Report: {target}", styles['Heading1'])
            elements.append(title)
            elements.append(Spacer(1, 0.3 * inch))

            # Summary
            summary_text = Paragraph(
                f"<b>Assessment Date:</b> {datetime.now().isoformat()}<br/>"
                f"<b>Total Findings:</b> {len(findings.get('vulnerabilities', []))}<br/>",
                styles['Normal']
            )
            elements.append(summary_text)
            elements.append(Spacer(1, 0.2 * inch))

            # Findings table
            findings_data = [['ID', 'Title', 'Severity', 'Remediation']]
            for vuln in findings.get('vulnerabilities', [])[:20]:  # Limit to 20 for brevity
                findings_data.append([
                    vuln.get('id', 'N/A'),
                    vuln.get('title', 'N/A')[:30],
                    vuln.get('severity', 'N/A'),
                    vuln.get('remediation', 'N/A')[:30]
                ])

            findings_table = Table(findings_data)
            findings_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(findings_table)

            # Build PDF
            doc.build(elements)
            logger.success(f"PDF report generated: {output_file}")
            return str(output_file)

        except ImportError:
            logger.warning("ReportLab not installed, skipping PDF generation")
            return None


class SARIFReportGenerator:
    """Generate SARIF format reports for CI/CD integration"""

    async def generate_sarif(
        self,
        findings: Dict,
        target: str,
        output_path: str
    ) -> str:
        """Generate SARIF report"""
        logger.info("Generating SARIF report")

        sarif_output = {
            'version': '2.1.0',
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'Cryptonix',
                        'version': '1.0.0',
                        'informationUri': 'https://github.com/cryptonix/autopent'
                    }
                },
                'results': []
            }]
        }

        # Convert findings to SARIF results
        for vuln in findings.get('vulnerabilities', []):
            severity_map = {
                'Critical': 'error',
                'High': 'error',
                'Medium': 'warning',
                'Low': 'note',
                'Info': 'none'
            }

            result = {
                'ruleId': vuln.get('id', 'unknown'),
                'message': {'text': vuln.get('title', 'Unknown vulnerability')},
                'severity': severity_map.get(vuln.get('severity', 'Medium'), 'warning'),
                'locations': [{
                    'physicalLocation': {
                        'address': {'absolutePath': target}
                    }
                }],
                'properties': {
                    'description': vuln.get('description', ''),
                    'remediation': vuln.get('remediation', '')
                }
            }
            sarif_output['runs'][0]['results'].append(result)

        output_file = Path(output_path) / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(sarif_output, f, indent=2)

        logger.success(f"SARIF report generated: {output_file}")
        return str(output_file)


class RemediationPlanner:
    """Plan remediation activities"""

    async def create_remediation_plan(
        self,
        vulnerabilities: List[Dict],
        resources_available: int = 5
    ) -> RemediationPlan:
        """Create prioritized remediation plan"""
        logger.info("Creating remediation plan")

        remediations = []
        quick_wins = []
        total_hours = 0
        total_cost = 0

        for vuln in sorted(vulnerabilities, key=lambda x: ['Critical', 'High', 'Medium', 'Low'].index(x.get('severity', 'Low'))):
            effort = self._estimate_effort(vuln)
            cost = effort * 200  # $200/hour

            remediation = Remediation(
                id=vuln.get('id', f'rem_{len(remediations)}'),
                title=vuln.get('title', 'Unknown'),
                description=vuln.get('description', ''),
                affected_systems=vuln.get('affected_systems', []),
                severity=vuln.get('severity', 'Medium'),
                effort_hours=effort,
                estimated_cost=cost,
                priority=self._calculate_priority(vuln),
                due_date=self._calculate_due_date(vuln),
                responsible_team=self._assign_team(vuln),
                success_criteria=[
                    f"Vulnerability {vuln.get('id')} no longer detectable",
                    "Change management approval obtained",
                    "User acceptance testing completed"
                ]
            )

            remediations.append(remediation)
            total_hours += effort
            total_cost += cost

            # Quick wins (< 4 hours)
            if effort < 4:
                quick_wins.append(remediation)

        # Calculate implementation weeks
        impl_weeks = max(1, total_hours // (resources_available * 40))

        plan = RemediationPlan(
            total_findings=len(vulnerabilities),
            critical_findings=len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
            estimated_total_hours=total_hours,
            estimated_total_cost=total_cost,
            implementation_weeks=impl_weeks,
            remediation_items=sorted(remediations, key=lambda x: x.priority, reverse=True),
            quick_wins=quick_wins
        )

        logger.success(f"Remediation plan created: {len(remediations)} items, {impl_weeks} weeks estimated")
        return plan

    def _estimate_effort(self, vuln: Dict) -> int:
        """Estimate effort in hours"""
        severity = vuln.get('severity', 'Medium')
        effort_map = {
            'Critical': 16,
            'High': 12,
            'Medium': 8,
            'Low': 4,
            'Info': 2
        }
        return effort_map.get(severity, 8)

    def _calculate_priority(self, vuln: Dict) -> int:
        """Calculate priority (1-10)"""
        severity = vuln.get('severity', 'Medium')
        priority_map = {
            'Critical': 10,
            'High': 8,
            'Medium': 6,
            'Low': 4,
            'Info': 2
        }
        return priority_map.get(severity, 5)

    def _calculate_due_date(self, vuln: Dict) -> str:
        """Calculate remediation due date"""
        from datetime import datetime, timedelta

        severity = vuln.get('severity', 'Medium')
        days_map = {
            'Critical': 7,  # 1 week
            'High': 14,  # 2 weeks
            'Medium': 30,  # 1 month
            'Low': 90,  # 3 months
            'Info': 180  # 6 months
        }

        due_date = datetime.now() + timedelta(days=days_map.get(severity, 30))
        return due_date.isoformat()

    def _assign_team(self, vuln: Dict) -> str:
        """Assign responsible team"""
        if 'web' in vuln.get('description', '').lower():
            return 'Web Security Team'
        elif 'database' in vuln.get('description', '').lower():
            return 'Database Team'
        elif 'network' in vuln.get('description', '').lower():
            return 'Network Team'
        else:
            return 'Infrastructure Team'


class ComplianceReportGenerator:
    """Generate compliance-focused reports"""

    async def map_to_frameworks(
        self,
        vulnerabilities: List[Dict]
    ) -> Dict[str, List[ComplianceMapping]]:
        """Map findings to compliance frameworks"""
        logger.info("Mapping to compliance frameworks")

        frameworks = {
            'NIST': await self._map_nist(vulnerabilities),
            'ISO27001': await self._map_iso27001(vulnerabilities),
            'PCI-DSS': await self._map_pci_dss(vulnerabilities),
            'GDPR': await self._map_gdpr(vulnerabilities),
            'HIPAA': await self._map_hipaa(vulnerabilities)
        }

        logger.success("Compliance mapping complete")
        return frameworks

    async def _map_nist(self, vulns: List[Dict]) -> List[ComplianceMapping]:
        return [
            ComplianceMapping(
                framework='NIST CSF',
                control_id='PR.AC-1',
                control_name='Access Control',
                violations=[v.get('title', '') for v in vulns if 'access' in v.get('description', '').lower()][:3],
                required_evidence=['Access logs', 'User provisioning records'],
                remediation_deadline='30 days'
            )
        ]

    async def _map_iso27001(self, vulns: List[Dict]) -> List[ComplianceMapping]:
        return []

    async def _map_pci_dss(self, vulns: List[Dict]) -> List[ComplianceMapping]:
        return []

    async def _map_gdpr(self, vulns: List[Dict]) -> List[ComplianceMapping]:
        return []

    async def _map_hipaa(self, vulns: List[Dict]) -> List[ComplianceMapping]:
        return []


class ComprehensiveReportGenerator:
    """Main comprehensive report generator"""

    def __init__(self, config: Dict):
        self.config = config
        self.html_gen = HTMLReportGenerator()
        self.pdf_gen = PDFReportGenerator()
        self.sarif_gen = SARIFReportGenerator()
        self.remediation_planner = RemediationPlanner()
        self.compliance_gen = ComplianceReportGenerator()

    async def generate_complete_report(
        self,
        target: str,
        findings: Dict,
        output_path: str,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """Generate all report formats"""
        logger.info(f"Generating comprehensive report for {target}")

        formats = formats or ['html', 'json', 'sarif']
        reports = {}

        try:
            # HTML Report
            if 'html' in formats:
                reports['html'] = await self.html_gen.generate_html(findings, target, output_path)

            # PDF Report
            if 'pdf' in formats:
                reports['pdf'] = await self.pdf_gen.generate_pdf(findings, target, output_path)

            # JSON Report
            if 'json' in formats:
                json_file = Path(output_path) / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                json_file.parent.mkdir(parents=True, exist_ok=True)
                with open(json_file, 'w') as f:
                    json.dump(findings, f, indent=2)
                reports['json'] = str(json_file)

            # SARIF Report
            if 'sarif' in formats:
                reports['sarif'] = await self.sarif_gen.generate_sarif(findings, target, output_path)

            # Remediation Plan
            remediation_plan = await self.remediation_planner.create_remediation_plan(
                findings.get('vulnerabilities', [])
            )

            logger.success(f"Complete report generated in {len(reports)} formats")

        except Exception as e:
            logger.error(f"Report generation failed: {e}")

        return reports

    async def integrate_with_ticketing(
        self,
        remediation_plan: RemediationPlan,
        jira_config: Dict
    ) -> List[str]:
        """Create tickets in Jira for remediation items"""
        logger.info("Integrating with Jira ticketing system")

        # Would create Jira tickets with remediation information
        ticket_ids = []

        try:
            from jira import JIRA

            jira = JIRA(server=jira_config.get('server'), auth=(jira_config.get('username'), jira_config.get('password')))

            for item in remediation_plan.remediation_items:
                ticket = jira.create_issue(
                    project=jira_config.get('project', 'SEC'),
                    issuetype='Task',
                    summary=item.title,
                    description=item.description,
                    assignee=item.responsible_team
                )
                ticket_ids.append(ticket.key)
                logger.success(f"Created ticket: {ticket.key}")

        except Exception as e:
            logger.error(f"Jira integration failed: {e}")

        return ticket_ids

    async def send_slack_notification(
        self,
        findings_summary: FindingSummary,
        slack_config: Dict
    ) -> bool:
        """Send findings summary to Slack"""
        logger.info("Sending Slack notification")

        try:
            from slack_sdk import WebClient

            client = WebClient(token=slack_config.get('bot_token'))

            message = f"""
            🔴 Security Assessment Complete
            Critical: {findings_summary.critical_count}
            High: {findings_summary.high_count}
            Medium: {findings_summary.medium_count}
            Low: {findings_summary.low_count}
            """

            response = client.chat_postMessage(
                channel=slack_config.get('channel', '#security'),
                text=message
            )

            logger.success("Slack notification sent")
            return True

        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False
