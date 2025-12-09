"""
Stage 10: Reporting & Remediation
Generate comprehensive reports in multiple formats
"""

from typing import Dict, Any
from pathlib import Path
from datetime import datetime
from loguru import logger
from stages.base import BaseStage
from modules.reporting.html_generator import HTMLReportGenerator
from modules.reporting.pdf_generator import PDFReportGenerator
from modules.reporting.json_exporter import JSONExporter
from modules.reporting.markdown_generator import MarkdownGenerator


class ReportingStage(BaseStage):
    
    @property
    def name(self) -> str:
        return "Reporting & Remediation"
    
    @property
    def description(self) -> str:
        return "Generate professional reports: HTML, PDF, JSON, Markdown"
    
    async def run(self) -> Dict[str, Any]:
        logger.info("📄 Generating reports...")
        
        # Collect all stage data
        all_data = {
            'osint': self.get_previous_stage_data('osint'),
            'discovery': self.get_previous_stage_data('discovery'),
            'vulnerabilities': self.get_previous_stage_data('vuln_scan'),
            'threat_model': self.get_previous_stage_data('threat_model'),
            'exploitation': self.get_previous_stage_data('exploitation'),
            'post_exploit': self.get_previous_stage_data('post_exploit'),
            'lateral_movement': self.get_previous_stage_data('lateral_movement'),
            'impact': self.get_previous_stage_data('impact_demo')
        }
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_dir = Path('reports') / timestamp
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate multiple formats
        html_gen = HTMLReportGenerator(self.config)
        html_path = await html_gen.generate(all_data, report_dir / 'report.html')
        
        pdf_gen = PDFReportGenerator(self.config)
        pdf_path = await pdf_gen.generate(all_data, report_dir / 'report.pdf')
        
        json_exp = JSONExporter(self.config)
        json_path = await json_exp.export(all_data, report_dir / 'report.json')
        
        md_gen = MarkdownGenerator(self.config)
        md_path = await md_gen.generate(all_data, report_dir / 'report.md')
        
        results = {
            'report_directory': str(report_dir),
            'html_report': str(html_path),
            'pdf_report': str(pdf_path),
            'json_export': str(json_path),
            'markdown_report': str(md_path)
        }
        
        logger.success(f"✅ Reports generated in: {report_dir}")
        
        return results
    
    async def generate_final_report(self, assessment_result) -> Path:
        """Generate the final comprehensive report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = Path('reports') / f'final_report_{timestamp}.html'
        
        html_gen = HTMLReportGenerator(self.config)
        await html_gen.generate_from_result(assessment_result, report_path)
        
        return report_path
