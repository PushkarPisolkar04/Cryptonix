"""PDF report generator"""
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from loguru import logger

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
except ImportError:
    SimpleDocTemplate = None

class PDFReportGenerator:
    def __init__(self, config):
        self.config = config
    
    async def generate(self, data: Dict, output_path) -> Any:
        logger.info(f"Generating PDF report: {output_path}")
        
        if not SimpleDocTemplate:
            logger.warning("reportlab not installed, generating text file instead")
            return await self._generate_text_fallback(data, output_path)
        
        try:
            doc = SimpleDocTemplate(str(output_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title = Paragraph(f"<b>AutoPenTest Security Assessment Report</b>", styles['Title'])
            story.append(title)
            story.append(Spacer(1, 12))
            
            # Summary
            summary_data = [
                ['Target:', data.get('target', 'Unknown')],
                ['Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Total Vulnerabilities:', str(len(data.get('vulnerabilities', [])))]
            ]
            summary_table = Table(summary_data)
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            # Findings
            story.append(Paragraph("<b>Findings</b>", styles['Heading1']))
            story.append(Spacer(1, 12))
            
            for vuln in data.get('vulnerabilities', [])[:20]:  # Limit to 20
                name = getattr(vuln, 'name', 'Unknown')
                severity = getattr(vuln, 'severity', 'info')
                story.append(Paragraph(f"<b>{severity.upper()}:</b> {name}", styles['Heading2']))
                story.append(Spacer(1, 6))
            
            doc.build(story)
            logger.success(f"PDF report generated: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return await self._generate_text_fallback(data, output_path)
    
    async def _generate_text_fallback(self, data: Dict, output_path):
        text_path = str(output_path).replace('.pdf', '.txt')
        content = f"""AutoPenTest Security Assessment Report
Target: {data.get('target', 'Unknown')}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Vulnerabilities: {len(data.get('vulnerabilities', []))}

Findings:
"""
        for vuln in data.get('vulnerabilities', []):
            content += f"\n- {getattr(vuln, 'severity', 'info').upper()}: {getattr(vuln, 'name', 'Unknown')}\n"
        
        Path(text_path).write_text(content, encoding='utf-8')
        return text_path
