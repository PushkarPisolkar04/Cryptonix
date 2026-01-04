"""HTML report generator"""
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from loguru import logger

try:
    from jinja2 import Template
except ImportError:
    Template = None

class HTMLReportGenerator:
    def __init__(self, config):
        self.config = config
    
    async def generate(self, data: Dict, output_path) -> Any:
        logger.info(f"Generating HTML report: {output_path}")
        
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Security Assessment Report - {{ data.target }}</title>
    <style>
        :root {
            --critical: #d32f2f;
            --high: #f57c00;
            --medium: #fbc02d;
            --low: #388e3c;
            --info: #616161;
            --primary: #1976d2;
            --secondary: #303f9f;
            --light: #f5f5f5;
            --dark: #212121;
            --white: #ffffff;
            --gray: #eeeeee;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: var(--light);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--white);
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
            min-height: 100vh;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: var(--white);
            padding: 2rem;
            text-align: center;
        }
        
        h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .content {
            padding: 2rem;
        }
        
        .summary-card {
            background: linear-gradient(135deg, #e3f2fd, #bbdefb);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .summary-item {
            background: rgba(255, 255, 255, 0.7);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }
        
        .summary-number {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary);
        }
        
        .summary-label {
            font-size: 0.9rem;
            color: var(--secondary);
        }
        
        h2 {
            color: var(--primary);
            margin: 2rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--primary);
        }
        
        .severity-filter {
            margin: 1rem 0;
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .filter-btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .filter-btn.active {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }
        
        .critical-btn { background: var(--critical); color: white; }
        .high-btn { background: var(--high); color: white; }
        .medium-btn { background: var(--medium); color: black; }
        .low-btn { background: var(--low); color: white; }
        .all-btn { background: var(--primary); color: white; }
        
        .vuln-card {
            background: var(--white);
            border-radius: 10px;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .vuln-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.15);
        }
        
        .vuln-header {
            padding: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #eee;
        }
        
        .vuln-title {
            font-size: 1.3rem;
            font-weight: 600;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9rem;
        }
        
        .critical { background: var(--critical); color: white; }
        .high { background: var(--high); color: white; }
        .medium { background: var(--medium); color: black; }
        .low { background: var(--low); color: white; }
        .info { background: var(--info); color: white; }
        
        .cvss-score {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-weight: bold;
            margin-left: 0.5rem;
            background: #666;
            color: white;
        }
        
        .vuln-body {
            padding: 1.5rem;
        }
        
        .vuln-section {
            margin-bottom: 1.5rem;
        }
        
        .section-title {
            font-weight: 600;
            color: var(--secondary);
            margin-bottom: 0.5rem;
            font-size: 1.1rem;
        }
        
        .section-content {
            padding-left: 1rem;
            line-height: 1.7;
        }
        
        .impact-list {
            list-style-type: disc;
            padding-left: 1.5rem;
        }
        
        .impact-list li {
            margin: 0.5rem 0;
        }
        
        code {
            background: #f5f5f5;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
        }
        
        pre {
            background: #f5f5f5;
            padding: 1rem;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin: 1rem 0;
        }
        
        .evidence-snippet {
            font-size: 0.85rem;
            color: #666;
            background: #fafafa;
            padding: 0.8rem;
            border-left: 3px solid var(--primary);
            margin: 0.5rem 0;
        }
        
        footer {
            background: var(--dark);
            color: var(--white);
            text-align: center;
            padding: 2rem;
            margin-top: 2rem;
        }
        
        .footer-content {
            max-width: 800px;
            margin: 0 auto;
        }
        
        .disclaimer {
            font-size: 0.9rem;
            opacity: 0.8;
            margin-top: 1rem;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 0;
            }
            
            header {
                padding: 1rem;
            }
            
            h1 {
                font-size: 1.8rem;
            }
            
            .content {
                padding: 1rem;
            }
            
            .vuln-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Professional Security Assessment Report</h1>
            <div class="subtitle">Comprehensive Vulnerability Analysis and Remediation Guidance</div>
        </header>
        
        <div class="content">
            <div class="summary-card">
                <h2>Executive Summary</h2>
                <p>This security assessment identifies vulnerabilities and provides actionable recommendations to strengthen your security posture.</p>
                
                <div class="summary-grid">
                    <div class="summary-item">
                        <div class="summary-number">{{ data.vulnerabilities|length }}</div>
                        <div class="summary-label">Total Issues</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{{ data.get('critical_vulns', 0) }}</div>
                        <div class="summary-label">Critical</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{{ data.get('high_vulns', 0) }}</div>
                        <div class="summary-label">High</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{{ data.get('medium_vulns', 0) }}</div>
                        <div class="summary-label">Medium</div>
                    </div>
                    <div class="summary-item">
                        <div class="summary-number">{{ data.get('low_vulns', 0) }}</div>
                        <div class="summary-label">Low</div>
                    </div>
                </div>
                
                <p><strong>Target:</strong> {{ data.target }}</p>
                <p><strong>Assessment Date:</strong> {{ timestamp }}</p>
            </div>
            
            <div class="severity-filter">
                <button class="filter-btn all-btn active" onclick="filterVulnerabilities('all')">All Vulnerabilities</button>
                <button class="filter-btn critical-btn" onclick="filterVulnerabilities('critical')">Critical</button>
                <button class="filter-btn high-btn" onclick="filterVulnerabilities('high')">High</button>
                <button class="filter-btn medium-btn" onclick="filterVulnerabilities('medium')">Medium</button>
                <button class="filter-btn low-btn" onclick="filterVulnerabilities('low')">Low</button>
            </div>
            
            <h2>Detailed Findings</h2>
            
            {% for vuln in data.vulnerabilities %}
            <div class="vuln-card" data-severity="{{ vuln.severity }}">
                <div class="vuln-header">
                    <div class="vuln-title">{{ vuln.name }}</div>
                    <div>
                        <span class="severity-badge {{ vuln.severity }}">{{ vuln.severity|upper }}</span>
                        {% if vuln.cvss_score %}
                            <span class="cvss-score">CVSS: {{ vuln.cvss_score }}</span>
                        {% endif %}
                    </div>
                </div>
                
                <div class="vuln-body">
                    <div class="vuln-section">
                        <div class="section-title">Description</div>
                        <div class="section-content">
                            <p>{{ vuln.description }}</p>
                        </div>
                    </div>
                    
                    {% if vuln.cve_id %}
                    <div class="vuln-section">
                        <div class="section-title">CVE/CWE ID</div>
                        <div class="section-content">
                            <p>{{ vuln.cve_id }}</p>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.url %}
                    <div class="vuln-section">
                        <div class="section-title">Affected URL</div>
                        <div class="section-content">
                            <p>{{ vuln.url }}</p>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.affected_application %}
                    <div class="vuln-section">
                        <div class="section-title">Affected Application</div>
                        <div class="section-content">
                            <p>{{ vuln.affected_application }}</p>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.affected_endpoint %}
                    <div class="vuln-section">
                        <div class="section-title">Affected Endpoint</div>
                        <div class="section-content">
                            <p>{{ vuln.affected_endpoint }}</p>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.owasp_category %}
                    <div class="vuln-section">
                        <div class="section-title">OWASP Category</div>
                        <div class="section-content">
                            <p>{{ vuln.owasp_category }}</p>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.technical_impact %}
                    <div class="vuln-section">
                        <div class="section-title">Technical Impact</div>
                        <div class="section-content">
                            <ul class="impact-list">
                            {% if vuln.technical_impact is iterable %}
                                {% for impact in vuln.technical_impact %}
                                    <li>{{ impact }}</li>
                                {% endfor %}
                            {% else %}
                                <li>{{ vuln.technical_impact }}</li>
                            {% endif %}
                            </ul>
                        </div>
                    </div>
                    {% endif %}
                    
                    {% if vuln.payload %}
                    <div class="vuln-section">
                        <div class="section-title">Proof of Concept</div>
                        <div class="section-content">
                            <code>{{ vuln.payload }}</code>
                        </div>
                    </div>
                    {% endif %}
                    
                    <div class="vuln-section">
                        <div class="section-title">Remediation</div>
                        <div class="section-content">
                            <p>{{ vuln.solution }}</p>
                        </div>
                    </div>
                    
                    {% if vuln.evidence %}
                    <div class="vuln-section">
                        <div class="section-title">Evidence</div>
                        <div class="section-content">
                            <div class="evidence-snippet">{{ vuln.evidence[:500] }}{% if vuln.evidence|length > 500 %}...{% endif %}</div>
                        </div>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>
        
        <footer>
            <div class="footer-content">
                <p>Generated by Professional Security Assessment Framework</p>
                <p class="disclaimer">⚠️ This report contains sensitive security information. Handle with care and share only with authorized personnel.</p>
                <p>Report generated on {{ timestamp }}</p>
            </div>
        </footer>
    </div>
    
    <script>
        function filterVulnerabilities(severity) {
            // Update active button
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Filter vulnerabilities
            const cards = document.querySelectorAll('.vuln-card');
            cards.forEach(card => {
                if (severity === 'all' || card.dataset.severity === severity) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
        """
        
        try:
            if Template:
                template = Template(html_template)
                html = template.render(data=data, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            else:
                html = html_template.replace('{{ data.target }}', str(data.get('target', 'Unknown')))
            
            Path(output_path).write_text(html, encoding='utf-8')
            logger.success(f"HTML report generated: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"HTML generation failed: {e}")
            return None
    
    async def generate_from_result(self, assessment_result, output_path):
        data = {
            'target': assessment_result.target,
            'vulnerabilities': assessment_result.vulnerabilities
        }
        return await self.generate(data, output_path)
