"""Report Generator - Creates HTML, JSON, and PDF reports"""

import logging
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates scan reports in various formats"""
    
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.template_dir = Path(__file__).parent / "templates"
        
        # Setup Jinja2 environment
        if self.template_dir.exists():
            self.jinja_env = Environment(
                loader=FileSystemLoader(str(self.template_dir)),
                autoescape=select_autoescape(['html', 'xml'])
            )
        else:
            self.jinja_env = None
            logger.warning(f"Template directory not found: {self.template_dir}")
    
    async def generate(self, results: Dict[str, Any], target_name: str, format: str = "html") -> str:
        """Generate report in specified format"""
        if format == "json":
            return self._generate_json(results, target_name)
        elif format == "html":
            return self._generate_html(results, target_name)
        elif format == "pdf":
            return self._generate_pdf(results, target_name)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, results: Dict[str, Any], target_name: str) -> str:
        """Generate JSON report"""
        output_file = self.output_dir / target_name / "report.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        return str(output_file)
    
    def _generate_html(self, results: Dict[str, Any], target_name: str) -> str:
        """Generate HTML report"""
        output_file = self.output_dir / target_name / "report.html"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Simple HTML template if no Jinja2 template exists
        html_content = self._create_simple_html(results, target_name)
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        return str(output_file)
    
    def _create_simple_html(self, results: Dict[str, Any], target_name: str) -> str:
        """Create simple HTML report"""
        target_url = results.get("target", {}).get("url", "Unknown")
        scan_time = results.get("start_time", "Unknown")
        
        # Count vulnerabilities
        vuln_count = 0
        for module_results in results.get("modules", {}).values():
            for module_data in module_results.values():
                if isinstance(module_data, dict) and "vulnerabilities" in module_data:
                    vuln_count += len(module_data["vulnerabilities"])
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {target_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; border-bottom: 2px solid #ddd; padding-bottom: 5px; }}
        .info-box {{ background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .vuln-high {{ background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
        .vuln-medium {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
        .vuln-low {{ background: #f1f8e9; border-left: 4px solid #8bc34a; padding: 10px; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th {{ background: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        .stat {{ display: inline-block; background: #e3f2fd; padding: 10px 20px; margin: 5px; border-radius: 5px; }}
        .footer {{ margin-top: 30px; text-align: center; color: #777; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 VulnWebScanner Report</h1>
        
        <div class="info-box">
            <strong>Target:</strong> {target_url}<br>
            <strong>Scan Time:</strong> {scan_time}<br>
            <strong>Target Name:</strong> {target_name}
        </div>
        
        <h2>📊 Summary</h2>
        <div class="stat"><strong>Vulnerabilities Found:</strong> {vuln_count}</div>
        
        <h2>📁 Output Files</h2>
        <ul>
            <li><strong>URLs:</strong> urls.txt</li>
            <li><strong>Endpoints:</strong> endpoints.json</li>
            <li><strong>Parameters:</strong> parameters.json</li>
            <li><strong>Vulnerabilities:</strong> vulnerabilities.json / vulnerabilities.csv</li>
            <li><strong>Summary:</strong> summary.json / summary.txt</li>
        </ul>
        
        <h2>🔍 Scan Results</h2>
        <p>Detailed results have been saved to individual files in the output directory.</p>
        <p>Check <code>summary.txt</code> for a complete overview of discovered assets and vulnerabilities.</p>
        
        <div class="footer">
            <p>Generated by VulnWebScanner v2.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _generate_pdf(self, results: Dict[str, Any], target_name: str) -> str:
        """Generate PDF report"""
        # Generate HTML first
        html_file = self._generate_html(results, target_name)
        
        # Convert to PDF (requires weasyprint)
        try:
            from weasyprint import HTML
            pdf_file = self.output_dir / target_name / "report.pdf"
            HTML(html_file).write_pdf(pdf_file)
            return str(pdf_file)
        except ImportError:
            logger.warning("WeasyPrint not installed, skipping PDF generation")
            return html_file
        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")
            return html_file
