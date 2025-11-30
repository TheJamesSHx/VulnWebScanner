"""
JSON reporting for VulnWebScanner -- For CI/CD & Automation

Features:
- Structured, machine-readable export of all findings
- Includes scan metadata, findings, and timestamp
"""
import json
from datetime import datetime
from typing import List, Dict
class JSONReportExporter:
    def generate(self, scan_metadata: Dict, findings: List[Dict], output_path: str = None) -> str:
        report = {
            'scan': scan_metadata,
            'findings': findings,
            'generated': datetime.now().isoformat()
        }
        path = output_path or f"report_{scan_metadata.get('id', 'scan')}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        return path
