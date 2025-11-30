"""
PDF reporting for VulnWebScanner -- Executive Summary

Features:
- CVSS and severity summary tables
- Detailed findings per module/category
- Date/time, scan metadata
- Professional layout, ready for client delivery
"""
from typing import List, Dict
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
import os
from datetime import datetime
class PDFReportGenerator:
    def generate(self, scan_metadata: Dict, findings: List[Dict], output_path: str = None) -> str:
        path = output_path or f"report_{scan_metadata.get('id', 'scan')}.pdf"
        doc = SimpleDocTemplate(path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = [Paragraph(f'<b>Vulnerability Scan Report</b> - {scan_metadata.get("target")}', styles['Title'])]
        story.append(Paragraph(f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', styles['Normal']))
        story.append(Spacer(1,16))
        # Summary Table
        summary_data = [['Severity','Count']]
        severities = ['critical','high','medium','low','info']
        s_counts = {s:0 for s in severities}
        for f in findings:
            sev = f.get('severity','info').lower()
            if sev in s_counts: s_counts[sev] +=1
        for s in severities:
            summary_data.append([s.title(), s_counts[s]])
        summary_table = Table(summary_data, hAlign='LEFT')
        summary_table.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
        ]))
        story.append(Paragraph('<b>Severity Overview</b>', styles['Heading2']))
        story.append(summary_table)
        story.append(Spacer(1,12))
        # Detailed findings table
        table_data = [['Type','Severity','Category','URL','Evidence','Remediation','CVSS']]
        for f in findings:
            table_data.append([
                f.get('type',''), f.get('severity',''), f.get('category',''),
                f.get('url',''), f.get('evidence',''), f.get('remediation',''), f.get('cvss_score','')
            ])
        findings_table = Table(table_data, hAlign='LEFT', repeatRows=1)
        findings_table.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.darkred),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),10),
            ('ROWBACKGROUNDS',(1,0),(-1,-1),[colors.whitesmoke,colors.lightgrey]),
            ('LINEBELOW', (0,0), (-1,0), 2, colors.darkred),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
        ]))
        story.append(Paragraph('<b>Detailed Findings</b>', styles['Heading2']))
        story.append(findings_table)
        story.append(Spacer(1,14))
        # Scan metadata
        story.append(Paragraph('<b>Scan Metadata</b>', styles['Heading2']))
        meta = ''
        for k,v in scan_metadata.items():
            meta += f'{k}: {v}\n'
        story.append(Paragraph(meta, styles['Code']))
        doc.build(story)
        return path
