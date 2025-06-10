"""
Professional compliance report generation service
Generates PDF reports for security compliance frameworks
"""

import io
import json
from datetime import datetime
from typing import Dict, List, Any
import base64

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, white
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class ComplianceReportGenerator:
    """Generate professional compliance reports"""
    
    def __init__(self):
        self.styles = None
        if REPORTLAB_AVAILABLE:
            self._setup_styles()
    
    def _setup_styles(self):
        """Setup custom styles for the report"""
        self.styles = getSampleStyleSheet()
        
        # Custom styles
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#1e293b'),
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=HexColor('#334155'),
            borderWidth=1,
            borderColor=HexColor('#e2e8f0'),
            borderPadding=8,
            backColor=HexColor('#f8fafc')
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=12,
            textColor=HexColor('#475569')
        ))
        
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            leading=14,
            textColor=HexColor('#374151'),
            backColor=HexColor('#f9fafb'),
            borderWidth=1,
            borderColor=HexColor('#d1d5db'),
            borderPadding=12
        ))
    
    def generate_iso27001_report(self, report_data: Dict[str, Any]) -> io.BytesIO:
        """Generate ISO 27001 compliance report"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("ReportLab is required for PDF generation. Install with: pip install reportlab")
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        story = []
        
        # Title page
        story.extend(self._create_title_page(report_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(report_data))
        story.append(PageBreak())
        
        # Asset inventory
        story.extend(self._create_asset_inventory(report_data))
        
        # Vulnerability assessment
        story.extend(self._create_vulnerability_assessment(report_data))
        
        # Risk analysis
        story.extend(self._create_risk_analysis(report_data))
        
        # Technology analysis
        story.extend(self._create_technology_analysis(report_data))
        
        # Compliance assessment
        story.extend(self._create_compliance_assessment(report_data))
        
        # Recommendations
        story.extend(self._create_recommendations(report_data))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _create_title_page(self, data: Dict[str, Any]) -> List:
        """Create report title page"""
        story = []
        
        # Title
        story.append(Paragraph("Security Compliance Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Organization info
        org_name = data.get('organization', {}).get('name', 'Unknown Organization')
        story.append(Paragraph(f"<b>Organization:</b> {org_name}", self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Report details
        generated_at = datetime.fromisoformat(data.get('generated_at', datetime.utcnow().isoformat()))
        story.append(Paragraph(f"<b>Report Date:</b> {generated_at.strftime('%B %d, %Y')}", self.styles['Normal']))
        story.append(Paragraph(f"<b>Framework:</b> ISO 27001:2013", self.styles['Normal']))
        story.append(Paragraph(f"<b>Report Type:</b> Attack Surface Assessment", self.styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Disclaimer
        disclaimer = """
        <b>CONFIDENTIAL</b><br/>
        This report contains confidential security information and should be handled according to 
        your organization's information security policies. Distribution should be limited to 
        authorized personnel only.
        """
        story.append(Paragraph(disclaimer, self.styles['ExecutiveSummary']))
        
        return story
    
    def _create_executive_summary(self, data: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Key metrics
        asset_stats = data.get('asset_stats', {})
        vuln_stats = data.get('vulnerability_stats', {})
        risk_metrics = data.get('risk_metrics', {})
        compliance = data.get('compliance_analysis', {})
        
        summary_text = f"""
        This report presents a comprehensive security assessment of {asset_stats.get('total', 0)} 
        digital assets within the organization's attack surface. The assessment identified 
        {vuln_stats.get('total', 0)} security findings across various severity levels.
        <br/><br/>
        <b>Key Findings:</b><br/>
        • Security Score: {risk_metrics.get('security_score', 'N/A')}/10<br/>
        • ISO 27001 Compliance Score: {compliance.get('overall_score', 'N/A')}%<br/>
        • Critical/High Risk Issues: {risk_metrics.get('critical_high_open', 0)}<br/>
        • Assets at Risk: {risk_metrics.get('assets_at_risk', 0)} ({risk_metrics.get('risk_percentage', 0)}%)<br/>
        <br/>
        <b>Compliance Status:</b> {compliance.get('compliance_level', 'Unknown').title()}
        """
        
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _create_asset_inventory(self, data: Dict[str, Any]) -> List:
        """Create asset inventory section"""
        story = []
        
        story.append(Paragraph("Asset Inventory", self.styles['SectionHeader']))
        
        asset_stats = data.get('asset_stats', {})
        by_type = asset_stats.get('by_type', {})
        
        # Asset summary table
        asset_data = [
            ['Asset Type', 'Count', 'Percentage'],
            ['Domains', str(by_type.get('domains', 0)), f"{(by_type.get('domains', 0) / max(asset_stats.get('total', 1), 1) * 100):.1f}%"],
            ['Subdomains', str(by_type.get('subdomains', 0)), f"{(by_type.get('subdomains', 0) / max(asset_stats.get('total', 1), 1) * 100):.1f}%"],
            ['IP Addresses', str(by_type.get('ip_addresses', 0)), f"{(by_type.get('ip_addresses', 0) / max(asset_stats.get('total', 1), 1) * 100):.1f}%"],
            ['Cloud Resources', str(by_type.get('cloud_resources', 0)), f"{(by_type.get('cloud_resources', 0) / max(asset_stats.get('total', 1), 1) * 100):.1f}%"],
            ['Services', str(by_type.get('services', 0)), f"{(by_type.get('services', 0) / max(asset_stats.get('total', 1), 1) * 100):.1f}%"],
            ['<b>Total</b>', f"<b>{asset_stats.get('total', 0)}</b>", '<b>100.0%</b>']
        ]
        
        asset_table = Table(asset_data, colWidths=[2*inch, 1*inch, 1*inch])
        asset_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, -1), (-1, -1), HexColor('#e2e8f0')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
        ]))
        
        story.append(asset_table)
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _create_vulnerability_assessment(self, data: Dict[str, Any]) -> List:
        """Create vulnerability assessment section"""
        story = []
        
        story.append(Paragraph("Vulnerability Assessment", self.styles['SectionHeader']))
        
        vuln_stats = data.get('vulnerability_stats', {})
        by_severity = vuln_stats.get('by_severity', {})
        
        # Vulnerability summary
        vuln_text = f"""
        A total of {vuln_stats.get('total', 0)} security findings were identified during the assessment.
        {vuln_stats.get('open', 0)} findings remain unresolved and require attention.
        """
        story.append(Paragraph(vuln_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Severity breakdown table
        severity_data = [
            ['Severity Level', 'Count', 'Status', 'Risk Level'],
            ['Critical', str(by_severity.get('critical', 0)), 'Immediate Action Required', 'Very High'],
            ['High', str(by_severity.get('high', 0)), 'Action Required', 'High'],
            ['Medium', str(by_severity.get('medium', 0)), 'Should Fix', 'Medium'],
            ['Low', str(by_severity.get('low', 0)), 'Consider Fixing', 'Low'],
            ['Info', str(by_severity.get('info', 0)), 'Informational', 'Very Low']
        ]
        
        severity_table = Table(severity_data, colWidths=[1.5*inch, 0.8*inch, 1.8*inch, 1*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1')),
            # Color code severity levels
            ('BACKGROUND', (0, 1), (-1, 1), HexColor('#fee2e2')),  # Critical - light red
            ('BACKGROUND', (0, 2), (-1, 2), HexColor('#fef3c7')),  # High - light yellow
            ('BACKGROUND', (0, 3), (-1, 3), HexColor('#fef3c7')),  # Medium - light yellow
            ('BACKGROUND', (0, 4), (-1, 4), HexColor('#ecfdf5')),  # Low - light green
            ('BACKGROUND', (0, 5), (-1, 5), HexColor('#f0f9ff'))   # Info - light blue
        ]))
        
        story.append(severity_table)
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _create_risk_analysis(self, data: Dict[str, Any]) -> List:
        """Create risk analysis section"""
        story = []
        
        story.append(Paragraph("Risk Analysis", self.styles['SectionHeader']))
        
        risk_metrics = data.get('risk_metrics', {})
        
        risk_text = f"""
        <b>Overall Risk Assessment:</b><br/>
        The organization's current security posture presents a risk level that requires attention.
        {risk_metrics.get('assets_at_risk', 0)} assets ({risk_metrics.get('risk_percentage', 0)}%) 
        have identified security vulnerabilities that could be exploited by threat actors.
        <br/><br/>
        <b>Critical Risk Factors:</b><br/>
        • {risk_metrics.get('critical_high_open', 0)} critical/high severity vulnerabilities require immediate attention<br/>
        • Security score of {risk_metrics.get('security_score', 'N/A')}/10 indicates room for improvement<br/>
        • Risk exposure affects {risk_metrics.get('risk_percentage', 0)}% of the digital asset portfolio
        """
        
        story.append(Paragraph(risk_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _create_technology_analysis(self, data: Dict[str, Any]) -> List:
        """Create technology analysis section"""
        story = []
        
        story.append(Paragraph("Technology Stack Analysis", self.styles['SectionHeader']))
        
        tech_analysis = data.get('technology_analysis', {})
        top_tech = tech_analysis.get('top_technologies', {})
        web_servers = tech_analysis.get('web_servers', {})
        
        if top_tech or web_servers:
            tech_text = f"""
            Analysis of the technology stack reveals {tech_analysis.get('total_unique_technologies', 0)} 
            unique technologies in use across the organization's digital assets.
            """
            story.append(Paragraph(tech_text, self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Top technologies table
            if top_tech:
                story.append(Paragraph("Most Common Technologies:", self.styles['SubHeader']))
                tech_data = [['Technology', 'Usage Count']]
                for tech, count in list(top_tech.items())[:5]:
                    tech_data.append([tech, str(count)])
                
                tech_table = Table(tech_data, colWidths=[2*inch, 1*inch])
                tech_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
                ]))
                story.append(tech_table)
                story.append(Spacer(1, 0.2*inch))
        else:
            story.append(Paragraph("No technology information available in current asset data.", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        return story
    
    def _create_compliance_assessment(self, data: Dict[str, Any]) -> List:
        """Create ISO 27001 compliance assessment section"""
        story = []
        
        story.append(Paragraph("ISO 27001 Compliance Assessment", self.styles['SectionHeader']))
        
        compliance = data.get('compliance_analysis', {})
        controls = compliance.get('controls', {})
        
        compliance_text = f"""
        <b>Overall Compliance Score: {compliance.get('overall_score', 'N/A')}%</b><br/>
        Compliance Level: {compliance.get('compliance_level', 'Unknown').title()}<br/><br/>
        The following ISO 27001 controls were assessed based on current security findings:
        """
        
        story.append(Paragraph(compliance_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # Controls assessment table
        control_data = [['Control', 'Name', 'Status', 'Score']]
        for control_id, control_info in controls.items():
            status = 'Compliant' if control_info['status'] == 'compliant' else 'Non-Compliant'
            control_data.append([
                control_id,
                control_info['name'],
                status,
                f"{control_info['score']}%"
            ])
        
        control_table = Table(control_data, colWidths=[1*inch, 2*inch, 1.2*inch, 0.8*inch])
        control_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
        ]))
        
        story.append(control_table)
        story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _create_recommendations(self, data: Dict[str, Any]) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        
        compliance = data.get('compliance_analysis', {})
        recommendations = compliance.get('recommendations', [])
        
        if recommendations:
            story.append(Paragraph("The following recommendations should be implemented to improve security posture and compliance:", self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            for i, rec in enumerate(recommendations, 1):
                priority_color = {
                    'critical': '#dc2626',
                    'high': '#ea580c',
                    'medium': '#ca8a04',
                    'low': '#16a34a'
                }.get(rec.get('priority', 'medium'), '#6b7280')
                
                rec_text = f"""
                <b>{i}. {rec.get('title', 'Recommendation')}</b> 
                [<font color="{priority_color}"><b>{rec.get('priority', 'medium').upper()}</b></font>]<br/>
                {rec.get('description', 'No description available.')}<br/>
                <i>Control: {rec.get('control', 'General')}</i>
                """
                story.append(Paragraph(rec_text, self.styles['Normal']))
                story.append(Spacer(1, 0.15*inch))
        else:
            story.append(Paragraph("No specific recommendations available at this time.", self.styles['Normal']))
        
        return story
