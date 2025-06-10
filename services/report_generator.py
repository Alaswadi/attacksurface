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
        
        # Asset coverage analysis
        story.extend(self._create_asset_coverage_analysis(report_data))

        # Asset inventory
        story.extend(self._create_asset_inventory(report_data))

        # Threat location mapping
        story.extend(self._create_threat_location_mapping(report_data))

        # Domain-specific threat analysis
        story.extend(self._create_domain_threat_analysis(report_data))

        # Vulnerability assessment
        story.extend(self._create_vulnerability_assessment(report_data))

        # Enhanced threat intelligence
        story.extend(self._create_enhanced_threat_intelligence(report_data))

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
        
        # Organization name (prominent)
        org_name = data.get('organization', {}).get('name', 'Unknown Organization')
        story.append(Paragraph(f"{org_name}", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))

        # Title
        story.append(Paragraph("Security Compliance Report", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))

        # Subtitle
        story.append(Paragraph("ISO 27001:2013 Attack Surface Assessment", self.styles['SubHeader']))
        story.append(Spacer(1, 0.3*inch))
        
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
        
        # Enhanced analysis data
        coverage_analysis = asset_stats.get('coverage_analysis', {})
        domain_analysis = data.get('domain_threat_analysis', {})
        threat_mapping = data.get('threat_location_mapping', {})

        # Asset coverage metrics
        coverage_percentage = coverage_analysis.get('coverage_percentage', 0)
        scanning_coverage = coverage_analysis.get('scanning_coverage', {})

        # Threat distribution
        assets_with_threats = len(threat_mapping.get('assets_with_threats', {}))
        high_risk_domains = domain_analysis.get('high_risk_domains', 0)
        total_domains = domain_analysis.get('total_domains', 0)

        summary_text = f"""
        This comprehensive security assessment evaluated the organization's complete digital attack surface across
        {asset_stats.get('total', 0)} digital assets spanning {len(asset_stats.get('by_type', {}))} asset categories.
        The assessment achieved {coverage_percentage}% scanning coverage and identified {vuln_stats.get('total', 0)}
        security vulnerabilities across {assets_with_threats} assets.
        <br/><br/>
        <b>Asset Coverage Analysis:</b><br/>
        • Infrastructure Scanning Coverage: {coverage_percentage}% of {asset_stats.get('total', 0)} total assets<br/>
        • Scanned Assets: {scanning_coverage.get('scanned_assets', 0)} assets analyzed<br/>
        • Never Scanned: {scanning_coverage.get('never_scanned', 0)} assets requiring initial assessment<br/>
        • Recently Scanned: {scanning_coverage.get('recently_scanned', 0)} assets (within 7 days)<br/>
        <br/>
        <b>Threat Distribution Heat Map:</b><br/>
        • Assets with Identified Threats: {assets_with_threats} of {asset_stats.get('total', 0)} total assets<br/>
        • High-Risk Domains: {high_risk_domains} of {total_domains} domains analyzed<br/>
        • Risk Concentration: {round((assets_with_threats / max(asset_stats.get('total', 1), 1)) * 100, 1)}% of infrastructure contains vulnerabilities<br/>
        <br/>
        <b>Security Posture Summary:</b><br/>
        • Security Score: {risk_metrics.get('security_score', 'N/A')}/10<br/>
        • ISO 27001 Compliance Score: {compliance.get('overall_score', 'N/A')}%<br/>
        • Critical/High Risk Issues: {risk_metrics.get('critical_high_open', 0)}<br/>
        • Domain Risk Distribution: {high_risk_domains} high-risk domains requiring immediate attention<br/>
        <br/>
        <b>Compliance Gap Analysis:</b> {compliance.get('compliance_level', 'Unknown').title()} -
        Specific asset and threat references provided in detailed sections below.
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

    def _create_asset_coverage_analysis(self, data: Dict[str, Any]) -> List:
        """Create comprehensive asset coverage analysis section"""
        story = []

        story.append(Paragraph("Asset Coverage Analysis", self.styles['SectionHeader']))

        coverage_data = data.get('asset_stats', {}).get('coverage_analysis', {})

        # Coverage overview
        coverage_text = f"""
        <b>Infrastructure Scanning Coverage:</b><br/>
        This analysis provides comprehensive visibility into the organization's digital asset
        discovery and scanning coverage across the entire attack surface.
        """
        story.append(Paragraph(coverage_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # Discovery timeline table
        discovery_timeline = coverage_data.get('discovery_timeline', {})
        timeline_data = [
            ['Time Period', 'Assets Discovered', 'Percentage'],
            ['Last 24 Hours', str(discovery_timeline.get('last_24h', 0)), f"{(discovery_timeline.get('last_24h', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%"],
            ['Last 7 Days', str(discovery_timeline.get('last_7d', 0)), f"{(discovery_timeline.get('last_7d', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%"],
            ['Last 30 Days', str(discovery_timeline.get('last_30d', 0)), f"{(discovery_timeline.get('last_30d', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%"],
            ['Older', str(discovery_timeline.get('older', 0)), f"{(discovery_timeline.get('older', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%"]
        ]

        timeline_table = Table(timeline_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
        ]))

        story.append(Paragraph("Asset Discovery Timeline:", self.styles['SubHeader']))
        story.append(timeline_table)
        story.append(Spacer(1, 0.2*inch))

        # Scanning coverage statistics
        scanning_coverage = coverage_data.get('scanning_coverage', {})
        coverage_percentage = coverage_data.get('coverage_percentage', 0)

        coverage_stats_text = f"""
        <b>Scanning Coverage Statistics:</b><br/>
        • Total Assets: {scanning_coverage.get('total_assets', 0)}<br/>
        • Scanned Assets: {scanning_coverage.get('scanned_assets', 0)} ({coverage_percentage}%)<br/>
        • Never Scanned: {scanning_coverage.get('never_scanned', 0)}<br/>
        • Recently Scanned (7 days): {scanning_coverage.get('recently_scanned', 0)}<br/>
        • Stale Scans (>30 days): {scanning_coverage.get('stale_scans', 0)}
        """
        story.append(Paragraph(coverage_stats_text, self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))

        return story

    def _create_threat_location_mapping(self, data: Dict[str, Any]) -> List:
        """Create threat location mapping section"""
        story = []

        story.append(Paragraph("Threat Location Mapping", self.styles['SectionHeader']))

        threat_mapping = data.get('threat_location_mapping', {})
        assets_with_threats = threat_mapping.get('assets_with_threats', {})

        threat_text = f"""
        <b>Asset-to-Vulnerability Relationship Analysis:</b><br/>
        This section identifies the specific locations where security threats have been discovered
        within the organization's attack surface, providing clear visibility into which assets
        contain vulnerabilities and their associated risk levels.
        """
        story.append(Paragraph(threat_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        if assets_with_threats:
            story.append(Paragraph(f"Assets with Identified Threats: {len(assets_with_threats)}", self.styles['SubHeader']))

            # Create table of top threatened assets
            threat_assets_data = [['Asset Name', 'Asset Type', 'Critical', 'High', 'Medium', 'Total Threats']]

            # Sort assets by total threat count
            sorted_assets = sorted(assets_with_threats.items(),
                                 key=lambda x: sum(x[1]['severity_counts'].values()), reverse=True)

            for asset_name, asset_data in sorted_assets[:10]:  # Top 10 most threatened assets
                severity_counts = asset_data['severity_counts']
                total_threats = sum(severity_counts.values())

                threat_assets_data.append([
                    asset_name[:30] + ('...' if len(asset_name) > 30 else ''),
                    asset_data['asset_type'].title(),
                    str(severity_counts.get('critical', 0)),
                    str(severity_counts.get('high', 0)),
                    str(severity_counts.get('medium', 0)),
                    str(total_threats)
                ])

            threat_assets_table = Table(threat_assets_data, colWidths=[2.5*inch, 1*inch, 0.7*inch, 0.7*inch, 0.7*inch, 0.8*inch])
            threat_assets_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
            ]))

            story.append(threat_assets_table)
        else:
            story.append(Paragraph("No assets with identified threats found.", self.styles['Normal']))

        story.append(Spacer(1, 0.3*inch))
        return story

    def _create_domain_threat_analysis(self, data: Dict[str, Any]) -> List:
        """Create domain-specific threat analysis section"""
        story = []

        story.append(Paragraph("Domain-Specific Threat Analysis", self.styles['SectionHeader']))

        domain_analysis = data.get('domain_threat_analysis', {})
        domain_breakdown = domain_analysis.get('domain_breakdown', {})

        domain_text = f"""
        <b>Domain Risk Assessment:</b><br/>
        Analysis of security threats across {domain_analysis.get('total_domains', 0)} domains,
        with {domain_analysis.get('high_risk_domains', 0)} domains classified as high-risk and
        {domain_analysis.get('domains_with_vulnerabilities', 0)} domains containing identified vulnerabilities.
        """
        story.append(Paragraph(domain_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        if domain_breakdown:
            # Create domain risk table
            domain_data = [['Domain', 'Risk Level', 'Assets', 'Vulnerabilities', 'Risk Score']]

            for domain, domain_info in list(domain_breakdown.items())[:10]:  # Top 10 domains
                domain_data.append([
                    domain[:25] + ('...' if len(domain) > 25 else ''),
                    domain_info['risk_level'].title(),
                    str(domain_info['total_assets']),
                    str(domain_info['total_vulnerabilities']),
                    str(domain_info['risk_score'])
                ])

            domain_table = Table(domain_data, colWidths=[2*inch, 1*inch, 0.8*inch, 1*inch, 0.8*inch])
            domain_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
            ]))

            story.append(Paragraph("Domain Risk Ranking:", self.styles['SubHeader']))
            story.append(domain_table)

        story.append(Spacer(1, 0.3*inch))
        return story

    def _create_enhanced_threat_intelligence(self, data: Dict[str, Any]) -> List:
        """Create enhanced threat intelligence section"""
        story = []

        story.append(Paragraph("Enhanced Threat Intelligence", self.styles['SectionHeader']))

        threat_intel = data.get('enhanced_threat_intelligence', {})
        attack_vectors = threat_intel.get('attack_vectors', {})

        intel_text = f"""
        <b>Attack Vector Analysis and Business Impact Assessment:</b><br/>
        Comprehensive analysis of identified threats with business impact context,
        attack vector categorization, and prioritized remediation guidance.
        """
        story.append(Paragraph(intel_text, self.styles['Normal']))
        story.append(Spacer(1, 0.2*inch))

        # Attack vectors analysis
        if attack_vectors:
            story.append(Paragraph("Attack Vector Distribution:", self.styles['SubHeader']))

            vector_data = [['Attack Vector', 'Count', 'Critical', 'High', 'Medium']]
            for vector, vector_info in attack_vectors.items():
                if vector != 'unknown':  # Skip unknown vectors for cleaner report
                    severities = vector_info['severities']
                    vector_data.append([
                        vector.title(),
                        str(vector_info['count']),
                        str(severities.get('critical', 0)),
                        str(severities.get('high', 0)),
                        str(severities.get('medium', 0))
                    ])

            vector_table = Table(vector_data, colWidths=[1.5*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
            vector_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
            ]))

            story.append(vector_table)

        # Remediation priority matrix
        remediation_matrix = threat_intel.get('remediation_priority_matrix', [])
        if remediation_matrix:
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("Top Priority Remediation Items:", self.styles['SubHeader']))

            priority_data = [['Priority', 'Vulnerability', 'Asset', 'Severity', 'Business Impact']]
            for i, item in enumerate(remediation_matrix[:5], 1):  # Top 5 priorities
                priority_data.append([
                    str(i),
                    item['title'][:30] + ('...' if len(item['title']) > 30 else ''),
                    item['asset_name'][:20] + ('...' if len(item['asset_name']) > 20 else ''),
                    item['severity'].title(),
                    item['business_impact'].title()
                ])

            priority_table = Table(priority_data, colWidths=[0.5*inch, 2*inch, 1.5*inch, 0.8*inch, 1*inch])
            priority_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#f1f5f9')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#334155')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (0, 0), (0, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e1'))
            ]))

            story.append(priority_table)

        story.append(Spacer(1, 0.3*inch))
        return story
