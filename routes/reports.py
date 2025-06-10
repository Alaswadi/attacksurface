from flask import Blueprint, request, jsonify, render_template, send_file, current_app
from flask_login import login_required, current_user
from models import db, Organization, Asset, Vulnerability, SeverityLevel, AssetType
from datetime import datetime, timedelta
import json
import io
import base64
from collections import defaultdict, Counter

reports_bp = Blueprint('reports', __name__)

@reports_bp.route('/api/reports/generate-pdf')
@login_required
def generate_pdf_report():
    """Generate and download PDF compliance report"""
    try:
        from services.report_generator import ComplianceReportGenerator

        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        # Get report data (reuse the existing function)
        report_data = _get_report_data_internal(org)

        # Generate PDF
        generator = ComplianceReportGenerator()
        pdf_buffer = generator.generate_iso27001_report(report_data)

        # Generate filename with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"Security_Compliance_Report_{org.name.replace(' ', '_')}_{timestamp}.pdf"

        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )

    except ImportError as e:
        current_app.logger.error(f"PDF generation dependencies missing: {str(e)}")
        return jsonify({
            'error': 'PDF generation not available. Please install reportlab: pip install reportlab'
        }), 500
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        current_app.logger.error(f"Error generating PDF report: {str(e)}")
        current_app.logger.error(f"Full traceback: {error_details}")
        print(f"PDF Generation Error: {str(e)}")
        print(f"Full traceback: {error_details}")
        return jsonify({'error': f'Failed to generate PDF report: {str(e)}'}), 500

@reports_bp.route('/api/reports/generate-html')
@login_required
def generate_html_report():
    """Generate and download HTML compliance report (no dependencies required)"""
    try:
        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        # Get report data
        report_data = _get_report_data_internal(org)

        # Generate HTML report
        html_content = generate_html_report_content(report_data)

        # Generate filename with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"Security_Compliance_Report_{org.name.replace(' ', '_')}_{timestamp}.html"

        # Create in-memory file
        html_buffer = io.BytesIO()
        html_buffer.write(html_content.encode('utf-8'))
        html_buffer.seek(0)

        return send_file(
            html_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='text/html'
        )

    except Exception as e:
        current_app.logger.error(f"Error generating HTML report: {str(e)}")
        return jsonify({'error': 'Failed to generate HTML report'}), 500

def _get_report_data_internal(org):
    """Internal function to get comprehensive report data for an organization"""
    # Get all assets with their vulnerabilities
    assets = Asset.query.filter_by(organization_id=org.id, is_active=True).all()

    # Get all vulnerabilities with asset relationships
    vulnerabilities = Vulnerability.query.filter_by(organization_id=org.id).all()

    # Enhanced asset coverage analysis
    try:
        asset_coverage_analysis = analyze_asset_coverage(assets)
    except Exception as e:
        print(f"Error in asset coverage analysis: {e}")
        asset_coverage_analysis = {}

    # Threat location mapping
    try:
        threat_location_mapping = analyze_threat_locations(assets, vulnerabilities)
    except Exception as e:
        print(f"Error in threat location mapping: {e}")
        threat_location_mapping = {}

    # Domain-specific threat analysis
    try:
        domain_threat_analysis = analyze_domain_threats(assets, vulnerabilities)
    except Exception as e:
        print(f"Error in domain threat analysis: {e}")
        domain_threat_analysis = {}

    # Enhanced threat intelligence
    try:
        enhanced_threat_intelligence = analyze_threat_intelligence(vulnerabilities, assets)
    except Exception as e:
        print(f"Error in enhanced threat intelligence: {e}")
        enhanced_threat_intelligence = {}

    # Calculate asset statistics
    asset_stats = {
        'total': len(assets),
        'by_type': {
            'domains': len([a for a in assets if a.asset_type == AssetType.DOMAIN]),
            'subdomains': len([a for a in assets if a.asset_type == AssetType.SUBDOMAIN]),
            'ip_addresses': len([a for a in assets if a.asset_type == AssetType.IP_ADDRESS]),
            'cloud_resources': len([a for a in assets if a.asset_type == AssetType.CLOUD_RESOURCE]),
            'services': len([a for a in assets if a.asset_type == AssetType.SERVICE])
        },
        'coverage_analysis': asset_coverage_analysis
    }

    # Calculate vulnerability statistics
    vuln_stats = {
        'total': len(vulnerabilities),
        'open': len([v for v in vulnerabilities if not v.is_resolved]),
        'resolved': len([v for v in vulnerabilities if v.is_resolved]),
        'by_severity': {
            'critical': len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
            'high': len([v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]),
            'medium': len([v for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
            'low': len([v for v in vulnerabilities if v.severity == SeverityLevel.LOW]),
            'info': len([v for v in vulnerabilities if v.severity == SeverityLevel.INFO])
        },
        'by_validation': {
            'validated': len([v for v in vulnerabilities if getattr(v, 'is_validated', True)]),
            'unvalidated': len([v for v in vulnerabilities if not getattr(v, 'is_validated', True)])
        }
    }

    # Calculate risk metrics
    critical_high_open = len([v for v in vulnerabilities
                            if v.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
                            and not v.is_resolved])

    assets_with_vulns = len(set([v.asset_id for v in vulnerabilities if not v.is_resolved]))

    risk_metrics = {
        'critical_high_open': critical_high_open,
        'assets_at_risk': assets_with_vulns,
        'risk_percentage': round((assets_with_vulns / len(assets) * 100) if assets else 0, 1),
        'security_score': calculate_security_score(vuln_stats, asset_stats)
    }

    # Technology analysis
    tech_analysis = analyze_technologies(assets)

    # Compliance analysis
    compliance_analysis = analyze_iso27001_compliance(vuln_stats, asset_stats, risk_metrics)

    # Recent activity (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_vulns = [v for v in vulnerabilities if v.discovered_at >= thirty_days_ago]
    recent_assets = [a for a in assets if a.discovered_at >= thirty_days_ago]

    recent_activity = {
        'new_vulnerabilities': len(recent_vulns),
        'new_assets': len(recent_assets),
        'resolved_vulnerabilities': len([v for v in vulnerabilities
                                       if v.resolved_at and v.resolved_at >= thirty_days_ago])
    }

    # Trend data (last 7 days)
    trend_data = generate_trend_data(org.id)

    return {
        'organization': {
            'name': org.name,
            'id': org.id,
            'created_at': org.created_at.isoformat() if org.created_at else None
        },
        'asset_stats': asset_stats,
        'vulnerability_stats': vuln_stats,
        'risk_metrics': risk_metrics,
        'technology_analysis': tech_analysis,
        'compliance_analysis': compliance_analysis,
        'recent_activity': recent_activity,
        'trend_data': trend_data,
        'threat_location_mapping': threat_location_mapping,
        'domain_threat_analysis': domain_threat_analysis,
        'enhanced_threat_intelligence': enhanced_threat_intelligence,
        'generated_at': datetime.utcnow().isoformat()
    }

@reports_bp.route('/api/reports/data')
@login_required
def get_report_data():
    """Get comprehensive report data for the organization"""
    try:
        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            return jsonify({'error': 'Organization not found'}), 404

        # Get report data using internal function
        report_data = _get_report_data_internal(org)

        return jsonify(report_data)

    except Exception as e:
        current_app.logger.error(f"Error generating report data: {str(e)}")
        return jsonify({'error': 'Failed to generate report data'}), 500

def calculate_security_score(vuln_stats, asset_stats):
    """Calculate a security score based on vulnerabilities and assets"""
    if asset_stats['total'] == 0:
        return 10.0
    
    # Base score
    score = 10.0
    
    # Deduct points for vulnerabilities
    critical_penalty = vuln_stats['by_severity']['critical'] * 2.0
    high_penalty = vuln_stats['by_severity']['high'] * 1.0
    medium_penalty = vuln_stats['by_severity']['medium'] * 0.5
    low_penalty = vuln_stats['by_severity']['low'] * 0.1
    
    total_penalty = critical_penalty + high_penalty + medium_penalty + low_penalty
    
    # Normalize penalty based on asset count
    normalized_penalty = total_penalty / asset_stats['total']
    
    score = max(0.0, score - normalized_penalty)
    return round(score, 1)

def analyze_technologies(assets):
    """Analyze technologies from asset metadata"""
    tech_counter = Counter()
    web_servers = Counter()
    
    for asset in assets:
        if asset.asset_metadata and 'http_probe' in asset.asset_metadata:
            http_data = asset.asset_metadata['http_probe']
            
            # Extract technologies
            if 'tech' in http_data:
                if isinstance(http_data['tech'], list):
                    for tech in http_data['tech']:
                        tech_counter[tech] += 1
                        
            # Extract web servers
            if 'webserver' in http_data:
                server = http_data['webserver'].split('/')[0] if '/' in http_data['webserver'] else http_data['webserver']
                web_servers[server] += 1
    
    return {
        'top_technologies': dict(tech_counter.most_common(10)),
        'web_servers': dict(web_servers.most_common(5)),
        'total_unique_technologies': len(tech_counter)
    }

def analyze_iso27001_compliance(vuln_stats, asset_stats, risk_metrics):
    """Analyze compliance with ISO 27001 requirements"""
    
    # ISO 27001 control assessment
    controls = {
        'A.12.1.2': {  # Change management
            'name': 'Change Management',
            'status': 'compliant' if vuln_stats['total'] < 10 else 'non_compliant',
            'score': max(0, 100 - (vuln_stats['total'] * 5))
        },
        'A.12.2.1': {  # Controls against malware
            'name': 'Malware Protection',
            'status': 'compliant' if vuln_stats['by_severity']['critical'] == 0 else 'non_compliant',
            'score': max(0, 100 - (vuln_stats['by_severity']['critical'] * 25))
        },
        'A.12.6.1': {  # Management of technical vulnerabilities
            'name': 'Vulnerability Management',
            'status': 'compliant' if risk_metrics['critical_high_open'] < 5 else 'non_compliant',
            'score': max(0, 100 - (risk_metrics['critical_high_open'] * 10))
        },
        'A.13.1.1': {  # Network controls
            'name': 'Network Security Controls',
            'status': 'compliant' if risk_metrics['risk_percentage'] < 20 else 'non_compliant',
            'score': max(0, 100 - risk_metrics['risk_percentage'])
        },
        'A.14.2.1': {  # Secure development policy
            'name': 'Secure Development',
            'status': 'compliant' if vuln_stats['by_severity']['high'] < 10 else 'non_compliant',
            'score': max(0, 100 - (vuln_stats['by_severity']['high'] * 5))
        }
    }
    
    # Calculate overall compliance score
    total_score = sum([control['score'] for control in controls.values()])
    overall_score = round(total_score / len(controls), 1)
    
    # Determine compliance level
    if overall_score >= 90:
        compliance_level = 'excellent'
    elif overall_score >= 75:
        compliance_level = 'good'
    elif overall_score >= 60:
        compliance_level = 'fair'
    else:
        compliance_level = 'poor'
    
    return {
        'overall_score': overall_score,
        'compliance_level': compliance_level,
        'controls': controls,
        'recommendations': generate_iso27001_recommendations(controls, vuln_stats)
    }

def generate_iso27001_recommendations(controls, vuln_stats):
    """Generate ISO 27001 compliance recommendations"""
    recommendations = []
    
    for control_id, control in controls.items():
        if control['status'] == 'non_compliant':
            if control_id == 'A.12.6.1':
                recommendations.append({
                    'priority': 'high',
                    'control': control_id,
                    'title': 'Implement Vulnerability Management Process',
                    'description': 'Establish a formal vulnerability management process to identify, assess, and remediate security vulnerabilities in a timely manner.'
                })
            elif control_id == 'A.12.2.1':
                recommendations.append({
                    'priority': 'critical',
                    'control': control_id,
                    'title': 'Address Critical Vulnerabilities',
                    'description': 'Immediately address all critical severity vulnerabilities to reduce malware infection risk.'
                })
    
    # Add general recommendations based on vulnerability stats
    if vuln_stats['by_severity']['critical'] > 0:
        recommendations.append({
            'priority': 'critical',
            'control': 'General',
            'title': 'Critical Vulnerability Remediation',
            'description': f'Remediate {vuln_stats["by_severity"]["critical"]} critical vulnerabilities immediately.'
        })
    
    return recommendations

def generate_trend_data(org_id):
    """Generate trend data for the last 7 days"""
    dates = []
    for i in range(7):
        date = datetime.utcnow() - timedelta(days=6-i)
        dates.append(date.strftime("%Y-%m-%d"))

    # In a real implementation, this would query actual historical data
    # For now, we'll generate sample trend data
    return {
        'dates': dates,
        'vulnerabilities_discovered': [2, 1, 3, 0, 2, 1, 0],
        'vulnerabilities_resolved': [1, 2, 1, 3, 1, 2, 1],
        'assets_discovered': [5, 3, 2, 1, 4, 2, 1],
        'security_score': [7.2, 7.5, 7.3, 7.8, 7.6, 8.0, 8.1]
    }

def generate_html_report_content(data):
    """Generate comprehensive HTML report content with enhanced analysis"""
    org_name = data.get('organization', {}).get('name', 'Unknown Organization')
    generated_at = datetime.utcnow().strftime('%B %d, %Y at %I:%M %p UTC')

    # Extract key metrics
    asset_stats = data.get('asset_stats', {})
    vuln_stats = data.get('vulnerability_stats', {})
    risk_metrics = data.get('risk_metrics', {})
    compliance = data.get('compliance_analysis', {})

    # Enhanced analysis data
    coverage_analysis = asset_stats.get('coverage_analysis', {})
    threat_mapping = data.get('threat_location_mapping', {})
    domain_analysis = data.get('domain_threat_analysis', {})
    threat_intelligence = data.get('enhanced_threat_intelligence', {})
    tech_analysis = data.get('technology_analysis', {})

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Compliance Report - {org_name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8fafc;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            border-radius: 10px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header .subtitle {{
            margin: 10px 0 0 0;
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .section {{
            background: white;
            margin: 30px 0;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #1e293b;
            border-bottom: 3px solid #4ade80;
            padding-bottom: 10px;
            margin-bottom: 25px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 25px 0;
        }}
        .metric-card {{
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4ade80;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #1e293b;
        }}
        .metric-label {{
            color: #64748b;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .table th, .table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        .table th {{
            background-color: #f1f5f9;
            font-weight: 600;
            color: #374151;
        }}
        .severity-critical {{ color: #dc2626; font-weight: bold; }}
        .severity-high {{ color: #ea580c; font-weight: bold; }}
        .severity-medium {{ color: #ca8a04; font-weight: bold; }}
        .severity-low {{ color: #16a34a; font-weight: bold; }}
        .severity-info {{ color: #6b7280; }}
        .compliance-excellent {{ color: #16a34a; font-weight: bold; }}
        .compliance-good {{ color: #2563eb; font-weight: bold; }}
        .compliance-fair {{ color: #ca8a04; font-weight: bold; }}
        .compliance-poor {{ color: #dc2626; font-weight: bold; }}
        .recommendation {{
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }}
        .recommendation.critical {{
            background: #fee2e2;
            border-left-color: #dc2626;
        }}
        .recommendation.high {{
            background: #fed7aa;
            border-left-color: #ea580c;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background: #f1f5f9;
            border-radius: 10px;
            color: #64748b;
            font-size: 0.9em;
        }}
        @media print {{
            body {{ background-color: white; }}
            .section {{ box-shadow: none; border: 1px solid #e2e8f0; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{org_name}</h1>
        <div class="subtitle">Security Compliance Report</div>
        <div class="subtitle">ISO 27001:2013 Comprehensive Attack Surface Assessment</div>
        <div class="subtitle">Generated on {generated_at}</div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>This report presents a comprehensive security assessment of <strong>{asset_stats.get('total', 0)}</strong>
        digital assets within the organization's attack surface. The assessment identified
        <strong>{vuln_stats.get('total', 0)}</strong> security findings across various severity levels.</p>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{risk_metrics.get('security_score', 'N/A')}/10</div>
                <div class="metric-label">Security Score</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{compliance.get('overall_score', 'N/A')}%</div>
                <div class="metric-label">ISO 27001 Compliance</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{risk_metrics.get('critical_high_open', 0)}</div>
                <div class="metric-label">Critical/High Issues</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{risk_metrics.get('assets_at_risk', 0)} ({risk_metrics.get('risk_percentage', 0)}%)</div>
                <div class="metric-label">Assets at Risk</div>
            </div>
        </div>

        <p><strong>Compliance Status:</strong>
        <span class="compliance-{compliance.get('compliance_level', 'unknown')}">{compliance.get('compliance_level', 'Unknown').title()}</span></p>
    </div>

    <div class="section">
        <h2>Asset Inventory</h2>
        <table class="table">
            <thead>
                <tr>
                    <th>Asset Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>"""

    # Asset breakdown table
    by_type = asset_stats.get('by_type', {})
    total_assets = asset_stats.get('total', 1)

    asset_types = [
        ('Domains', by_type.get('domains', 0)),
        ('Subdomains', by_type.get('subdomains', 0)),
        ('IP Addresses', by_type.get('ip_addresses', 0)),
        ('Cloud Resources', by_type.get('cloud_resources', 0)),
        ('Services', by_type.get('services', 0))
    ]

    for asset_type, count in asset_types:
        percentage = (count / max(total_assets, 1) * 100)
        html_content += f"""
                <tr>
                    <td>{asset_type}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>"""

    html_content += f"""
                <tr style="font-weight: bold; background-color: #f8fafc;">
                    <td>Total</td>
                    <td>{total_assets}</td>
                    <td>100.0%</td>
                </tr>
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Vulnerability Assessment</h2>
        <p>A total of <strong>{vuln_stats.get('total', 0)}</strong> security findings were identified during the assessment.
        <strong>{vuln_stats.get('open', 0)}</strong> findings remain unresolved and require attention.</p>

        <table class="table">
            <thead>
                <tr>
                    <th>Severity Level</th>
                    <th>Count</th>
                    <th>Status</th>
                    <th>Risk Level</th>
                </tr>
            </thead>
            <tbody>"""

    # Vulnerability breakdown
    by_severity = vuln_stats.get('by_severity', {})
    severity_data = [
        ('Critical', by_severity.get('critical', 0), 'Immediate Action Required', 'Very High', 'critical'),
        ('High', by_severity.get('high', 0), 'Action Required', 'High', 'high'),
        ('Medium', by_severity.get('medium', 0), 'Should Fix', 'Medium', 'medium'),
        ('Low', by_severity.get('low', 0), 'Consider Fixing', 'Low', 'low'),
        ('Info', by_severity.get('info', 0), 'Informational', 'Very Low', 'info')
    ]

    for severity, count, status, risk_level, css_class in severity_data:
        html_content += f"""
                <tr>
                    <td class="severity-{css_class}">{severity}</td>
                    <td>{count}</td>
                    <td>{status}</td>
                    <td>{risk_level}</td>
                </tr>"""

    html_content += f"""
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Risk Analysis</h2>
        <p><strong>Overall Risk Assessment:</strong><br>
        The organization's current security posture presents a risk level that requires attention.
        <strong>{risk_metrics.get('assets_at_risk', 0)}</strong> assets ({risk_metrics.get('risk_percentage', 0)}%)
        have identified security vulnerabilities that could be exploited by threat actors.</p>

        <p><strong>Critical Risk Factors:</strong></p>
        <ul>
            <li><strong>{risk_metrics.get('critical_high_open', 0)}</strong> critical/high severity vulnerabilities require immediate attention</li>
            <li>Security score of <strong>{risk_metrics.get('security_score', 'N/A')}/10</strong> indicates room for improvement</li>
            <li>Risk exposure affects <strong>{risk_metrics.get('risk_percentage', 0)}%</strong> of the digital asset portfolio</li>
        </ul>
    </div>"""

    # Technology analysis section
    if tech_analysis.get('top_technologies') or tech_analysis.get('web_servers'):
        html_content += f"""
    <div class="section">
        <h2>Technology Stack Analysis</h2>
        <p>Analysis of the technology stack reveals <strong>{tech_analysis.get('total_unique_technologies', 0)}</strong>
        unique technologies in use across the organization's digital assets.</p>"""

        if tech_analysis.get('top_technologies'):
            html_content += """
        <h3>Most Common Technologies:</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Technology</th>
                    <th>Usage Count</th>
                </tr>
            </thead>
            <tbody>"""

            for tech, count in list(tech_analysis.get('top_technologies', {}).items())[:5]:
                html_content += f"""
                <tr>
                    <td>{tech}</td>
                    <td>{count}</td>
                </tr>"""

            html_content += """
            </tbody>
        </table>"""

        html_content += """
    </div>"""

    # ISO 27001 Compliance section
    html_content += f"""
    <div class="section">
        <h2>ISO 27001 Compliance Assessment</h2>
        <p><strong>Overall Compliance Score: {compliance.get('overall_score', 'N/A')}%</strong><br>
        Compliance Level: <span class="compliance-{compliance.get('compliance_level', 'unknown')}">{compliance.get('compliance_level', 'Unknown').title()}</span></p>

        <p>The following ISO 27001 controls were assessed based on current security findings:</p>

        <table class="table">
            <thead>
                <tr>
                    <th>Control</th>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody>"""

    # Controls assessment
    controls = compliance.get('controls', {})
    for control_id, control_info in controls.items():
        status = 'Compliant' if control_info.get('status') == 'compliant' else 'Non-Compliant'
        status_class = 'compliance-good' if control_info.get('status') == 'compliant' else 'compliance-poor'
        html_content += f"""
                <tr>
                    <td>{control_id}</td>
                    <td>{control_info.get('name', 'Unknown')}</td>
                    <td class="{status_class}">{status}</td>
                    <td>{control_info.get('score', 0)}%</td>
                </tr>"""

    html_content += """
            </tbody>
        </table>
    </div>"""

    # Recommendations section
    recommendations = compliance.get('recommendations', [])
    if recommendations:
        html_content += """
    <div class="section">
        <h2>Recommendations</h2>
        <p>The following recommendations should be implemented to improve security posture and compliance:</p>"""

        for i, rec in enumerate(recommendations, 1):
            priority = rec.get('priority', 'medium')
            html_content += f"""
        <div class="recommendation {priority}">
            <h4>{i}. {rec.get('title', 'Recommendation')} [{priority.upper()}]</h4>
            <p>{rec.get('description', 'No description available.')}</p>
            <p><em>Control: {rec.get('control', 'General')}</em></p>
        </div>"""

        html_content += """
    </div>"""

    # Asset Coverage Analysis section
    coverage_percentage = coverage_analysis.get('coverage_percentage', 0)
    scanning_coverage = coverage_analysis.get('scanning_coverage', {})
    discovery_timeline = coverage_analysis.get('discovery_timeline', {})

    html_content += f"""
    <div class="section">
        <h2>Asset Coverage Analysis</h2>
        <p>Comprehensive visibility into the organization's digital asset discovery and scanning coverage across the entire attack surface.</p>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{coverage_percentage}%</div>
                <div class="metric-label">Infrastructure Scanning Coverage</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{scanning_coverage.get('scanned_assets', 0)}</div>
                <div class="metric-label">Scanned Assets</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{scanning_coverage.get('never_scanned', 0)}</div>
                <div class="metric-label">Never Scanned</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{scanning_coverage.get('recently_scanned', 0)}</div>
                <div class="metric-label">Recently Scanned (7 days)</div>
            </div>
        </div>

        <h3>Asset Discovery Timeline</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Time Period</th>
                    <th>Assets Discovered</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Last 24 Hours</td>
                    <td>{discovery_timeline.get('last_24h', 0)}</td>
                    <td>{(discovery_timeline.get('last_24h', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%</td>
                </tr>
                <tr>
                    <td>Last 7 Days</td>
                    <td>{discovery_timeline.get('last_7d', 0)}</td>
                    <td>{(discovery_timeline.get('last_7d', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%</td>
                </tr>
                <tr>
                    <td>Last 30 Days</td>
                    <td>{discovery_timeline.get('last_30d', 0)}</td>
                    <td>{(discovery_timeline.get('last_30d', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%</td>
                </tr>
                <tr>
                    <td>Older</td>
                    <td>{discovery_timeline.get('older', 0)}</td>
                    <td>{(discovery_timeline.get('older', 0) / max(sum(discovery_timeline.values()), 1) * 100):.1f}%</td>
                </tr>
            </tbody>
        </table>
    </div>"""

    # Threat Location Mapping section
    assets_with_threats = threat_mapping.get('assets_with_threats', {})

    html_content += f"""
    <div class="section">
        <h2>Threat Location Mapping</h2>
        <p>Specific identification of assets containing vulnerabilities with clear visibility into threat locations within the attack surface.</p>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{len(assets_with_threats)}</div>
                <div class="metric-label">Assets with Identified Threats</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{round((len(assets_with_threats) / max(asset_stats.get('total', 1), 1)) * 100, 1)}%</div>
                <div class="metric-label">Risk Concentration</div>
            </div>
        </div>"""

    if assets_with_threats:
        # Sort assets by total threat count
        sorted_assets = sorted(assets_with_threats.items(),
                             key=lambda x: sum(x[1]['severity_counts'].values()), reverse=True)

        html_content += """
        <h3>Top Threatened Assets</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Asset Name</th>
                    <th>Asset Type</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Total Threats</th>
                </tr>
            </thead>
            <tbody>"""

        for asset_name, asset_data in sorted_assets[:10]:  # Top 10 most threatened assets
            severity_counts = asset_data['severity_counts']
            total_threats = sum(severity_counts.values())

            html_content += f"""
                <tr>
                    <td>{asset_name[:40] + ('...' if len(asset_name) > 40 else '')}</td>
                    <td>{asset_data['asset_type'].title()}</td>
                    <td class="severity-critical">{severity_counts.get('critical', 0)}</td>
                    <td class="severity-high">{severity_counts.get('high', 0)}</td>
                    <td class="severity-medium">{severity_counts.get('medium', 0)}</td>
                    <td><strong>{total_threats}</strong></td>
                </tr>"""

        html_content += """
            </tbody>
        </table>"""

    html_content += """
    </div>"""

    # Domain-Specific Threat Analysis section
    domain_breakdown = domain_analysis.get('domain_breakdown', {})

    html_content += f"""
    <div class="section">
        <h2>Domain-Specific Threat Analysis</h2>
        <p>Analysis of security threats across {domain_analysis.get('total_domains', 0)} domains,
        with {domain_analysis.get('high_risk_domains', 0)} domains classified as high-risk.</p>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{domain_analysis.get('total_domains', 0)}</div>
                <div class="metric-label">Total Domains Analyzed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{domain_analysis.get('high_risk_domains', 0)}</div>
                <div class="metric-label">High-Risk Domains</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{domain_analysis.get('domains_with_vulnerabilities', 0)}</div>
                <div class="metric-label">Domains with Vulnerabilities</div>
            </div>
        </div>"""

    if domain_breakdown:
        html_content += """
        <h3>Domain Risk Ranking</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Risk Level</th>
                    <th>Assets</th>
                    <th>Vulnerabilities</th>
                    <th>Risk Score</th>
                </tr>
            </thead>
            <tbody>"""

        for domain, domain_info in list(domain_breakdown.items())[:10]:  # Top 10 domains
            risk_level = domain_info['risk_level']
            html_content += f"""
                <tr>
                    <td>{domain[:35] + ('...' if len(domain) > 35 else '')}</td>
                    <td><span class="domain-risk {risk_level}">{risk_level.title()}</span></td>
                    <td>{domain_info['total_assets']}</td>
                    <td>{domain_info['total_vulnerabilities']}</td>
                    <td><strong>{domain_info['risk_score']}</strong></td>
                </tr>"""

        html_content += """
            </tbody>
        </table>"""

    html_content += """
    </div>"""

    # Enhanced Threat Intelligence section
    attack_vectors = threat_intelligence.get('attack_vectors', {})
    remediation_matrix = threat_intelligence.get('remediation_priority_matrix', [])

    html_content += """
    <div class="section">
        <h2>Enhanced Threat Intelligence</h2>
        <p>Comprehensive analysis of identified threats with business impact context, attack vector categorization, and prioritized remediation guidance.</p>"""

    if attack_vectors:
        html_content += """
        <h3>Attack Vector Distribution</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Attack Vector</th>
                    <th>Count</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                </tr>
            </thead>
            <tbody>"""

        for vector, vector_info in attack_vectors.items():
            if vector != 'unknown':  # Skip unknown vectors for cleaner report
                severities = vector_info['severities']
                html_content += f"""
                    <tr>
                        <td>{vector.title()}</td>
                        <td><strong>{vector_info['count']}</strong></td>
                        <td class="severity-critical">{severities.get('critical', 0)}</td>
                        <td class="severity-high">{severities.get('high', 0)}</td>
                        <td class="severity-medium">{severities.get('medium', 0)}</td>
                    </tr>"""

        html_content += """
            </tbody>
        </table>"""

    if remediation_matrix:
        html_content += """
        <h3>Top Priority Remediation Items</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Vulnerability</th>
                    <th>Asset</th>
                    <th>Severity</th>
                    <th>Business Impact</th>
                </tr>
            </thead>
            <tbody>"""

        for i, item in enumerate(remediation_matrix[:5], 1):  # Top 5 priorities
            severity_class = f"severity-{item['severity']}"
            html_content += f"""
                <tr>
                    <td><strong>{i}</strong></td>
                    <td>{item['title'][:40] + ('...' if len(item['title']) > 40 else '')}</td>
                    <td>{item['asset_name'][:25] + ('...' if len(item['asset_name']) > 25 else '')}</td>
                    <td class="{severity_class}">{item['severity'].title()}</td>
                    <td>{item['business_impact'].title()}</td>
                </tr>"""

        html_content += """
            </tbody>
        </table>"""

    html_content += """
    </div>"""

    # Footer
    html_content += f"""
    <div class="footer">
        <p><strong>CONFIDENTIAL</strong></p>
        <p>This report contains confidential security information and should be handled according to
        your organization's information security policies. Distribution should be limited to
        authorized personnel only.</p>
        <p>Report generated on {generated_at} | Framework: ISO 27001:2013 | Comprehensive Attack Surface Assessment</p>
    </div>
</body>
</html>"""

    return html_content

def analyze_asset_coverage(assets):
    """Analyze comprehensive asset coverage and discovery timeline"""
    now = datetime.utcnow()

    # Discovery timeline analysis
    discovery_timeline = {
        'last_24h': 0,
        'last_7d': 0,
        'last_30d': 0,
        'older': 0
    }

    # Asset criticality analysis
    criticality_analysis = {
        'critical': 0,  # Assets with critical vulnerabilities
        'high': 0,      # Assets with high vulnerabilities
        'medium': 0,    # Assets with medium vulnerabilities
        'low': 0,       # Assets with low/info vulnerabilities
        'clean': 0      # Assets with no vulnerabilities
    }

    # Scanning coverage statistics
    scanning_coverage = {
        'total_assets': len(assets),
        'scanned_assets': 0,
        'never_scanned': 0,
        'recently_scanned': 0,  # Last 7 days
        'stale_scans': 0        # Older than 30 days
    }

    # Exposure level analysis
    exposure_levels = {
        'public': 0,     # Assets with public exposure
        'internal': 0,   # Internal assets
        'unknown': 0     # Unknown exposure
    }

    for asset in assets:
        # Discovery timeline
        if hasattr(asset, 'discovered_at') and asset.discovered_at:
            try:
                days_since_discovery = (now - asset.discovered_at).days
                if days_since_discovery <= 1:
                    discovery_timeline['last_24h'] += 1
                elif days_since_discovery <= 7:
                    discovery_timeline['last_7d'] += 1
                elif days_since_discovery <= 30:
                    discovery_timeline['last_30d'] += 1
                else:
                    discovery_timeline['older'] += 1
            except Exception as e:
                print(f"Error processing asset discovery date: {e}")
                discovery_timeline['older'] += 1

        # Scanning coverage
        if hasattr(asset, 'last_scanned') and asset.last_scanned:
            try:
                scanning_coverage['scanned_assets'] += 1
                days_since_scan = (now - asset.last_scanned).days
                if days_since_scan <= 7:
                    scanning_coverage['recently_scanned'] += 1
                elif days_since_scan > 30:
                    scanning_coverage['stale_scans'] += 1
            except Exception as e:
                print(f"Error processing asset scan date: {e}")
                scanning_coverage['scanned_assets'] += 1
        else:
            scanning_coverage['never_scanned'] += 1

        # Exposure level analysis (based on asset metadata)
        try:
            if hasattr(asset, 'asset_metadata') and asset.asset_metadata:
                http_probe = asset.asset_metadata.get('http_probe', {})
                if http_probe.get('status_code'):
                    exposure_levels['public'] += 1
                else:
                    exposure_levels['internal'] += 1
            else:
                exposure_levels['unknown'] += 1
        except Exception as e:
            print(f"Error processing asset metadata: {e}")
            exposure_levels['unknown'] += 1

        # Asset criticality (will be updated by vulnerability analysis)
        try:
            if not hasattr(asset, 'vulnerabilities') or not asset.vulnerabilities:
                criticality_analysis['clean'] += 1
        except Exception as e:
            print(f"Error processing asset vulnerabilities: {e}")
            criticality_analysis['clean'] += 1

    return {
        'discovery_timeline': discovery_timeline,
        'criticality_analysis': criticality_analysis,
        'scanning_coverage': scanning_coverage,
        'exposure_levels': exposure_levels,
        'coverage_percentage': round((scanning_coverage['scanned_assets'] / max(len(assets), 1)) * 100, 1)
    }

def analyze_threat_locations(assets, vulnerabilities):
    """Analyze specific threat locations and asset-to-vulnerability mapping"""
    threat_locations = {
        'assets_with_threats': {},
        'threat_distribution': {},
        'geographic_analysis': {},
        'network_segments': {}
    }

    # Create asset lookup
    asset_lookup = {asset.id: asset for asset in assets}

    # Analyze each vulnerability and its location
    for vuln in vulnerabilities:
        asset = asset_lookup.get(vuln.asset_id)
        if not asset:
            continue

        asset_name = asset.name
        asset_type = asset.asset_type.value

        # Initialize asset threat data if not exists
        if asset_name not in threat_locations['assets_with_threats']:
            threat_locations['assets_with_threats'][asset_name] = {
                'asset_type': asset_type,
                'asset_id': asset.id,
                'vulnerabilities': [],
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'technologies': [],
                'ports': [],
                'last_scanned': asset.last_scanned.isoformat() if asset.last_scanned else None,
                'discovery_method': asset.asset_metadata.get('discovery_method') if asset.asset_metadata else None
            }

        # Add vulnerability to asset
        threat_locations['assets_with_threats'][asset_name]['vulnerabilities'].append({
            'id': vuln.id,
            'title': vuln.title,
            'description': vuln.description,
            'severity': vuln.severity.value,
            'cve_id': vuln.cve_id,
            'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
            'is_resolved': vuln.is_resolved,
            'template_name': vuln.template_name,
            'cvss_score': vuln.cvss_score
        })

        # Update severity counts
        threat_locations['assets_with_threats'][asset_name]['severity_counts'][vuln.severity.value] += 1

        # Extract technology and port information from asset metadata
        if asset.asset_metadata:
            http_probe = asset.asset_metadata.get('http_probe', {})
            if http_probe.get('tech'):
                threat_locations['assets_with_threats'][asset_name]['technologies'] = http_probe.get('tech', [])

            ports = asset.asset_metadata.get('ports', [])
            if ports:
                threat_locations['assets_with_threats'][asset_name]['ports'] = ports

        # Threat distribution by asset type
        if asset_type not in threat_locations['threat_distribution']:
            threat_locations['threat_distribution'][asset_type] = {
                'total_assets': 0,
                'assets_with_threats': 0,
                'total_vulnerabilities': 0,
                'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            }

        threat_locations['threat_distribution'][asset_type]['total_vulnerabilities'] += 1
        threat_locations['threat_distribution'][asset_type]['severity_breakdown'][vuln.severity.value] += 1

    # Count total assets and assets with threats by type
    for asset in assets:
        asset_type = asset.asset_type.value
        if asset_type not in threat_locations['threat_distribution']:
            threat_locations['threat_distribution'][asset_type] = {
                'total_assets': 0,
                'assets_with_threats': 0,
                'total_vulnerabilities': 0,
                'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            }

        threat_locations['threat_distribution'][asset_type]['total_assets'] += 1

        if asset.name in threat_locations['assets_with_threats']:
            threat_locations['threat_distribution'][asset_type]['assets_with_threats'] += 1

    return threat_locations

def analyze_domain_threats(assets, vulnerabilities):
    """Analyze domain-specific threat patterns and risk scoring"""
    domain_analysis = {}

    # Create asset lookup
    asset_lookup = {asset.id: asset for asset in assets}

    # Group assets by parent domain
    domain_groups = {}
    for asset in assets:
        if asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            # Extract parent domain
            if asset.asset_type == AssetType.DOMAIN:
                parent_domain = asset.name
            else:
                # For subdomains, extract parent domain
                parts = asset.name.split('.')
                if len(parts) >= 2:
                    parent_domain = '.'.join(parts[-2:])
                else:
                    parent_domain = asset.name

            if parent_domain not in domain_groups:
                domain_groups[parent_domain] = {
                    'assets': [],
                    'subdomains': [],
                    'vulnerabilities': [],
                    'technologies': set(),
                    'ports': set(),
                    'risk_score': 0
                }

            domain_groups[parent_domain]['assets'].append(asset)
            if asset.asset_type == AssetType.SUBDOMAIN:
                domain_groups[parent_domain]['subdomains'].append(asset.name)

    # Analyze vulnerabilities by domain
    for vuln in vulnerabilities:
        asset = asset_lookup.get(vuln.asset_id)
        if not asset or asset.asset_type not in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            continue

        # Determine parent domain
        if asset.asset_type == AssetType.DOMAIN:
            parent_domain = asset.name
        else:
            parts = asset.name.split('.')
            if len(parts) >= 2:
                parent_domain = '.'.join(parts[-2:])
            else:
                parent_domain = asset.name

        if parent_domain in domain_groups:
            domain_groups[parent_domain]['vulnerabilities'].append({
                'asset_name': asset.name,
                'vulnerability': {
                    'title': vuln.title,
                    'severity': vuln.severity.value,
                    'cve_id': vuln.cve_id,
                    'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                    'is_resolved': vuln.is_resolved
                }
            })

    # Calculate domain risk scores and analysis
    for domain, data in domain_groups.items():
        # Risk scoring based on vulnerabilities
        risk_score = 0
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for vuln_data in data['vulnerabilities']:
            severity = vuln_data['vulnerability']['severity']
            severity_counts[severity] += 1

            # Risk scoring weights
            if severity == 'critical':
                risk_score += 10
            elif severity == 'high':
                risk_score += 7
            elif severity == 'medium':
                risk_score += 4
            elif severity == 'low':
                risk_score += 2
            elif severity == 'info':
                risk_score += 1

        # Collect technologies and ports
        for asset in data['assets']:
            if asset.asset_metadata:
                http_probe = asset.asset_metadata.get('http_probe', {})
                if http_probe.get('tech'):
                    data['technologies'].update(http_probe.get('tech', []))

                ports = asset.asset_metadata.get('ports', [])
                for port in ports:
                    if isinstance(port, dict) and 'port' in port:
                        data['ports'].add(f"{port['port']}/{port.get('protocol', 'tcp')}")

        # Finalize domain analysis
        domain_analysis[domain] = {
            'total_assets': len(data['assets']),
            'total_subdomains': len(data['subdomains']),
            'total_vulnerabilities': len(data['vulnerabilities']),
            'risk_score': risk_score,
            'risk_level': calculate_risk_level(risk_score),
            'severity_distribution': severity_counts,
            'technologies': list(data['technologies']),
            'open_ports': list(data['ports']),
            'subdomains': data['subdomains'][:10],  # Limit to first 10 for report
            'vulnerability_details': data['vulnerabilities'][:5]  # Limit to top 5 for report
        }

    # Sort domains by risk score
    sorted_domains = sorted(domain_analysis.items(), key=lambda x: x[1]['risk_score'], reverse=True)

    return {
        'domain_breakdown': dict(sorted_domains),
        'total_domains': len(domain_analysis),
        'high_risk_domains': len([d for d in domain_analysis.values() if d['risk_level'] in ['critical', 'high']]),
        'domains_with_vulnerabilities': len([d for d in domain_analysis.values() if d['total_vulnerabilities'] > 0])
    }

def calculate_risk_level(risk_score):
    """Calculate risk level based on risk score"""
    if risk_score >= 50:
        return 'critical'
    elif risk_score >= 25:
        return 'high'
    elif risk_score >= 10:
        return 'medium'
    elif risk_score >= 5:
        return 'low'
    else:
        return 'minimal'

def analyze_threat_intelligence(vulnerabilities, assets):
    """Analyze enhanced threat intelligence with business impact context"""
    threat_intelligence = {
        'attack_vectors': {},
        'business_impact_analysis': {},
        'remediation_priority_matrix': [],
        'vulnerability_patterns': {},
        'threat_trends': {}
    }

    # Create asset lookup
    asset_lookup = {asset.id: asset for asset in assets}

    # Analyze attack vectors
    attack_vector_mapping = {
        'web': ['xss', 'sql', 'csrf', 'lfi', 'rfi', 'ssrf', 'xxe'],
        'network': ['port', 'service', 'protocol', 'ssh', 'ftp', 'telnet'],
        'application': ['auth', 'session', 'crypto', 'injection', 'deserialization'],
        'infrastructure': ['ssl', 'tls', 'certificate', 'dns', 'subdomain'],
        'configuration': ['default', 'misconfiguration', 'exposure', 'disclosure']
    }

    for vuln in vulnerabilities:
        asset = asset_lookup.get(vuln.asset_id)
        if not asset:
            continue

        # Determine attack vector
        attack_vector = 'unknown'
        vuln_text = (vuln.title + ' ' + (vuln.description or '')).lower()

        for vector, keywords in attack_vector_mapping.items():
            if any(keyword in vuln_text for keyword in keywords):
                attack_vector = vector
                break

        if attack_vector not in threat_intelligence['attack_vectors']:
            threat_intelligence['attack_vectors'][attack_vector] = {
                'count': 0,
                'severities': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'examples': []
            }

        threat_intelligence['attack_vectors'][attack_vector]['count'] += 1
        threat_intelligence['attack_vectors'][attack_vector]['severities'][vuln.severity.value] += 1

        if len(threat_intelligence['attack_vectors'][attack_vector]['examples']) < 3:
            threat_intelligence['attack_vectors'][attack_vector]['examples'].append({
                'title': vuln.title,
                'asset': asset.name,
                'severity': vuln.severity.value
            })

        # Business impact analysis
        business_impact = determine_business_impact(vuln, asset)
        if business_impact not in threat_intelligence['business_impact_analysis']:
            threat_intelligence['business_impact_analysis'][business_impact] = {
                'count': 0,
                'assets_affected': set(),
                'total_risk_score': 0
            }

        threat_intelligence['business_impact_analysis'][business_impact]['count'] += 1
        threat_intelligence['business_impact_analysis'][business_impact]['assets_affected'].add(asset.name)

        # Add to remediation priority matrix
        priority_score = calculate_remediation_priority(vuln, asset)
        threat_intelligence['remediation_priority_matrix'].append({
            'vulnerability_id': vuln.id,
            'title': vuln.title,
            'asset_name': asset.name,
            'asset_type': asset.asset_type.value,
            'severity': vuln.severity.value,
            'priority_score': priority_score,
            'business_impact': business_impact,
            'remediation_effort': estimate_remediation_effort(vuln),
            'attack_vector': attack_vector
        })

    # Convert sets to counts for JSON serialization
    for impact_data in threat_intelligence['business_impact_analysis'].values():
        impact_data['unique_assets'] = len(impact_data['assets_affected'])
        del impact_data['assets_affected']

    # Sort remediation matrix by priority
    threat_intelligence['remediation_priority_matrix'].sort(
        key=lambda x: x['priority_score'], reverse=True
    )

    # Limit to top 20 for report
    threat_intelligence['remediation_priority_matrix'] = threat_intelligence['remediation_priority_matrix'][:20]

    return threat_intelligence

def determine_business_impact(vulnerability, asset):
    """Determine business impact level based on vulnerability and asset characteristics"""
    # High impact scenarios
    if vulnerability.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
        if asset.asset_type == AssetType.DOMAIN:
            return 'critical'
        elif 'admin' in asset.name.lower() or 'api' in asset.name.lower():
            return 'high'

    # Medium impact scenarios
    if vulnerability.severity == SeverityLevel.MEDIUM:
        if asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
            return 'medium'

    # Low impact scenarios
    if vulnerability.severity in [SeverityLevel.LOW, SeverityLevel.INFO]:
        return 'low'

    return 'medium'  # Default

def calculate_remediation_priority(vulnerability, asset):
    """Calculate remediation priority score"""
    score = 0

    # Severity weight (40% of score)
    severity_weights = {
        SeverityLevel.CRITICAL: 40,
        SeverityLevel.HIGH: 30,
        SeverityLevel.MEDIUM: 20,
        SeverityLevel.LOW: 10,
        SeverityLevel.INFO: 5
    }
    score += severity_weights.get(vulnerability.severity, 0)

    # Asset criticality weight (30% of score)
    if asset.asset_type == AssetType.DOMAIN:
        score += 30
    elif asset.asset_type == AssetType.SUBDOMAIN:
        if any(keyword in asset.name.lower() for keyword in ['admin', 'api', 'login', 'auth']):
            score += 25
        else:
            score += 15
    elif asset.asset_type == AssetType.SERVICE:
        score += 20
    else:
        score += 10

    # Exposure weight (20% of score)
    if asset.asset_metadata:
        http_probe = asset.asset_metadata.get('http_probe', {})
        if http_probe.get('status_code'):
            score += 20  # Publicly accessible
        else:
            score += 10  # Internal

    # Age weight (10% of score)
    if vulnerability.discovered_at:
        days_old = (datetime.utcnow() - vulnerability.discovered_at).days
        if days_old > 30:
            score += 10  # Older vulnerabilities get higher priority
        elif days_old > 7:
            score += 5

    return min(score, 100)  # Cap at 100

def estimate_remediation_effort(vulnerability):
    """Estimate remediation effort level"""
    title_lower = vulnerability.title.lower()

    # High effort
    if any(keyword in title_lower for keyword in ['architecture', 'design', 'framework', 'major']):
        return 'high'

    # Medium effort
    if any(keyword in title_lower for keyword in ['configuration', 'update', 'patch', 'version']):
        return 'medium'

    # Low effort
    if any(keyword in title_lower for keyword in ['header', 'cookie', 'redirect', 'disclosure']):
        return 'low'

    return 'medium'  # Default
