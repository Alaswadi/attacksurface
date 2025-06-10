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
        current_app.logger.error(f"Error generating PDF report: {str(e)}")
        return jsonify({'error': 'Failed to generate PDF report'}), 500

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
    """Internal function to get report data for an organization"""
    # Get all assets
    assets = Asset.query.filter_by(organization_id=org.id, is_active=True).all()

    # Get all vulnerabilities
    vulnerabilities = Vulnerability.query.filter_by(organization_id=org.id).all()

    # Calculate asset statistics
    asset_stats = {
        'total': len(assets),
        'by_type': {
            'domains': len([a for a in assets if a.asset_type == AssetType.DOMAIN]),
            'subdomains': len([a for a in assets if a.asset_type == AssetType.SUBDOMAIN]),
            'ip_addresses': len([a for a in assets if a.asset_type == AssetType.IP_ADDRESS]),
            'cloud_resources': len([a for a in assets if a.asset_type == AssetType.CLOUD_RESOURCE]),
            'services': len([a for a in assets if a.asset_type == AssetType.SERVICE])
        }
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
            'id': org.id
        },
        'asset_stats': asset_stats,
        'vulnerability_stats': vuln_stats,
        'risk_metrics': risk_metrics,
        'technology_analysis': tech_analysis,
        'compliance_analysis': compliance_analysis,
        'recent_activity': recent_activity,
        'trend_data': trend_data,
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
    """Generate HTML report content (no external dependencies)"""
    org_name = data.get('organization', {}).get('name', 'Unknown Organization')
    generated_at = datetime.utcnow().strftime('%B %d, %Y at %I:%M %p UTC')

    # Extract key metrics
    asset_stats = data.get('asset_stats', {})
    vuln_stats = data.get('vulnerability_stats', {})
    risk_metrics = data.get('risk_metrics', {})
    compliance = data.get('compliance_analysis', {})
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
        <h1>Security Compliance Report</h1>
        <div class="subtitle">ISO 27001:2013 Assessment</div>
        <div class="subtitle">{org_name}</div>
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

    # Footer
    html_content += f"""
    <div class="footer">
        <p><strong>CONFIDENTIAL</strong></p>
        <p>This report contains confidential security information and should be handled according to
        your organization's information security policies. Distribution should be limited to
        authorized personnel only.</p>
        <p>Report generated on {generated_at} | Framework: ISO 27001:2013</p>
    </div>
</body>
</html>"""

    return html_content
