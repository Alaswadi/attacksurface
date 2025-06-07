#!/usr/bin/env python3
"""
Celery tasks for Attack Surface Discovery SaaS
Background tasks for scanning, processing, and notifications
"""

import logging
from datetime import datetime, timedelta
from app import create_app
from models import db, Asset, Vulnerability, Alert, Organization, AssetType, SeverityLevel, AlertType

# Create Flask app and get Celery instance
flask_app = create_app()
celery = flask_app.celery

logger = logging.getLogger(__name__)

@celery.task(bind=True)
def test_task(self):
    """Test task to verify Celery is working"""
    logger.info("Test task executed successfully")
    return "Test task completed"

@celery.task(bind=True)
def scan_domain_task(self, domain, organization_id, scan_type='quick'):
    """
    Background task for domain scanning
    
    Args:
        domain (str): Domain to scan
        organization_id (int): Organization ID
        scan_type (str): Type of scan (quick, deep, full)
    
    Returns:
        dict: Scan results
    """
    try:
        logger.info(f"Starting {scan_type} scan for domain: {domain}")
        
        # Import scanning service
        from services.real_scanning_service import RealScanningService
        scanning_service = RealScanningService()
        
        # Perform the scan
        results = scanning_service.scan_domain(domain, organization_id, scan_type)
        
        logger.info(f"Scan completed for {domain}: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Scan failed for {domain}: {str(e)}")
        self.retry(countdown=60, max_retries=3)
        return {
            'success': False,
            'error': str(e),
            'domain': domain,
            'scan_type': scan_type
        }

@celery.task(bind=True)
def process_scan_results_task(self, scan_results, organization_id):
    """
    Background task to process and store scan results
    
    Args:
        scan_results (dict): Raw scan results
        organization_id (int): Organization ID
    
    Returns:
        dict: Processing summary
    """
    try:
        logger.info(f"Processing scan results for organization {organization_id}")
        
        # Process and store results
        summary = {
            'assets_created': 0,
            'vulnerabilities_found': 0,
            'alerts_generated': 0
        }
        
        # Store discovered assets
        if 'subdomains' in scan_results:
            for subdomain in scan_results['subdomains']:
                asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    organization_id=organization_id,
                    discovered_at=datetime.utcnow(),
                    is_active=True
                )
                db.session.add(asset)
                summary['assets_created'] += 1
        
        # Store vulnerabilities
        if 'vulnerabilities' in scan_results:
            for vuln_data in scan_results['vulnerabilities']:
                vulnerability = Vulnerability(
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description', ''),
                    severity=SeverityLevel.MEDIUM,  # Default severity
                    organization_id=organization_id,
                    discovered_at=datetime.utcnow(),
                    is_resolved=False
                )
                db.session.add(vulnerability)
                summary['vulnerabilities_found'] += 1
        
        # Generate alerts for critical findings
        if summary['vulnerabilities_found'] > 0:
            alert = Alert(
                title=f"Scan completed: {summary['vulnerabilities_found']} vulnerabilities found",
                description=f"Scan discovered {summary['assets_created']} assets and {summary['vulnerabilities_found']} vulnerabilities",
                alert_type=AlertType.VULNERABILITY,
                severity=SeverityLevel.INFO,
                organization_id=organization_id,
                created_at=datetime.utcnow(),
                is_resolved=False
            )
            db.session.add(alert)
            summary['alerts_generated'] += 1
        
        # Commit all changes
        db.session.commit()
        
        logger.info(f"Scan results processed: {summary}")
        return summary
        
    except Exception as e:
        logger.error(f"Failed to process scan results: {str(e)}")
        db.session.rollback()
        self.retry(countdown=60, max_retries=3)
        return {
            'success': False,
            'error': str(e)
        }

@celery.task(bind=True)
def cleanup_old_data_task(self, days_old=30):
    """
    Background task to cleanup old scan data
    
    Args:
        days_old (int): Number of days after which data is considered old
    
    Returns:
        dict: Cleanup summary
    """
    try:
        logger.info(f"Starting cleanup of data older than {days_old} days")
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        
        # Cleanup old resolved vulnerabilities
        old_vulns = Vulnerability.query.filter(
            Vulnerability.is_resolved == True,
            Vulnerability.resolved_at < cutoff_date
        ).count()
        
        Vulnerability.query.filter(
            Vulnerability.is_resolved == True,
            Vulnerability.resolved_at < cutoff_date
        ).delete()
        
        # Cleanup old resolved alerts
        old_alerts = Alert.query.filter(
            Alert.is_resolved == True,
            Alert.resolved_at < cutoff_date
        ).count()
        
        Alert.query.filter(
            Alert.is_resolved == True,
            Alert.resolved_at < cutoff_date
        ).delete()
        
        db.session.commit()
        
        summary = {
            'vulnerabilities_cleaned': old_vulns,
            'alerts_cleaned': old_alerts
        }
        
        logger.info(f"Cleanup completed: {summary}")
        return summary
        
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        db.session.rollback()
        return {
            'success': False,
            'error': str(e)
        }

@celery.task(bind=True)
def send_notification_task(self, user_id, message, notification_type='info'):
    """
    Background task to send notifications
    
    Args:
        user_id (int): User ID to send notification to
        message (str): Notification message
        notification_type (str): Type of notification (info, warning, error)
    
    Returns:
        dict: Notification result
    """
    try:
        logger.info(f"Sending {notification_type} notification to user {user_id}: {message}")
        
        # Here you would implement actual notification sending
        # For now, just log the notification
        
        return {
            'success': True,
            'user_id': user_id,
            'message': message,
            'type': notification_type,
            'sent_at': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

# Periodic tasks (if using Celery Beat)
@celery.task(bind=True)
def periodic_health_check(self):
    """Periodic health check task"""
    try:
        logger.info("Running periodic health check")
        
        # Check database connectivity
        db.session.execute('SELECT 1')
        
        # Check Redis connectivity
        celery.backend.get('health_check')
        
        return {
            'success': True,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'healthy'
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'unhealthy'
        }
