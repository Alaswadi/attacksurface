# Email Templates - AttackSurfacePro

This document describes the professional email template system implemented for AttackSurfacePro, providing automated email notifications for security events and user management.

## Overview

The email template system provides three main types of professional email notifications:

1. **User Invitation Emails** - For RBAC user management
2. **Security Alert Notifications** - For critical vulnerability discoveries
3. **Scan Completion Notifications** - For completed security scans

## Features

### Design & Branding
- **Dark Theme Consistency**: Matches the application's dark theme with `bg-slate-900` backgrounds and `bg-slate-800` cards
- **Professional Branding**: Includes AttackSurfacePro branding and enterprise-grade styling
- **Responsive Design**: Works across different email clients and devices
- **Color-coded Severity**: Uses consistent color coding for vulnerability severities

### Email Types

#### 1. User Invitation Emails
- **Purpose**: Invite new users to join organizations
- **Template**: `templates/emails/user_invitation.html`
- **Features**:
  - Organization and role information
  - Secure invitation links with expiration
  - Professional onboarding information
  - Clear call-to-action buttons

#### 2. Security Alert Notifications
- **Purpose**: Alert users to critical/high severity vulnerabilities
- **Template**: `templates/emails/security_alert.html`
- **Features**:
  - Vulnerability details (CVE, CVSS, category)
  - Affected asset information
  - Security recommendations
  - Organization security summary
  - Color-coded severity indicators

#### 3. Scan Completion Notifications
- **Purpose**: Notify users when security scans complete
- **Template**: `templates/emails/scan_completion.html`
- **Features**:
  - Comprehensive scan statistics
  - Asset discovery summary
  - Vulnerability count breakdown
  - Top vulnerabilities list
  - Scan duration and timing information

## Technical Implementation

### Email Service Architecture
- **Service Class**: `services/email_service.py`
- **SMTP Configuration**: Configurable through Settings → Integrations
- **Template Rendering**: Uses Flask's Jinja2 templating engine
- **Async Processing**: Email sending handled via Celery background tasks

### Database Models
- **EmailConfiguration**: SMTP settings per organization
- **EmailTemplate**: Customizable email templates
- **EmailNotificationSettings**: User notification preferences

### Integration Points

#### Scanning Workflow Integration
- **Large-scale scans**: Automatic completion emails after subdomain discovery and port scanning
- **Vulnerability scans**: Automatic security alerts for critical/high severity findings
- **Progressive scanning**: Real-time notifications as scan stages complete

#### User Management Integration
- **Invitation system**: Automatic emails when admins invite new users
- **Role-based access**: Respects organization boundaries and user permissions
- **Multi-tenant support**: Isolated email configurations per organization

## Configuration

### SMTP Setup
1. Navigate to **Settings → Integrations**
2. Configure SMTP server details:
   - Host, Port, Username, Password
   - TLS/SSL settings
   - From email and display name
3. Test configuration with built-in email test

### Email Template Testing
1. Go to **Settings → Integrations → Email Templates**
2. Select template type (Security Alert or Scan Completion)
3. Enter test email address
4. Send test email to preview template

### Notification Preferences
- Users can configure which email notifications they receive
- Options include: vulnerability alerts, scan completion, new assets, reports
- Digest frequency settings: immediate, hourly, daily, weekly

## Email Client Compatibility

The templates are designed to work across major email clients:
- **Outlook** (Desktop & Web)
- **Gmail** (Web & Mobile)
- **Apple Mail** (macOS & iOS)
- **Thunderbird**
- **Mobile clients** (iOS Mail, Android Gmail)

### Technical Considerations
- **Inline CSS**: All styles are inlined for maximum compatibility
- **Table-based layouts**: Ensures consistent rendering across clients
- **Dark mode support**: Includes media queries for dark mode email clients
- **Fallback fonts**: Uses web-safe font stacks

## Security Features

### Email Security
- **Template injection protection**: All user inputs are properly escaped
- **Secure token generation**: Invitation tokens use cryptographically secure random generation
- **Expiration handling**: All invitation links have configurable expiration times
- **Organization isolation**: Email configurations are isolated per organization

### Privacy & Compliance
- **Unsubscribe links**: All emails include unsubscribe functionality
- **Data minimization**: Only necessary data is included in email templates
- **Audit trail**: Email sending events are logged for compliance

## API Endpoints

### Email Configuration
- `GET/POST /api/settings/email/config` - Manage SMTP configuration
- `POST /api/settings/email/test` - Test SMTP configuration
- `POST /api/settings/email/test-templates` - Test email templates

### Background Tasks
- `send_scan_completion_email_task` - Async scan completion emails
- `send_security_alert_email_task` - Async security alert emails
- `send_user_invitation` - User invitation emails

## Customization

### Template Customization
Email templates can be customized per organization:
1. Templates are stored in the `EmailTemplate` database model
2. Support for both HTML and plain text versions
3. Jinja2 template variables for dynamic content
4. Default templates created automatically for new organizations

### Styling Customization
- Modify `templates/emails/base_email.html` for global styling changes
- Individual templates extend the base template
- CSS variables can be used for organization-specific branding

## Monitoring & Troubleshooting

### Email Delivery Monitoring
- SMTP connection testing built into settings interface
- Email sending status tracking in application logs
- Failed email delivery error handling and retry logic

### Common Issues
1. **SMTP Authentication**: Verify username/password and server settings
2. **Port blocking**: Ensure SMTP ports (587, 465, 25) are not blocked
3. **Spam filtering**: Check spam folders and whitelist sender addresses
4. **Template rendering**: Check Jinja2 template syntax and variable names

## Future Enhancements

### Planned Features
- **Email template editor**: Visual template customization interface
- **A/B testing**: Template performance testing capabilities
- **Advanced analytics**: Email open rates and click tracking
- **Integration APIs**: Webhook support for external email services
- **Bulk operations**: Mass email sending for organization-wide notifications

### Extensibility
The email system is designed to be easily extensible:
- Add new email types by creating new templates and service methods
- Integrate with external email services (SendGrid, Mailgun, etc.)
- Support for rich media content (images, attachments)
- Multi-language template support
