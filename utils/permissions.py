from functools import wraps
from flask import jsonify, abort, redirect, url_for, flash, request
from flask_login import current_user
from models import Organization, OrganizationUser, UserRole


def get_user_organization():
    """Get the current user's organization (either as owner or member)"""
    if not current_user.is_authenticated:
        return None

    # First check if user owns an organization
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if org:
        return org

    # If not an owner, check if user is a member of an organization
    membership = OrganizationUser.query.filter_by(user_id=current_user.id, is_active=True).first()
    if membership:
        return Organization.query.get(membership.organization_id)

    return None


def get_user_membership(organization_id=None):
    """Get the current user's organization membership"""
    if not current_user.is_authenticated:
        return None
    
    if organization_id is None:
        org = get_user_organization()
        if not org:
            return None
        organization_id = org.id
    
    return OrganizationUser.query.filter_by(
        user_id=current_user.id,
        organization_id=organization_id
    ).first()


def is_organization_owner():
    """Check if current user is the organization owner"""
    if not current_user.is_authenticated:
        return False
    org = get_user_organization()
    return org and org.user_id == current_user.id


def has_role(required_role):
    """Check if current user has the required role or higher"""
    if not current_user.is_authenticated:
        return False
    
    # Organization owner always has admin privileges
    if is_organization_owner():
        return True
    
    membership = get_user_membership()
    if not membership:
        return False
    
    if required_role == UserRole.ADMIN:
        return membership.role == UserRole.ADMIN
    elif required_role == UserRole.VIEWER:
        return membership.role in [UserRole.ADMIN, UserRole.VIEWER]
    
    return False


def has_permission(permission):
    """Check if current user has specific permission"""
    if not current_user.is_authenticated:
        return False
    
    # Organization owner always has all permissions
    if is_organization_owner():
        return True
    
    membership = get_user_membership()
    if not membership:
        return False
    
    return membership.has_permission(permission)


def require_role(required_role):
    """Decorator to require specific role for route access"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_role(required_role):
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_permission(permission):
    """Decorator to require specific permission for route access"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(permission):
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('You do not have permission to perform this action.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator to require admin role"""
    return require_role(UserRole.ADMIN)(f)


def viewer_or_admin_required(f):
    """Decorator to require viewer role or higher"""
    return require_role(UserRole.VIEWER)(f)


def get_user_role_display():
    """Get the current user's role for display purposes"""
    if not current_user.is_authenticated:
        return None
    
    if is_organization_owner():
        return "Owner"
    
    membership = get_user_membership()
    if not membership:
        return None
    
    return membership.role.value.title()


def can_manage_users():
    """Check if current user can manage other users"""
    return is_organization_owner() or has_role(UserRole.ADMIN)


def can_modify_assets():
    """Check if current user can add/edit/delete assets"""
    return has_permission('add_assets')


def can_run_scans():
    """Check if current user can run security scans"""
    return has_permission('run_scans')


def can_manage_settings():
    """Check if current user can manage organization settings"""
    return has_permission('manage_settings')


def can_view_reports():
    """Check if current user can view reports"""
    return has_permission('view_reports')


def can_view_assets():
    """Check if current user can view assets"""
    return has_permission('view_assets')


def can_view_vulnerabilities():
    """Check if current user can view vulnerabilities"""
    return has_permission('view_vulnerabilities')


def can_view_technologies():
    """Check if current user can view technologies"""
    return has_permission('view_technologies')
