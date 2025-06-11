from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, Organization, UserInvitation, OrganizationUser
from forms import LoginForm, RegisterForm
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard')
            flash('Login successful!', 'success')
            return redirect(next_page)
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Create default organization for the user
            org = Organization(name=f"{user.username}'s Organization", user_id=user.id)
            db.session.add(org)
            db.session.commit()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('auth/register.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/accept-invitation/<token>')
def accept_invitation(token):
    """Accept user invitation and create account or add to organization"""
    from models import UserInvitation, OrganizationUser, User
    from datetime import datetime

    # Find the invitation
    invitation = UserInvitation.query.filter_by(token=token, is_accepted=False).first()

    if not invitation:
        flash('Invalid or expired invitation link.', 'error')
        return redirect(url_for('auth.login'))

    # Check if invitation has expired
    if invitation.expires_at < datetime.utcnow():
        flash('This invitation has expired.', 'error')
        return redirect(url_for('auth.login'))

    # Check if user already exists
    existing_user = User.query.filter_by(email=invitation.email).first()

    if existing_user:
        # User exists, just add them to the organization
        try:
            # Check if they're already a member
            existing_membership = OrganizationUser.query.filter_by(
                user_id=existing_user.id,
                organization_id=invitation.organization_id
            ).first()

            if existing_membership:
                flash('You are already a member of this organization.', 'info')
                return redirect(url_for('dashboard'))

            # Add user to organization
            membership = OrganizationUser(
                user_id=existing_user.id,
                organization_id=invitation.organization_id,
                role=invitation.role,
                can_view_assets=invitation.can_view_assets,
                can_add_assets=invitation.can_add_assets,
                can_run_scans=invitation.can_run_scans,
                can_view_reports=invitation.can_view_reports,
                can_manage_settings=invitation.can_manage_settings
            )

            # Mark invitation as accepted
            invitation.is_accepted = True
            invitation.accepted_at = datetime.utcnow()

            db.session.add(membership)
            db.session.commit()

            flash(f'Successfully joined {invitation.organization.name}!', 'success')

            # Log them in if they're not already
            if not current_user.is_authenticated:
                login_user(existing_user)

            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash('Failed to accept invitation. Please try again.', 'error')
            return redirect(url_for('auth.login'))

    else:
        # User doesn't exist, redirect to registration with invitation data
        session['invitation_token'] = token
        flash('Please create an account to accept the invitation.', 'info')
        return redirect(url_for('auth.register', invitation=token))

@auth_bp.route('/register-with-invitation/<token>')
def register_with_invitation(token):
    """Register new user with invitation"""
    from models import UserInvitation

    # Find the invitation
    invitation = UserInvitation.query.filter_by(token=token, is_accepted=False).first()

    if not invitation:
        flash('Invalid or expired invitation link.', 'error')
        return redirect(url_for('auth.register'))

    # Check if invitation has expired
    if invitation.expires_at < datetime.utcnow():
        flash('This invitation has expired.', 'error')
        return redirect(url_for('auth.register'))

    # Pre-fill the registration form with invitation email
    form = RegisterForm()
    form.email.data = invitation.email

    if form.validate_on_submit():
        try:
            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                is_email_verified=True  # Email is verified through invitation
            )
            user.set_password(form.password.data)

            db.session.add(user)
            db.session.flush()  # Get user ID

            # Add user to organization
            membership = OrganizationUser(
                user_id=user.id,
                organization_id=invitation.organization_id,
                role=invitation.role,
                can_view_assets=invitation.can_view_assets,
                can_add_assets=invitation.can_add_assets,
                can_run_scans=invitation.can_run_scans,
                can_view_reports=invitation.can_view_reports,
                can_manage_settings=invitation.can_manage_settings
            )

            # Mark invitation as accepted
            invitation.is_accepted = True
            invitation.accepted_at = datetime.utcnow()

            db.session.add(membership)
            db.session.commit()

            # Log them in
            login_user(user)

            flash(f'Account created and joined {invitation.organization.name} successfully!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')

    return render_template('auth/register.html', form=form, invitation=invitation)
