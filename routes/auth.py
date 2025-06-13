from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, Organization, UserInvitation, OrganizationUser
from forms import LoginForm, RegisterForm, UserProfileForm, ChangePasswordForm
from datetime import datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    import logging

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)

            # Check if there's a pending invitation for this user
            invitation_token = session.get('invitation_token')
            if invitation_token:
                logging.info(f"🎫 User {user.email} logged in with pending invitation")
                session.pop('invitation_token', None)  # Remove from session
                return redirect(url_for('auth.accept_invitation', token=invitation_token))

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
    import logging

    if current_user.is_authenticated:
        logging.info(f"🔄 Already authenticated user {current_user.email} tried to register")
        return redirect(url_for('dashboard'))

    # Check if this is an invitation-based registration
    invitation_token = request.args.get('invitation')
    invitation = None

    if invitation_token:
        logging.info(f"🎫 Registration with invitation token: {invitation_token[:10]}...")
        invitation = UserInvitation.query.filter_by(token=invitation_token, is_accepted=False).first()
        if invitation and invitation.expires_at < datetime.utcnow():
            logging.warning(f"❌ Invitation expired for token: {invitation_token[:10]}...")
            flash('This invitation has expired.', 'error')
            invitation = None
        elif invitation:
            logging.info(f"✅ Valid invitation found for {invitation.email} to join {invitation.organization.name}")

    form = RegisterForm()

    # Pre-populate email if invitation exists
    if invitation and request.method == 'GET':
        form.email.data = invitation.email
        logging.info(f"📧 Pre-populated email field with {invitation.email}")

    if form.validate_on_submit():
        logging.info(f"📝 Registration form submitted for {form.email.data}")

        # Validate invitation if provided
        if invitation_token:
            if not invitation:
                logging.error(f"❌ Invalid invitation token during form submission: {invitation_token[:10]}...")
                flash('Invalid or expired invitation link.', 'error')
                return render_template('auth/register.html', form=form, invitation=invitation)

            # Ensure email matches invitation
            if form.email.data != invitation.email:
                logging.error(f"❌ Email mismatch: form={form.email.data}, invitation={invitation.email}")
                flash('Email address must match the invitation.', 'error')
                return render_template('auth/register.html', form=form, invitation=invitation)

        # Check if user already exists (double-check to prevent race conditions)
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            logging.error(f"❌ User {form.email.data} already exists during registration!")

            # If this is an invitation-based registration and user exists,
            # redirect them to the invitation acceptance flow
            if invitation:
                logging.info(f"🔄 Redirecting existing user to invitation acceptance")
                return redirect(url_for('auth.accept_invitation', token=invitation.token))
            else:
                flash('A user with this email already exists. Please log in instead.', 'error')
                return redirect(url_for('auth.login'))

        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)

        try:
            db.session.add(user)
            db.session.flush()  # Get user ID
            logging.info(f"👤 Created new user: {user.email} (ID: {user.id})")

            if invitation:
                # User is joining via invitation - add to organization
                logging.info(f"🏢 INVITATION FOUND: Adding user to organization {invitation.organization.name} as {invitation.role.value}")
                logging.info(f"🔍 Invitation details: ID={invitation.id}, Token={invitation.token[:10]}..., Org_ID={invitation.organization_id}")

                membership = OrganizationUser(
                    user_id=user.id,
                    organization_id=invitation.organization_id,
                    role=invitation.role,
                    joined_at=datetime.utcnow(),
                    is_active=True
                )

                # Mark invitation as accepted
                invitation.is_accepted = True
                invitation.accepted_at = datetime.utcnow()

                db.session.add(membership)
                db.session.commit()

                # Log them in
                login_user(user)

                logging.info(f"✅ Successfully created user and added to organization {invitation.organization.name}")
                logging.info(f"🔍 Membership created: User_ID={user.id}, Org_ID={invitation.organization_id}, Role={invitation.role.value}")
                flash(f'Account created and joined {invitation.organization.name} successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Regular registration - create default organization
                logging.warning(f"⚠️ NO INVITATION FOUND: Creating default organization for {user.username}")
                logging.info(f"🔍 invitation_token={invitation_token}, invitation object={invitation}")
                org = Organization(name=f"{user.username}'s Organization", user_id=user.id)
                db.session.add(org)
                db.session.commit()

                logging.info(f"✅ Successfully created user and default organization")
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
            logging.error(f"❌ Registration failed for {form.email.data}: {str(e)}")
            flash('Registration failed. Please try again.', 'error')

    return render_template('auth/register.html', form=form, invitation=invitation)

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
    import logging

    # Add detailed logging for debugging
    logging.info(f"🔍 Invitation acceptance started for token: {token[:10]}...")

    # Find the invitation
    invitation = UserInvitation.query.filter_by(token=token, is_accepted=False).first()

    if not invitation:
        logging.warning(f"❌ Invalid or expired invitation token: {token[:10]}...")
        flash('Invalid or expired invitation link.', 'error')
        return redirect(url_for('auth.login'))

    # Check if invitation has expired
    if invitation.expires_at < datetime.utcnow():
        logging.warning(f"❌ Invitation expired for {invitation.email}")
        flash('This invitation has expired.', 'error')
        return redirect(url_for('auth.login'))

    logging.info(f"✅ Valid invitation found for {invitation.email} to join org {invitation.organization.name}")

    # Check if user already exists
    existing_user = User.query.filter_by(email=invitation.email).first()

    logging.info(f"🔍 User existence check for {invitation.email}: {'EXISTS' if existing_user else 'NEW USER'}")

    if existing_user:
        logging.info(f"👤 Existing user found for {invitation.email} (ID: {existing_user.id})")

        # For existing users, require them to be authenticated as the correct user
        if not current_user.is_authenticated:
            logging.info(f"🔒 User {invitation.email} exists but is not authenticated - requiring login")
            flash(f'Please log in as {invitation.email} to accept this invitation.', 'info')
            session['invitation_token'] = token
            return redirect(url_for('auth.login'))

        if current_user.id != existing_user.id:
            logging.warning(f"🔒 User {invitation.email} exists but current user is {current_user.email} - requiring correct login")
            flash(f'Please log in as {invitation.email} to accept this invitation.', 'info')
            session['invitation_token'] = token
            return redirect(url_for('auth.login'))

        # User exists and is authenticated, add them to the organization
        try:
            # Check if they're already a member
            existing_membership = OrganizationUser.query.filter_by(
                user_id=existing_user.id,
                organization_id=invitation.organization_id
            ).first()

            if existing_membership:
                logging.info(f"ℹ️ User {invitation.email} is already a member of org {invitation.organization_id}")
                flash('You are already a member of this organization.', 'info')
                return redirect(url_for('dashboard'))

            # Add user to organization
            membership = OrganizationUser(
                user_id=existing_user.id,
                organization_id=invitation.organization_id,
                role=invitation.role,
                joined_at=datetime.utcnow(),
                is_active=True
            )

            # Mark invitation as accepted
            invitation.is_accepted = True
            invitation.accepted_at = datetime.utcnow()

            db.session.add(membership)
            db.session.commit()

            logging.info(f"✅ Added existing user {invitation.email} to org {invitation.organization.name} as {invitation.role.value}")
            flash(f'Successfully joined {invitation.organization.name}!', 'success')

            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            logging.error(f"❌ Failed to add existing user to organization: {str(e)}")
            flash('Failed to accept invitation. Please try again.', 'error')
            return redirect(url_for('auth.login'))

    else:
        # User doesn't exist, redirect to registration with invitation data
        logging.info(f"🆕 NEW USER DETECTED: {invitation.email} has no existing account")
        logging.info(f"🔄 Redirecting to registration form with invitation token: {token[:10]}...")
        session['invitation_token'] = token
        flash(f'Please create an account to join {invitation.organization.name}.', 'info')
        return redirect(url_for('auth.register', invitation=token))

@auth_bp.route('/debug-invitation/<token>')
def debug_invitation(token):
    """Debug route to test invitation logic without side effects"""
    from models import UserInvitation, User
    import logging

    logging.info(f"🔍 DEBUG: Testing invitation token: {token[:10]}...")

    # Find the invitation
    invitation = UserInvitation.query.filter_by(token=token, is_accepted=False).first()

    debug_info = {
        'token': token[:10] + '...',
        'invitation_found': invitation is not None,
        'invitation_details': None,
        'user_exists': None,
        'expected_flow': None,
        'current_user': None
    }

    if invitation:
        debug_info['invitation_details'] = {
            'email': invitation.email,
            'organization': invitation.organization.name,
            'role': invitation.role.value,
            'expires_at': invitation.expires_at.isoformat(),
            'is_expired': invitation.expires_at < datetime.utcnow()
        }

        # Check if user exists
        existing_user = User.query.filter_by(email=invitation.email).first()
        debug_info['user_exists'] = existing_user is not None

        if existing_user:
            debug_info['user_details'] = {
                'id': existing_user.id,
                'username': existing_user.username,
                'email': existing_user.email
            }
            debug_info['expected_flow'] = 'LOGIN_REQUIRED'
        else:
            debug_info['expected_flow'] = 'REGISTRATION_FORM'

    if current_user.is_authenticated:
        debug_info['current_user'] = {
            'id': current_user.id,
            'email': current_user.email,
            'username': current_user.username
        }

    # Return JSON response for easy debugging
    from flask import jsonify
    return jsonify(debug_info)

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management page"""
    import logging

    profile_form = UserProfileForm(
        original_email=current_user.email
    )
    password_form = ChangePasswordForm()

    # Pre-populate the profile form
    if request.method == 'GET':
        profile_form.email.data = current_user.email

    # Handle profile update
    if request.method == 'POST' and 'update_profile' in request.form:
        if profile_form.validate_on_submit():
            try:
                current_user.email = profile_form.email.data
                db.session.commit()

                logging.info(f"✅ User {current_user.id} updated profile successfully")
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('auth.profile'))

            except Exception as e:
                db.session.rollback()
                logging.error(f"❌ Failed to update profile for user {current_user.id}: {str(e)}")
                flash('Failed to update profile. Please try again.', 'error')

    # Handle password change
    if request.method == 'POST' and 'change_password' in request.form:
        if password_form.validate_on_submit():
            if current_user.check_password(password_form.current_password.data):
                try:
                    current_user.set_password(password_form.new_password.data)
                    db.session.commit()

                    logging.info(f"✅ User {current_user.id} changed password successfully")
                    flash('Password changed successfully!', 'success')
                    return redirect(url_for('auth.profile'))

                except Exception as e:
                    db.session.rollback()
                    logging.error(f"❌ Failed to change password for user {current_user.id}: {str(e)}")
                    flash('Failed to change password. Please try again.', 'error')
            else:
                flash('Current password is incorrect.', 'error')

    return render_template('profile.html',
                         profile_form=profile_form,
                         password_form=password_form)


