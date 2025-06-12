"""
RBAC Migration Script
Migrates existing user data to the new role-based access control system
"""

from models import db, User, Organization, OrganizationUser, UserInvitation, UserRole
from sqlalchemy import text

def migrate_to_rbac():
    """Migrate existing data to RBAC system"""
    print("Starting RBAC migration...")
    
    try:
        # 1. Update existing organization owners to have admin role
        print("1. Updating organization owners...")
        organizations = Organization.query.all()
        for org in organizations:
            # Check if owner already has a membership record
            existing_membership = OrganizationUser.query.filter_by(
                user_id=org.user_id,
                organization_id=org.id
            ).first()
            
            if not existing_membership:
                # Create admin membership for organization owner
                membership = OrganizationUser(
                    user_id=org.user_id,
                    organization_id=org.id,
                    role=UserRole.ADMIN
                )
                db.session.add(membership)
                print(f"   Created admin membership for user {org.user_id} in org {org.id}")
            else:
                # Update existing membership to admin role
                existing_membership.role = UserRole.ADMIN
                print(f"   Updated membership for user {org.user_id} in org {org.id} to admin")
        
        # 2. Update existing non-owner memberships to viewer role (default)
        print("2. Updating existing memberships...")
        memberships = OrganizationUser.query.all()
        for membership in memberships:
            # Check if this user is the organization owner
            org = Organization.query.get(membership.organization_id)
            if org and org.user_id != membership.user_id:
                # Non-owner, set to viewer role
                membership.role = UserRole.VIEWER
                print(f"   Updated membership for user {membership.user_id} to viewer role")
        
        # 3. Update pending invitations to use new role system
        print("3. Updating pending invitations...")
        invitations = UserInvitation.query.filter_by(is_accepted=False).all()
        for invitation in invitations:
            # Set default role to viewer if not already set to admin
            if not hasattr(invitation, 'role') or invitation.role not in [UserRole.ADMIN, UserRole.VIEWER]:
                invitation.role = UserRole.VIEWER
                print(f"   Updated invitation {invitation.id} to viewer role")
        
        # 4. Remove old permission columns (this would be done in actual migration)
        print("4. Schema changes would be applied here in production...")
        print("   - Remove individual permission columns from OrganizationUser")
        print("   - Remove individual permission columns from UserInvitation")
        print("   - Update UserRole enum to only include ADMIN and VIEWER")
        
        # Commit all changes
        db.session.commit()
        print("✅ RBAC migration completed successfully!")
        
        # Print summary
        admin_count = OrganizationUser.query.filter_by(role=UserRole.ADMIN).count()
        viewer_count = OrganizationUser.query.filter_by(role=UserRole.VIEWER).count()
        print(f"\nMigration Summary:")
        print(f"- Admin users: {admin_count}")
        print(f"- Viewer users: {viewer_count}")
        print(f"- Total memberships: {admin_count + viewer_count}")
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        db.session.rollback()
        raise

def verify_migration():
    """Verify the migration was successful"""
    print("\nVerifying migration...")
    
    # Check that all organization owners have admin role
    organizations = Organization.query.all()
    for org in organizations:
        membership = OrganizationUser.query.filter_by(
            user_id=org.user_id,
            organization_id=org.id
        ).first()
        
        if not membership:
            print(f"❌ Missing membership for org owner {org.user_id}")
            return False
        
        if membership.role != UserRole.ADMIN:
            print(f"❌ Org owner {org.user_id} does not have admin role")
            return False
    
    # Check that all memberships have valid roles
    memberships = OrganizationUser.query.all()
    for membership in memberships:
        if membership.role not in [UserRole.ADMIN, UserRole.VIEWER]:
            print(f"❌ Invalid role for membership {membership.id}")
            return False
    
    print("✅ Migration verification passed!")
    return True

if __name__ == "__main__":
    # This would be run as a separate script
    from app import create_app
    
    app = create_app()
    with app.app_context():
        migrate_to_rbac()
        verify_migration()
