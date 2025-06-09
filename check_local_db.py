#!/usr/bin/env python3
"""
Check the local database status
"""

from app import create_app, db
from models import Vulnerability
from sqlalchemy import inspect

app = create_app()
with app.app_context():
    # Check database columns
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns('vulnerability')]
    print(f"Database columns ({len(columns)}): {columns}")
    
    # Check vulnerabilities
    vulns = Vulnerability.query.all()
    print(f"\nFound {len(vulns)} vulnerabilities")
    
    if vulns:
        v = vulns[0]
        print(f"First vulnerability: {v.title}")
        print(f"Has confidence_score: {hasattr(v, 'confidence_score')}")
        print(f"Has is_validated: {hasattr(v, 'is_validated')}")
        print(f"Has template_name: {hasattr(v, 'template_name')}")
        
        # Try to access the new fields
        try:
            print(f"confidence_score value: {getattr(v, 'confidence_score', 'NOT_FOUND')}")
            print(f"is_validated value: {getattr(v, 'is_validated', 'NOT_FOUND')}")
            print(f"template_name value: {getattr(v, 'template_name', 'NOT_FOUND')}")
        except Exception as e:
            print(f"Error accessing new fields: {e}")
    
    # Check if we can create a vulnerability with new fields
    try:
        test_vuln = Vulnerability(
            title="Test Vulnerability",
            description="Test description",
            severity="medium",
            asset_id=1,
            organization_id=1,
            confidence_score=85,
            is_validated=True,
            template_name="test-template"
        )
        print("\n✅ Can create vulnerability with new fields")
    except Exception as e:
        print(f"\n❌ Cannot create vulnerability with new fields: {e}")
