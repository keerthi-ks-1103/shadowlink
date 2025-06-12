#!/usr/bin/env python3
"""
User Targeting Debug Script
Tests the user targeting logic that your simulation engine uses
"""

import sys
import os
from pathlib import Path

# Add the src directory to Python path
src_path = Path(__file__).parent / 'src'
if src_path.exists():
    sys.path.insert(0, str(src_path))

# Try to import your environment manager
try:
    # Adjust this import based on your actual module structure
    from core.iam.environment import IAMEnvironmentManager
    environment_manager_available = True
except ImportError as e:
    print(f"❌ Could not import IAMEnvironmentManager: {e}")
    environment_manager_available = False

def test_user_targeting():
    """Test user targeting logic"""
    
    print("🎯 ShadowLink User Targeting Debug")
    print("=" * 40)
    
    if not environment_manager_available:
        print("❌ Cannot proceed without IAMEnvironmentManager")
        return
    
    # Initialize environment manager
    manager = IAMEnvironmentManager()
    
    # Try to load environment
    env_file = 'data/mock_iam/environments/default.json'
    
    if not Path(env_file).exists():
        print(f"❌ Environment file not found: {env_file}")
        return
    
    print(f"📖 Loading environment from: {env_file}")
    
    if not manager.load_environment(env_file):
        print("❌ Failed to load environment")
        return
    
    print("✅ Environment loaded successfully")
    
    # Get all users
    all_users = manager.get_all_users()
    print(f"\n👥 Total users in environment: {len(all_users)}")
    
    if not all_users:
        print("❌ No users found - this explains why no attacks were executed!")
        return
    
    # Analyze each user for targeting potential
    print("\n🔍 User Analysis for Attack Targeting:")
    print("-" * 50)
    
    attack_candidates = []
    
    for user_id, user in all_users.items():
        print(f"\n👤 User: {user_id} ({user.username})")
        print(f"   Status: {user.status}")
        print(f"   MFA: {'✅' if user.mfa_enabled else '❌'}")
        print(f"   Failed Logins: {user.failed_login_attempts}")
        print(f"   Last Login: {user.last_login_days_ago} days ago")
        print(f"   Account Locked: {'✅' if user.account_locked else '❌'}")
        print(f"   Primary Role: {user.primary_role}")
        print(f"   Additional Roles: {user.additional_roles}")
        
        # Determine if this user is a good attack target
        target_reasons = []
        
        # Check various targeting criteria
        if user.status == 'active':
            target_reasons.append("active_account")
        
        if not user.mfa_enabled:
            target_reasons.append("no_mfa")
        
        if user.failed_login_attempts > 0:
            target_reasons.append("previous_failed_attempts")
        
        if user.last_login_days_ago > 30:
            target_reasons.append("stale_account")
        
        if not user.account_locked:
            target_reasons.append("unlocked_account")
        
        # Check for privileged roles
        privileged_roles = ['admin', 'administrator', 'manager', 'finance_manager', 'hr_manager']
        if user.primary_role in privileged_roles or any(role in privileged_roles for role in user.additional_roles):
            target_reasons.append("privileged_role")
        
        if target_reasons:
            attack_candidates.append({
                'user': user,
                'reasons': target_reasons
            })
            print(f"   🎯 ATTACK TARGET: {', '.join(target_reasons)}")
        else:
            print(f"   ⚪ Not a good target")
    
    # Summary
    print(f"\n📊 TARGETING SUMMARY:")
    print(f"   Total Users: {len(all_users)}")
    print(f"   Attack Candidates: {len(attack_candidates)}")
    
    if attack_candidates:
        print(f"\n🎯 TOP ATTACK TARGETS:")
        for i, candidate in enumerate(attack_candidates[:5], 1):
            user = candidate['user']
            reasons = candidate['reasons']
            print(f"   {i}. {user.user_id} ({user.username})")
            print(f"      Reasons: {', '.join(reasons)}")
    else:
        print("\n❌ NO ATTACK CANDIDATES FOUND!")
        print("   This explains why your simulation had 0 attacks.")
        print("\n🔧 Possible solutions:")
        print("   1. Add users with vulnerabilities to your IAM environment")
        print("   2. Set some users' MFA to false")
        print("   3. Add users with failed login attempts")
        print("   4. Ensure some users have 'active' status")
    
    # Test specific attack scenarios
    print(f"\n⚔️  ATTACK SCENARIO TESTING:")
    
    # Test vulnerable users function
    vulnerable_users = manager.find_vulnerable_users()
    print(f"   Vulnerable Users Found: {len(vulnerable_users)}")
    
    # Test privileged users function  
    privileged_users = manager.find_privileged_users()
    print(f"   Privileged Users Found: {len(privileged_users)}")
    
    # Test attack surface analysis
    if all_users:
        first_user_id = list(all_users.keys())[0]
        attack_surface = manager.find_attack_surface(first_user_id)
        print(f"   Attack Surface Analysis Available: {'✅' if attack_surface else '❌'}")
        
        if attack_surface:
            print(f"      Risk Factors: {len(attack_surface.get('risk_factors', []))}")
            print(f"      Attack Vectors: {len(attack_surface.get('attack_vectors', []))}")

def create_sample_vulnerable_environment():
    """Create a sample environment with vulnerable users for testing"""
    
    print("\n🔧 Creating Sample Vulnerable Environment")
    print("=" * 45)
    
    sample_env = {
        "environment_name": "Test Vulnerable Environment",
        "description": "Sample environment with vulnerable users for testing",
        "users": [
            {
                "user_id": "admin001",
                "username": "admin",
                "email": "admin@company.com",
                "full_name": "System Administrator",
                "department": "IT",
                "primary_role": "administrator",
                "additional_roles": [],
                "status": "active",
                "created_date": "2024-01-01",
                "last_login": "2024-06-01",
                "last_login_days_ago": 9,
                "mfa_enabled": False,  # VULNERABLE
                "password_last_changed": "2024-01-01",
                "failed_login_attempts": 2,  # VULNERABLE
                "account_locked": False,
                "vulnerability_notes": "Disabled MFA for troubleshooting"
            },
            {
                "user_id": "user001",
                "username": "jdoe",
                "email": "john.doe@company.com", 
                "full_name": "John Doe",
                "department": "Finance",
                "primary_role": "finance_manager",
                "additional_roles": ["user"],
                "status": "active",
                "created_date": "2024-02-01",
                "last_login": "2024-03-01",
                "last_login_days_ago": 100,  # VULNERABLE - STALE
                "mfa_enabled": True,
                "password_last_changed": "2024-02-01",
                "failed_login_attempts": 0,
                "account_locked": False
            },
            {
                "user_id": "user002", 
                "username": "bsmith",
                "email": "bob.smith@company.com",
                "full_name": "Bob Smith",
                "department": "HR",
                "primary_role": "hr_manager",
                "additional_roles": ["finance_viewer"],
                "status": "active",
                "created_date": "2024-01-15",
                "last_login": "2024-06-08",
                "last_login_days_ago": 2,
                "mfa_enabled": False,  # VULNERABLE
                "password_last_changed": "2024-01-15",
                "failed_login_attempts": 5,  # VULNERABLE
                "account_locked": False
            }
        ],
        "roles": {
            "administrator": {
                "permissions": ["*", "admin", "user_management", "system_config"],
                "risk_level": "critical",
                "description": "Full system administrator"
            },
            "finance_manager": {
                "permissions": ["finance_read", "finance_write", "reports"],
                "risk_level": "high", 
                "description": "Finance department manager"
            },
            "hr_manager": {
                "permissions": ["hr_read", "hr_write", "employee_data"],
                "risk_level": "high",
                "description": "HR department manager"
            },
            "user": {
                "permissions": ["basic_read"],
                "risk_level": "low",
                "description": "Standard user"
            },
            "finance_viewer": {
                "permissions": ["finance_read"],
                "risk_level": "medium",
                "description": "Finance read-only access"
            }
        }
    }
    
    # Save sample environment
    os.makedirs('data/mock_iam/environments', exist_ok=True)
    
    output_file = 'data/mock_iam/environments/vulnerable_test.json'
    
    import json
    with open(output_file, 'w') as f:
        json.dump(sample_env, f, indent=2)
    
    print(f"✅ Created sample vulnerable environment: {output_file}")
    print("🎯 This environment contains:")
    print("   • 1 Admin with no MFA + failed logins")  
    print("   • 1 Finance Manager with stale account")
    print("   • 1 HR Manager with no MFA + many failed logins")
    print("\n💡 Try running your simulation with this environment!")

def main():
    """Run user targeting diagnostics"""
    
    test_user_targeting()
    
    print("\n" + "=" * 60)
    print("Would you like to create a sample vulnerable environment? (y/n)")
    
    # For script automation, let's create it by default
    create_sample_vulnerable_environment()

if __name__ == '__main__':
    main()