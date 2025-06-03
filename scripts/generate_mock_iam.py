#!/usr/bin/env python3
"""
ShadowLink IAM Mock Data Generator
Generates realistic IAM environments with intentional vulnerabilities for threat simulation.
"""

import json
import random
from datetime import datetime, timedelta
from faker import Faker
import os
from pathlib import Path

fake = Faker()

class IAMDataGenerator:
    def __init__(self):
        self.departments = ['HR', 'Finance', 'Engineering', 'Marketing', 'Sales', 'Operations', 'Legal']
        self.roles = {
            'admin': {
                'permissions': ['*'],
                'risk_level': 'critical',
                'description': 'Full system administrator access'
            },
            'hr_manager': {
                'permissions': ['user.read', 'user.create', 'user.update', 'payroll.read', 'employee.read'],
                'risk_level': 'high',
                'description': 'HR management with employee data access'
            },
            'finance_manager': {
                'permissions': ['finance.read', 'finance.write', 'budget.read', 'budget.write', 'payroll.read'],
                'risk_level': 'high',
                'description': 'Financial data and budget management'
            },
            'developer': {
                'permissions': ['code.read', 'code.write', 'deploy.staging', 'logs.read'],
                'risk_level': 'medium',
                'description': 'Software development and staging deployment'
            },
            'senior_developer': {
                'permissions': ['code.read', 'code.write', 'deploy.staging', 'deploy.production', 'logs.read', 'db.read'],
                'risk_level': 'high',
                'description': 'Senior developer with production access'
            },
            'data_analyst': {
                'permissions': ['data.read', 'reports.generate', 'analytics.read'],
                'risk_level': 'medium',
                'description': 'Data analysis and reporting'
            },
            'marketing_user': {
                'permissions': ['marketing.read', 'marketing.write', 'social.post'],
                'risk_level': 'low',
                'description': 'Marketing content and social media'
            },
            'support_agent': {
                'permissions': ['tickets.read', 'tickets.update', 'customer.read'],
                'risk_level': 'low',
                'description': 'Customer support and ticket management'
            },
            'contractor': {
                'permissions': ['project.read', 'project.write'],
                'risk_level': 'low',
                'description': 'Temporary contractor access'
            }
        }
        
    def generate_user(self, user_id):
        """Generate a single user with potential vulnerabilities"""
        first_name = fake.first_name()
        last_name = fake.last_name()
        department = random.choice(self.departments)
        
        # Assign primary role based on department
        role_mapping = {
            'HR': ['hr_manager', 'support_agent'],
            'Finance': ['finance_manager', 'data_analyst'],
            'Engineering': ['developer', 'senior_developer', 'admin'],
            'Marketing': ['marketing_user', 'data_analyst'],
            'Sales': ['support_agent', 'data_analyst'],
            'Operations': ['admin', 'support_agent'],
            'Legal': ['support_agent', 'data_analyst']
        }
        
        primary_role = random.choice(role_mapping[department])
        
        # Generate user data
        user = {
            'user_id': f'user_{user_id:03d}',
            'username': f'{first_name.lower()}.{last_name.lower()}',
            'email': f'{first_name.lower()}.{last_name.lower()}@company.com',
            'full_name': f'{first_name} {last_name}',
            'department': department,
            'primary_role': primary_role,
            'additional_roles': [],
            'status': 'active',
            'created_date': fake.date_between(start_date='-2y', end_date='-1m').isoformat(),
            'last_login': fake.date_between(start_date='-30d', end_date='today').isoformat(),
            'mfa_enabled': True,
            'password_last_changed': fake.date_between(start_date='-180d', end_date='-1d').isoformat(),
            'failed_login_attempts': 0,
            'account_locked': False
        }
        
        # Inject vulnerabilities randomly
        self._inject_vulnerabilities(user, user_id)
        
        return user
    
    def _inject_vulnerabilities(self, user, user_id):
        """Inject various security vulnerabilities into user accounts"""
        
        # Vulnerability 1: Inactive admin accounts (5% chance)
        if user['primary_role'] == 'admin' and random.random() < 0.05:
            user['status'] = 'inactive'
            user['last_login'] = fake.date_between(start_date='-365d', end_date='-90d').isoformat()
            user['vulnerability_notes'] = 'Inactive admin account - potential security risk'
        
        # Vulnerability 2: High-privilege users without MFA (10% chance)
        if user['primary_role'] in ['admin', 'hr_manager', 'finance_manager', 'senior_developer'] and random.random() < 0.1:
            user['mfa_enabled'] = False
            user['vulnerability_notes'] = user.get('vulnerability_notes', '') + ' No MFA on privileged account;'
        
        # Vulnerability 3: Role overlap/excessive permissions (15% chance)
        if random.random() < 0.15:
            additional_role = random.choice(list(self.roles.keys()))
            if additional_role != user['primary_role']:
                user['additional_roles'].append(additional_role)
                user['vulnerability_notes'] = user.get('vulnerability_notes', '') + f' Role overlap: {additional_role};'
        
        # Vulnerability 4: Stale passwords (20% chance)
        if random.random() < 0.2:
            user['password_last_changed'] = fake.date_between(start_date='-2y', end_date='-365d').isoformat()
            user['vulnerability_notes'] = user.get('vulnerability_notes', '') + ' Stale password (>1 year);'
        
        # Vulnerability 5: Contractor with permanent access (contractors only)
        if user['primary_role'] == 'contractor' and random.random() < 0.3:
            user['status'] = 'active'
            user['created_date'] = fake.date_between(start_date='-18m', end_date='-12m').isoformat()
            user['vulnerability_notes'] = user.get('vulnerability_notes', '') + ' Long-term contractor access;'
        
        # Vulnerability 6: Failed login attempts pattern
        if random.random() < 0.08:
            user['failed_login_attempts'] = random.randint(3, 8)
            user['vulnerability_notes'] = user.get('vulnerability_notes', '') + ' Multiple failed login attempts;'
        
        # Clean up vulnerability notes
        if 'vulnerability_notes' in user:
            user['vulnerability_notes'] = user['vulnerability_notes'].strip(';')
    
    def generate_orphaned_roles(self):
        """Generate roles that aren't assigned to any users"""
        orphaned_roles = []
        
        # Create some legacy roles
        legacy_roles = [
            {
                'role_id': 'legacy_sap_admin',
                'permissions': ['sap.admin', 'sap.config', 'user.admin'],
                'risk_level': 'critical',
                'description': 'Legacy SAP administrator role - should be decommissioned',
                'status': 'deprecated',
                'created_date': fake.date_between(start_date='-3y', end_date='-2y').isoformat()
            },
            {
                'role_id': 'temp_project_manager',
                'permissions': ['project.admin', 'budget.read', 'team.manage'],
                'risk_level': 'medium',
                'description': 'Temporary project management role',
                'status': 'inactive',
                'created_date': fake.date_between(start_date='-1y', end_date='-6m').isoformat()
            }
        ]
        
        return legacy_roles
    
    def generate_environment(self, num_users=25):
        """Generate complete IAM environment"""
        
        print(f"🔄 Generating IAM environment with {num_users} users...")
        
        # Generate users
        users = []
        for i in range(1, num_users + 1):
            user = self.generate_user(i)
            users.append(user)
        
        # Generate orphaned roles
        orphaned_roles = self.generate_orphaned_roles()
        
        # Create complete environment
        environment = {
            'environment_name': 'default',
            'generated_date': datetime.now().isoformat(),
            'generator_version': '1.0',
            'total_users': len(users),
            'total_roles': len(self.roles) + len(orphaned_roles),
            'roles': {**self.roles, **{role['role_id']: role for role in orphaned_roles}},
            'users': users,
            'vulnerability_summary': self._generate_vulnerability_summary(users, orphaned_roles)
        }
        
        return environment
    
    def _generate_vulnerability_summary(self, users, orphaned_roles):
        """Generate summary of intentionally injected vulnerabilities"""
        summary = {
            'total_vulnerabilities': 0,
            'inactive_admins': 0,
            'no_mfa_privileged': 0,
            'role_overlaps': 0,
            'stale_passwords': 0,
            'long_term_contractors': 0,
            'failed_login_patterns': 0,
            'orphaned_roles': len(orphaned_roles)
        }
        
        for user in users:
            if 'vulnerability_notes' in user:
                summary['total_vulnerabilities'] += 1
                notes = user['vulnerability_notes']
                
                if 'Inactive admin' in notes:
                    summary['inactive_admins'] += 1
                if 'No MFA' in notes:
                    summary['no_mfa_privileged'] += 1
                if 'Role overlap' in notes:
                    summary['role_overlaps'] += 1
                if 'Stale password' in notes:
                    summary['stale_passwords'] += 1
                if 'contractor access' in notes:
                    summary['long_term_contractors'] += 1
                if 'failed login' in notes:
                    summary['failed_login_patterns'] += 1
        
        return summary
    
    def save_environment(self, environment, output_path):
        """Save environment to JSON file"""
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(environment, f, indent=2, default=str)
        
        print(f"✅ IAM environment saved to: {output_path}")
        print(f"📊 Generated {environment['total_users']} users with {environment['vulnerability_summary']['total_vulnerabilities']} vulnerabilities")

def main():
    """Main execution function"""
    generator = IAMDataGenerator()
    
    # Generate environment
    environment = generator.generate_environment(num_users=30)
    
    # Define output path
    output_path = Path('data/mock_iam/environments/default.json')
    
    # Save to file
    generator.save_environment(environment, output_path)
    
    # Print vulnerability summary
    vuln_summary = environment['vulnerability_summary']
    print(f"\n🔍 Vulnerability Summary:")
    print(f"   • Inactive admin accounts: {vuln_summary['inactive_admins']}")
    print(f"   • Privileged users without MFA: {vuln_summary['no_mfa_privileged']}")
    print(f"   • Users with role overlaps: {vuln_summary['role_overlaps']}")
    print(f"   • Stale passwords (>1 year): {vuln_summary['stale_passwords']}")
    print(f"   • Long-term contractor access: {vuln_summary['long_term_contractors']}")
    print(f"   • Failed login patterns: {vuln_summary['failed_login_patterns']}")
    print(f"   • Orphaned roles: {vuln_summary['orphaned_roles']}")
    print(f"\n🎯 Ready for threat simulation!")

if __name__ == '__main__':
    main()