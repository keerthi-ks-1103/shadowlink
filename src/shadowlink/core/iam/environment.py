#!/usr/bin/env python3
"""
ShadowLink IAM Environment Loader & Validator
Handles loading, validation, and querying of IAM environments for threat simulation.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass

@dataclass
class User:
    """IAM User data structure"""
    user_id: str
    username: str
    email: str
    full_name: str
    department: str
    primary_role: str
    additional_roles: List[str]
    status: str
    created_date: str
    last_login: str
    mfa_enabled: bool
    password_last_changed: str
    failed_login_attempts: int
    account_locked: bool
    vulnerability_notes: Optional[str] = None

@dataclass
class Role:
    """IAM Role data structure"""
    role_id: str
    permissions: List[str]
    risk_level: str
    description: str
    status: Optional[str] = 'active'
    created_date: Optional[str] = None

class IAMEnvironmentLoader:
    """Loads and validates IAM environments for threat simulation"""
    
    def __init__(self, environment_path: str = None):
        self.environment_path = environment_path
        self.environment_data = None
        self.users = {}
        self.roles = {}
        self.loaded = False
    
    def load_environment(self, environment_path: str = None) -> bool:
        """Load IAM environment from JSON file"""
        
        if environment_path:
            self.environment_path = environment_path
        
        if not self.environment_path:
            raise ValueError("Environment path not provided")
        
        try:
            print(f"🔄 Loading IAM environment from: {self.environment_path}")
            
            with open(self.environment_path, 'r') as f:
                self.environment_data = json.load(f)
            
            # Validate environment structure
            if not self._validate_environment():
                return False
            
            # Parse users and roles
            self._parse_users()
            self._parse_roles()
            
            self.loaded = True
            print(f"✅ IAM environment loaded successfully")
            print(f"   • {len(self.users)} users loaded")
            print(f"   • {len(self.roles)} roles loaded")
            
            return True
            
        except FileNotFoundError:
            print(f"❌ Environment file not found: {self.environment_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON format: {e}")
            return False
        except Exception as e:
            print(f"❌ Error loading environment: {e}")
            return False
    
    def _validate_environment(self) -> bool:
        """Validate environment structure and required fields"""
        
        required_fields = ['environment_name', 'users', 'roles']
        
        for field in required_fields:
            if field not in self.environment_data:
                print(f"❌ Missing required field: {field}")
                return False
        
        # Validate users structure
        if not isinstance(self.environment_data['users'], list):
            print("❌ Users field must be a list")
            return False
        
        # Validate roles structure
        if not isinstance(self.environment_data['roles'], dict):
            print("❌ Roles field must be a dictionary")
            return False
        
        # Validate individual users
        for i, user_data in enumerate(self.environment_data['users']):
            if not self._validate_user(user_data, i):
                return False
        
        print("✅ Environment structure validation passed")
        return True
    
    def _validate_user(self, user_data: Dict, index: int) -> bool:
        """Validate individual user structure"""
        
        required_user_fields = [
            'user_id', 'username', 'email', 'full_name', 
            'primary_role', 'status', 'mfa_enabled'
        ]
        
        for field in required_user_fields:
            if field not in user_data:
                print(f"❌ User {index}: Missing required field '{field}'")
                return False
        
        # Validate role exists
        primary_role = user_data['primary_role']
        if primary_role not in self.environment_data['roles']:
            print(f"❌ User {user_data['user_id']}: Primary role '{primary_role}' not found in roles")
            return False
        
        # Validate additional roles
        additional_roles = user_data.get('additional_roles', [])
        for role in additional_roles:
            if role not in self.environment_data['roles']:
                print(f"❌ User {user_data['user_id']}: Additional role '{role}' not found in roles")
                return False
        
        return True
    
    def _parse_users(self):
        """Parse users from environment data"""
        
        self.users = {}
        
        for user_data in self.environment_data['users']:
            user = User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                email=user_data['email'],
                full_name=user_data['full_name'],
                department=user_data.get('department', 'Unknown'),
                primary_role=user_data['primary_role'],
                additional_roles=user_data.get('additional_roles', []),
                status=user_data['status'],
                created_date=user_data.get('created_date', ''),
                last_login=user_data.get('last_login', ''),
                mfa_enabled=user_data['mfa_enabled'],
                password_last_changed=user_data.get('password_last_changed', ''),
                failed_login_attempts=user_data.get('failed_login_attempts', 0),
                account_locked=user_data.get('account_locked', False),
                vulnerability_notes=user_data.get('vulnerability_notes')
            )
            
            self.users[user.user_id] = user
    
    def _parse_roles(self):
        """Parse roles from environment data"""
        
        self.roles = {}
        
        for role_id, role_data in self.environment_data['roles'].items():
            # Handle both dict and nested dict formats
            if isinstance(role_data, dict) and 'permissions' in role_data:
                role = Role(
                    role_id=role_id,
                    permissions=role_data['permissions'],
                    risk_level=role_data.get('risk_level', 'medium'),
                    description=role_data.get('description', ''),
                    status=role_data.get('status', 'active'),
                    created_date=role_data.get('created_date')
                )
            else:
                # Handle legacy format where role_data might be simpler
                role = Role(
                    role_id=role_id,
                    permissions=role_data if isinstance(role_data, list) else [],
                    risk_level='medium',
                    description=f'Role: {role_id}'
                )
            
            self.roles[role_id] = role
    
    # Query Methods
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def get_role(self, role_id: str) -> Optional[Role]:
        """Get role by ID"""
        return self.roles.get(role_id)
    
    def get_user_permissions(self, user_id: str) -> List[str]:
        """Get all permissions for a user (primary + additional roles)"""
        user = self.get_user(user_id)
        if not user:
            return []
        
        permissions = set()
        
        # Add primary role permissions
        primary_role = self.get_role(user.primary_role)
        if primary_role:
            permissions.update(primary_role.permissions)
        
        # Add additional role permissions
        for role_id in user.additional_roles:
            role = self.get_role(role_id)
            if role:
                permissions.update(role.permissions)
        
        return list(permissions)
    
    def find_users_by_role(self, role_id: str) -> List[User]:
        """Find all users with a specific role"""
        users_with_role = []
        
        for user in self.users.values():
            if user.primary_role == role_id or role_id in user.additional_roles:
                users_with_role.append(user)
        
        return users_with_role
    
    def find_users_by_department(self, department: str) -> List[User]:
        """Find all users in a specific department"""
        return [user for user in self.users.values() if user.department == department]
    
    def find_vulnerable_users(self) -> List[User]:
        """Find users with noted vulnerabilities"""
        return [user for user in self.users.values() if user.vulnerability_notes]
    
    def find_privileged_users(self) -> List[User]:
        """Find users with high-risk roles"""
        privileged_users = []
        
        for user in self.users.values():
            # Check primary role
            primary_role = self.get_role(user.primary_role)
            if primary_role and primary_role.risk_level in ['high', 'critical']:
                privileged_users.append(user)
                continue
            
            # Check additional roles
            for role_id in user.additional_roles:
                role = self.get_role(role_id)
                if role and role.risk_level in ['high', 'critical']:
                    privileged_users.append(user)
                    break
        
        return privileged_users
    
    def find_inactive_users(self) -> List[User]:
        """Find inactive users"""
        return [user for user in self.users.values() if user.status != 'active']
    
    def find_attack_surface(self, user_id: str) -> Dict[str, Any]:
        """Identify potential attack surface for a user"""
        user = self.get_user(user_id)
        if not user:
            return {}
        
        permissions = self.get_user_permissions(user_id)
        
        attack_surface = {
            'user_id': user_id,
            'username': user.username,
            'total_permissions': len(permissions),
            'permissions': permissions,
            'risk_factors': [],
            'attack_vectors': []
        }
        
        # Analyze risk factors
        if not user.mfa_enabled:
            attack_surface['risk_factors'].append('No MFA enabled')
            attack_surface['attack_vectors'].append('credential_stuffing')
        
        if user.failed_login_attempts > 0:
            attack_surface['risk_factors'].append(f'{user.failed_login_attempts} failed login attempts')
            attack_surface['attack_vectors'].append('brute_force_attempt')
        
        if user.additional_roles:
            attack_surface['risk_factors'].append(f'Multiple roles: {len(user.additional_roles) + 1}')
            attack_surface['attack_vectors'].append('privilege_escalation')
        
        if '*' in permissions:
            attack_surface['risk_factors'].append('Administrative privileges')
            attack_surface['attack_vectors'].append('admin_abuse')
        
        if user.vulnerability_notes:
            attack_surface['risk_factors'].append(f'Known vulnerabilities: {user.vulnerability_notes}')
        
        return attack_surface
    
    def get_environment_stats(self) -> Dict[str, Any]:
        """Get comprehensive environment statistics"""
        if not self.loaded:
            return {}
        
        stats = {
            'total_users': len(self.users),
            'total_roles': len(self.roles),
            'active_users': len([u for u in self.users.values() if u.status == 'active']),
            'inactive_users': len([u for u in self.users.values() if u.status != 'active']),
            'privileged_users': len(self.find_privileged_users()),
            'vulnerable_users': len(self.find_vulnerable_users()),
            'users_without_mfa': len([u for u in self.users.values() if not u.mfa_enabled]),
            'departments': list(set(u.department for u in self.users.values())),
            'role_distribution': {}
        }
        
        # Role distribution
        for user in self.users.values():
            role = user.primary_role
            stats['role_distribution'][role] = stats['role_distribution'].get(role, 0) + 1
        
        return stats

# Usage example and testing
def main():
    """Example usage of IAM Environment Loader"""
    
    # Initialize loader
    loader = IAMEnvironmentLoader()
    
    # Load environment
    environment_path = 'data/mock_iam/environments/default.json'
    
    if loader.load_environment(environment_path):
        print(f"\n📊 Environment Statistics:")
        stats = loader.get_environment_stats()
        
        for key, value in stats.items():
            if key != 'role_distribution':
                print(f"   • {key.replace('_', ' ').title()}: {value}")
        
        print(f"\n🔍 Finding vulnerable users...")
        vulnerable_users = loader.find_vulnerable_users()
        
        for user in vulnerable_users[:5]:  # Show first 5
            print(f"   • {user.user_id} ({user.username}): {user.vulnerability_notes}")
        
        print(f"\n🎯 Attack surface analysis for user_001:")
        attack_surface = loader.find_attack_surface('user_001')
        if attack_surface:
            print(f"   • Permissions: {attack_surface['total_permissions']}")
            print(f"   • Risk factors: {len(attack_surface['risk_factors'])}")
            for factor in attack_surface['risk_factors']:
                print(f"     - {factor}")

if __name__ == '__main__':
    main()