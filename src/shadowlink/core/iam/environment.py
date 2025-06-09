"""
ShadowLink IAM Environment Manager - Combined Version
Handles loading, validation, and querying of IAM environments for threat simulation.
Combines features from both environment loader and IAM environment classes.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from dataclasses import dataclass


@dataclass
class User:
    """Enhanced IAM User data structure"""
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
    last_login_days_ago: int = 0
    vulnerability_notes: Optional[str] = None

@dataclass
class Role:
    """Enhanced IAM Role data structure"""
    role_id: str
    permissions: List[str]
    risk_level: str
    description: str
    status: Optional[str] = 'active'
    created_date: Optional[str] = None

@dataclass
class Permission:
    """IAM Permission data structure"""
    permission_id: str
    name: str
    description: str
    resource_type: str
    risk_level: str = 'medium'

class IAMEnvironmentManager:
    """
    Comprehensive IAM Environment Manager for ShadowLink threat simulation.
    Supports both single-file and multi-file IAM environment formats.
    """
    
    def __init__(self, data_path: str = None):
        self.data_path = Path(data_path) if data_path else None
        self.environment_data = None
        self.users: Dict[str, User] = {}
        self.roles: Dict[str, Role] = {}
        self.permissions: Dict[str, Permission] = {}
        self.loaded = False
        self.environment_name = "Unknown"
    
    def load_environment(self, path: Union[str, Path]) -> bool:
        """
        Load IAM environment from either single JSON file or directory structure
        
        Args:
            path: Path to environment file or directory
            
        Returns:
            True if loaded successfully, False otherwise
        """
        path = Path(path)
        
        if path.is_file() and path.suffix == '.json':
            return self._load_single_file_environment(path)
        elif path.is_dir():
            return self._load_multi_file_environment(path)
        else:
            print(f"❌ Invalid path: {path}")
            return False
    
    def _load_single_file_environment(self, file_path: Path) -> bool:
        """Load IAM environment from single JSON file"""
        try:
            print(f"🔄 Loading IAM environment from: {file_path}")
            
            with open(file_path, 'r') as f:
                self.environment_data = json.load(f)
            
            # Validate environment structure
            if not self._validate_single_file_environment():
                return False
            
            # Parse data
            self.environment_name = self.environment_data.get('environment_name', 'Unknown')
            self._parse_users_from_single_file()
            self._parse_roles_from_single_file()
            
            self.loaded = True
            self._print_load_success()
            return True
            
        except Exception as e:
            print(f"❌ Error loading single file environment: {e}")
            return False
    
    def _load_multi_file_environment(self, dir_path: Path) -> bool:
        """Load IAM environment from multiple JSON files"""
        try:
            print(f"🔄 Loading IAM environment from directory: {dir_path}")
            
            # Load users
            users_file = dir_path / "users.json"
            if users_file.exists():
                with open(users_file, "r") as f:
                    users_data = json.load(f)
                    self._parse_users_from_multi_file(users_data)
            
            # Load roles
            roles_file = dir_path / "roles.json"
            if roles_file.exists():
                with open(roles_file, "r") as f:
                    roles_data = json.load(f)
                    self._parse_roles_from_multi_file(roles_data)
            
            # Load permissions (optional)
            permissions_file = dir_path / "permissions.json"
            if permissions_file.exists():
                with open(permissions_file, "r") as f:
                    permissions_data = json.load(f)
                    self._parse_permissions_from_multi_file(permissions_data)
            
            self.loaded = True
            self._print_load_success()
            return True
            
        except Exception as e:
            print(f"❌ Error loading multi-file environment: {e}")
            return False
    
    def _validate_single_file_environment(self) -> bool:
        """Validate single file environment structure"""
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
            if not self._validate_user_data(user_data, i):
                return False
        
        print("✅ Environment structure validation passed")
        return True
    
    def _validate_user_data(self, user_data: Dict, index: int) -> bool:
        """Validate individual user structure"""
        required_user_fields = [
            'user_id', 'username', 'email', 'full_name', 
            'primary_role', 'status', 'mfa_enabled'
        ]
        
        for field in required_user_fields:
            if field not in user_data:
                print(f"❌ User {index}: Missing required field '{field}'")
                return False
        
        return True
    
    def _parse_users_from_single_file(self):
        """Parse users from single file environment data"""
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
                last_login_days_ago=user_data.get('last_login_days_ago', 0),
                vulnerability_notes=user_data.get('vulnerability_notes','')
            )
            
            self.users[user.user_id] = user
    
    def _parse_users_from_multi_file(self, users_data: Dict):
        """Parse users from multi-file format"""
        self.users = {}
        
        for user_data in users_data.get("users", []):
            # Handle both role formats - list of roles or primary + additional
            roles = user_data.get("roles", [])
            primary_role = roles[0] if roles else user_data.get("primary_role", "user")
            additional_roles = roles[1:] if len(roles) > 1 else user_data.get("additional_roles", [])
            
            user = User(
                user_id=user_data['user_id'],
                username=user_data.get('username', user_data['user_id']),
                email=user_data.get('email', f"{user_data['user_id']}@company.com"),
                full_name=user_data.get('name', getattr(user_data,'full_name', 'Unknown')),
                department=getattr(user_data,'department', 'Unknown'),
                primary_role=primary_role,
                additional_roles=additional_roles,
                status=user_data.get('status', 'active'),
                created_date=getattr(user_data,'created_date', ''),
                last_login=getattr(user_data,'last_login', ''),
                mfa_enabled=user_data.get('mfa_enabled', True),
                password_last_changed=getattr(user_data,'password_last_changed', ''),
                failed_login_attempts=getattr(user_data,'failed_login_attempts', 0),
                account_locked= getattr(user_data,'account_locked', False),
                last_login_days_ago=getattr(user_data,'last_login_days_ago', 0),
                vulnerability_notes=getattr(user_data,'vulnerability_notes')
            )
            
            self.users[user.user_id] = user
    
    def _parse_roles_from_single_file(self):
        """Parse roles from single file environment data"""
        self.roles = {}
        
        for role_id, role_data in self.environment_data['roles'].items():
            if isinstance(role_data, dict) and 'permissions' in role_data:
                role = Role(
                    role_id=role_id,
                    permissions=role_data['permissions'],
                    risk_level=role_data.get('risk_level', 'medium'),
                    description=role_data.get('description', ''),
                    status=role_data.get('status', 'active'),
                    created_date=role_data.get('created_date','')
                )
            else:
                # Handle legacy format
                role = Role(
                    role_id=role_id,
                    permissions=role_data if isinstance(role_data, list) else [],
                    risk_level='medium',
                    description=f'Role: {role_id}'
                )
            
            self.roles[role_id] = role
    
    def _parse_roles_from_multi_file(self, roles_data: Dict):
        """Parse roles from multi-file format"""
        self.roles = {}
        
        for role_data in roles_data.get("roles", []):
            role = Role(
                role_id=role_data['role_id'],
                permissions=role_data.get('permissions', []),
                risk_level=role_data.get('risk_level', 'medium'),
                description=role_data.get('description', ''),
                status=role_data.get('status', 'active'),
                created_date=role_data.get('created_date')
            )
            
            self.roles[role.role_id] = role
    
    def _parse_permissions_from_multi_file(self, permissions_data: Dict):
        """Parse permissions from multi-file format"""
        self.permissions = {}
        
        for perm_data in permissions_data.get("permissions", []):
            permission = Permission(
                permission_id=perm_data['permission_id'],
                name=perm_data.get('name', perm_data['permission_id']),
                description=perm_data.get('description', ''),
                resource_type=perm_data.get('resource_type', 'unknown'),
                risk_level=perm_data.get('risk_level', 'medium')
            )
            
            self.permissions[permission.permission_id] = permission
    
    def _print_load_success(self):
        """Print successful load message"""
        print(f"✅ IAM environment '{self.environment_name}' loaded successfully")
        print(f"   • {len(self.users)} users loaded")
        print(f"   • {len(self.roles)} roles loaded")
        if self.permissions:
            print(f"   • {len(self.permissions)} permissions loaded")
    
    # Query Methods
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def get_role(self, role_id: str) -> Optional[Role]:
        """Get role by ID"""
        return self.roles.get(role_id)
    
    def get_permission(self, permission_id: str) -> Optional[Permission]:
        """Get permission by ID"""
        return self.permissions.get(permission_id)
    
    def get_user_roles(self, user_id: str) -> List[str]:
        """Get all role IDs assigned to a user"""
        user = self.get_user(user_id)
        if not user:
            return []
        return [user.primary_role] + user.additional_roles
    
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
    
    def get_role_permissions(self, role_id: str) -> List[str]:
        """Get all permissions for a specific role"""
        role = self.get_role(role_id)
        return role.permissions if role else []
    
    def find_users_by_role(self, role_id: str) -> List[User]:
        """Find all users with a specific role"""
        users_with_role = []
        
        for user in self.users.values():
            if user.primary_role == role_id or role_id in user.additional_roles:
                users_with_role.append(user)
        
        return users_with_role
    
    def find_users_by_department(self, department: str) -> List[User]:
        """Find all users in a specific department"""
        return [user for user in self.users.values() 
                if user.department.lower() == department.lower()]
    
    def find_vulnerable_users(self) -> List[User]:
        """Find users with security vulnerabilities"""
        vulnerable_users = []
        
        for user in self.users.values():
            vulnerabilities = []
            
            # Check for various vulnerability indicators
            if not user.mfa_enabled:
                vulnerabilities.append("no_mfa")
            
            if user.failed_login_attempts >= 3:
                vulnerabilities.append("multiple_failed_logins")
            
            if user.status != "active":
                vulnerabilities.append("inactive_account")
            
            if user.last_login_days_ago > 90:
                vulnerabilities.append("stale_account")
            
            if user.account_locked:
                vulnerabilities.append("locked_account")
            
            if user.vulnerability_notes:
                vulnerabilities.append("documented_vulnerabilities")
            
            # Check for excessive permissions
            user_roles = self.get_user_roles(user.user_id)
            high_risk_roles = ["admin", "administrator", "finance_manager", "hr_manager"]
            if len([role for role in user_roles if role in high_risk_roles]) > 1:
                vulnerabilities.append("excessive_permissions")
            
            if vulnerabilities:
                vulnerable_users.append(user)
            
           
        
        return vulnerable_users
    
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
            'roles': self.get_user_roles(user_id),
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
        
        if '*' in permissions or 'admin' in permissions:
            attack_surface['risk_factors'].append('Administrative privileges')
            attack_surface['attack_vectors'].append('admin_abuse')
        
        if user.last_login_days_ago > 90:
            attack_surface['risk_factors'].append('Stale account (90+ days)')
            attack_surface['attack_vectors'].append('account_takeover')
        
        
        if user.vulnerability_notes:
            attack_surface['risk_factors'].append(f'Known vulnerabilities:{user.vulnerability_notes}')
        return attack_surface
    
    def get_environment_stats(self) -> Dict[str, Any]:
        """Get comprehensive environment statistics"""
        if not self.loaded:
            return {}
        
        vulnerable_users = self.find_vulnerable_users()
        privileged_users = self.find_privileged_users()
        
        # Department distribution
        dept_counts = {}
        for user in self.users.values():
            dept = user.department
            dept_counts[dept] = dept_counts.get(dept, 0) + 1
        
        # Role distribution
        role_counts = {}
        for user in self.users.values():
            role = user.primary_role
            role_counts[role] = role_counts.get(role, 0) + 1
        
        stats = {
            'environment_name': self.environment_name,
            'total_users': len(self.users),
            'total_roles': len(self.roles),
            'total_permissions': len(self.permissions),
            'active_users': len([u for u in self.users.values() if u.status == 'active']),
            'inactive_users': len([u for u in self.users.values() if u.status != 'active']),
            'privileged_users': len(privileged_users),
            'vulnerable_users': len(vulnerable_users),
            'users_without_mfa': len([u for u in self.users.values() if not u.mfa_enabled]),
            'locked_accounts': len([u for u in self.users.values() if u.account_locked]),
            'stale_accounts': len([u for u in self.users.values() if u.last_login_days_ago > 90]),
            'departments': dept_counts,
            'role_distribution': role_counts
        }
        
        return stats
    
    def get_all_users(self) -> Dict[str, User]:
        """Get all users in the system"""
        return self.users
    
    def get_all_roles(self) -> Dict[str, Role]:
        """Get all roles in the system"""
        return self.roles
    
    def get_all_permissions(self) -> Dict[str, Permission]:
        """Get all permissions in the system"""
        return self.permissions


# Usage example and testing
def main():
    """Example usage of Combined IAM Environment Manager"""
    
    # Initialize manager
    manager = IAMEnvironmentManager()
    
    # Try loading from different sources
    test_paths = [
        'data/mock_iam/environments/default.json',  # Single file
        'data/iam',  # Multi-file directory
        'environments/default.json'  # Alternative path
    ]
    
    loaded = False
    for path in test_paths:
        if Path(path).exists():
            if manager.load_environment(path):
                loaded = True
                break
    
    if not loaded:
        print("❌ Could not load any IAM environment from test paths")
        print("📝 Create a test environment file to use this manager")
        return
    
    # Display environment statistics
    print(f"\n📊 Environment Statistics:")
    stats = manager.get_environment_stats()
    
    for key, value in stats.items():
        if key not in ['departments', 'role_distribution']:
            print(f"   • {key.replace('_', ' ').title()}: {value}")
    
    print(f"\n🏢 Department Distribution:")
    for dept, count in stats.get('departments', {}).items():
        print(f"   • {dept}: {count} users")
    
    # Find vulnerable users
    print(f"\n🔍 Vulnerable Users Analysis:")
    vulnerable_users = manager.find_vulnerable_users()
    
    if vulnerable_users:
        for user in vulnerable_users[:5]:  # Show first 5
            vulnerabilities = []
            if not user.mfa_enabled:
                vulnerabilities.append("No MFA")
            if user.failed_login_attempts >= 3:
                vulnerabilities.append("Failed logins")
            if user.status != "active":
                vulnerabilities.append("Inactive")
            if user.last_login_days_ago > 90:
                vulnerabilities.append("Stale")
            
            print(f"   • {user.user_id} ({user.username}): {', '.join(vulnerabilities)}")
    else:
        print("   • No vulnerable users found")
    
    # Attack surface analysis
    if manager.users:
        first_user_id = list(manager.users.keys())[0]
        print(f"\n🎯 Attack Surface Analysis for {first_user_id}:")
        attack_surface = manager.find_attack_surface(first_user_id)
        
        if attack_surface:
            print(f"   • Total Permissions: {attack_surface['total_permissions']}")
            print(f"   • Roles: {', '.join(attack_surface['roles'])}")
            print(f"   • Risk Factors: {len(attack_surface['risk_factors'])}")
            for factor in attack_surface['risk_factors'][:3]:  # Show first 3
                print(f"     - {factor}")
            print(f"   • Potential Attack Vectors: {', '.join(attack_surface['attack_vectors'])}")


if __name__ == '__main__':
    main()