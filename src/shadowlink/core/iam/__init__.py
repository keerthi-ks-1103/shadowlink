
# ShadowLink IAM Data Schema Design
# This schema supports realistic vulnerability simulation scenarios

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
import json

class AccessLevel(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    ADMIN = "admin"
    DELETE = "delete"

class ResourceType(Enum):
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    API_ENDPOINT = "api_endpoint"
    SYSTEM_CONFIG = "system_config"
    USER_DATA = "user_data"
    FINANCIAL_DATA = "financial_data"

class UserStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"

@dataclass
class Permission:
    """Individual permission - what action can be performed on what resource"""
    resource_id: str
    resource_type: ResourceType
    access_level: AccessLevel
    conditions: Dict[str, str] = field(default_factory=dict)  # e.g., {"time_restricted": "business_hours"}
    
    def to_dict(self) -> Dict:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type.value,
            "access_level": self.access_level.value,
            "conditions": self.conditions
        }

@dataclass
class Role:
    """Role defines a collection of permissions"""
    role_id: str
    name: str
    description: str
    permissions: List[Permission]
    parent_roles: List[str] = field(default_factory=list)  # Role inheritance
    is_privileged: bool = False
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    last_modified: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "role_id": self.role_id,
            "name": self.name,
            "description": self.description,
            "permissions": [p.to_dict() for p in self.permissions],
            "parent_roles": self.parent_roles,
            "is_privileged": self.is_privileged,
            "created_date": self.created_date,
            "last_modified": self.last_modified
        }

@dataclass
class User:
    """User with assigned roles and access history"""
    user_id: str
    username: str
    email: str
    department: str
    manager_id: Optional[str]
    roles: List[str]  # List of role_ids
    status: UserStatus
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    last_login: Optional[str] = None
    password_last_changed: str = field(default_factory=lambda: datetime.now().isoformat())
    failed_login_attempts: int = 0
    is_service_account: bool = False
    
    # Vulnerability indicators
    has_weak_password: bool = False
    account_never_used: bool = False
    excessive_permissions: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "department": self.department,
            "manager_id": self.manager_id,
            "roles": self.roles,
            "status": self.status.value,
            "created_date": self.created_date,
            "last_login": self.last_login,
            "password_last_changed": self.password_last_changed,
            "failed_login_attempts": self.failed_login_attempts,
            "is_service_account": self.is_service_account,
            "has_weak_password": self.has_weak_password,
            "account_never_used": self.account_never_used,
            "excessive_permissions": self.excessive_permissions
        }

@dataclass
class Resource:
    """System resource that can be accessed"""
    resource_id: str
    name: str
    resource_type: ResourceType
    sensitivity_level: str  # "public", "internal", "confidential", "restricted"
    owner_id: str
    location: str  # File path, database name, etc.
    
    def to_dict(self) -> Dict:
        return {
            "resource_id": self.resource_id,
            "name": self.name,
            "resource_type": self.resource_type.value,
            "sensitivity_level": self.sensitivity_level,
            "owner_id": self.owner_id,
            "location": self.location
        }

class IAMEnvironment:
    """Main IAM environment containing all users, roles, permissions, and resources"""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.roles: Dict[str, Role] = {}
        self.resources: Dict[str, Resource] = {}
        self.access_logs: List[Dict] = []
        
    def add_user(self, user: User) -> None:
        self.users[user.user_id] = user
        
    def add_role(self, role: Role) -> None:
        self.roles[role.role_id] = role
        
    def add_resource(self, resource: Resource) -> None:
        self.resources[resource.resource_id] = resource
        
    def can_user_access_resource(self, user_id: str, resource_id: str, access_level: AccessLevel) -> bool:
        """Check if user can access resource with given access level"""
        if user_id not in self.users or resource_id not in self.resources:
            return False
            
        user = self.users[user_id]
        if user.status != UserStatus.ACTIVE:
            return False
            
        # Check all user's roles and their permissions
        for role_id in user.roles:
            if role_id in self.roles:
                role = self.roles[role_id]
                for permission in role.permissions:
                    if (permission.resource_id == resource_id and 
                        permission.access_level == access_level):
                        return True
                        
        return False
    
    def get_user_permissions(self, user_id: str) -> List[Permission]:
        """Get all permissions for a user across all their roles"""
        permissions = []
        if user_id in self.users:
            user = self.users[user_id]
            for role_id in user.roles:
                if role_id in self.roles:
                    permissions.extend(self.roles[role_id].permissions)
        return permissions
    
    def to_dict(self) -> Dict:
        return {
            "users": {uid: user.to_dict() for uid, user in self.users.items()},
            "roles": {rid: role.to_dict() for rid, role in self.roles.items()},
            "resources": {rid: resource.to_dict() for rid, resource in self.resources.items()},
            "access_logs": self.access_logs
        }
    
    def save_to_file(self, filepath: str) -> None:
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'IAMEnvironment':
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        env = cls()
        
        # Load resources first
        for rid, rdata in data.get('resources', {}).items():
            resource = Resource(
                resource_id=rdata['resource_id'],
                name=rdata['name'],
                resource_type=ResourceType(rdata['resource_type']),
                sensitivity_level=rdata['sensitivity_level'],
                owner_id=rdata['owner_id'],
                location=rdata['location']
            )
            env.add_resource(resource)
        
        # Load roles
        for rid, rdata in data.get('roles', {}).items():
            permissions = []
            for pdata in rdata['permissions']:
                permission = Permission(
                    resource_id=pdata['resource_id'],
                    resource_type=ResourceType(pdata['resource_type']),
                    access_level=AccessLevel(pdata['access_level']),
                    conditions=pdata.get('conditions', {})
                )
                permissions.append(permission)
            
            role = Role(
                role_id=rdata['role_id'],
                name=rdata['name'],
                description=rdata['description'],
                permissions=permissions,
                parent_roles=rdata.get('parent_roles', []),
                is_privileged=rdata.get('is_privileged', False),
                created_date=rdata.get('created_date', datetime.now().isoformat()),
                last_modified=rdata.get('last_modified', datetime.now().isoformat())
            )
            env.add_role(role)
        
        # Load users
        for uid, udata in data.get('users', {}).items():
            user = User(
                user_id=udata['user_id'],
                username=udata['username'],
                email=udata['email'],
                department=udata['department'],
                manager_id=udata.get('manager_id'),
                roles=udata['roles'],
                status=UserStatus(udata['status']),
                created_date=udata.get('created_date', datetime.now().isoformat()),
                last_login=udata.get('last_login'),
                password_last_changed=udata.get('password_last_changed', datetime.now().isoformat()),
                failed_login_attempts=udata.get('failed_login_attempts', 0),
                is_service_account=udata.get('is_service_account', False),
                has_weak_password=udata.get('has_weak_password', False),
                account_never_used=udata.get('account_never_used', False),
                excessive_permissions=udata.get('excessive_permissions', False)
            )
            env.add_user(user)
        
        env.access_logs = data.get('access_logs', [])
        return env

# Example usage and sample data creation
def create_sample_iam_environment() -> IAMEnvironment:
    """Create a sample IAM environment with realistic vulnerabilities"""
    env = IAMEnvironment()
    
    # Create sample resources
    resources = [
        Resource("db_hr", "HR Database", ResourceType.DATABASE, "confidential", "admin", "/db/hr"),
        Resource("db_finance", "Finance Database", ResourceType.DATABASE, "restricted", "admin", "/db/finance"),
        Resource("file_payroll", "Payroll Files", ResourceType.FILE_SYSTEM, "restricted", "hr_manager", "/files/payroll"),
        Resource("api_user_mgmt", "User Management API", ResourceType.API_ENDPOINT, "internal", "dev_lead", "/api/users"),
        Resource("config_system", "System Configuration", ResourceType.SYSTEM_CONFIG, "restricted", "admin", "/etc/system")
    ]
    
    for resource in resources:
        env.add_resource(resource)
    
    # Create sample roles with permissions
    roles = [
        Role("admin", "System Administrator", "Full system access", [
            Permission("db_hr", ResourceType.DATABASE, AccessLevel.ADMIN),
            Permission("db_finance", ResourceType.DATABASE, AccessLevel.ADMIN),
            Permission("config_system", ResourceType.SYSTEM_CONFIG, AccessLevel.ADMIN)
        ], is_privileged=True),
        
        Role("hr_manager", "HR Manager", "HR department access", [
            Permission("db_hr", ResourceType.DATABASE, AccessLevel.WRITE),
            Permission("file_payroll", ResourceType.FILE_SYSTEM, AccessLevel.READ)
        ]),
        
        Role("developer", "Software Developer", "Development access", [
            Permission("api_user_mgmt", ResourceType.API_ENDPOINT, AccessLevel.WRITE),
            Permission("db_hr", ResourceType.DATABASE, AccessLevel.READ)  # Potentially excessive
        ]),
        
        # Vulnerable role - too many permissions
        Role("contractor", "External Contractor", "Temporary access", [
            Permission("db_hr", ResourceType.DATABASE, AccessLevel.READ),
            Permission("db_finance", ResourceType.DATABASE, AccessLevel.READ),  # Vulnerability!
            Permission("file_payroll", ResourceType.FILE_SYSTEM, AccessLevel.READ)
        ])
    ]
    
    for role in roles:
        env.add_role(role)
    
    # Create sample users with various vulnerability patterns
    users = [
        User("user_001", "john.admin", "john@company.com", "IT", None, ["admin"], UserStatus.ACTIVE),
        User("user_002", "sarah.hr", "sarah@company.com", "HR", "user_001", ["hr_manager"], UserStatus.ACTIVE),
        User("user_003", "mike.dev", "mike@company.com", "Engineering", "user_001", ["developer"], UserStatus.ACTIVE),
        
        # Vulnerable users
        User("user_004", "temp.contractor", "temp@contractor.com", "External", None, 
             ["contractor"], UserStatus.ACTIVE, has_weak_password=True),
        
        User("user_005", "old.employee", "old@company.com", "Finance", None, 
             ["hr_manager", "developer"], UserStatus.INACTIVE, account_never_used=True),  # Orphaned account
        
        User("user_006", "service.account", "service@company.com", "System", None,
             ["admin"], UserStatus.ACTIVE, is_service_account=True, excessive_permissions=True)
    ]
    
    for user in users:
        env.add_user(user)
    
    return env

# Test the schema
if __name__ == "__main__":
    # Create sample environment
    iam_env = create_sample_iam_environment()
    
    # Test access control
    print("Testing access control:")
    print(f"Can john.admin access HR DB with ADMIN rights? {iam_env.can_user_access_resource('user_001', 'db_hr', AccessLevel.ADMIN)}")
    print(f"Can temp.contractor access Finance DB? {iam_env.can_user_access_resource('user_004', 'db_finance', AccessLevel.READ)}")
    
    # Save to file
    iam_env.save_to_file("sample_iam_environment.json")
    print("\nSample IAM environment saved to 'sample_iam_environment.json'")
    
    # Load from file test
    loaded_env = IAMEnvironment.load_from_file("sample_iam_environment.json")
    print(f"Loaded environment has {len(loaded_env.users)} users and {len(loaded_env.roles)} roles")
