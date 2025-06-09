
import random
from typing import Dict, List, Any, Tuple, Optional
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))

from base_attack import (
    BaseAttack,
    AttackResult,
    calculate_attack_severity,
    generate_remediation_suggestions
)

def safe_get_attribute(obj, attribute, default=None):
    """Safely get attribute from object or dictionary"""
    if hasattr(obj, attribute):
        return getattr(obj, attribute)
    elif isinstance(obj, dict):
        return obj.get(attribute, default)
    else:
        return default
class PrivilegeEscalationAttack(BaseAttack):
    """
    Privilege Escalation Attack Simulation
    
    Simulates various privilege escalation techniques:
    - Role inheritance exploitation
    - Permission accumulation
    - Temporary privilege abuse
    - Cross-department role access
    - Administrative backdoors
    """
    
    def __init__(self):
        super().__init__(
            name="Privilege Escalation",
            description="Simulates attempts to gain higher privileges than originally assigned"
        )
        
        # Role hierarchy and risk levels
        self.role_hierarchy = {
            "user": 1,
            "developer": 2,
            "support": 2,
            "analyst": 3,
            "team_lead": 4,
            "manager": 5,
            "hr_manager": 6,
            "finance_manager": 6,
            "system_admin": 7,
            "admin": 8,
            "super_admin": 9
        }
        
        # High-value target roles
        self.high_value_roles = [
            "admin", "super_admin", "system_admin", 
            "finance_manager", "hr_manager"
        ]
        
        # Escalation paths (source_role -> possible_target_roles)
        self.escalation_paths = {
            "user": ["developer", "support", "analyst"],
            "developer": ["team_lead", "system_admin"],
            "support": ["team_lead", "analyst"],
            "analyst": ["manager", "team_lead"],
            "team_lead": ["manager", "system_admin"],
            "manager": ["hr_manager", "finance_manager", "admin"],
            "hr_manager": ["admin"],
            "finance_manager": ["admin"],
            "system_admin": ["admin", "super_admin"]
        }
        self.base_escalation_rate = 0.5  # Increased from lower values
        self.role_confusion_base = 0.6   # High success for role confusion
        self.cross_dept_base = 0.4       # Increased cross-department success
        self.temp_abuse_base = 0.45
    
    def can_attack(self, iam_env, target_user_id: str) -> bool:
        """
        Check if privilege escalation attack can be attempted
        
        Args:
            iam_env: IAM environment instance
            target_user_id: Target user ID
            
        Returns:
            True if attack is possible, False otherwise
        """
        if not super().can_attack(iam_env, target_user_id):
            return False
        
        user = iam_env.get_user(target_user_id)
        user_roles = iam_env.get_user_roles(target_user_id)
        
        # Need at least one role to escalate from
        if not user_roles:
            return False
        
        # Check if user has potential escalation paths
        for role in user_roles:
            if role in self.escalation_paths:
                return True
        
        # Check for multiple roles (potential for role confusion attacks)
        if len(user_roles) > 1:
            return True
        
        return False
    
    def execute(self, iam_env, target_user_id: str) -> AttackResult:
        user = iam_env.get_user(target_user_id)
        if not user:
            print(f"[DEBUG] User {target_user_id} not found")
            return self._create_failed_result(target_user_id, "User not found")

        can_escalate = self.can_attack(iam_env, target_user_id)
        print(f"[DEBUG] can_attack for user {target_user_id}: {can_escalate}")
        if not can_escalate:
            return self._create_failed_result(target_user_id, "No privilege escalation paths available")

        user_roles = iam_env.get_user_roles(target_user_id)
        current_permissions = iam_env.get_user_permissions(target_user_id)

        escalation_strategy, target_role, success_probability = self._analyze_escalation_opportunities(
            iam_env, target_user_id, user_roles
            )

        print(f"[DEBUG] escalation_strategy: {escalation_strategy}, target_role: {target_role}, success_probability: {success_probability}")

    # For testing, temporarily force success_probability high to check flow:
    # success_probability = 0.9  # uncomment to test positive success flow

        attack_details = self._simulate_escalation_attempt(
            escalation_strategy, user_roles, target_role, success_probability
            )

        attack_success = random.random() < success_probability
        print(f"[DEBUG] attack_success: {attack_success}")

        if attack_success:
            return self._create_successful_result(
                iam_env, target_user_id, escalation_strategy, 
                target_role, attack_details, current_permissions
                )
        else:
            return self._create_failed_result(
                target_user_id, 
                f"Privilege escalation to {target_role} failed", 
                attack_details
                )

    
    
    def _analyze_escalation_opportunities(self, iam_env, target_user_id: str, 
                                       user_roles: List[str]) -> Tuple[str, str, float]:
        """
        Analyze available escalation opportunities and choose the best strategy
        
        Args:
            iam_env: IAM environment instance
            target_user_id: Target user ID
            user_roles: Current user roles
            
        Returns:
            Tuple of (strategy, target_role, success_probability)
        """
        strategies = []
        
        # Strategy 1: Direct role escalation
        for current_role in user_roles:
            if current_role in self.escalation_paths:
                for target_role in self.escalation_paths[current_role]:
                    success_prob = self._calculate_direct_escalation_probability(
                        current_role, target_role
                    )
                    strategies.append(("direct_escalation", target_role, success_prob))
        
        # Strategy 2: Role confusion (multiple roles)
        if len(user_roles) > 1:
            highest_role = max(user_roles, key=lambda r: self.role_hierarchy.get(r, 0))
            success_prob = self._calculate_role_confusion_probability(user_roles)
            strategies.append(("role_confusion", highest_role, success_prob))
        
        # Strategy 3: Cross-department escalation
        user = iam_env.get_user(target_user_id)
        user_dept = getattr(user, "department", "")
        if user_dept:
            cross_dept_targets = self._find_cross_department_targets(iam_env, user_dept)
            for target_role in cross_dept_targets:
                success_prob = self._calculate_cross_department_probability(user_roles, target_role)
                strategies.append(("cross_department", target_role, success_prob))
        
        # Strategy 4: Temporary privilege abuse
        temp_targets = ["system_admin", "admin"]
        for target_role in temp_targets:
            if target_role not in user_roles:
                success_prob = self._calculate_temporary_abuse_probability(user_roles)
                strategies.append(("temporary_abuse", target_role, success_prob))
        
        # Choose the strategy with highest success probability
        if not strategies:
            return "no_strategy", "none", 0.0
        
        best_strategy = max(strategies, key=lambda x: x[2])
        return best_strategy
    
    def _calculate_direct_escalation_probability(self, current_role: str, target_role: str) -> float:
        """Calculate success probability for direct role escalation"""
        current_level = self.role_hierarchy.get(current_role, 1)
        target_level = self.role_hierarchy.get(target_role, 1)
        
        # Base probability decreases with role gap
        level_gap = target_level - current_level
        base_prob = max(0.25, self.base_escalation_rate - (level_gap * 0.05))
        
        # High-value roles are harder to escalate to
        if target_role in self.high_value_roles:
            base_prob *= 0.8
        
        return min(base_prob, 0.9)
    
    def _calculate_role_confusion_probability(self, user_roles: List[str]) -> float:
        """Calculate success probability for role confusion attacks"""
        # More roles = higher confusion potential
        base_prob = self.role_confusion_base + (len(user_roles) * 0.15)
        
        # Check for conflicting role combinations
        role_levels = [self.role_hierarchy.get(role, 1) for role in user_roles]
        level_spread = max(role_levels) - min(role_levels)
        
        if level_spread >= 3:  # Significant level difference
            base_prob *= 1.8
        
        return min(base_prob, 0.9)
    
    def _calculate_cross_department_probability(self, user_roles: List[str], target_role: str) -> float:
        """Calculate success probability for cross-department escalation"""
        base_prob = self.cross_dept_base
        
        # Users with multiple departments have higher success
        if any(role in ["developer", "system_admin", "support"] for role in user_roles):
            base_prob *= 2.5 
        
        return min(base_prob, 0.7)
    
    def _calculate_temporary_abuse_probability(self, user_roles: List[str]) -> float:
        """Calculate success probability for temporary privilege abuse"""
        base_prob = 0.2
        
        # IT and system roles have higher access to temporary privileges
        if any(role in ["developer", "system_admin", "support"] for role in user_roles):
            base_prob *= 2.0
        
        return min(base_prob, 0.5)
    
    def _find_cross_department_targets(self, iam_env, user_dept: str) -> List[str]:
        """Find potential cross-department escalation targets"""
        dept_role_mapping = {
            "IT": ["system_admin", "admin"],
            "Finance": ["finance_manager"],
            "HR": ["hr_manager"],
            "Operations": ["manager", "team_lead"],
            "Security": ["admin", "system_admin"]
        }
        
        targets = []
        for dept, roles in dept_role_mapping.items():
            if dept != user_dept:
                targets.extend(roles)
        
        return list(set(targets))
    
    def _simulate_escalation_attempt(self, strategy: str, current_roles: List[str], 
                                   target_role: str, success_probability: float) -> Dict[str, Any]:
        """
        Simulate the escalation attempt details
        
        Args:
            strategy: Escalation strategy used
            current_roles: Current user roles
            target_role: Target role for escalation
            success_probability: Calculated success probability
            
        Returns:
            Dictionary with attack simulation details
        """
        escalation_techniques = {
            "direct_escalation": [
                "Role assignment manipulation", "Permission inheritance abuse",
                "Workflow exploitation", "API endpoint abuse"
            ],
            "role_confusion": [
                "Multiple role exploitation", "Permission overlap abuse",
                "Role precedence manipulation", "Context switching attack"
            ],
            "cross_department": [
                "Department transfer simulation", "Cross-functional access abuse",
                "Shared resource exploitation", "Inter-department role mimicry"
            ],
            "temporary_abuse": [
                "Temporary access extension", "Emergency privilege abuse",
                "Maintenance window exploitation", "Service account impersonation"
            ]
        }
        
        techniques_used = escalation_techniques.get(strategy, ["Generic escalation"])
        
        attack_details = {
            "escalation_strategy": strategy,
            "current_roles": current_roles,
            "target_role": target_role,
            "success_probability": round(success_probability, 3),
            "techniques_used": random.sample(techniques_used, min(2, len(techniques_used))),
            "attack_duration_minutes": random.randint(10, 120),
            "tools_used": random.choice([
                "PowerShell Empire", "BloodHound", "Custom Scripts",
                "Metasploit", "Manual Exploitation", "Social Engineering"
            ]),
            "detection_evasion": [
                "Gradual privilege increase", "Normal working hours attack",
                "Legitimate tool usage", "Low-noise techniques"
            ],
            "persistence_methods": [
                "Role assignment modification", "Permission caching",
                "Backdoor account creation", "Token manipulation"
            ]
        }
        
        return attack_details
    
    def _create_successful_result(self, iam_env, target_user_id: str, strategy: str,
                                target_role: str, attack_details: Dict[str, Any],
                                original_permissions: List[str]) -> AttackResult:
        """Create successful privilege escalation result"""
        
        # Get elevated permissions
        elevated_permissions = iam_env.get_permissions(target_role)
        new_permissions = list(set(original_permissions + elevated_permissions))
        
        # Calculate severity
        severity = calculate_attack_severity(new_permissions, [target_role])
        
        # Enhanced attack details
        attack_details.update({
            "escalation_successful": True,
            "original_permissions_count": len(original_permissions),
            "new_permissions_count": len(new_permissions),
            "permissions_gained": len(new_permissions) - len(original_permissions),
            "elevated_role": target_role,
            "privilege_level_increase": self.role_hierarchy.get(target_role, 1)
        })
        
        # Generate specific remediation suggestions
        remediation = self._generate_escalation_remediation(strategy, target_role, attack_details)
        
        result = AttackResult(
            attack_name=self.name,
            target_user_id=target_user_id,
            success=True,
            severity=severity,
            access_gained=new_permissions,
            details=attack_details,
            remediation_suggestions=remediation
        )
        
        self.log_attack(result)
        return result
    
    def _create_failed_result(self, target_user_id: str, reason: str,
                            attack_details: Dict[str, Any] = None) -> AttackResult:
        """Create failed privilege escalation result"""
        
        if attack_details is None:
            attack_details = {}
        
        attack_details.update({
            "escalation_successful": False,
            "failure_reason": reason
        })
        
        result = AttackResult(
            attack_name=self.name,
            target_user_id=target_user_id,
            success=False,
            severity="low",
            access_gained=[],
            details=attack_details,
            remediation_suggestions=[
                "Monitor for privilege escalation attempts",
                "Review role assignment procedures",
                "Implement privilege escalation detection"
            ]
        )
        
        self.log_attack(result)
        return result
    
    def _generate_escalation_remediation(self, strategy: str, target_role: str,
                                       attack_details: Dict[str, Any]) -> List[str]:
        """Generate specific remediation suggestions based on escalation type"""
        
        base_suggestions = [
            "Implement principle of least privilege",
            "Regular access reviews and audits",
            "Monitor privilege escalation activities"
        ]
        
        strategy_specific = {
            "direct_escalation": [
                "Implement role assignment approval workflows",
                "Add monitoring for role modifications",
                "Restrict direct role escalation paths"
            ],
            "role_confusion": [
                "Review users with multiple roles",
                "Implement role conflict detection",
                "Clarify role precedence rules"
            ],
            "cross_department": [
                "Implement department-based access controls",
                "Review cross-departmental role assignments",
                "Add approval for cross-department access"
            ],
            "temporary_abuse": [
                "Implement temporary privilege expiration",
                "Monitor emergency access usage",
                "Add approval for temporary privilege grants"
            ]
        }
        
        suggestions = base_suggestions + strategy_specific.get(strategy, [])
        
        # Add role-specific suggestions
        if target_role in self.high_value_roles:
            suggestions.extend([
                f"Implement additional security for {target_role} role",
                "Add multi-approval for high-privilege roles",
                "Implement privileged access management (PAM)"
            ])
        
        return suggestions


# Example usage and testing
if __name__ == "__main__":
    print("🔍 Privilege Escalation Attack Module Test")
    
    # Mock IAM environment for testing
    class MockIAMEnv:
        def __init__(self):
            self.users = {
                "user_001": {
                    "user_id": "user_001",
                    "name": "John Developer",
                    "status": "active",
                    "department": "IT",
                    "roles": ["developer", "user"]
                }
            }
            
            self.role_permissions = {
                "user": ["system.read", "profile.edit"],
                "developer": ["code.read", "code.write", "deploy.staging"],
                "team_lead": ["team.manage", "project.read", "deploy.production"],
                "system_admin": ["system.admin", "user.manage", "config.write"],
                "admin": ["admin.full_access", "system.config", "user.delete"]
            }
        
        def get_user(self, user_id):
            return self.users.get(user_id)
        
        def get_user_roles(self, user_id):
            user = self.get_user(user_id)
            return getattr(user,"roles", []) if user else []
        
        def get_user_permissions(self, user_id):
            roles = self.get_user_roles(user_id)
            permissions = []
            for role in roles:
                permissions.extend(self.get_permissions(role))
            return list(set(permissions))
        
        def get_permissions(self, role_id):
            return self.role_permissions.get(role_id, [])
    
    # Test privilege escalation attack
    mock_iam = MockIAMEnv()
    pe_attack = PrivilegeEscalationAttack()
    
    print("\n🧪 Testing Privilege Escalation Attack:")
    result = pe_attack.execute(mock_iam, "user_001")
    
    print(f"✅ Attack Result: {result.success}")
    print(f"   Strategy: {result.details.get('escalation_strategy')}")
    print(f"   Target Role: {result.details.get('target_role')}")
    print(f"   Severity: {result.severity}")
    print(f"   Permissions Gained: {result.details.get('permissions_gained', 0)}")
    print(f"   Techniques: {result.details.get('techniques_used', [])}")
    
    print(f"\n📊 Attack Statistics:")
    print(f"   Success Rate: {pe_attack.get_success_rate():.1f}%")
    print(f"   Total Attempts: {pe_attack.attack_count}")
    
    print("\n🎯 Privilege Escalation Attack Module Ready!")