from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid


class AttackResult:
    """
    Standardized attack result structure
    """
    def __init__(self, 
                 attack_name: str,
                 target_user_id: str,
                 success: bool,
                 severity: str = "low",
                 access_gained: List[str] = None,
                 details: Dict[str, Any] = None,
                 remediation_suggestions: List[str] = None):
        
        self.attack_id = str(uuid.uuid4())[:8]
        self.attack_name = attack_name
        self.target_user_id = target_user_id
        self.success = success
        self.severity = severity  # low, medium, high, critical
        self.access_gained = access_gained or []
        self.details = details or {}
        self.remediation_suggestions = remediation_suggestions or []
        self.timestamp = datetime.now().isoformat()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert attack result to dictionary for logging"""
        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "target_user_id": self.target_user_id,
            "success": self.success,
            "severity": self.severity,
            "access_gained": self.access_gained,
            "details": self.details,
            "remediation_suggestions": self.remediation_suggestions,
            "timestamp": self.timestamp
        }


class BaseAttack(ABC):
    """
    Abstract base class for all attack simulations in ShadowLink
    
    All attack modules must inherit from this class and implement the execute method
    """
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.logs = []
        self.attack_count = 0
        self.successful_attacks = 0
        
    @abstractmethod
    def execute(self, iam_env, target_user_id: str) -> AttackResult:
        """
        Execute the attack simulation against a target user
        
        Args:
            iam_env: IAM environment instance with user/role/permission data
            target_user_id: The target user to attack
            
        Returns:
            AttackResult object containing attack outcome and details
        """
        pass
    
    def can_attack(self, iam_env, target_user_id: str) -> bool:
        """
        Check if this attack is applicable to the target user
        Override this method to add attack-specific preconditions
        
        Args:
            iam_env: IAM environment instance
            target_user_id: The target user
            
        Returns:
            True if attack can be attempted, False otherwise
        """
        user = iam_env.get_user(target_user_id)
        if user is None:
            return False
        
        # Handle both dictionary and object user types
        if hasattr(user, 'status'):
            return user.status == "active"
        elif isinstance(user, dict):
            return user.get("status") == "active"
        else:
            # If no status attribute, assume active
            return True
    
    def log_attack(self, result: AttackResult):
        """
        Log the attack result
        
        Args:
            result: AttackResult object to log
        """
        self.logs.append(result.to_dict())
        self.attack_count += 1
        if result.success:
            self.successful_attacks += 1
    
    def get_success_rate(self) -> float:
        """
        Calculate attack success rate
        
        Returns:
            Success rate as percentage (0-100)
        """
        if self.attack_count == 0:
            return 0.0
        return (self.successful_attacks / self.attack_count) * 100
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """
        Get distribution of attack severities
        
        Returns:
            Dictionary with severity levels as keys and counts as values
        """
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for log_entry in self.logs:
            severity = log_entry.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts
    
    def get_recent_attacks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most recent attack logs
        
        Args:
            limit: Maximum number of logs to return
            
        Returns:
            List of recent attack log dictionaries
        """
        return self.logs[-limit:] if len(self.logs) >= limit else self.logs
    
    def reset_logs(self):
        """Clear all attack logs and reset counters"""
        self.logs = []
        self.attack_count = 0
        self.successful_attacks = 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive attack statistics
        
        Returns:
            Dictionary with attack statistics
        """
        return {
            "attack_name": self.name,
            "description": self.description,
            "total_attempts": self.attack_count,
            "successful_attacks": self.successful_attacks,
            "success_rate": f"{self.get_success_rate():.1f}%",
            "severity_distribution": self.get_severity_distribution(),
            "recent_attacks": len(self.logs)
        }
    
    def __str__(self) -> str:
        return f"{self.name} Attack (Success Rate: {self.get_success_rate():.1f}%)"
    
    def __repr__(self) -> str:
        return f"BaseAttack(name='{self.name}', attempts={self.attack_count}, success_rate={self.get_success_rate():.1f}%)"


# Utility functions for attack modules

def get_user_attribute(user, attribute: str, default=None):
    """
    Safely get user attribute, handling both object and dictionary user types
    
    Args:
        user: User object or dictionary
        attribute: Attribute name to get
        default: Default value if attribute not found
        
    Returns:
        Attribute value or default
    """
    if hasattr(user, attribute):
        return getattr(user, attribute, default)
    elif isinstance(user, dict):
        return user.get(attribute, default)
    else:
        return default


def calculate_attack_severity(access_gained: List[str], user_roles: List[str]) -> str:
    """
    Calculate attack severity based on access gained and user roles
    
    Args:
        access_gained: List of permissions/resources accessed
        user_roles: List of user roles
        
    Returns:
        Severity level: low, medium, high, critical
    """
    high_risk_permissions = [
        "admin.full_access", "finance.write", "hr.salary_access", 
        "system.config", "user.delete", "backup.access"
    ]
    
    high_risk_roles = ["admin", "finance_manager", "hr_manager", "system_admin"]
    
    # Critical: Admin access or multiple high-risk permissions
    if any("admin" in perm for perm in access_gained) or len(access_gained) >= 5:
        return "critical"
    
    # High: High-risk permissions or roles
    if any(perm in high_risk_permissions for perm in access_gained):
        return "high"
    
    if any(role in high_risk_roles for role in user_roles):
        return "high"
    
    # Medium: Multiple permissions or sensitive data access
    if len(access_gained) >= 3 or any("finance" in perm or "hr" in perm for perm in access_gained):
        return "medium"
    
    # Low: Basic access
    return "low"


def generate_remediation_suggestions(attack_name: str, success: bool, details: Dict[str, Any]) -> List[str]:
    """
    Generate remediation suggestions based on attack results
    
    Args:
        attack_name: Name of the attack
        success: Whether attack was successful
        details: Attack details dictionary
        
    Returns:
        List of remediation suggestions
    """
    suggestions = []
    
    if not success:
        return ["No immediate action required - attack was unsuccessful"]
    
    # Common suggestions based on attack type
    if "brute_force" in attack_name.lower():
        suggestions.extend([
            "Enable multi-factor authentication (MFA) for this user",
            "Implement account lockout policies after failed login attempts",
            "Monitor for unusual login patterns",
            "Consider password complexity requirements"
        ])
    
    elif "privilege_escalation" in attack_name.lower():
        suggestions.extend([
            "Review and audit user role assignments",
            "Implement principle of least privilege",
            "Add approval workflows for role changes",
            "Monitor privilege usage patterns"
        ])
    
    elif "lateral_movement" in attack_name.lower():
        suggestions.extend([
            "Implement network segmentation",
            "Monitor cross-system access patterns",
            "Review shared account usage",
            "Add additional authentication for system-to-system access"
        ])
    
    # Add MFA suggestion if not enabled
    if details.get("mfa_enabled") is False:
        suggestions.append("Enable MFA for enhanced security")
    
    # Add account review if inactive
    if details.get("account_status") == "inactive":
        suggestions.append("Review and disable unused accounts")
    
    return list(set(suggestions))  # Remove duplicates


# Example usage and testing
if __name__ == "__main__":
    print("🔍 BaseAttack Abstract Class Test")
    print("This is an abstract class - cannot be instantiated directly")
    print("Attack modules should inherit from BaseAttack and implement execute()")
    
    # Test utility functions
    print("\n🧪 Testing Utility Functions:")
    
    # Test severity calculation
    test_access = ["finance.read", "hr.read", "admin.config"]
    test_roles = ["developer", "admin"]
    severity = calculate_attack_severity(test_access, test_roles)
    print(f"✅ Severity for {test_access}: {severity}")
    
    # Test remediation suggestions
    suggestions = generate_remediation_suggestions("brute_force", True, {"mfa_enabled": False})
    print(f"✅ Remediation suggestions: {suggestions[:2]}...")
    
    # Test user attribute getter
    class TestUser:
        def __init__(self):
            self.status = "active"
            self.mfa_enabled = True
    
    test_user = TestUser()
    print(f"✅ User attribute test: {get_user_attribute(test_user, 'status')}")
    
    print("\n🎯 Ready for specific attack implementations!")