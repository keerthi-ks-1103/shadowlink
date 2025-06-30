import random
from typing import Dict, List, Any
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))

from shadowlink.simulation.attacks.base_attack import (
    BaseAttack,
    AttackResult,
    calculate_attack_severity,
    generate_remediation_suggestions,
    get_user_attribute
)


class BruteForceAttack(BaseAttack):
    """
    Brute Force Attack Simulation
    
    Simulates password brute force attacks against user accounts.
    Success depends on:
    - MFA status (no MFA = higher success chance)
    - Failed login attempts history
    - Account lockout policies
    - Password strength indicators
    """
    
    def __init__(self):
        super().__init__(
            name="Brute Force", 
            description="Simulates password brute force attacks against user login credentials"
        )
        
        # Attack configuration
        self.base_success_rate = 0.45  # 45% base success rate
        self.mfa_protection_factor = 0.2  # MFA reduces success to 20%
        self.lockout_threshold = 5  # Account locks after 5 failed attempts
        self.vulnerable_user_bonus = 0.3
        self.weak_password_multiplier = 5.0
    
    def can_attack(self, iam_env, target_user_id: str) -> bool:
        """
        Check if brute force attack can be attempted
        
        Args:
            iam_env: IAM environment instance
            target_user_id: Target user ID
            
        Returns:
            True if attack is possible, False otherwise
        """
        if not super().can_attack(iam_env, target_user_id):
            return False
            
        user = iam_env.get_user(target_user_id)
        
        # Cannot attack if account is already locked
        if get_user_attribute(user, "account_locked", False):
            return False
        if get_user_attribute(user, "login_disabled", False):
            return False
            
        return True
    
    def execute(self, iam_env, target_user_id: str) -> AttackResult:
        """
        Execute brute force attack simulation
        
        Args:
            iam_env: IAM environment instance
            target_user_id: Target user ID
            
        Returns:
            AttackResult with attack outcome
        """
        user = iam_env.get_user(target_user_id)
        if not user:
            return self._create_failed_result(target_user_id, "User not found")
        
        # Check if attack is possible
        if not self.can_attack(iam_env, target_user_id):
            return self._create_failed_result(
                target_user_id, 
                "Attack not possible - account locked or login disabled"
            )
        
        # Gather user information for attack simulation using safe attribute getter
        mfa_enabled = get_user_attribute(user, "mfa_enabled", True)
        failed_attempts = get_user_attribute(user, "failed_login_attempts", 0)
        password_strength = get_user_attribute(user, "password_strength", "medium")  # weak, medium, strong
        last_password_change = get_user_attribute(user, "last_password_change_days", 30)
        
        # Calculate attack success probability
        success_probability = self._calculate_success_probability(
            mfa_enabled, failed_attempts, password_strength, last_password_change
        )
        
        # Simulate attack attempts
        attack_details = self._simulate_attack_attempts(
            target_user_id, success_probability, failed_attempts
        )
        
        # Determine if attack succeeds
        attack_success = random.random() < success_probability
        
        if attack_success:
            return self._create_successful_result(iam_env, target_user_id, attack_details)
        else:
            return self._create_failed_result(target_user_id, "Brute force attempt failed", attack_details)
    
    def _calculate_success_probability(self, mfa_enabled: bool, failed_attempts: int, 
                                     password_strength: str, last_password_change_days: int) -> float:
        """
        Calculate probability of brute force success based on security factors
        
        Args:
            mfa_enabled: Whether MFA is enabled
            failed_attempts: Number of previous failed login attempts
            password_strength: Password strength (weak/medium/strong)
            last_password_change_days: Days since last password change
            
        Returns:
            Success probability (0.0 to 1.0)
        """
        probability = self.base_success_rate
        
        # MFA significantly reduces success rate
        if mfa_enabled:
            probability *= self.mfa_protection_factor
        else:
            probability *= 3.0  # No MFA triples success rate
        
        # High failed attempts indicate potential vulnerability
        if failed_attempts >= 3:
            probability *= (1 + (failed_attempts * 0.4))  # 40% increase per failed attempt
        
        # Password strength affects success
        strength_multipliers = {
            "weak": self.weak_password_multiplier,
            "medium": 1.0,
            "strong": 0.3
        }
        probability *= strength_multipliers.get(password_strength, 1.5)
        
        # Old passwords are more vulnerable
        if last_password_change_days > 90:
            probability *= 2.0
        elif last_password_change_days > 180:
            probability *= 3.0
        
        if failed_attempts > 0 and not mfa_enabled:
            probability += self.vulnerable_user_bonus
        
        # Cap probability at minimum 0.25 (25%) and maximum 0.95 (95%)
        probability = max(probability, 0.25)
        return min(probability, 0.95)
    
    def _simulate_attack_attempts(self, target_user_id: str, success_probability: float, 
                                failed_attempts: int) -> Dict[str, Any]:
        """
        Simulate the attack process and gather details
        
        Args:
            target_user_id: Target user ID
            success_probability: Calculated success probability
            failed_attempts: Existing failed attempts
            
        Returns:
            Dictionary with attack simulation details
        """
        # Simulate number of attempts needed
        max_attempts = random.randint(50, 500)  # Typical brute force attempts
        attempts_made = random.randint(10, max_attempts)
        
        # Common passwords tried (for realism)
        common_passwords = [
            "password123", "admin", "123456", "qwerty", "password", 
            "letmein", "welcome", "monkey", "dragon", "master"
        ]
        
        attack_details = {
            "attack_method": "password_brute_force",
            "attempts_made": attempts_made,
            "max_attempts": max_attempts,
            "success_probability": round(success_probability, 3),
            "existing_failed_attempts": failed_attempts,
            "common_passwords_tried": random.sample(common_passwords, min(5, len(common_passwords))),
            "attack_duration_minutes": random.randint(5, 60),
            "source_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "curl/7.68.0",
                "Python-requests/2.25.1",
                "Automated-Scanner-v1.0"
            ])
        }
        
        return attack_details
    
    def _create_successful_result(self, iam_env, target_user_id: str, 
                                attack_details: Dict[str, Any]) -> AttackResult:
        """
        Create successful attack result with access details
        
        Args:
            iam_env: IAM environment instance
            target_user_id: Target user ID
            attack_details: Attack simulation details
            
        Returns:
            AttackResult for successful attack
        """
        user = iam_env.get_user(target_user_id)
        user_permissions = iam_env.get_user_permissions(target_user_id)
        user_roles = iam_env.get_user_roles(target_user_id)
        
        # Calculate severity based on access gained
        severity = calculate_attack_severity(user_permissions, user_roles)
        
        # Enhanced attack details for successful attack
        attack_details.update({
            "credentials_compromised": True,
            "account_accessed": True,
            "mfa_bypassed": not get_user_attribute(user, "mfa_enabled", True),
            "access_level": get_user_attribute(user, "access_level", "standard"),
            "department_accessed": get_user_attribute(user, "department", "unknown")
        })
        
        # Generate remediation suggestions
        remediation = generate_remediation_suggestions(
            self.name, True, {
                "mfa_enabled": get_user_attribute(user, "mfa_enabled", True),
                "failed_attempts": get_user_attribute(user, "failed_login_attempts", 0),
                "password_strength": get_user_attribute(user, "password_strength", "medium")
            }
        )
        
        result = AttackResult(
            attack_name=self.name,
            target_user_id=target_user_id,
            success=True,
            severity=severity,
            access_gained=user_permissions,
            details=attack_details,
            remediation_suggestions=remediation
        )
        
        # Log the attack
        self.log_attack(result)
        
        return result
    
    def _create_failed_result(self, target_user_id: str, reason: str, 
                            attack_details: Dict[str, Any] = None) -> AttackResult:
        """
        Create failed attack result
        
        Args:
            target_user_id: Target user ID
            reason: Reason for failure
            attack_details: Optional attack details
            
        Returns:
            AttackResult for failed attack
        """
        if attack_details is None:
            attack_details = {}
        
        attack_details.update({
            "failure_reason": reason,
            "credentials_compromised": False,
            "account_accessed": False
        })
        
        result = AttackResult(
            attack_name=self.name,
            target_user_id=target_user_id,
            success=False,
            severity="low",
            access_gained=[],
            details=attack_details,
            remediation_suggestions=["Monitor for continued brute force attempts", "Consider implementing rate limiting"]
        )
        
        # Log the attack
        self.log_attack(result)
        
        return result


# Enhanced brute force variants
class CredentialStuffingAttack(BruteForceAttack):
    """
    Credential Stuffing variant - uses known username/password combinations
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Credential Stuffing"
        self.description = "Uses leaked credentials from data breaches to attempt login"
        self.base_success_rate = 0.25  # Higher success rate due to real credentials
    
    def _simulate_attack_attempts(self, target_user_id: str, success_probability: float, 
                                failed_attempts: int) -> Dict[str, Any]:
        """Override to simulate credential stuffing specific details"""
        attack_details = super()._simulate_attack_attempts(target_user_id, success_probability, failed_attempts)
        
        # Add credential stuffing specific details
        attack_details.update({
            "attack_method": "credential_stuffing",
            "breach_sources": random.sample([
                "LinkedIn-2012", "Adobe-2013", "Yahoo-2014", "Equifax-2017", 
                "Facebook-2019", "Twitter-2020", "Generic-Database"
            ], random.randint(1, 3)),
            "credential_lists_used": random.randint(1, 5),
            "automated_tool": random.choice([
                "Sentry MBA", "OpenBullet", "Custom Script", "Hydra", "Medusa"
            ])
        })
        
        return attack_details


class DictionaryAttack(BruteForceAttack):
    """
    Dictionary Attack variant - uses common passwords and variations
    """
    
    def __init__(self):
        super().__init__()
        self.name = "Dictionary Attack"
        self.description = "Uses dictionary of common passwords and targeted variations"
        self.base_success_rate = 0.20
    
    def _simulate_attack_attempts(self, target_user_id: str, success_probability: float, 
                                failed_attempts: int) -> Dict[str, Any]:
        """Override to simulate dictionary attack specific details"""
        attack_details = super()._simulate_attack_attempts(target_user_id, success_probability, failed_attempts)
        
        # Add dictionary attack specific details
        dictionaries_used = [
            "rockyou.txt", "common-passwords.txt", "company-specific.txt",
            "seasonal-passwords.txt", "keyboard-patterns.txt"
        ]
        
        attack_details.update({
            "attack_method": "dictionary_attack",
            "dictionaries_used": random.sample(dictionaries_used, random.randint(1, 3)),
            "password_variations": [
                "base_word + numbers", "base_word + special_chars", 
                "capitalization_variants", "year_appended", "common_substitutions"
            ],
            "total_dictionary_size": random.randint(10000, 100000)
        })
        
        return attack_details


# Factory function to create appropriate brute force attack
def create_brute_force_attack(attack_type: str = "standard") -> BruteForceAttack:
    """
    Factory function to create different types of brute force attacks
    
    Args:
        attack_type: Type of attack ("standard", "credential_stuffing", "dictionary")
        
    Returns:
        Appropriate BruteForceAttack instance
    """
    attack_types = {
        "standard": BruteForceAttack,
        "credential_stuffing": CredentialStuffingAttack,
        "dictionary": DictionaryAttack
    }
    
    attack_class = attack_types.get(attack_type, BruteForceAttack)
    return attack_class()


# Example usage and testing
if __name__ == "__main__":
    print("🔍 Brute Force Attack Module Test")
    
    # Mock IAM environment for testing
    class MockUser:
        def __init__(self, user_id):
            self.user_id = user_id
            self.name = "Test User"
            self.status = "active"
            self.mfa_enabled = False
            self.failed_login_attempts = 4
            self.password_strength = "weak"
            self.last_password_change_days = 120
            self.department = "IT"
            self.access_level = "standard"
    
    class MockIAMEnv:
        def get_user(self, user_id):
            return MockUser(user_id)
        
        def get_user_permissions(self, user_id):
            return ["system.read", "data.access", "reports.view"]
        
        def get_user_roles(self, user_id):
            return ["developer", "user"]
    
    # Test different attack types
    mock_iam = MockIAMEnv()
    
    print("\n🧪 Testing Standard Brute Force Attack:")
    bf_attack = BruteForceAttack()
    result = bf_attack.execute(mock_iam, "test_user_001")
    
    print(f"✅ Attack Result: {result.success}")
    print(f"   Severity: {result.severity}")
    print(f"   Access Gained: {len(result.access_gained)} permissions")
    print(f"   Remediation Suggestions: {len(result.remediation_suggestions)}")
    
    print("\n🧪 Testing Credential Stuffing Attack:")
    cs_attack = CredentialStuffingAttack()
    result2 = cs_attack.execute(mock_iam, "test_user_002")
    
    print(f"✅ Attack Result: {result2.success}")
    print(f"   Method: {result2.details.get('attack_method')}")
    print(f"   Breach Sources: {result2.details.get('breach_sources', [])}")
    
    print("\n🧪 Testing Dictionary Attack:")
    dict_attack = DictionaryAttack()
    result3 = dict_attack.execute(mock_iam, "test_user_003")
    
    print(f"✅ Attack Result: {result3.success}")
    print(f"   Method: {result3.details.get('attack_method')}")
    print(f"   Dictionaries: {result3.details.get('dictionaries_used', [])}")
    
    print(f"\n📊 Attack Statistics:")
    print(f"   Standard BF Success Rate: {bf_attack.get_success_rate():.1f}%")
    print(f"   Credential Stuffing Success Rate: {cs_attack.get_success_rate():.1f}%")
    print(f"   Dictionary Attack Success Rate: {dict_attack.get_success_rate():.1f}%")
    
    print("\n🎯 Brute Force Attack Module Ready!")