# attack_success_config.py
# Configuration file to adjust attack success rates

import random
from typing import Dict, List, Any, Tuple

class AttackSuccessConfig:
    """
    Configuration class to control attack success rates
    """
    
    def __init__(self, 
                 global_success_multiplier: float = 1.0,
                 minimum_success_rate: float = 0.1,
                 maximum_success_rate: float = 0.9):
        """
        Initialize attack success configuration
        
        Args:
            global_success_multiplier: Multiply all success rates by this factor
            minimum_success_rate: Minimum success rate for any attack
            maximum_success_rate: Maximum success rate for any attack
        """
        self.global_success_multiplier = global_success_multiplier
        self.minimum_success_rate = minimum_success_rate
        self.maximum_success_rate = maximum_success_rate
        
        # Attack-specific configurations
        self.brute_force_config = {
            "base_success_rate": 0.35,  # Increased from 0.15
            "mfa_protection_factor": 0.15,  # Increased from 0.05
            "no_mfa_multiplier": 2.5,  # Increased from 2.0
            "weak_password_multiplier": 4.0,  # Increased from 3.0
            "failed_attempts_bonus": 0.3,  # Increased from 0.2
        }
        
        self.privilege_escalation_config = {
            "base_escalation_rate": 0.45,  # Increased base rate
            "role_confusion_base": 0.4,  # Increased from 0.3
            "cross_department_base": 0.35,  # Increased from 0.25
            "temporary_abuse_base": 0.3,  # Increased from 0.2
            "high_value_role_penalty": 0.7,  # Reduced penalty (was 0.5)
        }
        
        # Force success for testing (set to True to guarantee successes)
        self.force_success_mode = False
        self.force_success_rate = 0.8  # Percentage of attacks that will succeed in force mode
    
    def adjust_success_rate(self, base_rate: float, attack_type: str = "general") -> float:
        """
        Adjust success rate based on configuration
        
        Args:
            base_rate: Original success rate
            attack_type: Type of attack for specific adjustments
            
        Returns:
            Adjusted success rate
        """
        if self.force_success_mode:
            return self.force_success_rate
        
        # Apply global multiplier
        adjusted_rate = base_rate * self.global_success_multiplier
        
        # Apply bounds
        adjusted_rate = max(self.minimum_success_rate, adjusted_rate)
        adjusted_rate = min(self.maximum_success_rate, adjusted_rate)
        
        return adjusted_rate
    
    def should_force_success(self) -> bool:
        """
        Determine if attack should be forced to succeed (for testing)
        
        Returns:
            True if attack should succeed, False otherwise
        """
        if self.force_success_mode:
            return random.random() < self.force_success_rate
        return False


# Global configuration instance
attack_config = AttackSuccessConfig()

# Quick configuration presets
def set_high_success_rates():
    """Set configuration for high success rates (good for testing)"""
    global attack_config
    attack_config.global_success_multiplier = 3.0
    attack_config.minimum_success_rate = 0.3
    attack_config.brute_force_config["base_success_rate"] = 0.6
    attack_config.privilege_escalation_config["base_escalation_rate"] = 0.7
    print("✅ Set HIGH success rates (good for testing)")

def set_medium_success_rates():
    """Set configuration for medium success rates (realistic simulation)"""
    global attack_config
    attack_config.global_success_multiplier = 1.5
    attack_config.minimum_success_rate = 0.2
    attack_config.brute_force_config["base_success_rate"] = 0.35
    attack_config.privilege_escalation_config["base_escalation_rate"] = 0.45
    print("✅ Set MEDIUM success rates (realistic simulation)")

def set_low_success_rates():
    """Set configuration for low success rates (secure environment)"""
    global attack_config
    attack_config.global_success_multiplier = 0.8
    attack_config.minimum_success_rate = 0.05
    attack_config.brute_force_config["base_success_rate"] = 0.15
    attack_config.privilege_escalation_config["base_escalation_rate"] = 0.25
    print("✅ Set LOW success rates (secure environment)")

def enable_force_success_mode(success_rate: float = 0.8):
    """Enable force success mode for testing"""
    global attack_config
    attack_config.force_success_mode = True
    attack_config.force_success_rate = success_rate
    print(f"✅ Enabled FORCE SUCCESS mode ({success_rate*100}% success rate)")

def disable_force_success_mode():
    """Disable force success mode"""
    global attack_config
    attack_config.force_success_mode = False
    print("✅ Disabled force success mode")


# Modified BruteForceAttack class with configurable success rates
class ConfigurableBruteForceAttack:
    """
    Modified brute force attack with configurable success rates
    """
    
    def _calculate_success_probability(self, mfa_enabled: bool, failed_attempts: int, 
                                     password_strength: str, last_password_change_days: int) -> float:
        """
        Calculate probability with configuration adjustments
        """
        config = attack_config.brute_force_config
        
        # Start with configured base rate
        probability = config["base_success_rate"]
        
        # MFA impact
        if mfa_enabled:
            probability *= config["mfa_protection_factor"]
        else:
            probability *= config["no_mfa_multiplier"]
        
        # High failed attempts indicate vulnerability
        if failed_attempts >= 3:
            probability *= (1 + (failed_attempts * config["failed_attempts_bonus"]))
        
        # Password strength
        strength_multipliers = {
            "weak": config["weak_password_multiplier"],
            "medium": 1.0,
            "strong": 0.4
        }
        probability *= strength_multipliers.get(password_strength, 1.0)
        
        # Old passwords
        if last_password_change_days > 90:
            probability *= 1.5
        elif last_password_change_days > 180:
            probability *= 2.0
        
        # Apply global configuration
        probability = attack_config.adjust_success_rate(probability, "brute_force")
        
        return probability
    
    def execute_with_config(self, iam_env, target_user_id: str):
        """
        Execute attack with configuration checks
        """
        # Check if we should force success
        if attack_config.should_force_success():
            print(f"🎯 Forcing success for {target_user_id} (config mode)")
            return self._create_forced_success_result(iam_env, target_user_id)
        
        # Continue with normal execution logic
        return self._execute_normal(iam_env, target_user_id)


# Modified PrivilegeEscalationAttack class with configurable success rates
class ConfigurablePrivilegeEscalationAttack:
    """
    Modified privilege escalation attack with configurable success rates
    """
    
    def _calculate_direct_escalation_probability(self, current_role: str, target_role: str) -> float:
        """Calculate success probability with configuration"""
        config = attack_config.privilege_escalation_config
        
        current_level = self.role_hierarchy.get(current_role, 1)
        target_level = self.role_hierarchy.get(target_role, 1)
        
        level_gap = target_level - current_level
        base_prob = max(0.1, config["base_escalation_rate"] - (level_gap * 0.1))
        
        # High-value roles penalty (reduced)
        if target_role in self.high_value_roles:
            base_prob *= config["high_value_role_penalty"]
        
        return attack_config.adjust_success_rate(base_prob, "privilege_escalation")
    
    def _calculate_role_confusion_probability(self, user_roles: List[str]) -> float:
        """Calculate role confusion probability with configuration"""
        config = attack_config.privilege_escalation_config
        
        base_prob = config["role_confusion_base"] + (len(user_roles) * 0.1)
        
        role_levels = [self.role_hierarchy.get(role, 1) for role in user_roles]
        level_spread = max(role_levels) - min(role_levels)
        
        if level_spread >= 3:
            base_prob *= 1.5
        
        return attack_config.adjust_success_rate(base_prob, "privilege_escalation")


# Testing and demonstration functions
def test_success_rate_configurations():
    """Test different success rate configurations"""
    print("🧪 Testing Success Rate Configurations\n")
    
    # Test with different configurations
    configurations = [
        ("High Success Rates", set_high_success_rates),
        ("Medium Success Rates", set_medium_success_rates),
        ("Low Success Rates", set_low_success_rates),
    ]
    
    for config_name, config_func in configurations:
        print(f"--- {config_name} ---")
        config_func()
        
        # Simulate some probability calculations
        test_probabilities = []
        for i in range(10):
            # Simulate brute force probability
            bf_prob = attack_config.adjust_success_rate(0.15, "brute_force")
            test_probabilities.append(bf_prob)
        
        avg_prob = sum(test_probabilities) / len(test_probabilities)
        print(f"Average adjusted probability: {avg_prob:.3f} ({avg_prob*100:.1f}%)")
        print()

def demonstrate_force_success_mode():
    """Demonstrate force success mode"""
    print("🎯 Demonstrating Force Success Mode\n")
    
    # Enable force success
    enable_force_success_mode(0.8)
    
    # Simulate 10 attacks
    successes = 0
    for i in range(10):
        if attack_config.should_force_success():
            successes += 1
    
    print(f"Forced successes: {successes}/10 ({successes*10}%)")
    
    # Disable force success
    disable_force_success_mode()

def get_recommended_settings_for_testing():
    """Get recommended settings for testing with higher success rates"""
    print("💡 Recommended Settings for Testing:")
    print("1. For high success rates (good for testing): set_high_success_rates()")
    print("2. For guaranteed successes: enable_force_success_mode(0.8)")
    print("3. For realistic simulation: set_medium_success_rates()")
    print("\nExample usage:")
    print("from attack_success_config import set_high_success_rates")
    print("set_high_success_rates()  # Apply before running simulation")


if __name__ == "__main__":
    print("⚙️ Attack Success Rate Configuration Module")
    print("=" * 50)
    
    test_success_rate_configurations()
    demonstrate_force_success_mode()
    get_recommended_settings_for_testing()
    
    print("\n🎯 Configuration module ready!")
    print("Import this module and call configuration functions before running your simulation.")