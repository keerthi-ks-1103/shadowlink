"""
ShadowLink Threat Simulation Engine
Main orchestrator for running attack simulations against IAM environments
"""

import json
import random
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import sys
import os

# Add the project root and src directories to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
src_dir = os.path.join(project_root, 'src')
sys.path.insert(0, project_root)
sys.path.insert(0, src_dir)

try:
    # Import IAM environment manager
    from shadowlink.core.iam.environment import IAMEnvironmentManager
    
    # Import attack modules with proper path handling
    from shadowlink.simulation.attacks.brute_force import BruteForceAttack, CredentialStuffingAttack, DictionaryAttack
    from shadowlink.simulation.attacks.privilege_escalation import PrivilegeEscalationAttack
    #from shadowlink.simulation.attacks.lateral_movement import LateralMovementAttack
    
    # Import base attack for result handling
    from shadowlink.simulation.attacks.base_attack import AttackResult
    
except ImportError as e:
    # Fallback imports for local testing
    print(f"Warning: Could not import from shadowlink package: {e}")
    print("Attempting local imports...")
    
    try:
        # Try relative imports from current directory structure
        from core.iam.environment import IAMEnvironmentManager
        from attacks.brute_force import BruteForceAttack, CredentialStuffingAttack, DictionaryAttack
        from attacks.privilege_escalation import PrivilegeEscalationAttack
        # from lateral_movement import LateralMovementAttack
        from attacks.base_attack import AttackResult
    except ImportError as e2:
        print(f"Local imports also failed: {e2}")
        # Create dummy classes for testing
        class IAMEnvironmentManager:
            def __init__(self):
                self.users = {}
                self.roles = {}
                self.permissions = {}
            
            def load_environment(self, path):
                pass
            
            def get_user(self, user_id):
                return self.users.get(user_id)
            
            def get_user_permissions(self, user_id):
                return []
            
            def get_user_roles(self, user_id):
                return []
        
        class AttackResult:
            def __init__(self, attack_name, target_user_id, success, severity, access_gained, details, remediation_suggestions):
                self.attack_name = attack_name
                self.target_user_id = target_user_id
                self.success = success
                self.severity = severity
                self.access_gained = access_gained
                self.details = details
                self.remediation_suggestions = remediation_suggestions
        
        class BruteForceAttack:
            def __init__(self):
                self.name = "Brute Force"
                self.base_success_rate = 0.45
            
            def execute(self, iam_env, target_user_id):
                return AttackResult(
                    self.name, target_user_id, random.random() > 0.5,
                    "medium", ["test.access"], {}, ["Enable MFA"]
                )
            
            def get_success_rate(self):
                return self.base_success_rate * 100
        
        class PrivilegeEscalationAttack:
            def __init__(self):
                self.name = "Privilege Escalation"
                self.base_success_rate = 0.35
            
            def execute(self, iam_env, target_user_id):
                return AttackResult(
                    self.name, target_user_id, random.random() > 0.6,
                    "high", ["admin.access"], {"escalation_path": ["user", "admin"]}, ["Review role assignments"]
                )
            
            def get_success_rate(self):
                return self.base_success_rate * 100


def safe_get_attribute(obj, attribute, default=None):
    """Safely get attribute from object or dictionary"""
    if hasattr(obj, attribute):
        return getattr(obj, attribute)
    elif isinstance(obj, dict):
        return obj.get(attribute, default)
    else:
        return default


class SimulationEngine:
    """Main engine for running threat simulations"""

    def __init__(self, iam_env: IAMEnvironmentManager, seed: Optional[int] = None):
        self.iam_env = iam_env
        self.logs = []
        self.simulation_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        if seed is not None:
            random.seed(seed)
            logging.info(f"Random seed set to: {seed}")

        # Initialize available attack modules
        self.attacks = []
        self._initialize_attacks()
        self._setup_logging()

    def _initialize_attacks(self):
        """Initialize all available attack modules"""
        try:
            # Core attack modules
            self.attacks.extend([
                BruteForceAttack(),
                PrivilegeEscalationAttack(),
            ])
            
            # Try to add optional attack modules
            try:
                # Add credential stuffing and dictionary attacks if available
                self.attacks.extend([
                    CredentialStuffingAttack(),
                    DictionaryAttack(),
                ])
            except (NameError, AttributeError):
                pass
            
            # Try to add lateral movement if available
            
                
        except Exception as e:
            logging.warning(f"Error initializing attacks: {e}")
            # Ensure we have at least basic attacks
            if not self.attacks:
                self.attacks = [BruteForceAttack(), PrivilegeEscalationAttack()]

        logging.info(f"Initialized {len(self.attacks)} attack modules: {[a.name for a in self.attacks]}")

    def _setup_logging(self):
        """Setup logging configuration"""
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / f"simulation_{self.simulation_id}.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def run_simulation(self, target_users: Optional[List[str]] = None, 
                      attack_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run comprehensive simulation against target users
        
        Args:
            target_users: List of user IDs to target (None = all users)
            attack_filter: List of attack names to include (None = all attacks)
        """
        self.logger.info(f"Starting simulation {self.simulation_id}")

        if target_users is None:
            target_users = list(self.iam_env.users.keys()) if hasattr(self.iam_env, 'users') else ['test_user']

        # Filter attacks if specified
        attacks_to_run = self.attacks
        if attack_filter:
            attacks_to_run = [a for a in self.attacks if a.name in attack_filter]

        self.logger.info(f"Targeting {len(target_users)} users with {len(attacks_to_run)} attack modules")

        simulation_results = {
            "simulation_id": self.simulation_id,
            "timestamp": datetime.now().isoformat(),
            "target_users": target_users,
            "attacks_executed": [],
            "summary": {
                "total_attacks": 0,
                "successful_attacks": 0,
                "failed_attacks": 0,
                "compromised_users": set(),
                "attack_types": {},
                "high_severity_attacks": 0,
                "critical_vulnerabilities": []
            }
        }

        for user_id in target_users:
            self.logger.info(f"Running attack modules against user: {user_id}")
            
            for attack in attacks_to_run:
                try:
                    self.logger.debug(f"Executing {attack.name} against {user_id}")
                    result = attack.execute(self.iam_env, user_id)

                    if result:
                        # Convert AttackResult object to dictionary for logging
                        result_dict = self._attack_result_to_dict(result)
                        self.log_results(result_dict)
                        simulation_results["attacks_executed"].append(result_dict)
                        self._update_summary(simulation_results["summary"], result_dict)

                except Exception as e:
                    self.logger.error(f"Error executing {attack.name} against {user_id}: {str(e)}")
                    error_result = {
                        "user": user_id,
                        "attack": attack.name,
                        "success": False,
                        "severity": "low",
                        "error": str(e),
                        "timestamp": datetime.now().isoformat(),
                        "access": [],
                        "details": {"error": str(e)},
                        "remediation": ["Investigate attack module error"]
                    }
                    self.log_results(error_result)
                    simulation_results["attacks_executed"].append(error_result)
                    self._update_summary(simulation_results["summary"], error_result)

        # Convert set to list for JSON serialization
        simulation_results["summary"]["compromised_users"] = list(
            simulation_results["summary"]["compromised_users"]
        )

        # Add risk analysis
        self._analyze_risks(simulation_results)

        # Save results
        self._save_simulation_log(simulation_results)

        self.logger.info(f"Simulation {self.simulation_id} completed")
        self.logger.info(
            f"Results: {simulation_results['summary']['successful_attacks']}/"
            f"{simulation_results['summary']['total_attacks']} attacks successful"
        )

        return simulation_results

    def _attack_result_to_dict(self, result) -> Dict[str, Any]:
        """Convert AttackResult object to dictionary"""
        if hasattr(result, '__dict__'):
            # If it's an AttackResult object, convert to dict
            result_dict = {
                "user": safe_get_attribute(result, 'target_user_id', 'unknown'),
                "attack": safe_get_attribute(result, 'attack_name', 'unknown'),
                "success": safe_get_attribute(result, 'success', False),
                "severity": safe_get_attribute(result, 'severity', 'low'),
                "access": safe_get_attribute(result, 'access_gained', []),
                "details": safe_get_attribute(result, 'details', {}),
                "remediation": safe_get_attribute(result, 'remediation_suggestions', []),
                "timestamp": datetime.now().isoformat()
            }
        elif isinstance(result, dict):
            # If it's already a dictionary, normalize it
            result_dict = result.copy()
            # Ensure required fields exist with correct names
            if 'user' not in result_dict:
                result_dict['user'] = result_dict.get('target_user_id', 'unknown')
            if 'attack' not in result_dict:
                result_dict['attack'] = result_dict.get('attack_name', 'unknown')
            if 'access' not in result_dict:
                result_dict['access'] = result_dict.get('access_gained', [])
            if 'remediation' not in result_dict:
                result_dict['remediation'] = result_dict.get('remediation_suggestions', [])
            if 'severity' not in result_dict:
                result_dict['severity'] = 'low'
            if 'details' not in result_dict:
                result_dict['details'] = {}
            if 'timestamp' not in result_dict:
                result_dict['timestamp'] = datetime.now().isoformat()
        else:
            # Fallback for unexpected types
            result_dict = {
                "user": "unknown",
                "attack": "unknown",
                "success": False,
                "severity": "low",
                "access": [],
                "details": {"error": "Unexpected result type"},
                "remediation": ["Review attack module implementation"],
                "timestamp": datetime.now().isoformat()
            }
        
        return result_dict

    def _update_summary(self, summary: Dict[str, Any], result: Dict[str, Any]):
        """Update simulation summary with attack result"""
        summary["total_attacks"] += 1

        if result.get("success", False):
            summary["successful_attacks"] += 1
            summary["compromised_users"].add(result["user"])
            
            # Track high severity attacks
            if result.get("severity") in ["high", "critical"]:
                summary["high_severity_attacks"] += 1
                
                # Track critical vulnerabilities
                vulnerability = {
                    "user": result["user"],
                    "attack": result["attack"],
                    "severity": result["severity"],
                    "access_gained": result.get("access", []),
                    "timestamp": result.get("timestamp")
                }
                summary["critical_vulnerabilities"].append(vulnerability)
        else:
            summary["failed_attacks"] += 1

        attack_type = result["attack"]
        if attack_type not in summary["attack_types"]:
            summary["attack_types"][attack_type] = {"total": 0, "successful": 0, "success_rate": "0%"}

        summary["attack_types"][attack_type]["total"] += 1
        if result.get("success", False):
            summary["attack_types"][attack_type]["successful"] += 1
        
        # Update success rate
        total = summary["attack_types"][attack_type]["total"]
        successful = summary["attack_types"][attack_type]["successful"]
        summary["attack_types"][attack_type]["success_rate"] = f"{(successful / total) * 100:.1f}%"

    def _analyze_risks(self, simulation_results: Dict[str, Any]):
        """Analyze simulation results for risk patterns"""
        summary = simulation_results["summary"]
        
        # Calculate overall risk score
        total_attacks = summary["total_attacks"]
        if total_attacks > 0:
            success_rate = summary["successful_attacks"] / total_attacks
            high_severity_rate = summary["high_severity_attacks"] / total_attacks
            
            # Risk score: 0-100 based on success rate and severity
            risk_score = min(100, int((success_rate * 70) + (high_severity_rate * 30)))
            
            summary["risk_analysis"] = {
                "overall_risk_score": risk_score,
                "risk_level": "Critical" if risk_score >= 80 else "High" if risk_score >= 60 else "Medium" if risk_score >= 30 else "Low",
                "success_rate": f"{success_rate * 100:.1f}%",
                "high_severity_rate": f"{high_severity_rate * 100:.1f}%",
                "compromised_user_rate": f"{len(summary['compromised_users']) / len(simulation_results['target_users']) * 100:.1f}%"
            }

    def log_results(self, result: Dict[str, Any]):
        """Log simulation results"""
        if "timestamp" not in result:
            result["timestamp"] = datetime.now().isoformat()

        self.logs.append(result)

        status = "SUCCESS" if result.get("success", False) else "FAILED"
        severity = result.get("severity", "low").upper()
        
        # Create a more informative log message
        base_message = f"[{status}] [{severity}] {result['attack']} against {result['user']}"
        
        if result.get("success", False):
            access_count = len(result.get("access", []))
            details_note = result.get("details", {}).get("note", "")
            self.logger.info(f"{base_message} - Gained {access_count} permissions {details_note}")
            
            # Log specific access gained (limited to avoid spam)
            access_list = result.get("access", [])
            if access_list and len(access_list) <= 10:
                self.logger.info(f"  → Access gained: {', '.join(access_list)}")
            elif len(access_list) > 10:
                self.logger.info(f"  → Access gained: {', '.join(access_list[:10])}... (+{len(access_list)-10} more)")
        else:
            failure_reason = (result.get("details", {}).get("failure_reason") or 
                            result.get("error", "No additional details"))
            self.logger.info(f"{base_message} - {failure_reason}")

        # Log escalation paths if present
        escalation_path = (result.get("escalation_path") or 
                          result.get("details", {}).get("escalation_path"))
        if escalation_path and isinstance(escalation_path, list):
            self.logger.info(f"  → Escalation path: {' → '.join(escalation_path)}")

        # Log critical remediation suggestions
        remediation = result.get("remediation", [])
        if remediation and result.get("success", False):
            critical_fixes = [r for r in remediation if any(word in r.lower() for word in ['mfa', 'disable', 'revoke', 'critical'])]
            if critical_fixes:
                self.logger.warning(f"  → Critical fixes needed: {'; '.join(critical_fixes[:3])}")

    def run_targeted_simulation(self, user_id: str, attack_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Run targeted simulation against specific user"""
        self.logger.info(f"Running targeted simulation against {user_id}")

        results = []
        attacks_to_run = [
            attack for attack in self.attacks 
            if attack_types is None or attack.name in attack_types
        ]

        self.logger.info(f"Running {len(attacks_to_run)} attacks against {user_id}")

        for attack in attacks_to_run:
            try:
                result = attack.execute(self.iam_env, user_id)
                if result:
                    result_dict = self._attack_result_to_dict(result)
                    self.log_results(result_dict)
                    results.append(result_dict)
                    
            except Exception as e:
                self.logger.error(f"Error in targeted simulation: {str(e)}")
                error_result = {
                    "user": user_id,
                    "attack": attack.name,
                    "success": False,
                    "severity": "low",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat(),
                    "access": [],
                    "details": {"error": str(e)},
                    "remediation": ["Investigate attack module error"]
                }
                self.log_results(error_result)
                results.append(error_result)

        return results

    def get_simulation_stats(self) -> Dict[str, Any]:
        """Get comprehensive simulation statistics"""
        if not self.logs:
            return {"message": "No attacks executed yet"}

        total_attacks = len(self.logs)
        successful_attacks = sum(1 for log in self.logs if log.get("success", False))

        attack_breakdown = {}
        severity_breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for log in self.logs:
            attack_type = log["attack"]
            severity = log.get("severity", "low")
            
            # Attack type breakdown
            if attack_type not in attack_breakdown:
                attack_breakdown[attack_type] = {"total": 0, "successful": 0}
            attack_breakdown[attack_type]["total"] += 1
            if log.get("success", False):
                attack_breakdown[attack_type]["successful"] += 1
            
            # Severity breakdown
            if severity in severity_breakdown:
                severity_breakdown[severity] += 1

        # Add success rates to breakdown
        for attack_type, stats in attack_breakdown.items():
            if stats["total"] > 0:
                stats["success_rate"] = f"{(stats['successful'] / stats['total']) * 100:.1f}%"
            else:
                stats["success_rate"] = "0%"

        compromised_users = list(set(log["user"] for log in self.logs if log.get("success", False)))
        unique_targets = len(set(log["user"] for log in self.logs))
        
        # Calculate risk metrics
        high_risk_attacks = sum(1 for log in self.logs if log.get("severity") in ["high", "critical"] and log.get("success"))
        
        return {
            "simulation_id": self.simulation_id,
            "total_attacks": total_attacks,
            "successful_attacks": successful_attacks,
            "failed_attacks": total_attacks - successful_attacks,
            "success_rate": f"{(successful_attacks / total_attacks) * 100:.1f}%" if total_attacks > 0 else "0%",
            "attack_breakdown": attack_breakdown,
            "severity_breakdown": severity_breakdown,
            "compromised_users": compromised_users,
            "compromised_user_count": len(compromised_users),
            "unique_targets": unique_targets,
            "high_risk_successful_attacks": high_risk_attacks,
            "risk_score": min(100, int((successful_attacks / max(total_attacks, 1)) * 70 + (high_risk_attacks / max(total_attacks, 1)) * 30))
        }

    def _save_simulation_log(self, results: Dict[str, Any]):
        """Save simulation results to log file"""
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "simulation_log.json"

        try:
            if log_file.exists():
                with open(log_file, 'r', encoding='utf-8') as f:
                    all_logs = json.load(f)
            else:
                all_logs = {"simulations": []}

            all_logs["simulations"].append(results)
            
            # Keep only last 50 simulations to prevent file from getting too large
            if len(all_logs["simulations"]) > 50:
                all_logs["simulations"] = all_logs["simulations"][-50:]

            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(all_logs, f, indent=2, default=str, ensure_ascii=False)

            self.logger.info(f"Simulation results saved to {log_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save simulation log: {str(e)}")

    def clear_logs(self):
        """Clear simulation logs"""
        self.logs.clear()
        self.logger.info("Simulation logs cleared")

    def export_results(self, format_type: str = "json") -> str:
        """Export simulation results in specified format"""
        if format_type.lower() == "json":
            return json.dumps(self.get_simulation_stats(), indent=2, default=str)
        elif format_type.lower() == "csv":
            # Basic CSV export functionality
            import csv
            import io
            
            output = io.StringIO()
            if self.logs:
                # Flatten the logs for CSV export
                flattened_logs = []
                for log in self.logs:
                    flat_log = {
                        "timestamp": log.get("timestamp", ""),
                        "user": log.get("user", ""),
                        "attack": log.get("attack", ""),
                        "success": log.get("success", False),
                        "severity": log.get("severity", "low"),
                        "access_count": len(log.get("access", [])),
                        "remediation_count": len(log.get("remediation", [])),
                        "details": str(log.get("details", {}))
                    }
                    flattened_logs.append(flat_log)
                
                if flattened_logs:
                    fieldnames = flattened_logs[0].keys()
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(flattened_logs)
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format_type}")

    def get_attack_modules(self) -> List[str]:
        """Get list of available attack module names"""
        return [attack.name for attack in self.attacks]

    def get_user_targets(self) -> List[str]:
        """Get list of available user targets"""
        if hasattr(self.iam_env, 'users'):
            return list(self.iam_env.users.keys())
        else:
            return []


# === SUCCESS RATE TUNING HELPERS ===

def apply_success_rate_patches():
    """
    Apply patches to increase attack success rates for better demonstrations.
    Returns patch functions for different attack types.
    """
    print("🔧 Applying success rate patches for demo purposes...")

    def patch_brute_force_success_rate(attack_instance):
        """Patch brute force attack for higher success rate"""
        if hasattr(attack_instance, 'base_success_rate'):
            attack_instance.base_success_rate = 0.65  # Increased from 0.45
        if hasattr(attack_instance, 'mfa_protection_factor'):
            attack_instance.mfa_protection_factor = 0.4  # Increased from 0.2
        print(f"✅ Patched {attack_instance.name} success rates")

    def patch_privilege_escalation_success_rate(attack_instance):
        """Patch privilege escalation attack for higher success rate"""
        if hasattr(attack_instance, '_calculate_direct_escalation_probability'):
            original_calc = attack_instance._calculate_direct_escalation_probability

            def enhanced_calc(current_role, target_role):
                base_result = original_calc(current_role, target_role)
                return min(base_result * 1.8, 0.80)  # Boost success rate

            attack_instance._calculate_direct_escalation_probability = enhanced_calc
            print(f"✅ Patched {attack_instance.name} success rates")

    return patch_brute_force_success_rate, patch_privilege_escalation_success_rate


def apply_global_success_boost(engine: SimulationEngine, boost_factor: float = 1.5):
    """
    Apply a global success rate boost to all attack modules.
    
    Args:
        engine: SimulationEngine instance
        boost_factor: Multiplier for success rates (e.g., 1.5 = 50% boost)
    """
    print(f"🚀 Applying global success boost factor: {boost_factor}x")
    
    for attack in engine.attacks:
        # Try to boost various success rate attributes
        attrs_to_boost = ['base_success_rate', 'success_probability', 'escalation_probability']
        
        for attr in attrs_to_boost:
            if hasattr(attack, attr):
                current_value = getattr(attack, attr)
                if isinstance(current_value, (int, float)):
                    new_value = min(current_value * boost_factor, 0.85)  # Cap at 85%
                    setattr(attack, attr, new_value)
                    print(f"  ✅ Boosted {attack.name}.{attr}: {current_value:.2f} → {new_value:.2f}")


if __name__ == "__main__":
    """
    Main execution block for testing the ShadowLink simulation engine
    """
    print("🔥 ShadowLink Threat Simulation Engine")
    print("="*50)
    
    try:
        # Initialize IAM environment manager
        env_manager = IAMEnvironmentManager()
        
        # Try to load environment data
        environment_paths = [
            "data/mock_iam/environments/default.json",
            "data/environments/default.json",
            "environments/default.json",
            "default.json"
        ]
        
        environment_loaded = False
        for env_path in environment_paths:
            try:
                env_manager.load_environment(env_path)
                print(f"✅ Loaded environment from: {env_path}")
                environment_loaded = True
                break
            except (FileNotFoundError, json.JSONDecodeError):
                continue
        
        if not environment_loaded:
            print("⚠️  No environment file found, creating test environment")
            # Create minimal test environment
            env_manager.users = {
                "test_admin": {
                    "user_id": "test_admin", 
                    "name": "Test Administrator", 
                    "status": "active",
                    "mfa_enabled": False,
                    "failed_login_attempts": 1,
                    "password_strength": "medium",
                    "department": "IT",
                    "access_level": "admin",
                    "roles": ["admin", "user"]
                },
                "test_user": {
                    "user_id": "test_user", 
                    "name": "Test User", 
                    "status": "active",
                    "mfa_enabled": True,
                    "failed_login_attempts": 0,
                    "password_strength": "strong",
                    "department": "Sales",
                    "access_level": "standard",
                    "roles": ["user"]
                },
                "vulnerable_user": {
                    "user_id": "vulnerable_user", 
                    "name": "Vulnerable User", 
                    "status": "active",
                    "mfa_enabled": False,
                    "failed_login_attempts": 5,
                    "password_strength": "weak",
                    "department": "Marketing",
                    "access_level": "standard",
                    "last_password_change_days": 200,
                    "roles": ["user", "temp_admin"]
                }
            }

        # Initialize the simulation engine
        print(f"\n🚀 Initializing ShadowLink Engine...")
        engine = SimulationEngine(env_manager, seed=42)

        print(f"✅ Engine initialized with {len(engine.attacks)} attack modules:")
        for attack in engine.attacks:
            print(f"   - {attack.name}")

        # Apply success rate patches for better demo results
        print(f"\n🔧 Applying success rate optimizations...")
        bf_patch, pe_patch = apply_success_rate_patches()
        
        for attack in engine.attacks:
            if "Brute Force" in attack.name:
                bf_patch(attack)
            elif "Privilege Escalation" in attack.name:
                pe_patch(attack)

        # Apply global boost for demo purposes
        apply_global_success_boost(engine, 1.3)

        # Run the simulation
        # Run comprehensive simulation
        # Run comprehensive simulation
        print("🎯 Running comprehensive simulation...")
        target_users = list(env_manager.users.keys())
        print(f"Target users: {target_users}")
        
        simulation_results = engine.run_simulation(target_users=target_users)
        
        # Display results summary
        print(f"\n📊 SIMULATION RESULTS")
        print("="*50)
        summary = simulation_results["summary"]
        print(f"Simulation ID: {simulation_results['simulation_id']}")
        print(f"Total Attacks: {summary['total_attacks']}")
        print(f"Successful Attacks: {summary['successful_attacks']}")
        print(f"Failed Attacks: {summary['failed_attacks']}")
        
        # Safe success rate calculation
        if summary['total_attacks'] > 0:
            success_rate = (summary['successful_attacks']/summary['total_attacks']*100)
            print(f"Success Rate: {success_rate:.1f}%")
        else:
            print("Success Rate: N/A (No attacks executed)")
            print("⚠️  WARNING: No attacks were executed. This may indicate an issue with the attack modules.")
        
        print(f"Compromised Users: {len(summary['compromised_users'])}/{len(target_users)}")
        
        # Risk analysis
        if "risk_analysis" in summary:
            risk_info = summary["risk_analysis"]
            print(f"\n🚨 RISK ANALYSIS")
            print(f"Overall Risk Score: {risk_info['overall_risk_score']}/100")
            print(f"Risk Level: {risk_info['risk_level']}")
            print(f"High Severity Attacks: {summary['high_severity_attacks']}")
        
        # Attack breakdown
        if summary["attack_types"]:
            print(f"\n⚔️  ATTACK BREAKDOWN")
            for attack_type, stats in summary["attack_types"].items():
                print(f"  {attack_type}: {stats['successful']}/{stats['total']} ({stats['success_rate']})")
        else:
            print(f"\n⚔️  ATTACK BREAKDOWN: No attacks executed")
        
        # Critical vulnerabilities
        if summary["critical_vulnerabilities"]:
            print(f"\n🔥 CRITICAL VULNERABILITIES FOUND:")
            for vuln in summary["critical_vulnerabilities"][:5]:  # Show top 5
                print(f"  • {vuln['user']} - {vuln['attack']} ({vuln['severity']})")
        
        # Compromised users details
        if summary["compromised_users"]:
            print(f"\n💀 COMPROMISED USERS:")
            for user in summary["compromised_users"]:
                user_attacks = [r for r in simulation_results["attacks_executed"] 
                               if r["user"] == user and r["success"]]
                attack_count = len(user_attacks)
                high_sev_count = len([a for a in user_attacks if a["severity"] in ["high", "critical"]])
                print(f"  • {user}: {attack_count} successful attacks ({high_sev_count} high/critical)")
        else:
            print(f"\n💀 COMPROMISED USERS: None")
        
        # Debug information if no attacks executed
        if summary['total_attacks'] == 0:
            print(f"\n🔍 DEBUG INFORMATION:")
            print(f"Available attack modules: {len(engine.attacks)}")
            for i, attack in enumerate(engine.attacks):
                print(f"  {i+1}. {attack.name} - {type(attack).__name__}")
            print(f"Target users found: {len(target_users)}")
            for user in target_users:
                print(f"  - {user}")
            
            # Try to manually execute one attack for debugging
            if engine.attacks and target_users:
                print(f"\n🔧 Manual attack test:")
                test_attack = engine.attacks[0]
                test_user = target_users[0]
                try:
                    print(f"Testing {test_attack.name} against {test_user}...")
                    test_result = test_attack.execute(env_manager, test_user)
                    print(f"Test result type: {type(test_result)}")
                    print(f"Test result: {test_result}")
                except Exception as e:
                    print(f"Manual test failed: {e}")
                    import traceback
                    print(f"Traceback: {traceback.format_exc()}")
        
        print(f"\n🎯 Running targeted simulation example...")
        # Example targeted simulation
        if target_users:
            test_user = target_users[0]  # Use first available user
            try:
                targeted_results = engine.run_targeted_simulation(test_user, ["Brute Force"])
                print(f"Targeted results for {test_user}: {len(targeted_results)} attacks executed")
                for result in targeted_results:
                    status = "✅ SUCCESS" if result["success"] else "❌ FAILED"
                    print(f"  {status} - {result['attack']} ({result['severity']})")
            except Exception as e:
                print(f"Targeted simulation failed: {e}")
        
        # Display comprehensive stats
        print(f"\n📈 COMPREHENSIVE STATISTICS")
        print("="*50)
        try:
            stats = engine.get_simulation_stats()
            if "message" in stats:
                print(f"Stats: {stats['message']}")
            else:
                print(f"Risk Score: {stats.get('risk_score', 0)}/100")
                print(f"Unique Targets: {stats.get('unique_targets', 0)}")
                print(f"High-Risk Successful Attacks: {stats.get('high_risk_successful_attacks', 0)}")
        except Exception as e:
            print(f"Failed to get stats: {e}")
        
        # Export results example
        print(f"\n💾 EXPORTING RESULTS...")
        try:
            json_export = engine.export_results("json")
            print(f"JSON export size: {len(json_export)} characters")
            
            csv_export = engine.export_results("csv")
            print(f"CSV export size: {len(csv_export)} characters")
            print("✅ Export completed successfully")
        except Exception as e:
            print(f"❌ Export failed: {e}")
        
        # Available modules and targets
        print(f"\n🛠️  AVAILABLE MODULES: {', '.join(engine.get_attack_modules())}")
        print(f"🎯 AVAILABLE TARGETS: {', '.join(engine.get_user_targets())}")
        
        # Recommendations
        print(f"\n💡 SECURITY RECOMMENDATIONS")
        print("="*50)
        
        if summary["successful_attacks"] > 0:
            recommendations = set()
            for attack_result in simulation_results["attacks_executed"]:
                if attack_result["success"] and attack_result.get("remediation"):
                    recommendations.update(attack_result["remediation"][:2])  # Top 2 per attack
            
            if recommendations:
                for i, rec in enumerate(list(recommendations)[:10], 1):  # Top 10 recommendations
                    print(f"  {i}. {rec}")
            else:
                print("  No specific recommendations available")
        else:
            print("  🎉 No successful attacks detected! Your environment appears secure.")
            print("  General recommendations:")
            print("    1. Ensure MFA is enabled for all users")
            print("    2. Regular password policy enforcement")
            print("    3. Monitor failed login attempts")
            print("    4. Regular security assessments")
        
        print(f"\n🏁 Simulation completed!")
        print(f"📝 Detailed logs saved to: data/logs/simulation_{engine.simulation_id}.log")
        print(f"📊 Results saved to: data/logs/simulation_log.json")
        
    except KeyboardInterrupt:
        print(f"\n⏹️  Simulation interrupted by user")
    except Exception as e:
        print(f"\n❌ Simulation failed with error: {str(e)}")
        import traceback
        print(f"Full traceback:\n{traceback.format_exc()}")
        
        # Additional debugging for the specific error
        print(f"\n🔧 DEBUG INFO:")
        try:
            print(f"Engine attacks: {len(engine.attacks) if 'engine' in locals() else 'Engine not initialized'}")
            print(f"Environment users: {len(env_manager.users) if 'env_manager' in locals() else 'Environment not loaded'}")
            if 'simulation_results' in locals():
                print(f"Simulation results keys: {list(simulation_results.keys())}")
                print(f"Summary keys: {list(simulation_results.get('summary', {}).keys())}")
        except Exception as debug_e:
            print(f"Debug info failed: {debug_e}")
            
    finally:
        print(f"\n🔒 ShadowLink Engine shutdown complete")
        print("="*50)