"""
ShadowLink Threat Simulation Engine
Main orchestrator for running attack simulations against IAM encd
ironments
"""

import json
import random
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import sys
import os
# Add the src directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, src_dir)

from shadowlink.core.iam.environment import IAMEnvironmentManager

# Add root project directory to sys.path
from attacks.brute_force import BruteForceAttack
from attacks.privilege_escalation import PrivilegeEscalationAttack
# from shadowlink.simulation.attacks.lateral_movement import LateralMovementAttack
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

        self.attacks = [
            BruteForceAttack(),
            PrivilegeEscalationAttack(),
        ]

        self._setup_logging()

    def _setup_logging(self):
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

    def run_simulation(self, target_users: Optional[List[str]] = None) -> Dict[str, Any]:
        self.logger.info(f"Starting simulation {self.simulation_id}")

        if target_users is None:
            target_users = list(self.iam_env.users.keys())

        self.logger.info(f"Targeting {len(target_users)} users with {len(self.attacks)} attack modules")

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
                "attack_types": {}
            }
        }

        for user_id in target_users:
            self.logger.info(f"Running all attack modules against user: {user_id}")
            for attack in self.attacks:
                try:
                    self.logger.debug(f"Executing {attack.name} attack module against {user_id}")
                    result = attack.execute(self.iam_env, user_id)

                    if result:
                        self.log_results(result)
                        simulation_results["attacks_executed"].append(result)
                        self._update_summary(simulation_results["summary"], result)

                except Exception as e:
                    self.logger.error(f"Error executing {attack.name} against {user_id}: {str(e)}")
                    error_result = {
                        "user": user_id,
                        "attack": attack.name,
                        "success": False,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    }
                    self.log_results(error_result)
                    simulation_results["attacks_executed"].append(error_result)

        simulation_results["summary"]["compromised_users"] = list(
            simulation_results["summary"]["compromised_users"]
        )

        self._save_simulation_log(simulation_results)

        self.logger.info(f"Simulation {self.simulation_id} completed")
        self.logger.info(f"Results: {simulation_results['summary']['successful_attacks']}/{simulation_results['summary']['total_attacks']} attacks successful")

        return simulation_results

    def _update_summary(self, summary: Dict[str, Any], result: Dict[str, Any]):
        summary["total_attacks"] += 1

        if result.get("success", False):
            summary["successful_attacks"] += 1
            summary["compromised_users"].add(result["user"])
        else:
            summary["failed_attacks"] += 1

        attack_type = result["attack"]
        if attack_type not in summary["attack_types"]:
            summary["attack_types"][attack_type] = {"total": 0, "successful": 0}

        summary["attack_types"][attack_type]["total"] += 1
        if result.get("success", False):
            summary["attack_types"][attack_type]["successful"] += 1

    def log_results(self, result: Dict[str, Any]):
        if "timestamp" not in result:
            result["timestamp"] = datetime.now().isoformat()

        self.logs.append(result)

        status = "SUCCESS" if result.get("success", False) else "FAILED"
        self.logger.info(
            f"[{status}] {result['attack']} against {result['user']} - "
            f"{result.get('note', 'No additional details')}"
        )

        if result.get("success", False) and result.get("access"):
            self.logger.info(f"  → Gained access to: {', '.join(result['access'])}")

        if result.get("escalation_path"):
            self.logger.info(f"  → Escalation path: {' → '.join(result['escalation_path'])}")

    def _save_simulation_log(self, results: Dict[str, Any]):
        log_dir = Path("data/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "simulation_log.json"

        if log_file.exists():
            with open(log_file, 'r') as f:
                all_logs = json.load(f)
        else:
            all_logs = {"simulations": []}

        all_logs["simulations"].append(results)

        with open(log_file, 'w') as f:
            json.dump(all_logs, f, indent=2, default=str)

        self.logger.info(f"Simulation results saved to {log_file}")

    def run_targeted_simulation(self, user_id: str, attack_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        self.logger.info(f"Running targeted simulation against {user_id}")

        results = []
        attacks_to_run = [attack for attack in self.attacks if attack_types is None or attack.name in attack_types]

        for attack in attacks_to_run:
            try:
                result = attack.execute(self.iam_env, user_id)
                if result:
                    self.log_results(result)
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Error in targeted simulation: {str(e)}")
                error_result = {
                    "user": user_id,
                    "attack": attack.name,
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                self.log_results(error_result)
                results.append(error_result)

        return results

    def get_simulation_stats(self) -> Dict[str, Any]:
        if not self.logs:
            return {"message": "No attacks executed yet"}

        total_attacks = len(self.logs)
        successful_attacks = sum(1 for log in self.logs if log.get("success", False))

        attack_breakdown = {}
        for log in self.logs:
            attack_type = log["attack"]
            if attack_type not in attack_breakdown:
                attack_breakdown[attack_type] = {"total": 0, "successful": 0}
            attack_breakdown[attack_type]["total"] += 1
            if log.get("success", False):
                attack_breakdown[attack_type]["successful"] += 1

        return {
            "total_attacks": total_attacks,
            "successful_attacks": successful_attacks,
            "success_rate": f"{(successful_attacks / total_attacks) * 100:.1f}%" if total_attacks > 0 else "0%",
            "attack_breakdown": attack_breakdown,
            "compromised_users": list(set(log["user"] for log in self.logs if log.get("success", False)))
        }


# === SUCCESS RATE TUNING HELPERS ===

def apply_quick_success_rate_fixes():
    """
    Patch attack classes for higher success rates.
    Returns two patch functions for BruteForce and PrivilegeEscalation.
    """
    print("🔧 Applying quick success rate fixes...")

    def patch_brute_force_success_rate(attack_instance):
        attack_instance.base_success_rate = 0.45
        attack_instance.mfa_protection_factor = 0.2
        print("✅ Patched BruteForceAttack success rates")

    def patch_privilege_escalation_success_rate(attack_instance):
        original_calc = attack_instance._calculate_direct_escalation_probability

        def new_calc(current_role, target_role):
            base_result = original_calc(current_role, target_role)
            return min(base_result * 2.5, 0.8)

        attack_instance._calculate_direct_escalation_probability = new_calc
        print("✅ Patched PrivilegeEscalationAttack success rates")

    return patch_brute_force_success_rate, patch_privilege_escalation_success_rate


def override_attack_success_rates(attack_instances: list, min_success_rate: float = 0.3, max_success_rate: float = 0.8):
    """
    Override success rate calculations with bounded random values.
    """
    print(f"🎯 Overriding success rates: {min_success_rate*100:.0f}% - {max_success_rate*100:.0f}%")

    for attack in attack_instances:
        if hasattr(attack, '_calculate_success_probability'):
            def new_calc(*args, **kwargs):
                return random.uniform(min_success_rate, max_success_rate)
            attack._calculate_success_probability = new_calc
if __name__ == "__main__":
    from shadowlink.core.iam.environment import IAMEnvironmentManager

    # Create a dummy or loaded IAM environment
    env_manager = IAMEnvironmentManager()
    env_manager.load_environment("data/mock_iam/environments/default.json")  # Adjust path as needed

    # Initialize the simulation engine
    engine = SimulationEngine(env_manager, seed=42)

    # OPTIONAL: Patch success rates
    brute_patch, priv_patch = apply_quick_success_rate_fixes()
    for attack in engine.attacks:
        if isinstance(attack, BruteForceAttack):
            brute_patch(attack)
        elif isinstance(attack, PrivilegeEscalationAttack):
            priv_patch(attack)

    # Run the simulation
    results = engine.run_simulation()

    # Print summary
    print("\n=== Simulation Summary ===")
    summary = results["summary"]
    print(f"Simulation ID: {results['simulation_id']}")
    print(f"Total Attacks: {summary['total_attacks']}")
    print(f"Successful: {summary['successful_attacks']}")
    print(f"Failed: {summary['failed_attacks']}")
    print(f"Compromised Users: {', '.join(summary['compromised_users']) if summary['compromised_users'] else 'None'}")
    print("Attack Types Breakdown:")
    for attack, stats in summary["attack_types"].items():
        success_rate = (stats['successful'] / stats['total']) * 100 if stats['total'] else 0
        print(f"  - {attack}: {stats['successful']}/{stats['total']} successful ({success_rate:.1f}%)")
