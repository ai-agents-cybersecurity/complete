import asyncio
import random
from typing import Dict, Any
from datetime import datetime, timedelta

# --- Kill Switch Components ---
class TimeBasedKillSwitch:
    def __init__(self, timeout_minutes=60):
        self.start_time = datetime.now()
        self.timeout = timedelta(minutes=timeout_minutes)
    def is_expired(self):
        return datetime.now() - self.start_time > self.timeout

class ThresholdKillSwitch:
    def __init__(self, error_threshold=0.2):
        self.error_threshold = error_threshold
        self.error_count = 0
        self.total_actions = 0
    def record_action_result(self, success: bool):
        self.total_actions += 1
        if not success:
            self.error_count += 1
    def is_triggered(self):
        if self.total_actions == 0:
            return False
        return (self.error_count / self.total_actions) > self.error_threshold

class ManualKillSwitch:
    def __init__(self):
        self.active = True
        self.reason = ""
    def is_active(self):
        return self.active
    def emergency_stop(self, reason, triggered_by):
        self.active = False
        self.reason = f"{reason} (by {triggered_by})"

class ComprehensiveKillSwitch:
    """
    Multi-layered kill switch system combining all protection mechanisms
    """
    def __init__(self):
        self.time_switch = TimeBasedKillSwitch(timeout_minutes=60)
        self.threshold_switch = ThresholdKillSwitch()
        self.manual_switch = ManualKillSwitch()
        self.global_enabled = True
    def is_safe_to_proceed(self) -> tuple[bool, str]:
        if not self.global_enabled:
            return False, "Global automation disabled"
        if not self.manual_switch.is_active():
            return False, f"Manual kill switch: {self.manual_switch.reason}"
        if self.threshold_switch.is_triggered():
            return False, "Error threshold exceeded"
        if self.time_switch.is_expired():
            return False, "Time-based kill switch expired"
        return True, "All systems nominal"
    def record_action_result(self, success: bool):
        self.threshold_switch.record_action_result(success)
    def emergency_stop_all(self, reason: str, triggered_by: str):
        self.manual_switch.emergency_stop(reason, triggered_by)
        self.global_enabled = False
        print("🚨 ALL KILL SWITCHES ACTIVATED - SYSTEM SHUTDOWN")
    def status_report(self) -> Dict[str, Any]:
        safe, reason = self.is_safe_to_proceed()
        return {
            'overall_status': 'SAFE' if safe else 'HALTED',
            'reason': reason,
            'global_enabled': self.global_enabled,
            'manual_switch_active': self.manual_switch.is_active(),
            'threshold_triggered': self.threshold_switch.is_triggered(),
            'time_expired': self.time_switch.is_expired(),
            'error_rate': self.threshold_switch.error_count / max(self.threshold_switch.total_actions, 1),
            'total_actions': self.threshold_switch.total_actions
        }

# --- Example usage in a security agent ---
class SafeSecurityAgent:
    def __init__(self):
        self.kill_switch = ComprehensiveKillSwitch()
        self.actions_performed = 0
    async def perform_security_action(self, action_details: Dict[str, Any]) -> bool:
        safe, reason = self.kill_switch.is_safe_to_proceed()
        if not safe:
            print(f"❌ Action blocked: {reason}")
            return False
        print(f"🔄 Executing: {action_details['action']}")
        try:
            await asyncio.sleep(1)
            success = random.random() > 0.1
            self.kill_switch.record_action_result(success)
            self.actions_performed += 1
            if success:
                print(f"✅ Success: {action_details['action']}")
            else:
                print(f"❌ Failed: {action_details['action']}")
            return success
        except Exception as e:
            print(f"💥 Error: {str(e)}")
            self.kill_switch.record_action_result(False)
            return False
    def get_status(self):
        return {
            'actions_performed': self.actions_performed,
            'kill_switch_status': self.kill_switch.status_report()
        }

# Demonstration
def main():
    async def demo_kill_switches():
        agent = SafeSecurityAgent()
        actions = [
            {'action': 'block_ip', 'target': '203.0.113.1'},
            {'action': 'quarantine_file', 'target': 'suspicious.exe'},
            {'action': 'disable_account', 'target': 'user123'},
            {'action': 'isolate_host', 'target': 'workstation-45'},
            {'action': 'update_firewall', 'target': 'main_gateway'}
        ]
        for action in actions:
            await agent.perform_security_action(action)
            await asyncio.sleep(0.5)
        status = agent.get_status()
        print("\n" + "="*50)
        print("📊 FINAL STATUS REPORT")
        print("="*50)
        print(f"Actions performed: {status['actions_performed']}")
        print(f"Overall status: {status['kill_switch_status']['overall_status']}")
        print(f"Error rate: {status['kill_switch_status']['error_rate']:.1%}")
        print("\n🚨 SIMULATING EMERGENCY SITUATION")
        agent.kill_switch.emergency_stop_all(
            reason="Detected agent compromise", 
            triggered_by="Security Analyst"
        )
        await agent.perform_security_action({'action': 'test_action', 'target': 'test'})
    asyncio.run(demo_kill_switches())

if __name__ == "__main__":
    main()
