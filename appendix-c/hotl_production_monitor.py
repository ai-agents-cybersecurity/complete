# hotl_production_monitor.py
import asyncio
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import json

class HumanOperatorTrustLevel(Enum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    FULL = 4

@dataclass
class OperatorAction:
    operator_id: str
    action_type: str
    timestamp: float
    context: Dict
    success: bool
    notes: Optional[str] = None

@dataclass
class OperatorProfile:
    operator_id: str
    trust_level: HumanOperatorTrustLevel = HumanOperatorTrustLevel.UNKNOWN
    actions: List[OperatorAction] = field(default_factory=list)
    mfa_verified: bool = False
    last_action_time: float = 0.0

class HOTLProductionMonitor:
    def __init__(self):
        self.operators: Dict[str, OperatorProfile] = {}
        self.action_log: List[OperatorAction] = []
        self.metrics = {
            'total_actions': 0,
            'successful_actions': 0,
            'failed_actions': 0,
            'mfa_verified': 0
        }
    def register_operator(self, operator_id: str, mfa_verified: bool = False):
        if operator_id not in self.operators:
            self.operators[operator_id] = OperatorProfile(
                operator_id=operator_id,
                mfa_verified=mfa_verified
            )
    def record_action(self, operator_id: str, action_type: str, context: Dict, success: bool, notes: Optional[str] = None):
        now = time.time()
        action = OperatorAction(
            operator_id=operator_id,
            action_type=action_type,
            timestamp=now,
            context=context,
            success=success,
            notes=notes
        )
        self.action_log.append(action)
        if operator_id in self.operators:
            self.operators[operator_id].actions.append(action)
            self.operators[operator_id].last_action_time = now
        self.metrics['total_actions'] += 1
        if success:
            self.metrics['successful_actions'] += 1
        else:
            self.metrics['failed_actions'] += 1
        if self.operators[operator_id].mfa_verified:
            self.metrics['mfa_verified'] += 1
        self._update_trust(operator_id)
    def _update_trust(self, operator_id: str):
        profile = self.operators[operator_id]
        actions = profile.actions[-20:]
        success_rate = sum(a.success for a in actions) / max(1, len(actions))
        if success_rate > 0.95 and profile.mfa_verified:
            profile.trust_level = HumanOperatorTrustLevel.FULL
        elif success_rate > 0.85:
            profile.trust_level = HumanOperatorTrustLevel.HIGH
        elif success_rate > 0.7:
            profile.trust_level = HumanOperatorTrustLevel.MEDIUM
        elif success_rate > 0.5:
            profile.trust_level = HumanOperatorTrustLevel.LOW
        else:
            profile.trust_level = HumanOperatorTrustLevel.UNKNOWN
    def get_operator_status(self, operator_id: str) -> Dict:
        if operator_id not in self.operators:
            return {'status': 'not_registered'}
        profile = self.operators[operator_id]
        return {
            'operator_id': operator_id,
            'trust_level': profile.trust_level.name,
            'total_actions': len(profile.actions),
            'last_action_time': profile.last_action_time,
            'mfa_verified': profile.mfa_verified
        }
    def export_metrics(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
    def export_action_log(self, path: str):
        with open(path, 'w') as f:
            json.dump([a.__dict__ for a in self.action_log], f, indent=2)
# Example usage
if __name__ == "__main__":
    monitor = HOTLProductionMonitor()
    monitor.register_operator('alice', mfa_verified=True)
    monitor.record_action('alice', 'approve', {'ticket': 123}, True)
    monitor.record_action('alice', 'deny', {'ticket': 124}, False, notes='Policy violation')
    print(monitor.get_operator_status('alice'))
    monitor.export_metrics('hotl_metrics.json')
    monitor.export_action_log('hotl_action_log.json')
