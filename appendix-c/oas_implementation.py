import time
import json
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

@dataclass
class OASPolicy:
    id: str
    name: str
    description: str
    rules: List[Dict]
    created_at: float
    updated_at: float
    enabled: bool = True
    tags: Optional[List[str]] = None

@dataclass
class OASActionLog:
    timestamp: float
    action: str
    policy_id: str
    context: Dict
    result: str
    signature: str

class OASManager:
    def __init__(self):
        self.policies: Dict[str, OASPolicy] = {}
        self.action_logs: List[OASActionLog] = []
    def add_policy(self, name: str, description: str, rules: List[Dict], tags: Optional[List[str]] = None) -> str:
        policy_id = hashlib.sha256(f"{name}{time.time()}".encode()).hexdigest()
        now = time.time()
        policy = OASPolicy(
            id=policy_id,
            name=name,
            description=description,
            rules=rules,
            created_at=now,
            updated_at=now,
            tags=tags
        )
        self.policies[policy_id] = policy
        return policy_id
    def update_policy(self, policy_id: str, description: Optional[str] = None, rules: Optional[List[Dict]] = None, enabled: Optional[bool] = None):
        if policy_id not in self.policies:
            raise ValueError("Policy not found")
        policy = self.policies[policy_id]
        if description:
            policy.description = description
        if rules:
            policy.rules = rules
        if enabled is not None:
            policy.enabled = enabled
        policy.updated_at = time.time()
    def evaluate_action(self, action: str, context: Dict) -> Dict:
        for policy in self.policies.values():
            if not policy.enabled:
                continue
            for rule in policy.rules:
                if rule.get('action') == action and self._context_matches(rule, context):
                    result = rule.get('result', 'allow')
                    log = self._log_action(action, policy.id, context, result)
                    return {'result': result, 'policy': policy.id, 'log': asdict(log)}
        log = self._log_action(action, 'none', context, 'no_match')
        return {'result': 'no_match', 'policy': None, 'log': asdict(log)}
    def _context_matches(self, rule: Dict, context: Dict) -> bool:
        for k, v in rule.get('conditions', {}).items():
            if context.get(k) != v:
                return False
        return True
    def _log_action(self, action: str, policy_id: str, context: Dict, result: str) -> OASActionLog:
        timestamp = time.time()
        log = OASActionLog(
            timestamp=timestamp,
            action=action,
            policy_id=policy_id,
            context=context,
            result=result,
            signature=self._sign_log(action, policy_id, context, result, timestamp)
        )
        self.action_logs.append(log)
        return log
    def _sign_log(self, action, policy_id, context, result, timestamp) -> str:
        data = json.dumps({
            'action': action,
            'policy_id': policy_id,
            'context': context,
            'result': result,
            'timestamp': timestamp
        }, sort_keys=True).encode()
        return hashlib.sha256(data).hexdigest()
    def export_logs(self, path: str):
        with open(path, 'w') as f:
            json.dump([asdict(log) for log in self.action_logs], f, indent=2)
    def export_policies(self, path: str):
        with open(path, 'w') as f:
            json.dump([asdict(p) for p in self.policies.values()], f, indent=2)
# Example usage
if __name__ == "__main__":
    oas = OASManager()
    pid = oas.add_policy(
        name="Block dangerous ops",
        description="Block delete in prod",
        rules=[{'action': 'delete', 'conditions': {'env': 'prod'}, 'result': 'deny'}],
        tags=["critical"]
    )
    print(oas.evaluate_action('delete', {'env': 'prod'}))
    oas.export_logs('oas_logs.json')
    oas.export_policies('oas_policies.json')
