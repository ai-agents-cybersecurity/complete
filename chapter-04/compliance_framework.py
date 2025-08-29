from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Any, Dict
import json
import hashlib
from datetime import datetime, timedelta

class ComplianceLevel(Enum):
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss" 
    SOX = "sox"
    GDPR = "gdpr"
    FISMA = "fisma"

@dataclass
class ComplianceRequirement:
    level: ComplianceLevel
    explanation_required: bool
    human_oversight_required: bool
    audit_trail_required: bool
    data_retention_days: int
    notification_required: bool

class ComplianceFramework:
    """Framework for ensuring automated decisions meet compliance requirements"""
    def __init__(self):
        self.requirements = {
            ComplianceLevel.HIPAA: ComplianceRequirement(
                level=ComplianceLevel.HIPAA,
                explanation_required=True,
                human_oversight_required=True,
                audit_trail_required=True,
                data_retention_days=2555,  # 7 years
                notification_required=True
            ),
            ComplianceLevel.PCI_DSS: ComplianceRequirement(
                level=ComplianceLevel.PCI_DSS,
                explanation_required=True,
                human_oversight_required=False,
                audit_trail_required=True,
                data_retention_days=365,
                notification_required=False
            ),
            ComplianceLevel.GDPR: ComplianceRequirement(
                level=ComplianceLevel.GDPR,
                explanation_required=True,  # Right to explanation
                human_oversight_required=True,
                audit_trail_required=True,
                data_retention_days=1095,  # 3 years
                notification_required=True
            )
        }
    def validate_automated_decision(self, 
                                  decision: Dict[str, Any], 
                                  compliance_levels: List[ComplianceLevel]) -> Dict[str, Any]:
        validation_result = {
            'compliant': True,
            'violations': [],
            'requirements_met': [],
            'additional_actions_needed': []
        }
        for level in compliance_levels:
            req = self.requirements[level]
            if req.explanation_required and not decision.get('explanation'):
                validation_result['compliant'] = False
                validation_result['violations'].append(f"{level.value}: Missing explanation")
                validation_result['additional_actions_needed'].append("Generate decision explanation")
            if req.human_oversight_required and not decision.get('human_approved'):
                validation_result['compliant'] = False
                validation_result['violations'].append(f"{level.value}: Missing human oversight")
                validation_result['additional_actions_needed'].append("Require human approval")
            if req.audit_trail_required and not decision.get('audit_trail'):
                validation_result['compliant'] = False
                validation_result['violations'].append(f"{level.value}: Missing audit trail")
                validation_result['additional_actions_needed'].append("Generate audit trail")
            if not validation_result['violations']:
                validation_result['requirements_met'].append(level.value)
        return validation_result
    def generate_audit_trail(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        audit_trail = {
            'decision_id': decision.get('id', self._generate_decision_id()),
            'timestamp': datetime.now().isoformat(),
            'decision_type': decision.get('type'),
            'input_data_hash': self._hash_input_data(decision.get('input_data', {})),
            'algorithm_version': decision.get('algorithm_version', '1.0'),
            'confidence_score': decision.get('confidence_score'),
            'decision_outcome': decision.get('outcome'),
            'human_reviewer': decision.get('human_reviewer'),
            'review_timestamp': decision.get('review_timestamp'),
            'explanation': decision.get('explanation'),
            'compliance_levels': decision.get('compliance_levels', []),
            'data_sources': decision.get('data_sources', []),
            'retention_until': self._calculate_retention_date(decision.get('compliance_levels', []))
        }
        return audit_trail
    def _generate_decision_id(self) -> str:
        return f"decision_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    def _hash_input_data(self, input_data: Dict[str, Any]) -> str:
        data_string = json.dumps(input_data, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()
    def _calculate_retention_date(self, compliance_levels: List[str]) -> str:
        max_retention_days = 0
        for level_str in compliance_levels:
            try:
                level = ComplianceLevel(level_str)
                req = self.requirements[level]
                max_retention_days = max(max_retention_days, req.data_retention_days)
            except ValueError:
                continue
        if max_retention_days == 0:
            max_retention_days = 365  # Default 1 year
        retention_date = datetime.now() + timedelta(days=max_retention_days)
        return retention_date.isoformat()

def main():
    compliance_framework = ComplianceFramework()
    security_decision = {
        'id': 'sec_001',
        'type': 'user_account_lockout',
        'input_data': {'user_id': 'jdoe', 'failed_attempts': 5},
        'outcome': 'account_locked',
        'confidence_score': 0.95,
        'algorithm_version': '2.1',
        'explanation': 'Account locked due to excessive failed login attempts (5 attempts in 10 minutes)',
        'human_approved': True,
        'human_reviewer': 'security_analyst_1',
        'review_timestamp': '2024-01-15T10:30:00Z',
        'compliance_levels': ['hipaa', 'gdpr']
    }
    validation = compliance_framework.validate_automated_decision(
        security_decision,
        [ComplianceLevel.HIPAA, ComplianceLevel.GDPR]
    )
    print("Compliance Validation Result:")
    print(f"Compliant: {validation['compliant']}")
    if validation['violations']:
        print(f"Violations: {validation['violations']}")
    if validation['additional_actions_needed']:
        print(f"Actions needed: {validation['additional_actions_needed']}")
    audit_trail = compliance_framework.generate_audit_trail(security_decision)
    print(f"\nAudit Trail Generated:")
    print(f"Decision ID: {audit_trail['decision_id']}")
    print(f"Retention until: {audit_trail['retention_until']}")

if __name__ == "__main__":
    main()
