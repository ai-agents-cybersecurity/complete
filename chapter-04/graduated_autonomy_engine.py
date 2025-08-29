from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

class AutomationLevel(Enum):
    AUTOMATED = 1      # Full automation for routine tasks
    ASSISTED = 2       # AI recommendations with one-click approval  
    COLLABORATIVE = 3  # Human-AI partnership for complex decisions
    MANUAL = 4        # Full human control for critical situations

@dataclass
class SecurityDecision:
    threat_type: str
    risk_level: int  # 1-10 scale
    asset_criticality: int  # 1-10 scale
    business_impact: str
    confidence_score: float
    recommended_action: str
    automation_level: AutomationLevel
    approval_required: bool = False
    escalation_path: Optional[str] = None

class GraduatedAutonomyEngine:
    """
    Implements graduated autonomy for cybersecurity decisions
    using the air traffic control model
    """
    def __init__(self):
        self.decision_matrix = self._build_decision_matrix()
        self.circuit_breakers = self._initialize_circuit_breakers()
        self.kill_switches = self._initialize_kill_switches()
    def _build_decision_matrix(self) -> Dict[str, Dict[str, AutomationLevel]]:
        """
        Define automation levels based on risk and asset criticality
        Similar to air traffic control routing rules
        """
        return {
            'malware_detection': {
                'low_risk_low_criticality': AutomationLevel.AUTOMATED,
                'low_risk_high_criticality': AutomationLevel.ASSISTED,
                'high_risk_low_criticality': AutomationLevel.ASSISTED,
                'high_risk_high_criticality': AutomationLevel.COLLABORATIVE
            },
            'network_intrusion': {
                'low_risk_low_criticality': AutomationLevel.ASSISTED,
                'low_risk_high_criticality': AutomationLevel.COLLABORATIVE,
                'high_risk_low_criticality': AutomationLevel.COLLABORATIVE,
                'high_risk_high_criticality': AutomationLevel.MANUAL
            },
            'data_exfiltration': {
                'low_risk_low_criticality': AutomationLevel.COLLABORATIVE,
                'low_risk_high_criticality': AutomationLevel.MANUAL,
                'high_risk_low_criticality': AutomationLevel.MANUAL,
                'high_risk_high_criticality': AutomationLevel.MANUAL
            }
        }
    def _initialize_circuit_breakers(self) -> Dict[str, float]:
        return {'recent_false_positives': 0.0, 'system_load': 0.0}
    def _initialize_kill_switches(self) -> Dict[str, bool]:
        return {'global': False}
    async def determine_response_level(self, threat_data: Dict[str, Any]) -> SecurityDecision:
        """
        Determine appropriate automation level based on threat characteristics
        Like air traffic control determining routing vs. human control
        """
        threat_type = threat_data.get('type', 'unknown')
        risk_level = threat_data.get('risk_level', 5)
        asset_criticality = threat_data.get('asset_criticality', 5)
        confidence = threat_data.get('confidence_score', 0.5)
        # Determine risk category
        risk_category = self._categorize_risk(risk_level, asset_criticality)
        # Look up automation level
        automation_level = self.decision_matrix.get(threat_type, {}).get(
            risk_category, AutomationLevel.MANUAL
        )
        # Check circuit breakers
        if self._circuit_breaker_triggered(threat_data):
            automation_level = AutomationLevel.MANUAL
        # Build decision object
        decision = SecurityDecision(
            threat_type=threat_type,
            risk_level=risk_level,
            asset_criticality=asset_criticality,
            business_impact=self._assess_business_impact(threat_data),
            confidence_score=confidence,
            recommended_action=self._generate_recommendation(threat_data),
            automation_level=automation_level,
            approval_required=automation_level in [AutomationLevel.COLLABORATIVE, AutomationLevel.MANUAL]
        )
        return decision
    def _categorize_risk(self, risk_level: int, asset_criticality: int) -> str:
        """Categorize overall risk level"""
        if risk_level <= 3 and asset_criticality <= 3:
            return 'low_risk_low_criticality'
        elif risk_level <= 3 and asset_criticality > 3:
            return 'low_risk_high_criticality' 
        elif risk_level > 3 and asset_criticality <= 3:
            return 'high_risk_low_criticality'
        else:
            return 'high_risk_high_criticality'
    def _circuit_breaker_triggered(self, threat_data: Dict[str, Any]) -> bool:
        """
        Check if circuit breakers should force human control
        Like emergency protocols in air traffic control
        """
        if self.circuit_breakers['recent_false_positives'] > 0.1:
            return True
        if self.circuit_breakers['system_load'] > 0.9:
            return True
        return False
    def _assess_business_impact(self, threat_data: Dict[str, Any]) -> str:
        return threat_data.get('business_impact', 'unknown')
    def _generate_recommendation(self, threat_data: Dict[str, Any]) -> str:
        return f"Respond to {threat_data.get('type', 'unknown')}"
