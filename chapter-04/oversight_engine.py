from enum import Enum
from typing import Dict, Tuple, Any
import numpy as np

class OversightLevel(Enum):
    AUTOMATED = "automated"        # No human involvement
    HOTL = "human_on_the_loop"    # Human monitoring
    HITL = "human_in_the_loop"    # Human approval required
    MANUAL = "manual_only"        # Human-only decision

class RiskFactors:
    """Define risk factors for oversight decisions"""
    ASSET_CRITICALITY = {
        'low': 1,      # Development systems
        'medium': 3,   # Staging systems  
        'high': 5,     # Production systems
        'critical': 7  # Life-safety systems
    }
    BUSINESS_IMPACT = {
        'minimal': 1,   # < $10K impact
        'low': 2,       # $10K - $100K
        'moderate': 3,  # $100K - $1M
        'high': 5,      # $1M - $10M
        'critical': 7   # > $10M or life-safety
    }
    THREAT_TYPE = {
        'malware': 2,
        'intrusion': 3,
        'data_exfiltration': 5,
        'insider': 4,
        'unknown': 1
    }

class OversightEngine:
    """Engine to determine oversight level based on risk"""
    def __init__(self):
        self.thresholds = {
            OversightLevel.AUTOMATED: 0,
            OversightLevel.HOTL: 7,
            OversightLevel.HITL: 12,
            OversightLevel.MANUAL: 18
        }
    def calculate_risk_score(self, factors: Dict[str, Any]) -> int:
        ac = RiskFactors.ASSET_CRITICALITY.get(factors.get('asset_criticality', 'low'), 1)
        bi = RiskFactors.BUSINESS_IMPACT.get(factors.get('business_impact', 'minimal'), 1)
        tt = RiskFactors.THREAT_TYPE.get(factors.get('threat_type', 'unknown'), 1)
        # Use weighted sum
        score = int(2*ac + 2*bi + 3*tt)
        return score
    def determine_oversight_level(self, factors: Dict[str, Any]) -> Tuple[OversightLevel, int]:
        score = self.calculate_risk_score(factors)
        if score >= self.thresholds[OversightLevel.MANUAL]:
            return OversightLevel.MANUAL, score
        elif score >= self.thresholds[OversightLevel.HITL]:
            return OversightLevel.HITL, score
        elif score >= self.thresholds[OversightLevel.HOTL]:
            return OversightLevel.HOTL, score
        else:
            return OversightLevel.AUTOMATED, score

def main():
    engine = OversightEngine()
    scenarios = [
        {'asset_criticality': 'low', 'business_impact': 'minimal', 'threat_type': 'malware'},
        {'asset_criticality': 'high', 'business_impact': 'critical', 'threat_type': 'data_exfiltration'},
        {'asset_criticality': 'critical', 'business_impact': 'high', 'threat_type': 'intrusion'},
        {'asset_criticality': 'medium', 'business_impact': 'moderate', 'threat_type': 'insider'}
    ]
    for i, s in enumerate(scenarios, 1):
        level, score = engine.determine_oversight_level(s)
        print(f"Scenario {i}: Oversight Level: {level.value}, Risk Score: {score}")

if __name__ == "__main__":
    main()
