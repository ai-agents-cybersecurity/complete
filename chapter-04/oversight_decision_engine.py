from enum import Enum
from typing import Dict, Tuple, Any

class OversightLevel(Enum):
    AUTOMATED = "automated"        # No human involvement
    HOTL = "human_on_the_loop"    # Human monitoring
    HITL = "human_in_the_loop"    # Human approval required
    MANUAL = "manual_only"        # Human-only decision

class RiskFactors:
    ASSET_CRITICALITY = {
        'low': 1,
        'medium': 3,
        'high': 5,
        'critical': 7
    }
    BUSINESS_IMPACT = {
        'minimal': 1,
        'low': 2,
        'medium': 4,
        'high': 6,
        'critical': 8
    }
    REVERSIBILITY = {
        'fully_reversible': 1,
        'reversible': 2,
        'partially_reversible': 4,
        'irreversible': 6
    }
    CONFIDENCE_SCORE = {
        'very_high': 1,
        'high': 2,
        'medium': 4,
        'low': 6,
        'very_low': 8
    }

class OversightDecisionEngine:
    def __init__(self):
        self.risk_weights = {
            'asset_criticality': 0.3,
            'business_impact': 0.3,
            'reversibility': 0.25,
            'confidence_score': 0.15
        }
        self.oversight_thresholds = {
            (0, 2.5): OversightLevel.AUTOMATED,
            (2.5, 4.0): OversightLevel.HOTL,
            (4.0, 6.0): OversightLevel.HITL,
            (6.0, float('inf')): OversightLevel.MANUAL
        }
    def determine_oversight_level(self, 
                                asset_criticality: str,
                                business_impact: str,
                                reversibility: str,
                                confidence_score: str,
                                special_circumstances: Dict[str, bool] = None) -> Tuple[OversightLevel, Dict[str, Any]]:
        risk_scores = {
            'asset_criticality': RiskFactors.ASSET_CRITICALITY[asset_criticality],
            'business_impact': RiskFactors.BUSINESS_IMPACT[business_impact],
            'reversibility': RiskFactors.REVERSIBILITY[reversibility],
            'confidence_score': RiskFactors.CONFIDENCE_SCORE[confidence_score]
        }
        weighted_score = sum(
            risk_scores[factor] * self.risk_weights[factor] 
            for factor in risk_scores
        )
        base_oversight = self._score_to_oversight(weighted_score)
        final_oversight = self._apply_special_circumstances(
            base_oversight, special_circumstances or {}
        )
        explanation = self._generate_explanation(
            risk_scores, weighted_score, base_oversight, final_oversight, special_circumstances
        )
        return final_oversight, explanation
    def _score_to_oversight(self, score: float) -> OversightLevel:
        for (min_score, max_score), oversight in self.oversight_thresholds.items():
            if min_score <= score < max_score:
                return oversight
        return OversightLevel.MANUAL
    def _apply_special_circumstances(self, base_oversight: OversightLevel, circumstances: Dict[str, bool]) -> OversightLevel:
        force_manual = [
            'regulatory_compliance_required',
            'life_safety_impact',
            'legal_investigation_active',
            'known_threat_actor_involved'
        ]
        force_hitl = [
            'customer_data_involved',
            'financial_transaction',
            'privileged_account_action',
            'cross_tenant_impact'
        ]
        if any(circumstances.get(condition, False) for condition in force_manual):
            return OversightLevel.MANUAL
        if any(circumstances.get(condition, False) for condition in force_hitl):
            if base_oversight in [OversightLevel.AUTOMATED, OversightLevel.HOTL]:
                return OversightLevel.HITL
        return base_oversight
    def _generate_explanation(self, 
                            risk_scores: Dict[str, int],
                            weighted_score: float,
                            base_oversight: OversightLevel,
                            final_oversight: OversightLevel,
                            circumstances: Dict[str, bool]) -> Dict[str, Any]:
        return {
            'weighted_risk_score': round(weighted_score, 2),
            'risk_breakdown': risk_scores,
            'base_recommendation': base_oversight.value,
            'final_recommendation': final_oversight.value,
            'special_circumstances': {k: v for k, v in (circumstances or {}).items() if v},
            'explanation': self._generate_text_explanation(
                weighted_score, base_oversight, final_oversight, circumstances or {}
            )
        }
    def _generate_text_explanation(self,
                                 score: float,
                                 base: OversightLevel,
                                 final: OversightLevel,
                                 circumstances: Dict[str, bool]) -> str:
        explanation = f"Risk score: {score:.2f} → Base recommendation: {base.value}"
        if base != final:
            active_circumstances = [k for k, v in circumstances.items() if v]
            explanation += f" → Elevated to {final.value} due to: {', '.join(active_circumstances)}"
        return explanation

def main():
    engine = OversightDecisionEngine()
    scenarios = [
        {
            'name': 'Routine Malware Block',
            'asset_criticality': 'low',
            'business_impact': 'minimal',
            'reversibility': 'fully_reversible',
            'confidence_score': 'very_high',
            'circumstances': {}
        },
        {
            'name': 'Production Server Isolation',
            'asset_criticality': 'critical',
            'business_impact': 'high',
            'reversibility': 'partially_reversible',
            'confidence_score': 'high',
            'circumstances': {'customer_data_involved': True}
        },
        {
            'name': 'Medical Device Security Update',
            'asset_criticality': 'critical',
            'business_impact': 'critical',
            'reversibility': 'irreversible',
            'confidence_score': 'medium',
            'circumstances': {'life_safety_impact': True, 'regulatory_compliance_required': True}
        },
        {
            'name': 'User Account Suspension',
            'asset_criticality': 'medium',
            'business_impact': 'low',
            'reversibility': 'reversible',
            'confidence_score': 'high',
            'circumstances': {'privileged_account_action': True}
        }
    ]
    print("🌳 OVERSIGHT DECISION TREE EXAMPLES")
    print("=" * 60)
    for scenario in scenarios:
        oversight, explanation = engine.determine_oversight_level(
            asset_criticality=scenario['asset_criticality'],
            business_impact=scenario['business_impact'],
            reversibility=scenario['reversibility'],
            confidence_score=scenario['confidence_score'],
            special_circumstances=scenario['circumstances']
        )
        print(f"\n📋 Scenario: {scenario['name']}")
        print(f"   Oversight Level: {oversight.value.upper()}")
        print(f"   Risk Score: {explanation['weighted_risk_score']}")
        print(f"   Explanation: {explanation['explanation']}")
        if explanation['special_circumstances']:
            print(f"   Special Circumstances: {list(explanation['special_circumstances'].keys())}")

if __name__ == "__main__":
    main()
