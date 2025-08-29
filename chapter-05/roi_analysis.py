from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from enum import Enum
import matplotlib.pyplot as plt
import numpy as np

class CostCategory(Enum):
    INFRASTRUCTURE = "infrastructure"
    OPERATIONS = "operations"
    DEVELOPMENT = "development"
    COMPLIANCE = "compliance"
    TRAINING = "training"

class BenefitCategory(Enum):
    TIME_SAVINGS = "time_savings"
    ERROR_REDUCTION = "error_reduction"
    IMPROVED_RESPONSE = "improved_response_time"
    REDUCED_INCIDENTS = "reduced_incidents"
    ANALYST_PRODUCTIVITY = "analyst_productivity"

@dataclass
class CostModel:
    base_infrastructure_cost_monthly: float = 5000
    cost_per_agent_monthly: float = 150
    development_cost_per_agent: float = 25000
    compliance_audit_cost_annual: float = 50000
    training_cost_per_person: float = 5000
    def calculate_monthly_cost(self, agent_count: int, team_size: int, include_compliance: bool = True) -> Dict[str, float]:
        infrastructure_cost = self.base_infrastructure_cost_monthly * (1 + np.log(agent_count + 1) * 0.2)
        operations_cost = agent_count * self.cost_per_agent_monthly
        development_cost_monthly = (agent_count * self.development_cost_per_agent) / 36
        compliance_cost_monthly = self.compliance_audit_cost_annual / 12 if include_compliance else 0
        training_cost_monthly = (team_size * self.training_cost_per_person) / 12
        return {
            CostCategory.INFRASTRUCTURE.value: infrastructure_cost,
            CostCategory.OPERATIONS.value: operations_cost,
            CostCategory.DEVELOPMENT.value: development_cost_monthly,
            CostCategory.COMPLIANCE.value: compliance_cost_monthly,
            CostCategory.TRAINING.value: training_cost_monthly
        }
@dataclass
class BenefitModel:
    analyst_hourly_rate: float = 75
    incident_response_hours_saved: float = 8
    false_positive_reduction_rate: float = 0.6
    response_time_improvement_factor: float = 0.3
    incidents_per_month: int = 100
    def calculate_monthly_benefit(self, agent_count: int, baseline_analyst_hours: float = 2000) -> Dict[str, float]:
        automation_efficiency = min(0.8, agent_count * 0.05)
        time_savings_hours = baseline_analyst_hours * automation_efficiency
        time_savings_value = time_savings_hours * self.analyst_hourly_rate
        false_positive_hours_saved = (self.incidents_per_month * 0.5 * self.false_positive_reduction_rate * self.analyst_hourly_rate)
        response_improvement_value = (self.incidents_per_month * self.incident_response_hours_saved * self.response_time_improvement_factor * self.analyst_hourly_rate)
        incident_reduction_rate = min(0.4, agent_count * 0.02)
        prevented_incident_value = (self.incidents_per_month * incident_reduction_rate * 50000)
        productivity_multiplier = 1 + (agent_count * 0.01)
        productivity_value = (baseline_analyst_hours * 0.3 * (productivity_multiplier - 1) * self.analyst_hourly_rate)
        return {
            BenefitCategory.TIME_SAVINGS.value: time_savings_value,
            BenefitCategory.ERROR_REDUCTION.value: false_positive_hours_saved,
            BenefitCategory.IMPROVED_RESPONSE.value: response_improvement_value,
            BenefitCategory.REDUCED_INCIDENTS.value: prevented_incident_value,
            BenefitCategory.ANALYST_PRODUCTIVITY.value: productivity_value
        }
class ROICalculator:
    def __init__(self, cost_model: CostModel, benefit_model: BenefitModel):
        self.cost_model = cost_model
        self.benefit_model = benefit_model
    def analyze_scaling_scenarios(self, max_agents: int = 100, team_size: int = 10) -> Dict[str, Any]:
        scenarios = []
        agent_counts = [1, 5, 10, 25, 50, 75, 100]
        for agent_count in agent_counts:
            if agent_count > max_agents:
                continue
            monthly_costs = self.cost_model.calculate_monthly_cost(agent_count, team_size)
            monthly_benefits = self.benefit_model.calculate_monthly_benefit(agent_count)
            total_monthly_cost = sum(monthly_costs.values())
            total_monthly_benefit = sum(monthly_benefits.values())
            monthly_net_benefit = total_monthly_benefit - total_monthly_cost
            annual_cost = total_monthly_cost * 12
            annual_benefit = total_monthly_benefit * 12
            roi_percentage = ((annual_benefit - annual_cost) / annual_cost * 100) if annual_cost > 0 else 0
            if monthly_net_benefit > 0:
                payback_months = total_monthly_cost / monthly_net_benefit
            else:
                payback_months = float('inf')
            scenarios.append({
                'agent_count': agent_count,
                'monthly_cost': total_monthly_cost,
                'monthly_benefit': total_monthly_benefit,
                'monthly_net_benefit': monthly_net_benefit,
                'annual_roi_percentage': roi_percentage,
                'payback_months': payback_months,
                'cost_breakdown': monthly_costs,
                'benefit_breakdown': monthly_benefits
            })
        return {
            'scenarios': scenarios,
            'optimal_scenario': self._find_optimal_scenario(scenarios),
            'break_even_point': self._find_break_even_point(scenarios)
        }
    def _find_optimal_scenario(self, scenarios: List[Dict]) -> Dict[str, Any]:
        if not scenarios:
            return {}
        optimal = max(scenarios, key=lambda x: x['monthly_net_benefit'])
        return {
            'agent_count': optimal['agent_count'],
            'monthly_net_benefit': optimal['monthly_net_benefit'],
            'roi_percentage': optimal['annual_roi_percentage']
        }
    def _find_break_even_point(self, scenarios: List[Dict]) -> Optional[int]:
        for scenario in scenarios:
            if scenario['monthly_net_benefit'] > 0:
                return scenario['agent_count']
        return None
    def generate_executive_summary(self, analysis: Dict[str, Any]) -> str:
        optimal = analysis['optimal_scenario']
        break_even = analysis['break_even_point']
        summary = f"""
EXECUTIVE SUMMARY: AI AGENT SCALING ROI ANALYSIS

KEY FINDINGS:
• Optimal Scale: {optimal['agent_count']} agents delivering ${optimal['monthly_net_benefit']:,.0f} monthly net benefit
• ROI at Optimal Scale: {optimal['roi_percentage']:.1f}% annual return on investment
• Break-even Point: {break_even} agents (minimum viable scale)
• Payback Period: {[s for s in analysis['scenarios'] if s['agent_count'] == optimal['agent_count']][0]['payback_months']:.1f} months

BUSINESS IMPACT:
• Monthly cost savings of ${optimal['monthly_net_benefit']:,.0f} at optimal scale
• Annual net benefit of ${optimal['monthly_net_benefit'] * 12:,.0f}
• Strong business case for scaling beyond break-even point

RECOMMENDATION:
{"Deploy at optimal scale for maximum ROI" if break_even else "Reassess cost model - current projections show negative ROI"}
        """
        return summary.strip()
def demo_roi_analysis():
    print("💰 ROI ANALYSIS FOR AGENT SCALING")
    print("=" * 60)
    cost_model = CostModel()
    benefit_model = BenefitModel()
    calculator = ROICalculator(cost_model, benefit_model)
    analysis = calculator.analyze_scaling_scenarios(max_agents=100, team_size=10)
    print("\n📊 SCALING SCENARIOS:")
    print("-" * 80)
    print(f"{'Agents':<8} {'Monthly Cost':<15} {'Monthly Benefit':<16} {'Net Benefit':<13} {'ROI %':<8}")
    print("-" * 80)
    for scenario in analysis['scenarios']:
        print(f"{scenario['agent_count']:<8} "
              f"${scenario['monthly_cost']:>10,.0f}    "
              f"${scenario['monthly_benefit']:>12,.0f}     "
              f"${scenario['monthly_net_benefit']:>9,.0f}    "
              f"{scenario['annual_roi_percentage']:>5.1f}%")
    print("\n" + "="*60)
    print(calculator.generate_executive_summary(analysis))
    optimal_scenario = [s for s in analysis['scenarios'] 
                       if s['agent_count'] == analysis['optimal_scenario']['agent_count']][0]
    print(f"\n📋 DETAILED BREAKDOWN - OPTIMAL SCENARIO ({optimal_scenario['agent_count']} agents):")
    print("-" * 40)
    print("MONTHLY COSTS:")
    for category, cost in optimal_scenario['cost_breakdown'].items():
        print(f"  {category.title()}: ${cost:,.0f}")
    print("\nMONTHLY BENEFITS:")
    for category, benefit in optimal_scenario['benefit_breakdown'].items():
        print(f"  {category.replace('_', ' ').title()}: ${benefit:,.0f}")
if __name__ == "__main__":
    demo_roi_analysis()
