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
    """Model for calculating costs at different scales"""
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
    """Model for calculating benefits at different scales"""
    analyst_hourly_rate: float = 75
    incident_response_hours_saved: float = 8
    false_positive_reduction_rate: float = 0.6
    response_time_improvement_factor: float = 0.3
    incidents_per_month: int = 100
    def calculate_monthly_benefit(self, agent_count: int, team_size: int, baseline_incidents: int = None) -> Dict[str, float]:
        if baseline_incidents is None:
            baseline_incidents = self.incidents_per_month
        time_savings = agent_count * self.incident_response_hours_saved * self.analyst_hourly_rate
        error_reduction = baseline_incidents * self.false_positive_reduction_rate * self.analyst_hourly_rate
        improved_response = baseline_incidents * self.response_time_improvement_factor * self.analyst_hourly_rate
        reduced_incidents = baseline_incidents * 0.2 * self.analyst_hourly_rate
        analyst_productivity = team_size * 0.1 * self.analyst_hourly_rate * 160
        return {
            BenefitCategory.TIME_SAVINGS.value: time_savings,
            BenefitCategory.ERROR_REDUCTION.value: error_reduction,
            BenefitCategory.IMPROVED_RESPONSE.value: improved_response,
            BenefitCategory.REDUCED_INCIDENTS.value: reduced_incidents,
            BenefitCategory.ANALYST_PRODUCTIVITY.value: analyst_productivity
        }
def plot_cost_benefit(costs: Dict[str, float], benefits: Dict[str, float]):
    categories = list(costs.keys()) + list(benefits.keys())
    values = list(costs.values()) + list(benefits.values())
    colors = ['red'] * len(costs) + ['green'] * len(benefits)
    plt.figure(figsize=(10, 5))
    plt.bar(categories, values, color=colors)
    plt.title('Monthly Cost vs. Benefit (USD)')
    plt.ylabel('USD')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
# Example usage
def main():
    cost_model = CostModel()
    benefit_model = BenefitModel()
    agent_count = 20
    team_size = 8
    costs = cost_model.calculate_monthly_cost(agent_count, team_size)
    benefits = benefit_model.calculate_monthly_benefit(agent_count, team_size)
    print('COSTS:', costs)
    print('BENEFITS:', benefits)
    plot_cost_benefit(costs, benefits)
if __name__ == "__main__":
    main()
