# EU AI Act Compliance Tracker
from datetime import datetime, timedelta
import json

class AIActComplianceTracker:
    def __init__(self):
        self.systems = {}
        self.compliance_requirements = {
            'risk_assessment': {'required': True, 'frequency': 'quarterly'},
            'bias_audit': {'required': True, 'frequency': 'monthly'},
            'human_oversight': {'required': True, 'frequency': 'continuous'},
            'transparency_docs': {'required': True, 'frequency': 'annual'},
            'technical_docs': {'required': True, 'frequency': 'on_change'},
            'record_keeping': {'required': True, 'frequency': 'continuous'}
        }
    def register_ai_system(self, system_id, risk_level, deployment_date):
        """Register a new AI system for compliance tracking"""
        self.systems[system_id] = {
            'risk_level': risk_level,
            'deployment_date': deployment_date,
            'compliance_status': {},
            'last_review': None,
            'overdue_items': []
        }
    def update_compliance_item(self, system_id, item, status, date_completed):
        """Update compliance status for a specific requirement"""
        if system_id in self.systems:
            self.systems[system_id]['compliance_status'][item] = {
                'status': status,
                'date_completed': date_completed,
                'next_due': self._calculate_next_due_date(item, date_completed)
            }
    def _calculate_next_due_date(self, item, date_completed):
        freq = self.compliance_requirements[item]['frequency']
        dt = datetime.strptime(date_completed, "%Y-%m-%d")
        if freq == 'quarterly':
            return (dt + timedelta(days=90)).strftime("%Y-%m-%d")
        elif freq == 'monthly':
            return (dt + timedelta(days=30)).strftime("%Y-%m-%d")
        elif freq == 'annual':
            return (dt + timedelta(days=365)).strftime("%Y-%m-%d")
        elif freq == 'on_change':
            return None
        elif freq == 'continuous':
            return None
        return None
    def check_overdue_items(self, system_id, current_date):
        """Check for overdue compliance items"""
        overdue = []
        if system_id in self.systems:
            for item, req in self.compliance_requirements.items():
                status = self.systems[system_id]['compliance_status'].get(item)
                if status and status['next_due']:
                    if datetime.strptime(status['next_due'], "%Y-%m-%d") < datetime.strptime(current_date, "%Y-%m-%d"):
                        overdue.append(item)
                elif req['required']:
                    overdue.append(item)
            self.systems[system_id]['overdue_items'] = overdue
        return overdue
    def export_compliance_report(self, system_id, output_path):
        """Export compliance report as JSON"""
        if system_id in self.systems:
            with open(output_path, 'w') as f:
                json.dump(self.systems[system_id], f, indent=2)
    def summary(self, system_id):
        """Print summary for a registered system"""
        if system_id in self.systems:
            s = self.systems[system_id]
            print(f"System: {system_id}")
            print(f"Risk Level: {s['risk_level']}")
            print(f"Deployment Date: {s['deployment_date']}")
            print(f"Compliance Status:")
            for item, status in s['compliance_status'].items():
                print(f"  {item}: {status['status']} (Next Due: {status['next_due']})")
            print(f"Overdue Items: {s['overdue_items']}")
# Example usage
if __name__ == "__main__":
    tracker = AIActComplianceTracker()
    tracker.register_ai_system("agent-001", "high", "2025-01-01")
    tracker.update_compliance_item("agent-001", "risk_assessment", "complete", "2025-03-01")
    tracker.update_compliance_item("agent-001", "bias_audit", "pending", "2025-07-01")
    tracker.check_overdue_items("agent-001", "2025-08-18")
    tracker.summary("agent-001")
    tracker.export_compliance_report("agent-001", "agent-001_compliance.json")
