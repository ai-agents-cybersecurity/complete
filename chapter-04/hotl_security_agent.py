import asyncio
import random
from typing import Dict, Any
from datetime import datetime, timedelta

class HOTLSecurityAgent:
    """
    Human-on-the-Loop agent that acts autonomously 
    but allows human intervention
    """
    def __init__(self):
        self.monitoring_queue = []
        self.intervention_window = 30  # 30 second intervention window
        self.auto_actions = []
    async def execute_monitored_action(self, action_details: Dict[str, Any]):
        """
        Execute action with human monitoring capability
        """
        action_id = f"action_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        monitoring_item = {
            'id': action_id,
            'action': action_details,
            'status': 'executing',
            'started_at': datetime.now(),
            'intervention_expires': datetime.now() + timedelta(seconds=self.intervention_window)
        }
        self.monitoring_queue.append(monitoring_item)
        await self.display_monitoring_alert(monitoring_item)
        success = await self.execute_with_intervention_window(monitoring_item)
        return success
    async def display_monitoring_alert(self, item: Dict[str, Any]):
        print(f"\n👁️  MONITORING: {item['action']['action']}")
        print(f"   Target: {item['action']['target']}")  
        print(f"   Risk Level: {item['action']['risk_level']}/10")
        print(f"   Intervention window: {self.intervention_window}s")
        print(f"   Type 'STOP {item['id']}' to intervene")
    async def execute_with_intervention_window(self, monitoring_item: Dict[str, Any]):
        intervention_task = asyncio.create_task(
            self.monitor_for_intervention(monitoring_item['id'])
        )
        execution_task = asyncio.create_task(
            self.delayed_execution(monitoring_item)
        )
        done, pending = await asyncio.wait(
            [intervention_task, execution_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in done:
            result = task.result()
            if isinstance(result, dict) and result.get('action') == 'intervention':
                print(f"🛑 Human intervention: Action {monitoring_item['id']} stopped")
                return False
        print(f"✅ Action completed: {monitoring_item['action']['action']}")
        return True
    async def monitor_for_intervention(self, action_id: str):
        await asyncio.sleep(15)  # Check halfway through intervention window
        if random.random() < 0.1:  # 10% intervention rate
            return {'action': 'intervention', 'reason': 'human_override'}
        return {'action': 'no_intervention'}
    async def delayed_execution(self, monitoring_item: Dict[str, Any]):
        await asyncio.sleep(self.intervention_window)
        await self.perform_action(monitoring_item['action'])
        return {'action': 'completed'}
    async def perform_action(self, action_details: Dict[str, Any]):
        await asyncio.sleep(2)
        print(f"🔧 Executed: {action_details['action']} on {action_details['target']}")

def main():
    async def demo_hotl():
        agent = HOTLSecurityAgent()
        medium_risk_action = {
            'action': 'block_suspicious_ip',
            'target': '198.51.100.42',
            'risk_level': 5,
            'justification': 'Multiple failed authentication attempts'
        }
        await agent.execute_monitored_action(medium_risk_action)
    asyncio.run(demo_hotl())

if __name__ == "__main__":
    main()
