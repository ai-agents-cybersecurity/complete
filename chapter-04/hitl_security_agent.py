import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

class HITLSecurityAgent:
    """
    Human-in-the-Loop security agent that requires explicit approval
    for all actions above a certain risk threshold
    """
    def __init__(self):
        self.pending_approvals = {}
        self.approval_timeout = 300  # 5 minutes
        self.approved_actions = set()
    async def request_action_approval(self, 
                                    action: str, 
                                    target: str, 
                                    risk_level: int,
                                    justification: str) -> Optional[str]:
        """
        Request human approval for a security action
        Returns approval ID if granted, None if denied/timeout
        """
        approval_id = f"approval_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        approval_request = {
            'id': approval_id,
            'action': action,
            'target': target,
            'risk_level': risk_level,
            'justification': justification,
            'requested_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(seconds=self.approval_timeout),
            'status': 'pending'
        }
        self.pending_approvals[approval_id] = approval_request
        await self.display_approval_request(approval_request)
        approved = await self.wait_for_approval(approval_id)
        if approved:
            self.approved_actions.add(approval_id)
            return approval_id
        else:
            return None
    async def display_approval_request(self, request: Dict[str, Any]):
        """Display approval request to human operator"""
        print("\n" + "="*60)
        print("🚨 SECURITY ACTION APPROVAL REQUIRED")
        print("="*60)
        print(f"Request ID: {request['id']}")
        print(f"Action: {request['action']}")
        print(f"Target: {request['target']}")
        print(f"Risk Level: {request['risk_level']}/10")
        print(f"Justification: {request['justification']}")
        print(f"Expires: {request['expires_at']}")
        print("\nOptions:")
        print("  [A] Approve")
        print("  [D] Deny") 
        print("  [M] Modify")
        print("="*60)
    async def wait_for_approval(self, approval_id: str) -> bool:
        """
        Wait for human approval (simulated for demo)
        In production, this would integrate with a ticketing system
        """
        import random
        decision_time = random.uniform(2, 30)
        await asyncio.sleep(decision_time)
        approved = random.random() < 0.85
        if approval_id in self.pending_approvals:
            self.pending_approvals[approval_id]['status'] = 'approved' if approved else 'denied'
        result = "✅ APPROVED" if approved else "❌ DENIED"
        print(f"\n{result}: Request {approval_id}")
        return approved
    async def execute_high_risk_action(self, action_details: Dict[str, Any]):
        """Execute action only after human approval"""
        if action_details.get('risk_level', 0) >= 7:
            approval_id = await self.request_action_approval(
                action=action_details['action'],
                target=action_details['target'],
                risk_level=action_details['risk_level'],
                justification=action_details['justification']
            )
            if approval_id is None:
                print(f"❌ Action denied or timed out: {action_details['action']}")
                return False
            print(f"✅ Executing approved action: {action_details['action']}")
            await self.perform_action(action_details)
            return True
        else:
            print(f"🔄 Auto-executing low-risk action: {action_details['action']}")
            await self.perform_action(action_details)
            return True
    async def perform_action(self, action_details: Dict[str, Any]):
        """Simulate actual action execution"""
        await asyncio.sleep(1)
        print(f"✓ Completed: {action_details['action']} on {action_details['target']}")

# Example usage
def main():
    async def demo_hitl():
        agent = HITLSecurityAgent()
        high_risk_action = {
            'action': 'isolate_critical_server',
            'target': 'production-db-01',
            'risk_level': 8,
            'justification': 'Detected lateral movement from compromised admin account'
        }
        await agent.execute_high_risk_action(high_risk_action)
    asyncio.run(demo_hitl())

if __name__ == "__main__":
    main()
