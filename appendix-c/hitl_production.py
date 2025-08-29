# hitl_production.py
import asyncio
import time
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import uuid

class ApprovalPriority(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ApprovalRequest:
    id: str
    agent_id: str
    action: Dict
    context: Dict
    risk_score: float
    priority: ApprovalPriority
    requested_at: float
    expires_at: float
    requires_mfa: bool = False
    minimum_approvers: int = 1

class HITLProductionGate:
    def __init__(self, sla_seconds: Dict[ApprovalPriority, int]):
        self.sla_seconds = sla_seconds
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        self.approval_metrics = {
            'total_requests': 0,
            'approved': 0,
            'denied': 0,
            'expired': 0,
            'avg_response_time': 0
        }
    async def request_approval(
        self,
        action: Dict,
        context: Dict,
        priority: ApprovalPriority = ApprovalPriority.MEDIUM
    ) -> Tuple[bool, Dict]:
        request_id = str(uuid.uuid4())
        risk_score = self._calculate_risk_score(action, context)
        requires_mfa = risk_score > 0.7
        minimum_approvers = 2 if risk_score > 0.8 else 1
        now = time.time()
        expires_at = now + self.sla_seconds.get(priority, 60)
        request = ApprovalRequest(
            id=request_id,
            agent_id=context.get('agent_id', 'unknown'),
            action=action,
            context=context,
            risk_score=risk_score,
            priority=priority,
            requested_at=now,
            expires_at=expires_at,
            requires_mfa=requires_mfa,
            minimum_approvers=minimum_approvers
        )
        self.pending_approvals[request_id] = request
        self.approval_metrics['total_requests'] += 1
        approval_task = asyncio.create_task(
            self._route_approval_request(request)
        )
        try:
            response = await asyncio.wait_for(
                approval_task,
                timeout=self.sla_seconds[priority]
            )
            response_time = time.time() - request.requested_at
            self._update_metrics(response, response_time)
            await self._audit_decision(request, response)
            return response['approved'], response
        except asyncio.TimeoutError:
            self.approval_metrics['expired'] += 1
            if priority == ApprovalPriority.CRITICAL:
                return False, {
                    'approved': False,
                    'reason': 'Timeout - critical action denied by default',
                    'request_id': request_id
                }
            else:
                return self._handle_timeout(request)
    async def _route_approval_request(self, request: ApprovalRequest) -> Dict:
        if request.priority == ApprovalPriority.CRITICAL:
            channels = ['pagerduty', 'slack_critical', 'email_oncall']
        elif request.priority == ApprovalPriority.HIGH:
            channels = ['slack_security', 'teams_soc']
        else:
            channels = ['slack_general', 'approval_queue']
        formatted_request = self._format_for_human(request)
        tasks = [
            self._send_to_channel(channel, formatted_request)
            for channel in channels
        ]
        done, pending = await asyncio.wait(
            tasks, 
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        return await list(done)[0]
    def _calculate_risk_score(self, action: Dict, context: Dict) -> float:
        score = 0.0
        high_risk_actions = ['delete', 'shutdown', 'modify_config', 'escalate_privileges']
        if action.get('type') in high_risk_actions:
            score += 0.3
        affected_count = action.get('affected_resources', 0)
        if affected_count > 100:
            score += 0.3
        elif affected_count > 10:
            score += 0.2
        hour = time.localtime().tm_hour
        if hour < 6 or hour > 22:
            score += 0.2
        if context.get('first_time_action', False):
            score += 0.2
        score += context.get('anomaly_score', 0) * 0.3
        return min(1.0, score)
    def _format_for_human(self, request: ApprovalRequest) -> Dict:
        return {
            'id': request.id,
            'title': f"Approval Required: {request.action.get('type', 'Unknown Action')}",
            'agent': request.agent_id,
            'description': request.action.get('description', 'No description provided'),
            'risk_level': self._risk_to_text(request.risk_score),
            'affected_resources': request.action.get('affected_resources', []),
            'justification': request.context.get('justification', 'Automated action'),
            'expires_in_seconds': int(request.expires_at - time.time()),
            'approve_link': f"https://approval.system/approve/{request.id}",
            'deny_link': f"https://approval.system/deny/{request.id}",
            'details_link': f"https://approval.system/details/{request.id}",
            'requires_mfa': request.requires_mfa,
            'minimum_approvers': request.minimum_approvers
        }
    def _risk_to_text(self, score: float) -> str:
        if score < 0.3:
            return "LOW"
        elif score < 0.6:
            return "MEDIUM"
        elif score < 0.8:
            return "HIGH"
        else:
            return "CRITICAL"
    async def _audit_decision(self, request: ApprovalRequest, response: Dict):
        audit_record = {
            'timestamp': time.time(),
            'request_id': request.id,
            'agent_id': request.agent_id,
            'action': request.action,
            'risk_score': request.risk_score,
            'decision': response.get('approved'),
            'approver': response.get('approver_id'),
            'reason': response.get('reason'),
            'response_time': response.get('response_time'),
            'mfa_verified': response.get('mfa_verified', False)
        }
        audit_record['signature'] = self._sign_record(audit_record)
        await self._store_audit_record(audit_record)
    def _update_metrics(self, response: Dict, response_time: float):
        if response['approved']:
            self.approval_metrics['approved'] += 1
        else:
            self.approval_metrics['denied'] += 1
        total = self.approval_metrics['total_requests']
        avg = self.approval_metrics['avg_response_time']
        self.approval_metrics['avg_response_time'] = (
            (avg * (total - 1) + response_time) / total
        )
    def _handle_timeout(self, request: ApprovalRequest) -> Tuple[bool, Dict]:
        if request.risk_score < 0.5:
            return True, {
                'approved': True,
                'reason': 'Timeout - low risk action auto-approved',
                'monitoring_level': 'enhanced',
                'request_id': request.id
            }
        else:
            return False, {
                'approved': False,
                'reason': 'Timeout - action denied by default',
                'request_id': request.id
            }
    async def _send_to_channel(self, channel: str, request: Dict) -> Dict:
        await asyncio.sleep(0.1)
        return {
            'approved': True,
            'approver_id': 'human_operator_1',
            'reason': 'Action verified and approved',
            'response_time': time.time(),
            'channel': channel,
            'mfa_verified': True
        }
    def _sign_record(self, record: Dict) -> str:
        import hashlib
        return hashlib.sha256(
            json.dumps(record, sort_keys=True).encode()
        ).hexdigest()
    async def _store_audit_record(self, record: Dict):
        pass
    def get_metrics_summary(self) -> Dict:
        approval_rate = (
            self.approval_metrics['approved'] /
            max(1, self.approval_metrics['total_requests'])
        )
        return {
            **self.approval_metrics,
            'approval_rate': approval_rate,
            'pending_count': len(self.pending_approvals),
            'oldest_pending': min(
                [r.requested_at for r in self.pending_approvals.values()],
                default=None
            )
        }
# Example usage
if __name__ == "__main__":
    gate = HITLProductionGate({
        ApprovalPriority.LOW: 120,
        ApprovalPriority.MEDIUM: 60,
        ApprovalPriority.HIGH: 30,
        ApprovalPriority.CRITICAL: 10
    })
    async def demo():
        action = {'type': 'delete_data', 'critical_asset': True}
        context = {'agent_id': 'agent-xyz', 'is_production': True}
        approved, details = await gate.request_approval(action, context, ApprovalPriority.CRITICAL)
        print(f"Approved: {approved}, Details: {details}")
    asyncio.run(demo())
    gate.export_approval_log("approval_log.json")
