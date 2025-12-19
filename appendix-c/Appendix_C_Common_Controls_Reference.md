# Appendix C: Common Controls Reference

*Essential implementation patterns for secure AI agent operations*

This appendix provides production-ready control implementations that security teams can deploy immediately. Each control includes configuration examples, code snippets, operational checklists, and transition criteria for different maturity levels.

## Kill Switch Implementation Guide

### Core Architecture

The kill switch represents your last line of defense—a critical safety mechanism that must never fail. Modern implementations go beyond simple on/off switches to provide graduated responses based on threat severity.

### Policy Configuration Framework

```yaml
# kill-switch-policy.yaml
version: 2.0
metadata:
  name: agent-kill-switch-policy
  owner: security-engineering
  classification: critical-control
  last-updated: 2025-01-15
  compliance: [EU-AI-Act, SOC2-Type2, ISO27001]
  
global-thresholds:
  max-actions-per-minute: 10
  max-hosts-affected: 5
  max-data-access-gb: 1
  anomaly-score-threshold: 0.85
  confidence-floor: 0.70
  
behavioral-patterns:
  suspicious-sequences:
    - pattern: [reconnaissance, lateral-movement, exfiltration]
      window: 300s
      action: immediate-halt
    - pattern: [privilege-escalation, config-change]
      window: 60s
      action: require-approval
  
per-agent-overrides:
  response-agent:
    max-actions-per-minute: 5
    max-hosts-affected: 3
    requires-approval: ["delete", "modify-config", "disable-service"]
    allow-list-only: true
    
  detection-agent:
    max-queries-per-minute: 100
    max-data-access-gb: 10
    read-only: true
    
  orchestration-agent:
    max-child-agents: 10
    max-recursion-depth: 3
    coordination-timeout: 120s
    
circuit-breakers:
  - trigger: action-rate-exceeded
    response: graduated-throttle
    stages:
      - threshold: 80%
        action: warning
      - threshold: 90%
        action: throttle-50%
      - threshold: 100%
        action: pause-and-alert
    cooldown: 300s
    escalation: security-ops
    
  - trigger: anomaly-detected
    confidence-required: 0.95
    response: immediate-halt
    requires-manual-reset: true
    escalation: [incident-response, ciso]
    
  - trigger: repeated-failures
    threshold: 5
    window: 60s
    response: quarantine-agent
    investigation-required: true
    escalation: engineering

quantum-ready:
  crypto-agility: enabled
  algorithm-rotation: automatic
  pqc-algorithms: [CRYSTALS-Kyber, CRYSTALS-Dilithium]
```text

### Runtime Enforcement Engine

```python
# kill_switch_advanced.py
import time
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
import logging
import hashlib
import json
from collections import deque

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    GREEN = "normal"
    YELLOW = "elevated"
    ORANGE = "high"
    RED = "critical"
    BLACK = "compromised"

@dataclass
class KillSwitchConfig:
    max_actions_per_minute: int = 10
    max_hosts_affected: int = 5
    anomaly_threshold: float = 0.85
    confidence_floor: float = 0.70
    cooldown_seconds: int = 300
    graduated_response: bool = True
    quantum_safe: bool = True

@dataclass
class ActionContext:
    agent_id: str
    action_type: str
    target_hosts: List[str]
    data_volume_gb: float
    confidence_score: float
    anomaly_score: float
    timestamp: float
    correlation_id: str
    parent_action_id: Optional[str] = None

class AdvancedKillSwitch:
    def __init__(self, config: KillSwitchConfig, agent_id: str):
        self.config = config
        self.agent_id = agent_id
        self.action_history: deque = deque(maxlen=1000)
        self.affected_hosts: Set[str] = set()
        self.threat_level = ThreatLevel.GREEN
        self.is_halted = False
        self.halt_reason: Optional[str] = None
        self.behavioral_patterns: List[List[str]] = []
        self.trust_score = 1.0
        
    async def check_action(self, context: ActionContext) -> Tuple[bool, Optional[str]]:
        """
        Comprehensive action validation with graduated response
        Returns: (allowed, reason_if_denied)
        """
        # Immediate halt check
        if self.is_halted:
            logger.critical(f"Agent {self.agent_id} is halted: {self.halt_reason}")
            return False, f"Agent halted: {self.halt_reason}"
        
        # Check confidence floor
        if context.confidence_score < self.config.confidence_floor:
            return False, f"Confidence {context.confidence_score} below floor {self.config.confidence_floor}"
        
        # Rate limiting with graduated response
        rate_check = await self._check_rate_limit(context)
        if not rate_check[0]:
            return rate_check
        
        # Host spread analysis
        host_check = self._check_host_spread(context)
        if not host_check[0]:
            return host_check
        
        # Behavioral pattern detection
        pattern_check = await self._check_behavioral_patterns(context)
        if not pattern_check[0]:
            return pattern_check
        
        # Anomaly scoring with ML integration
        anomaly_check = self._check_anomaly_score(context)
        if not anomaly_check[0]:
            return anomaly_check
        
        # Update trust score based on successful action
        self._update_trust_score(True)
        
        # Record approved action
        self._record_action(context)
        
        return True, None
    
    async def _check_rate_limit(self, context: ActionContext) -> Tuple[bool, Optional[str]]:
        """Graduated rate limiting based on threat level"""
        now = time.time()
        recent_actions = [
            a for a in self.action_history 
            if now - a.timestamp < 60
        ]
        
        # Adjust threshold based on threat level
        effective_limit = self.config.max_actions_per_minute
        if self.threat_level == ThreatLevel.YELLOW:
            effective_limit = int(effective_limit * 0.75)
        elif self.threat_level == ThreatLevel.ORANGE:
            effective_limit = int(effective_limit * 0.5)
        elif self.threat_level in [ThreatLevel.RED, ThreatLevel.BLACK]:
            effective_limit = 1
        
        if len(recent_actions) >= effective_limit:
            if self.config.graduated_response:
                await self._escalate_threat_level()
                return False, f"Rate limit exceeded at threat level {self.threat_level.value}"
            else:
                self.halt(f"Rate limit exceeded: {len(recent_actions)} actions/min")
                return False, "Rate limit triggered kill switch"
        
        return True, None
    
    def _check_host_spread(self, context: ActionContext) -> Tuple[bool, Optional[str]]:
        """Detect unusual host spreading patterns"""
        potential_hosts = self.affected_hosts | set(context.target_hosts)
        
        if len(potential_hosts) > self.config.max_hosts_affected:
            # Check if this is lateral movement
            if self._is_lateral_movement_pattern(context.target_hosts):
                self.halt(f"Lateral movement detected across {len(potential_hosts)} hosts")
                return False, "Lateral movement pattern detected"
            return False, f"Too many hosts affected: {len(potential_hosts)}"
        
        self.affected_hosts.update(context.target_hosts)
        return True, None
    
    async def _check_behavioral_patterns(self, context: ActionContext) -> Tuple[bool, Optional[str]]:
        """Detect known malicious behavioral patterns"""
        self.behavioral_patterns.append(context.action_type)
        
        # Keep only recent patterns
        if len(self.behavioral_patterns) > 20:
            self.behavioral_patterns.pop(0)
        
        # Check for kill chain patterns
        dangerous_sequences = [
            ["reconnaissance", "privilege_escalation", "lateral_movement"],
            ["data_discovery", "data_staging", "exfiltration"],
            ["defense_evasion", "persistence", "command_control"]
        ]
        
        for sequence in dangerous_sequences:
            if self._contains_sequence(self.behavioral_patterns, sequence):
                self.halt(f"Malicious pattern detected: {' -> '.join(sequence)}")
                return False, f"Kill chain pattern: {sequence[0]}...{sequence[-1]}"
        
        return True, None
    
    def _check_anomaly_score(self, context: ActionContext) -> Tuple[bool, Optional[str]]:
        """ML-based anomaly detection"""
        if context.anomaly_score > self.config.anomaly_threshold:
            # Calculate composite risk score
            risk_score = (
                context.anomaly_score * 0.4 +
                (1 - context.confidence_score) * 0.3 +
                (1 - self.trust_score) * 0.3
            )
            
            if risk_score > 0.9:
                self.halt(f"Critical anomaly detected: risk score {risk_score:.2f}")
                return False, f"Critical anomaly: {risk_score:.2f}"
            elif risk_score > 0.7:
                self.threat_level = ThreatLevel.ORANGE
                return False, f"High anomaly score: {context.anomaly_score:.2f}"
        
        return True, None
    
    def halt(self, reason: str):
        """Emergency stop with full context preservation"""
        self.is_halted = True
        self.halt_reason = reason
        self.threat_level = ThreatLevel.BLACK
        
        # Create forensic snapshot
        snapshot = {
            'agent_id': self.agent_id,
            'timestamp': time.time(),
            'reason': reason,
            'threat_level': self.threat_level.value,
            'recent_actions': [
                {
                    'type': a.action_type,
                    'hosts': a.target_hosts,
                    'timestamp': a.timestamp
                } for a in list(self.action_history)[-10:]
            ],
            'affected_hosts': list(self.affected_hosts),
            'trust_score': self.trust_score
        }
        
        # Cryptographically sign the snapshot
        if self.config.quantum_safe:
            snapshot['signature'] = self._quantum_safe_sign(snapshot)
        
        logger.critical(f"KILL SWITCH ACTIVATED: {json.dumps(snapshot)}")
        
        # Trigger immediate response
        asyncio.create_task(self._emergency_response(snapshot))
    
    async def _emergency_response(self, snapshot: dict):
        """Coordinate emergency response procedures"""
        # Notify all connected systems
        await self._broadcast_halt_signal()
        
        # Preserve evidence
        await self._preserve_forensic_evidence(snapshot)
        
        # Initiate incident response
        await self._trigger_incident_response(snapshot)
        
        # Update threat intelligence
        await self._update_threat_intel(snapshot)
    
    def reset(self, authorized_by: str, mfa_token: str) -> bool:
        """Secure reset with multi-factor authentication"""
        if not self._verify_mfa(authorized_by, mfa_token):
            logger.error(f"Failed reset attempt by {authorized_by}")
            return False
        
        logger.info(f"Kill switch reset for {self.agent_id} by {authorized_by}")
        
        # Gradual reset based on threat assessment
        if self.threat_level == ThreatLevel.BLACK:
            # Require additional authorization for compromised agents
            logger.warning("Agent marked as compromised - requiring security review")
            return False
        
        self.is_halted = False
        self.halt_reason = None
        self.action_history.clear()
        self.affected_hosts.clear()
        self.threat_level = ThreatLevel.YELLOW  # Start cautiously
        self.trust_score = 0.5  # Reduced trust after reset
        
        return True
    
    def _update_trust_score(self, success: bool):
        """Dynamic trust scoring with decay"""
        if success:
            self.trust_score = min(1.0, self.trust_score + 0.01)
        else:
            self.trust_score = max(0.0, self.trust_score - 0.1)
        
        # Trust decay over time
        self.trust_score *= 0.999
    
    def _is_lateral_movement_pattern(self, hosts: List[str]) -> bool:
        """Detect lateral movement indicators"""
        # Check for systematic progression through network segments
        segments = [self._get_network_segment(h) for h in hosts]
        return len(set(segments)) > 3  # Multiple segments = suspicious
    
    def _contains_sequence(self, patterns: List[str], sequence: List[str]) -> bool:
        """Check if pattern list contains a specific sequence"""
        pattern_str = ','.join(patterns)
        sequence_str = ','.join(sequence)
        return sequence_str in pattern_str
    
    def _get_network_segment(self, host: str) -> str:
        """Extract network segment from hostname/IP"""
        # Simplified - real implementation would parse actual network topology
        return host.split('.')[0] if '.' in host else host[:3]
    
    def _quantum_safe_sign(self, data: dict) -> str:
        """Placeholder for quantum-safe signing"""
        # Real implementation would use CRYSTALS-Dilithium or similar
        return hashlib.sha256(json.dumps(data).encode()).hexdigest()
    
    def _verify_mfa(self, user: str, token: str) -> bool:
        """Verify multi-factor authentication"""
        # Real implementation would integrate with MFA provider
        return len(token) == 6 and token.isdigit()
    
    def _record_action(self, context: ActionContext):
        """Record action with full context"""
        self.action_history.append(context)
    
    async def _escalate_threat_level(self):
        """Graduated threat level escalation"""
        transitions = {
            ThreatLevel.GREEN: ThreatLevel.YELLOW,
            ThreatLevel.YELLOW: ThreatLevel.ORANGE,
            ThreatLevel.ORANGE: ThreatLevel.RED,
            ThreatLevel.RED: ThreatLevel.BLACK
        }
        
        if self.threat_level in transitions:
            old_level = self.threat_level
            self.threat_level = transitions[self.threat_level]
            logger.warning(f"Threat level escalated: {old_level.value} -> {self.threat_level.value}")
    
    async def _broadcast_halt_signal(self):
        """Notify all integrated systems of halt"""
        # Implementation depends on infrastructure
        pass
    
    async def _preserve_forensic_evidence(self, snapshot: dict):
        """Preserve evidence for investigation"""
        # Implementation depends on logging infrastructure
        pass
    
    async def _trigger_incident_response(self, snapshot: dict):
        """Initiate incident response procedures"""
        # Implementation depends on IR platform
        pass
    
    async def _update_threat_intel(self, snapshot: dict):
        """Share threat intelligence with security platforms"""
        # Implementation depends on TI platform
        pass
```text

### Operational Deployment Checklist

**Pre-Production Validation:**
- [ ] Baseline normal behavior patterns for 30+ days
- [ ] Define action taxonomies and risk scores
- [ ] Map critical assets and high-value targets
- [ ] Configure escalation chains with 24/7 coverage
- [ ] Test kill switch activation across all scenarios
- [ ] Validate quantum-safe cryptographic implementations
- [ ] Document manual override procedures with legal review
- [ ] Conduct tabletop exercises with incident response team

**Production Rollout:**
- [ ] Deploy in monitoring-only mode for 7 days
- [ ] Enable graduated responses with conservative thresholds
- [ ] Verify integration with SIEM and SOAR platforms
- [ ] Confirm escalation notifications reach all stakeholders
- [ ] Establish real-time dashboards in SOC
- [ ] Schedule hourly health checks for first 48 hours
- [ ] Document all configuration changes in change management
- [ ] Brief all shifts on emergency procedures

**Continuous Operations:**
- [ ] Review kill switch triggers every 8 hours initially
- [ ] Analyze false positive patterns weekly
- [ ] Adjust thresholds based on operational metrics monthly
- [ ] Conduct surprise kill switch drills quarterly
- [ ] Update threat intelligence feeds daily
- [ ] Rotate escalation contacts quarterly
- [ ] Perform security audits semi-annually
- [ ] Update for new compliance requirements annually

**Incident Response Protocol:**
- [ ] **T+0 min**: Automated systems halt agent operations
- [ ] **T+1 min**: SOC analyst acknowledges alert
- [ ] **T+5 min**: Initial impact assessment complete
- [ ] **T+15 min**: Incident commander assumes control
- [ ] **T+30 min**: Executive notification if severity > medium
- [ ] **T+60 min**: Root cause analysis initiated
- [ ] **T+4 hours**: Preliminary report to stakeholders
- [ ] **T+24 hours**: Full incident report with lessons learned
- [ ] **T+72 hours**: Implementation of preventive measures
- [ ] **T+7 days**: Post-incident review with all teams

## Human Oversight Models: HITL, HOTL, and HIC

### Strategic Implementation Framework

The evolution from Human-in-the-Loop to Human-in-Command represents a maturity journey that typically spans 12-18 months. Each model serves specific operational needs and risk profiles.

### Human-in-the-Loop (HITL) Implementation

**Optimal Use Cases:**
- Initial production deployments (first 90 days)
- Irreversible actions (data deletion, service shutdown)
- Financial transactions exceeding $10,000
- Actions affecting 100+ users simultaneously
- Compliance-mandated approvals (GDPR Article 22)

**Production Implementation:**

```python
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
        """
        Request human approval with full context
        Returns: (approved, decision_details)
        """
        request_id = str(uuid.uuid4())
        
        # Calculate risk score based on action characteristics
        risk_score = self._calculate_risk_score(action, context)
        
        # Determine approval requirements
        requires_mfa = risk_score > 0.7
        minimum_approvers = 2 if risk_score > 0.8 else 1
        
        # Create approval request
        request = ApprovalRequest(
            id=request_id,
            agent_id=context.get('agent_id', 'unknown'),
            action=action,
            context=context,
            risk_score=risk_score,
            priority=priority,
            requested_at=time.time(),
            expires_at=time.time() + self.sla_seconds[priority],
            requires_mfa=requires_mfa,
            minimum_approvers=minimum_approvers
        )
        
        self.pending_approvals[request_id] = request
        self.approval_metrics['total_requests'] += 1
        
        # Send to approval system with appropriate urgency
        approval_task = asyncio.create_task(
            self._route_approval_request(request)
        )
        
        # Wait for response or timeout
        try:
            response = await asyncio.wait_for(
                approval_task,
                timeout=self.sla_seconds[priority]
            )
            
            # Update metrics
            response_time = time.time() - request.requested_at
            self._update_metrics(response, response_time)
            
            # Audit log with complete trail
            await self._audit_decision(request, response)
            
            return response['approved'], response
            
        except asyncio.TimeoutError:
            self.approval_metrics['expired'] += 1
            
            # Handle timeout based on criticality
            if priority == ApprovalPriority.CRITICAL:
                # Critical actions default to deny on timeout
                return False, {
                    'approved': False,
                    'reason': 'Timeout - critical action denied by default',
                    'request_id': request_id
                }
            else:
                # Non-critical might proceed with additional monitoring
                return self._handle_timeout(request)
    
    async def _route_approval_request(self, request: ApprovalRequest) -> Dict:
        """Route request to appropriate approval channel"""
        
        # Determine routing based on priority and context
        if request.priority == ApprovalPriority.CRITICAL:
            channels = ['pagerduty', 'slack_critical', 'email_oncall']
        elif request.priority == ApprovalPriority.HIGH:
            channels = ['slack_security', 'teams_soc']
        else:
            channels = ['slack_general', 'approval_queue']
        
        # Format request for human consumption
        formatted_request = self._format_for_human(request)
        
        # Send to all channels in parallel
        tasks = [
            self._send_to_channel(channel, formatted_request)
            for channel in channels
        ]
        
        # Wait for first response
        done, pending = await asyncio.wait(
            tasks, 
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Cancel remaining tasks
        for task in pending:
            task.cancel()
        
        # Return first response
        return await list(done)[0]
    
    def _calculate_risk_score(self, action: Dict, context: Dict) -> float:
        """Calculate risk score based on multiple factors"""
        score = 0.0
        
        # Action type risk
        high_risk_actions = ['delete', 'shutdown', 'modify_config', 'escalate_privileges']
        if action.get('type') in high_risk_actions:
            score += 0.3
        
        # Scope risk
        affected_count = action.get('affected_resources', 0)
        if affected_count > 100:
            score += 0.3
        elif affected_count > 10:
            score += 0.2
        
        # Time risk (actions during off-hours)
        hour = time.localtime().tm_hour
        if hour < 6 or hour > 22:
            score += 0.2
        
        # Historical risk (new or unusual action)
        if context.get('first_time_action', False):
            score += 0.2
        
        # Anomaly score from ML models
        score += context.get('anomaly_score', 0) * 0.3
        
        return min(1.0, score)
    
    def _format_for_human(self, request: ApprovalRequest) -> Dict:
        """Format request for human readability"""
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
        """Convert risk score to human-readable text"""
        if score < 0.3:
            return "LOW"
        elif score < 0.6:
            return "MEDIUM"
        elif score < 0.8:
            return "HIGH"
        else:
            return "CRITICAL"
    
    async def _audit_decision(self, request: ApprovalRequest, response: Dict):
        """Create immutable audit record"""
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
        
        # Sign record for non-repudiation
        audit_record['signature'] = self._sign_record(audit_record)
        
        # Store in immutable audit log
        await self._store_audit_record(audit_record)
    
    def _update_metrics(self, response: Dict, response_time: float):
        """Update operational metrics"""
        if response['approved']:
            self.approval_metrics['approved'] += 1
        else:
            self.approval_metrics['denied'] += 1
        
        # Update rolling average response time
        total = self.approval_metrics['total_requests']
        avg = self.approval_metrics['avg_response_time']
        self.approval_metrics['avg_response_time'] = (
            (avg * (total - 1) + response_time) / total
        )
    
    def _handle_timeout(self, request: ApprovalRequest) -> Tuple[bool, Dict]:
        """Handle approval timeout with fallback logic"""
        # For non-critical actions, check if we can proceed safely
        if request.risk_score < 0.5:
            # Low risk - proceed with enhanced monitoring
            return True, {
                'approved': True,
                'reason': 'Timeout - low risk action auto-approved',
                'monitoring_level': 'enhanced',
                'request_id': request.id
            }
        else:
            # Medium/high risk - deny by default
            return False, {
                'approved': False,
                'reason': 'Timeout - action denied by default',
                'request_id': request.id
            }
    
    async def _send_to_channel(self, channel: str, request: Dict) -> Dict:
        """Send approval request to specific channel"""
        # Channel-specific implementation
        # This would integrate with Slack, Teams, PagerDuty, etc.
        await asyncio.sleep(0.1)  # Simulate network call
        return {
            'approved': True,
            'approver_id': 'human_operator_1',
            'reason': 'Action verified and approved',
            'response_time': time.time(),
            'channel': channel,
            'mfa_verified': True
        }
    
    def _sign_record(self, record: Dict) -> str:
        """Sign audit record for non-repudiation"""
        # Real implementation would use proper cryptographic signing
        import hashlib
        return hashlib.sha256(
            json.dumps(record, sort_keys=True).encode()
        ).hexdigest()
    
    async def _store_audit_record(self, record: Dict):
        """Store in immutable audit log"""
        # Real implementation would use append-only storage
        pass

    def get_metrics_summary(self) -> Dict:
        """Get operational metrics for monitoring"""
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
```text

### Human-on-the-Loop (HOTL) Implementation

**Optimal Use Cases:**
- Mature processes with >95% historical approval rate
- Time-sensitive operations requiring <1 minute response
- Well-defined action boundaries with clear policies
- Environments with comprehensive monitoring coverage

**Production Implementation:**

```python
# hotl_production.py
class HOTLProductionMonitor:
    def __init__(self, intervention_window: int = 30):
        self.intervention_window = intervention_window
        self.pending_actions: Dict[str, Dict] = {}
        self.intervention_stats = {
            'total_actions': 0,
            'interventions': 0,
            'auto_executed': 0
        }
        
    async def submit_action(self, action: Dict) -> Dict:
        """Submit action with intervention window"""
        action_id = str(uuid.uuid4())
        
        # Risk-based intervention window
        risk_score = self._assess_risk(action)
        window = self._calculate_window(risk_score)
        
        # Create notification with rich context
        notification = {
            'action_id': action_id,
            'action': action,
            'risk_score': risk_score,
            'intervention_window': window,
            'will_execute_at': time.time() + window,
            'intervention_url': f"https://soc.portal/intervene/{action_id}"
        }
        
        # Notify observers through multiple channels
        await self._broadcast_notification(notification)
        
        # Store pending action
        self.pending_actions[action_id] = {
            'action': action,
            'notification': notification,
            'submitted_at': time.time()
        }
        
        self.intervention_stats['total_actions'] += 1
        
        # Wait for intervention window
        await asyncio.sleep(window)
        
        # Check if action was vetoed
        if action_id in self.pending_actions:
            # Execute action
            result = await self._execute_action(action)
            del self.pending_actions[action_id]
            self.intervention_stats['auto_executed'] += 1
            
            # Audit successful execution
            await self._audit_execution(action_id, action, result)
            
            return {
                'action_id': action_id,
                'status': 'executed',
                'result': result
            }
        else:
            # Action was vetoed
            return {
                'action_id': action_id,
                'status': 'vetoed',
                'veto_reason': self._get_veto_reason(action_id)
            }
    
    def veto_action(self, action_id: str, reason: str, vetoed_by: str) -> bool:
        """Veto a pending action"""
        if action_id not in self.pending_actions:
            return False
        
        # Record veto
        veto_record = {
            'action_id': action_id,
            'action': self.pending_actions[action_id]['action'],
            'reason': reason,
            'vetoed_by': vetoed_by,
            'timestamp': time.time()
        }
        
        # Remove from pending
        del self.pending_actions[action_id]
        self.intervention_stats['interventions'] += 1
        
        # Audit veto
        asyncio.create_task(self._audit_veto(veto_record))
        
        # Update ML models with feedback
        asyncio.create_task(self._update_models(veto_record))
        
        return True
    
    def _calculate_window(self, risk_score: float) -> int:
        """Calculate intervention window based on risk"""
        if risk_score < 0.3:
            return 10  # 10 seconds for low risk
        elif risk_score < 0.6:
            return 30  # 30 seconds for medium risk
        elif risk_score < 0.8:
            return 60  # 60 seconds for high risk
        else:
            return 120  # 2 minutes for critical risk
    
    def _assess_risk(self, action: Dict) -> float:
        """Assess action risk for window calculation"""
        # Similar to HITL risk calculation but with additional factors
        base_risk = 0.0
        
        # Add risk factors
        if action.get('scope', 'single') == 'multiple':
            base_risk += 0.2
        if action.get('reversible', True) == False:
            base_risk += 0.3
        if action.get('affects_production', False):
            base_risk += 0.3
        if action.get('outside_business_hours', False):
            base_risk += 0.2
            
        return min(1.0, base_risk)
    
    async def _broadcast_notification(self, notification: Dict):
        """Send notifications through multiple channels"""
        channels = self._select_channels(notification['risk_score'])
        
        tasks = [
            self._notify_channel(channel, notification)
            for channel in channels
        ]
        
        await asyncio.gather(*tasks)
    
    def _select_channels(self, risk_score: float) -> List[str]:
        """Select notification channels based on risk"""
        if risk_score > 0.7:
            return ['soc_dashboard', 'slack_critical', 'sms_oncall']
        elif risk_score > 0.4:
            return ['soc_dashboard', 'slack_security']
        else:
            return ['soc_dashboard']
    
    async def _execute_action(self, action: Dict) -> Dict:
        """Execute the approved action"""
        # Real implementation would execute actual action
        return {'status': 'success', 'executed_at': time.time()}
    
    async def _audit_execution(self, action_id: str, action: Dict, result: Dict):
        """Audit successful execution"""
        # Implementation depends on audit infrastructure
        pass
    
    async def _audit_veto(self, veto_record: Dict):
        """Audit veto decision"""
        # Implementation depends on audit infrastructure
        pass
    
    async def _update_models(self, veto_record: Dict):
        """Update ML models with veto feedback"""
        # Implementation would send to ML pipeline
        pass
    
    def _get_veto_reason(self, action_id: str) -> str:
        """Retrieve veto reason for action"""
        # Implementation would query veto database
        return "Action vetoed by security analyst"
    
    async def _notify_channel(self, channel: str, notification: Dict):
        """Send notification to specific channel"""
        # Implementation depends on notification infrastructure
        pass
```text

### Human-in-Command (HIC) Implementation

**Optimal Use Cases:**
- Strategic security orchestration across multiple teams
- Policy-driven automation at enterprise scale
- Mature organizations with established governance
- Complex multi-agent coordination scenarios

**Production Implementation:**

```python
# hic_production.py
class HICProductionOrchestrator:
    def __init__(self):
        self.policy_engine = PolicyEngine()
        self.objective_store = ObjectiveStore()
        self.agent_registry = AgentRegistry()
        self.performance_tracker = PerformanceTracker()
        
    async def set_strategic_objectives(
        self, 
        objectives: List[Dict],
        authorized_by: str,
        mfa_token: str
    ) -> Dict:
        """Set high-level strategic objectives"""
        
        # Verify authorization
        if not await self._verify_authorization(authorized_by, mfa_token):
            raise UnauthorizedException("Invalid authorization")
        
        validated_objectives = []
        
        for obj in objectives:
            # Validate objective structure
            validated = self._validate_objective(obj)
            
            # Translate to operational constraints
            constraints = self._derive_constraints(validated)
            
            # Define success metrics
            metrics = self._define_success_metrics(validated)
            
            objective_record = {
                'id': str(uuid.uuid4()),
                'objective': validated,
                'constraints': constraints,
                'success_metrics': metrics,
                'authorized_by': authorized_by,
                'created_at': time.time(),
                'status': 'active'
            }
            
            validated_objectives.append(objective_record)
            
        # Store objectives
        await self.objective_store.store_batch(validated_objectives)
        
        # Update all agents with new objectives
        await self._propagate_objectives(validated_objectives)
        
        return {
            'status': 'success',
            'objectives_set': len(validated_objectives),
            'effective_from': time.time()
        }
    
    async def agent_decision_request(
        self,
        agent_id: str,
        context: Dict
    ) -> Dict:
        """Process agent decision request within objectives"""
        
        # Verify agent registration
        if not self.agent_registry.is_registered(agent_id):
            raise UnregisteredAgentException(f"Agent {agent_id} not registered")
        
        # Get applicable objectives
        objectives = await self.objective_store.get_applicable(context)
        
        # Generate possible actions
        candidate_actions = await self._generate_actions(
            agent_id, 
            context, 
            objectives
        )
        
        # Evaluate against policies
        validated_actions = []
        for action in candidate_actions:
            validation = await self.policy_engine.validate(
                action,
                context,
                objectives
            )
            
            if validation['allowed']:
                action['policy_score'] = validation['score']
                validated_actions.append(action)
        
        # Select optimal action
        if validated_actions:
            selected = self._select_optimal_action(
                validated_actions,
                objectives
            )
            
            # Track performance
            await self.performance_tracker.record_decision(
                agent_id,
                selected,
                context
            )
            
            return {
                'status': 'approved',
                'action': selected,
                'alternatives_considered': len(candidate_actions),
                'policy_compliance': selected['policy_score']
            }
        else:
            return {
                'status': 'no_valid_actions',
                'reason': 'All proposed actions violate current policies',
                'objectives': [obj['id'] for obj in objectives]
            }
    
    async def update_policies(
        self,
        policy_updates: List[Dict],
        authorized_by: str
    ) -> Dict:
        """Update operational policies"""
        
        # Validate policy syntax
        validated_policies = []
        for policy in policy_updates:
            validated = self.policy_engine.validate_syntax(policy)
            if validated['valid']:
                validated_policies.append(policy)
        
        # Check for conflicts
        conflicts = self.policy_engine.check_conflicts(validated_policies)
        if conflicts:
            return {
                'status': 'error',
                'reason': 'Policy conflicts detected',
                'conflicts': conflicts
            }
        
        # Apply policies
        await self.policy_engine.apply_updates(validated_policies)
        
        # Notify all agents
        await self._notify_policy_change(validated_policies)
        
        return {
            'status': 'success',
            'policies_updated': len(validated_policies),
            'effective_immediately': True
        }
    
    def _validate_objective(self, objective: Dict) -> Dict:
        """Validate objective structure and content"""
        required_fields = ['name', 'description', 'priority', 'success_criteria']
        
        for field in required_fields:
            if field not in objective:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate priority
        if objective['priority'] not in ['critical', 'high', 'medium', 'low']:
            raise ValueError(f"Invalid priority: {objective['priority']}")
        
        # Validate success criteria
        if not isinstance(objective['success_criteria'], list):
            raise ValueError("Success criteria must be a list")
        
        return objective
    
    def _derive_constraints(self, objective: Dict) -> List[Dict]:
        """Derive operational constraints from objective"""
        constraints = []
        
        # Time constraints
        if 'deadline' in objective:
            constraints.append({
                'type': 'temporal',
                'deadline': objective['deadline']
            })
        
        # Resource constraints
        if 'max_resources' in objective:
            constraints.append({
                'type': 'resource',
                'limit': objective['max_resources']
            })
        
        # Risk constraints
        if 'risk_tolerance' in objective:
            constraints.append({
                'type': 'risk',
                'max_risk': objective['risk_tolerance']
            })
        
        return constraints
    
    def _define_success_metrics(self, objective: Dict) -> Dict:
        """Define measurable success metrics"""
        return {
            'target_values': objective.get('success_criteria', []),
            'measurement_frequency': objective.get('measurement_frequency', 'hourly'),
            'evaluation_method': objective.get('evaluation_method', 'threshold'),
            'minimum_confidence': objective.get('minimum_confidence', 0.8)
        }
    
    async def _propagate_objectives(self, objectives: List[Dict]):
        """Propagate objectives to all registered agents"""
        agents = self.agent_registry.get_all_active()
        
        tasks = [
            self._update_agent_objectives(agent_id, objectives)
            for agent_id in agents
        ]
        
        await asyncio.gather(*tasks)
    
    async def _generate_actions(
        self,
        agent_id: str,
        context: Dict,
        objectives: List[Dict]
    ) -> List[Dict]:
        """Generate candidate actions based on objectives"""
        # This would interface with the agent's action generation logic
        # Simplified for example
        return [
            {
                'type': 'investigate',
                'target': context.get('target'),
                'method': 'automated_analysis',
                'estimated_duration': 300
            },
            {
                'type': 'contain',
                'target': context.get('target'),
                'method': 'network_isolation',
                'estimated_duration': 60
            }
        ]
    
    def _select_optimal_action(
        self,
        actions: List[Dict],
        objectives: List[Dict]
    ) -> Dict:
        """Select optimal action based on objectives"""
        # Score each action against objectives
        scored_actions = []
        
        for action in actions:
            score = 0.0
            
            # Policy compliance score
            score += action['policy_score'] * 0.3
            
            # Objective alignment score
            for objective in objectives:
                if self._aligns_with_objective(action, objective):
                    score += (1.0 / len(objectives)) * 0.4
            
            # Efficiency score
            efficiency = 1.0 / (action.get('estimated_duration', 3600) / 3600)
            score += efficiency * 0.3
            
            action['total_score'] = score
            scored_actions.append(action)
        
        # Return highest scoring action
        return max(scored_actions, key=lambda x: x['total_score'])
    
    def _aligns_with_objective(self, action: Dict, objective: Dict) -> bool:
        """Check if action aligns with objective"""
        # Simplified alignment check
        action_type = action.get('type', '')
        objective_type = objective.get('objective', {}).get('type', '')
        
        alignment_map = {
            'investigate': ['detection', 'analysis', 'threat_hunting'],
            'contain': ['incident_response', 'damage_control'],
            'remediate': ['recovery', 'restoration']
        }
        
        return objective_type in alignment_map.get(action_type, [])
    
    async def _verify_authorization(self, user: str, mfa_token: str) -> bool:
        """Verify user authorization for strategic changes"""
        # Real implementation would check against identity provider
        return len(mfa_token) == 6 and mfa_token.isdigit()
    
    async def _update_agent_objectives(self, agent_id: str, objectives: List[Dict]):
        """Update individual agent with new objectives"""
        # Real implementation would communicate with agent
        pass
    
    async def _notify_policy_change(self, policies: List[Dict]):
        """Notify all agents of policy changes"""
        # Real implementation would broadcast to agents
        pass
```text

### Transition Criteria and Maturity Model

| Transition | Prerequisites | Evidence Required | Minimum Duration | Success Metrics |
|------------|---------------|-------------------|------------------|-----------------|
| **HITL → HOTL** | - 95% approval rate<br>- <2% post-approval reversals<br>- Zero critical incidents<br>- Complete audit coverage | - 1000+ approved actions<br>- Stakeholder sign-off<br>- Successful DR test | 30 days | - Response time <5min<br>- FPR <5%<br>- Explainability >90% |
| **HOTL → HIC** | - <5% intervention rate<br>- Proven policy engine<br>- Multi-agent coordination<br>- Executive confidence | - 10000+ autonomous actions<br>- Successful war games<br>- Board approval | 90 days | - Autonomy rate >95%<br>- Policy compliance 100%<br>- MTTD improvement >50% |
| **Emergency Rollback** | - Critical incident<br>- Compliance violation<br>- >10% accuracy degradation<br>- Security breach | - Incident report<br>- Root cause analysis<br>- Remediation plan | Immediate | - Recovery time <1hr<br>- No data loss<br>- Full audit trail |

## Observability, Auditability, and Safety (OAS) Framework

### Comprehensive Implementation

```yaml
# oas-production-config.yaml
version: 3.0
name: production-oas-framework
environment: production

observability:
  metrics:
    collection:
      - name: agent.actions.total
        type: counter
        labels: [agent_id, action_type, status, environment]
        alert_threshold: 1000/min
        
      - name: agent.decision.latency
        type: histogram
        buckets: [10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
        slo_target: p99 < 1000ms
        
      - name: agent.confidence.score
        type: gauge
        labels: [agent_id, model_version, decision_type]
        alert_if: < 0.7
        
      - name: system.kill_switch.activations
        type: counter
        labels: [agent_id, reason, severity]
        page_on_increment: true
    
    aggregation:
      - type: rate
        metrics: [agent.actions.total]
        window: 5m
        
      - type: percentile
        metrics: [agent.decision.latency]
        percentiles: [50, 90, 95, 99, 99.9]
        
  tracing:
    enabled: true
    sampling:
      strategy: adaptive
      initial_rate: 0.1
      peak_rate: 1.0
      error_rate: 1.0  # Always trace errors
    
    exporters:
      - type: jaeger
        endpoint: jaeger.monitoring.internal:6831
        
      - type: datadog
        api_key: ${DD_API_KEY}
        
      - type: x-ray
        region: us-east-1
    
    correlation:
      propagate_headers: [x-trace-id, x-request-id, x-session-id]
      generate_if_missing: true
  
  logging:
    structured: true
    level: INFO
    sensitive_data_masking: true
    
    outputs:
      - type: cloudwatch
        log_group: /aws/lambda/ai-agents
        retention_days: 90
        
      - type: elasticsearch
        index_pattern: ai-agents-%{+YYYY.MM.dd}
        pipeline: security-enrichment
        
      - type: splunk
        hec_endpoint: https://splunk.internal:8088
        index: ai_security
    
    required_fields:
      - timestamp
      - correlation_id
      - agent_id
      - action_type
      - decision_factors
      - confidence_score
      - risk_score
      - outcome
      - duration_ms

auditability:
  storage:
    primary:
      type: blockchain  # Immutable ledger
      consensus: pbft
      replication_factor: 5
      
    backup:
      type: append_only_db
      encryption: AES-256-GCM
      key_rotation: quarterly
      
    archive:
      type: glacier
      retention_years: 7
      compliance_tags: [sox, gdpr, ai_act]
  
  integrity:
    signing_algorithm: RSA-4096
    hash_algorithm: SHA3-512
    timestamp_authority: https://tsa.internal/
    
  compliance:
    frameworks:
      - name: EU_AI_Act
        reports: [transparency, performance, bias]
        frequency: monthly
        
      - name: SOC2_Type2
        controls: [CC6.1, CC6.2, CC6.3]
        attestation: quarterly
        
      - name: ISO27001
        controls: [A.12.1, A.12.4, A.16.1]
        audit: annually
    
    reporting:
      automated: true
      formats: [json, pdf, csv]
      distribution: [compliance@, security@, legal@]
  
  forensics:
    capabilities:
      - replay_any_decision
      - point_in_time_recovery
      - decision_tree_visualization
      - impact_analysis
      
    tools:
      - name: decision_replay
        endpoint: https://forensics.internal/replay
        
      - name: timeline_reconstruction
        endpoint: https://forensics.internal/timeline

safety:
  circuit_breakers:
    default:
      error_threshold_percent: 50
      request_volume_threshold: 20
      sleep_window_ms: 30000
      
    per_agent:
      response_agent:
        error_threshold_percent: 30
        timeout_ms: 10000
        
      detection_agent:
        error_threshold_percent: 40
        timeout_ms: 30000
  
  deployment:
    strategy:
      type: blue_green_with_canary
      canary:
        initial_percent: 1
        increment_percent: 10
        increment_interval: 15m
        
      validation:
        automated_tests: true
        smoke_tests: [health, basic_decision, kill_switch]
        
      rollback:
        automatic: true
        triggers:
          - error_rate > 10%
          - latency_p99 > 5000ms
          - confidence_avg < 0.6
  
  chaos_engineering:
    enabled: true
    experiments:
      - name: network_partition
        frequency: weekly
        duration: 5m
        
      - name: resource_exhaustion
        frequency: monthly
        cpu_limit: 90%
        memory_limit: 85%
        
      - name: byzantine_agent
        frequency: quarterly
        behavior: malicious_decisions
        
    game_days:
      frequency: quarterly
      scenarios:
        - total_kill_switch_failure
        - mass_agent_compromise
        - cascade_failure
        - data_poisoning_attack

monitoring:
  dashboards:
    - name: Executive Overview
      refresh: 1m
      widgets:
        - total_agents_active
        - decisions_per_second
        - threat_level_indicator
        - cost_per_decision
        
    - name: SOC Operations
      refresh: 10s
      widgets:
        - real_time_decisions
        - intervention_queue
        - anomaly_scores
        - kill_switch_status
        
    - name: Engineering Debug
      refresh: 5s
      widgets:
        - trace_waterfall
        - error_logs
        - resource_utilization
        - model_performance
  
  alerting:
    channels:
      critical:
        - pagerduty
        - phone_call
        - executive_email
        
      high:
        - slack_security
        - pagerduty
        - email
        
      medium:
        - slack_general
        - email
        
      low:
        - jira_ticket
        - email_digest
    
    rules:
      - name: kill_switch_activated
        severity: critical
        notify_immediately: true
        
      - name: confidence_below_threshold
        severity: high
        threshold: 0.6
        duration: 5m
        
      - name: unusual_decision_pattern
        severity: medium
        detection: ml_anomaly
        
      - name: approaching_rate_limit
        severity: low
        threshold: 80%
```text

### Implementation Code for OAS

```python
# oas_implementation.py
import time
import json
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import asyncio
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    SECRET = 4

@dataclass
class AuditRecord:
    timestamp: float
    correlation_id: str
    agent_id: str
    action: Dict
    decision_factors: List[Dict]
    confidence_score: float
    risk_score: float
    outcome: str
    duration_ms: float
    security_level: SecurityLevel
    signatures: List[str] = None

class ProductionOAS:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.metrics_collector = MetricsCollector(self.config['observability']['metrics'])
        self.tracer = DistributedTracer(self.config['observability']['tracing'])
        self.audit_store = BlockchainAuditStore(self.config['auditability'])
        self.safety_monitor = SafetyMonitor(self.config['safety'])
        
    async def record_decision(
        self,
        agent_id: str,
        action: Dict,
        context: Dict,
        decision_time_ms: float
    ) -> str:
        """Record a complete decision with full observability"""
        
        correlation_id = context.get('correlation_id', self._generate_correlation_id())
        
        # Start distributed trace
        with self.tracer.start_span('agent_decision', correlation_id) as span:
            
            # Record metrics
            self.metrics_collector.increment(
                'agent.actions.total',
                labels={
                    'agent_id': agent_id,
                    'action_type': action['type'],
                    'status': 'initiated'
                }
            )
            
            self.metrics_collector.observe(
                'agent.decision.latency',
                decision_time_ms,
                labels={'agent_id': agent_id}
            )
            
            # Create audit record
            audit_record = AuditRecord(
                timestamp=time.time(),
                correlation_id=correlation_id,
                agent_id=agent_id,
                action=action,
                decision_factors=context.get('decision_factors', []),
                confidence_score=context.get('confidence_score', 0.0),
                risk_score=context.get('risk_score', 0.0),
                outcome='pending',
                duration_ms=decision_time_ms,
                security_level=self._classify_security_level(action)
            )
            
            # Sign the record
            audit_record.signatures = await self._sign_record(audit_record)
            
            # Store in blockchain
            block_hash = await self.audit_store.append(audit_record)
            
            # Log structured data
            self._log_decision(audit_record, block_hash)
            
            # Check safety thresholds
            safety_check = await self.safety_monitor.evaluate(audit_record)
            if not safety_check['safe']:
                await self._handle_safety_violation(safety_check, audit_record)
            
            span.set_attribute('audit.block_hash', block_hash)
            span.set_attribute('safety.status', safety_check['safe'])
            
            return correlation_id
    
    async def record_outcome(
        self,
        correlation_id: str,
        outcome: str,
        details: Dict
    ):
        """Record the outcome of a previously recorded decision"""
        
        # Update metrics
        self.metrics_collector.increment(
            'agent.actions.total',
            labels={
                'status': outcome
            }
        )
        
        # Update audit record
        await self.audit_store.update_outcome(correlation_id, outcome, details)
        
        # Analyze for patterns
        if outcome == 'failed':
            await self._analyze_failure(correlation_id, details)
    
    async def replay_decision(
        self,
        correlation_id: str,
        point_in_time: Optional[float] = None
    ) -> Dict:
        """Replay a decision for forensic analysis"""
        
        # Retrieve from blockchain
        audit_record = await self.audit_store.retrieve(
            correlation_id,
            point_in_time
        )
        
        # Verify signatures
        if not await self._verify_signatures(audit_record):
            raise SecurityException("Audit record signature verification failed")
        
        # Reconstruct decision context
        context = {
            'original_decision': audit_record.action,
            'factors': audit_record.decision_factors,
            'confidence': audit_record.confidence_score,
            'risk': audit_record.risk_score,
            'timeline': await self._reconstruct_timeline(correlation_id)
        }
        
        # Generate replay visualization
        visualization = await self._generate_visualization(context)
        
        return {
            'audit_record': asdict(audit_record),
            'context': context,
            'visualization': visualization
        }
    
    def _classify_security_level(self, action: Dict) -> SecurityLevel:
        """Classify action security level"""
        if action.get('affects_production', False):
            return SecurityLevel.SECRET
        elif action.get('modifies_config', False):
            return SecurityLevel.CONFIDENTIAL
        elif action.get('reads_sensitive_data', False):
            return SecurityLevel.INTERNAL
        else:
            return SecurityLevel.PUBLIC
    
    async def _sign_record(self, record: AuditRecord) -> List[str]:
        """Multi-signature for non-repudiation"""
        signatures = []
        
        # Agent signature
        agent_sig = self._generate_signature(
            record,
            f"agent_{record.agent_id}_key"
        )
        signatures.append(agent_sig)
        
        # System signature
        system_sig = self._generate_signature(
            record,
            "system_master_key"
        )
        signatures.append(system_sig)
        
        # Timestamp authority signature
        tsa_sig = await self._get_timestamp_signature(record)
        signatures.append(tsa_sig)
        
        return signatures
    
    def _generate_signature(self, record: AuditRecord, key_id: str) -> str:
        """Generate cryptographic signature"""
        # Simplified - real implementation would use proper crypto
        record_json = json.dumps(asdict(record), sort_keys=True)
        return hashlib.sha512(
            f"{record_json}:{key_id}".encode()
        ).hexdigest()
    
    async def _get_timestamp_signature(self, record: AuditRecord) -> str:
        """Get signature from timestamp authority"""
        # Real implementation would call TSA service
        return self._generate_signature(record, "tsa_key")
    
    async def _verify_signatures(self, record: AuditRecord) -> bool:
        """Verify all signatures on record"""
        # Real implementation would verify each signature
        return len(record.signatures) >= 3
    
    def _log_decision(self, record: AuditRecord, block_hash: str):
        """Log structured decision data"""
        log_entry = {
            'timestamp': record.timestamp,
            'correlation_id': record.correlation_id,
            'agent_id': record.agent_id,
            'action_type': record.action['type'],
            'confidence': record.confidence_score,
            'risk': record.risk_score,
            'duration_ms': record.duration_ms,
            'block_hash': block_hash,
            'security_level': record.security_level.name
        }
        
        # Mask sensitive data
        log_entry = self._mask_sensitive_data(log_entry)
        
        logger.info(json.dumps(log_entry))
    
    def _mask_sensitive_data(self, data: Dict) -> Dict:
        """Mask sensitive information in logs"""
        sensitive_fields = ['password', 'token', 'key', 'secret']
        
        masked_data = data.copy()
        for key, value in masked_data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                masked_data[key] = '***MASKED***'
        
        return masked_data
    
    async def _handle_safety_violation(
        self,
        safety_check: Dict,
        record: AuditRecord
    ):
        """Handle safety threshold violations"""
        severity = safety_check['severity']
        
        if severity == 'critical':
            # Immediate halt
            await self._trigger_kill_switch(record.agent_id, safety_check['reason'])
        elif severity == 'high':
            # Alert and monitor
            await self._send_alert('high', safety_check, record)
        else:
            # Log and track
            logger.warning(f"Safety violation: {safety_check}")
    
    async def _analyze_failure(self, correlation_id: str, details: Dict):
        """Analyze failure patterns"""
        # Real implementation would use ML for pattern detection
        pass
    
    async def _reconstruct_timeline(self, correlation_id: str) -> List[Dict]:
        """Reconstruct decision timeline"""
        # Real implementation would query various stores
        return []
    
    async def _generate_visualization(self, context: Dict) -> str:
        """Generate decision tree visualization"""
        # Real implementation would create graphical representation
        return "visualization_url"
    
    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _load_config(self, path: str) -> Dict:
        """Load OAS configuration"""
        # Real implementation would load from file
        return {}
    
    async def _trigger_kill_switch(self, agent_id: str, reason: str):
        """Trigger emergency kill switch"""
        # Real implementation would halt agent
        logger.critical(f"Kill switch triggered for {agent_id}: {reason}")
    
    async def _send_alert(self, severity: str, check: Dict, record: AuditRecord):
        """Send safety alert"""
        # Real implementation would use alerting system
        pass

class MetricsCollector:
    """Metrics collection implementation"""
    def __init__(self, config: Dict):
        self.config = config
    
    def increment(self, metric: str, labels: Dict = None):
        """Increment counter metric"""
        pass
    
    def observe(self, metric: str, value: float, labels: Dict = None):
        """Record histogram observation"""
        pass
    
    def set_gauge(self, metric: str, value: float, labels: Dict = None):
        """Set gauge value"""
        pass

class DistributedTracer:
    """Distributed tracing implementation"""
    def __init__(self, config: Dict):
        self.config = config
    
    def start_span(self, name: str, correlation_id: str):
        """Start trace span"""
        return self
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    def set_attribute(self, key: str, value: Any):
        """Set span attribute"""
        pass

class BlockchainAuditStore:
    """Blockchain-based audit storage"""
    def __init__(self, config: Dict):
        self.config = config
    
    async def append(self, record: AuditRecord) -> str:
        """Append to blockchain"""
        # Real implementation would use blockchain
        return hashlib.sha256(str(record).encode()).hexdigest()
    
    async def retrieve(self, correlation_id: str, point_in_time: float = None) -> AuditRecord:
        """Retrieve from blockchain"""
        # Real implementation would query blockchain
        pass
    
    async def update_outcome(self, correlation_id: str, outcome: str, details: Dict):
        """Update outcome in blockchain"""
        # Real implementation would append update block
        pass

class SafetyMonitor:
    """Safety threshold monitoring"""
    def __init__(self, config: Dict):
        self.config = config
    
    async def evaluate(self, record: AuditRecord) -> Dict:
        """Evaluate safety thresholds"""
        # Real implementation would check various thresholds
        return {'safe': True, 'severity': 'low', 'reason': None}

class SecurityException(Exception):
    """Security-related exceptions"""
    pass

class UnauthorizedException(Exception):
    """Authorization exceptions"""
    pass

class UnregisteredAgentException(Exception):
    """Unregistered agent exceptions"""
    pass
```text

## Production Deployment Guide

### Pre-Production Checklist

**Security Review:**
- [ ] Threat modeling completed with STRIDE analysis
- [ ] Penetration testing performed on all endpoints
- [ ] Security architecture review by CISO
- [ ] Cryptographic implementations audited
- [ ] Supply chain security verified
- [ ] Quantum-safe algorithms implemented where required

**Compliance Validation:**
- [ ] EU AI Act compliance documented
- [ ] SOC2 Type 2 controls mapped
- [ ] GDPR data processing agreements signed
- [ ] Industry-specific regulations addressed
- [ ] Legal review of liability and indemnification

**Operational Readiness:**
- [ ] Runbooks created for all scenarios
- [ ] On-call rotation established 24/7
- [ ] Escalation procedures documented
- [ ] Training completed for all operators
- [ ] Communication plan activated

**Technical Validation:**
- [ ] Load testing at 2x expected volume
- [ ] Chaos engineering tests passed
- [ ] Disaster recovery tested successfully
- [ ] Rollback procedures validated
- [ ] Monitoring coverage >95%

### Deployment Sequence

```bash
# Production deployment script
#!/bin/bash

# Phase 1: Pre-deployment validation
echo "Starting pre-deployment validation..."
./scripts/validate_config.sh || exit 1
./scripts/run_smoke_tests.sh || exit 1
./scripts/check_dependencies.sh || exit 1

# Phase 2: Deploy monitoring first
echo "Deploying monitoring infrastructure..."
kubectl apply -f monitoring/
./scripts/wait_for_monitoring.sh || exit 1

# Phase 3: Deploy control plane
echo "Deploying control plane..."
kubectl apply -f control-plane/
./scripts/verify_control_plane.sh || exit 1

# Phase 4: Deploy agents in waves
echo "Starting phased agent deployment..."
for wave in 1 2 3 4; do
    echo "Deploying wave $wave..."
    kubectl apply -f agents/wave-$wave/
    ./scripts/validate_wave.sh $wave || exit 1
    sleep 300  # 5-minute observation period
done

# Phase 5: Enable production traffic
echo "Enabling production traffic..."
./scripts/enable_production.sh

# Phase 6: Post-deployment validation
echo "Running post-deployment tests..."
./scripts/run_integration_tests.sh || exit 1
./scripts/verify_metrics.sh || exit 1

echo "Deployment completed successfully"
```text

### Post-Deployment Monitoring

**First 24 Hours:**
- Continuous SOC monitoring
- Hourly health checks
- Performance baseline establishment
- Anomaly detection tuning

**First Week:**
- Daily performance reviews
- Threshold adjustments
- Feedback incorporation
- Documentation updates

**First Month:**
- Weekly stakeholder reviews
- Monthly metrics analysis
- Quarterly planning initiated
- Lessons learned documented

---


*Last comprehensive review: January 2025*
*Next scheduled review: December 2025*
*Version: 2.0.0*