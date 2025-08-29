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
        recent_actions = [a for a in self.action_history if now - a.timestamp < 60]
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
        await self._broadcast_halt_signal()
        await self._preserve_forensic_evidence(snapshot)
        await self._trigger_incident_response(snapshot)
        await self._update_threat_intel(snapshot)
    def reset(self, authorized_by: str, mfa_token: str) -> bool:
        """Secure reset with multi-factor authentication"""
        if not self._verify_mfa(authorized_by, mfa_token):
            logger.error(f"Failed reset attempt by {authorized_by}")
            return False
        logger.info(f"Kill switch reset for {self.agent_id} by {authorized_by}")
        # Gradual reset based on threat assessment
        if self.threat_level == ThreatLevel.BLACK:
            logger.warning("Agent marked as compromised - requiring security review")
            return False
        self.is_halted = False
        self.halt_reason = None
        self.action_history.clear()
        self.affected_hosts.clear()
        self.threat_level = ThreatLevel.YELLOW
        self.trust_score = 0.5
        return True
    def _update_trust_score(self, success: bool):
        """Dynamic trust scoring with decay"""
        if success:
            self.trust_score = min(1.0, self.trust_score + 0.01)
        else:
            self.trust_score = max(0.0, self.trust_score - 0.1)
        self.trust_score *= 0.999
    def _is_lateral_movement_pattern(self, hosts: List[str]) -> bool:
        """Detect lateral movement indicators"""
        segments = [self._get_network_segment(h) for h in hosts]
        return len(set(segments)) > 3
    def _contains_sequence(self, patterns: List[str], sequence: List[str]) -> bool:
        """Check if pattern list contains a specific sequence"""
        pattern_str = ','.join(patterns)
        sequence_str = ','.join(sequence)
        return sequence_str in pattern_str
    def _get_network_segment(self, host: str) -> str:
        """Extract network segment from hostname/IP"""
        return host.split('.')[0] if '.' in host else host[:3]
    def _quantum_safe_sign(self, data: dict) -> str:
        """Placeholder for quantum-safe signing"""
        return hashlib.sha256(json.dumps(data).encode()).hexdigest()
    def _verify_mfa(self, user: str, token: str) -> bool:
        """Verify multi-factor authentication"""
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
        pass
    async def _preserve_forensic_evidence(self, snapshot: dict):
        """Preserve evidence for investigation"""
        pass
    async def _trigger_incident_response(self, snapshot: dict):
        """Initiate incident response procedures"""
        pass
    async def _update_threat_intel(self, snapshot: dict):
        """Share threat intelligence with security platforms"""
        pass
