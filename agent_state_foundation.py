from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import Enum
import asyncio
import json
import time
from datetime import datetime

class AgentState(Enum):
    INITIALIZING = "initializing"
    READY = "ready"
    PROCESSING = "processing"
    ERROR = "error"
    SHUTDOWN = "shutdown"

@dataclass
class AgentMetrics:
    """Foundation-layer agent metrics"""
    processed_events: int = 0
    error_count: int = 0
    average_response_time: float = 0.0
    last_activity: Optional[datetime] = None
    memory_usage_mb: float = 0.0
    cpu_utilization: float = 0.0

class FoundationAgent:
    """
    Foundation layer agent with built-in scalability patterns
    This base class includes patterns that enable future scaling
    """
    
    def __init__(self, agent_id: str, agent_type: str):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.state = AgentState.INITIALIZING
        self.metrics = AgentMetrics()
        self.config = {}
        self.event_queue = asyncio.Queue()
        self.shutdown_event = asyncio.Event()
        # Scaling-ready patterns implemented from foundation
        self.health_check_interval = 30  # seconds
        self.max_queue_size = 1000
        self.processing_timeout = 60  # seconds
    async def start(self):
        """Start agent with health monitoring"""
        self.state = AgentState.READY
        self.metrics.last_activity = datetime.now()
        # Start background tasks that enable scaling
        asyncio.create_task(self._health_monitor())
        asyncio.create_task(self._process_events())
        print(f"✅ Agent {self.agent_id} started ({self.agent_type})")
    async def _health_monitor(self):
        """Health monitoring that works at any scale"""
        while not self.shutdown_event.is_set():
            try:
                # Update health metrics
                self.metrics.memory_usage_mb = self._get_memory_usage()
                self.metrics.cpu_utilization = self._get_cpu_utilization()
                # Check queue health
                if self.event_queue.qsize() > self.max_queue_size * 0.9:
                    print(f"⚠️  Agent {self.agent_id}: Queue near capacity ({self.event_queue.qsize()})")
                # Check for error rates
                if self.metrics.processed_events > 0:
                    error_rate = self.metrics.error_count / self.metrics.processed_events
                    if error_rate > 0.1:  # 10% error threshold
                        print(f"🚨 Agent {self.agent_id}: High error rate ({error_rate:.1%})")
                await asyncio.sleep(self.health_check_interval)
            except Exception as e:
                print(f"❌ Health monitor error for {self.agent_id}: {str(e)}")
    async def _process_events(self):
        """Event processing with built-in scaling patterns"""
        while not self.shutdown_event.is_set():
            try:
                # Use timeout to prevent hanging
                event = await asyncio.wait_for(
                    self.event_queue.get(), 
                    timeout=self.processing_timeout
                )
                start_time = time.time()
                # Process event (implemented by subclasses)
                result = await self.process_event(event)
                # Update metrics
                processing_time = time.time() - start_time
                self.metrics.processed_events += 1
                self.metrics.last_activity = datetime.now()
                # Update rolling average response time
                if self.metrics.average_response_time == 0:
                    self.metrics.average_response_time = processing_time
                else:
                    # Exponential moving average
                    alpha = 0.1
                    self.metrics.average_response_time = (
                        alpha * processing_time + 
                        (1 - alpha) * self.metrics.average_response_time
                    )
                # Mark task as done
                self.event_queue.task_done()
            except asyncio.TimeoutError:
                continue  # No events to process
            except Exception as e:
                self.metrics.error_count += 1
                print(f"❌ Processing error in {self.agent_id}: {str(e)}")
    async def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Override this method in subclasses"""
        raise NotImplementedError("Subclasses must implement process_event")
    async def submit_event(self, event: Dict[str, Any]) -> bool:
        """Submit event for processing with backpressure handling"""
        if self.event_queue.qsize() >= self.max_queue_size:
            print(f"⚠️  Queue full for agent {self.agent_id}, dropping event")
            return False
        await self.event_queue.put(event)
        return True
    def get_status(self) -> Dict[str, Any]:
        """Get agent status (crucial for scaling monitoring)"""
        return {
            'agent_id': self.agent_id,
            'agent_type': self.agent_type,
            'state': self.state.value,
            'queue_size': self.event_queue.qsize(),
            'metrics': {
                'processed_events': self.metrics.processed_events,
                'error_count': self.metrics.error_count,
                'error_rate': self.metrics.error_count / max(self.metrics.processed_events, 1),
                'average_response_time': self.metrics.average_response_time,
                'memory_usage_mb': self.metrics.memory_usage_mb,
                'cpu_utilization': self.metrics.cpu_utilization,
                'last_activity': self.metrics.last_activity.isoformat() if self.metrics.last_activity else None
            }
        }
    def _get_memory_usage(self) -> float:
        """Get memory usage in MB (simplified for demo)"""
        import psutil
        import os
        try:
            process = psutil.Process(os.getpid())
            return process.memory_info().rss / 1024 / 1024
        except:
            return 0.0
    def _get_cpu_utilization(self) -> float:
        """Get CPU utilization percentage (simplified for demo)"""
        import psutil
        try:
            return psutil.cpu_percent(interval=0.1)
        except:
            return 0.0
    async def shutdown(self):
        """Graceful shutdown"""
        print(f"🛑 Shutting down agent {self.agent_id}")
        self.state = AgentState.SHUTDOWN
        self.shutdown_event.set()
        # Wait for current events to complete
        await self.event_queue.join()
# Example specialized agent
class ThreatDetectionAgent(FoundationAgent):
    """Example threat detection agent built on scalable foundation"""
    def __init__(self, agent_id: str):
        super().__init__(agent_id, "threat_detection")
        self.threat_signatures = self.load_threat_signatures()
    def load_threat_signatures(self) -> Dict[str, Any]:
        """Load threat detection signatures"""
        # In production, this would load from a database or threat intelligence feed
        return {
            'malware_hashes': ['d41d8cd98f00b204e9800998ecf8427e'],
            'suspicious_domains': ['malicious.example.com'],
            'attack_patterns': ['credential_stuffing', 'lateral_movement']
        }
    async def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process security events for threats"""
        event_type = event.get('type', '')
        if event_type == 'file_scan':
            return await self._scan_file(event)
        elif event_type == 'network_connection':
            return await self._check_network_connection(event)
        elif event_type == 'user_behavior':
            return await self._analyze_user_behavior(event)
        else:
            return {'action': 'unknown_event_type', 'risk_score': 0}
    async def _scan_file(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Scan file for malware"""
        file_hash = event.get('file_hash', '')
        # Simulate processing time
        await asyncio.sleep(0.1)
        if file_hash in self.threat_signatures['malware_hashes']:
            return {
                'action': 'quarantine',
                'risk_score': 0.9,
                'reason': 'known_malware_hash'
            }
        return {'action': 'allow', 'risk_score': 0.1}
    async def _check_network_connection(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Check network connection for threats"""
        domain = event.get('domain', '')
        # Simulate processing time
        await asyncio.sleep(0.05)
        if domain in self.threat_signatures['suspicious_domains']:
            return {
                'action': 'block',
                'risk_score': 0.8,
                'reason': 'suspicious_domain'
            }
        return {'action': 'allow', 'risk_score': 0.2}
    async def _analyze_user_behavior(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze user behavior for anomalies"""
        behavior_pattern = event.get('pattern', '')
        # Simulate processing time  
        await asyncio.sleep(0.2)
        if behavior_pattern in self.threat_signatures['attack_patterns']:
            return {
                'action': 'investigate',
                'risk_score': 0.7,
                'reason': 'suspicious_behavior_pattern'
            }
        return {'action': 'monitor', 'risk_score': 0.3}
# Foundation layer management
class FoundationManager:
    """Manages small-scale agent deployment"""
    def __init__(self):
        self.agents: Dict[str, FoundationAgent] = {}
        self.monitoring_interval = 60  # seconds
    async def deploy_agent(self, agent: FoundationAgent):
        """Deploy agent with monitoring"""
        self.agents[agent.agent_id] = agent
        await agent.start()
        # Start monitoring task
        asyncio.create_task(self._monitor_agent(agent.agent_id))
    async def _monitor_agent(self, agent_id: str):
        """Monitor individual agent health"""
        while agent_id in self.agents:
            try:
                agent = self.agents[agent_id]
                status = agent.get_status()
                # Log status (in production, send to monitoring system)
                print(f"📊 {agent_id}: {status['metrics']['processed_events']} events, "
                      f"{status['metrics']['error_rate']:.1%} error rate, "
                      f"{status['queue_size']} queued")
                await asyncio.sleep(self.monitoring_interval)
            except Exception as e:
                print(f"❌ Monitoring error for {agent_id}: {str(e)}")
                break
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get overall cluster status"""
        total_events = sum(agent.metrics.processed_events for agent in self.agents.values())
        total_errors = sum(agent.metrics.error_count for agent in self.agents.values())
        return {
            'agent_count': len(self.agents),
            'total_events_processed': total_events,
            'total_errors': total_errors,
            'overall_error_rate': total_errors / max(total_events, 1),
            'agents': {agent_id: agent.get_status() for agent_id, agent in self.agents.items()}
        }
# Example usage
async def demo_foundation_layer():
    """Demonstrate foundation layer agent deployment"""
    print("🏗️  FOUNDATION LAYER DEMO")
    print("=" * 50)
    manager = FoundationManager()
    # Deploy agents
    agent1 = ThreatDetectionAgent("td-001")
    agent2 = ThreatDetectionAgent("td-002")
    await manager.deploy_agent(agent1)
    await manager.deploy_agent(agent2)
    # Simulate event processing
    events = [
        {'type': 'file_scan', 'file_hash': 'd41d8cd98f00b204e9800998ecf8427e', 'filename': 'suspicious.exe'},
        {'type': 'network_connection', 'domain': 'malicious.example.com', 'ip': '203.0.113.1'},
        {'type': 'user_behavior', 'pattern': 'credential_stuffing', 'user': 'jdoe'},
        {'type': 'file_scan', 'file_hash': 'benign_file_hash', 'filename': 'document.pdf'}
    ]
    # Submit events to agents (round-robin)
    for i, event in enumerate(events):
        agent = agent1 if i % 2 == 0 else agent2
        await agent.submit_event(event)
    # Let agents process events
    await asyncio.sleep(2)
    # Show cluster status
    status = manager.get_cluster_status()
    print(f"\n📊 CLUSTER STATUS:")
    print(f"   Agents: {status['agent_count']}")
    print(f"   Total Events: {status['total_events_processed']}")
    print(f"   Error Rate: {status['overall_error_rate']:.1%}")
    # Shutdown
    for agent in manager.agents.values():
        await agent.shutdown()
# Run the demo
asyncio.run(demo_foundation_layer())
