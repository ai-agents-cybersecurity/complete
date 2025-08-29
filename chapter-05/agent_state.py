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
        """Get current memory usage in MB"""
        import psutil
        import os
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    
    def _get_cpu_utilization(self) -> float:
        """Get current CPU utilization"""
        import psutil
        return psutil.cpu_percent(interval=0.1)
    
    async def shutdown(self):
        """Graceful shutdown"""
        print(f"🔄 Shutting down agent {self.agent_id}")
        self.state = AgentState.SHUTDOWN
        self.shutdown_event.set()
        
        # Wait for current events to finish
        await self.event_queue.join()
        print(f"✅ Agent {self.agent_id} shutdown complete")
