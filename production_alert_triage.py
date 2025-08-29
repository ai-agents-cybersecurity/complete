import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime
from langchain.agents import AgentExecutor
from langchain.memory import ConversationBufferMemory
from langchain.tools import Tool
import redis
import json

class ProductionAlertTriageAgent:
    """Production-ready alert triage with full observability"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.redis_client = redis.Redis.from_url(config['redis_url'])
        self.setup_logging()
        self.setup_metrics()
        self.initialize_agent()
        
    def setup_logging(self):
        """Configure structured logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_metrics(self):
        """Initialize Prometheus metrics"""
        from prometheus_client import Counter, Histogram, Gauge
        
        self.alerts_processed = Counter(
            'alerts_processed_total',
            'Total alerts processed',
            ['severity', 'source']
        )
        
        self.processing_time = Histogram(
            'alert_processing_seconds',
            'Time to process alerts',
            ['severity']
        )
        
        self.active_investigations = Gauge(
            'active_investigations',
            'Currently active investigations'
        )
        
    async def triage_alert(self, alert: Dict) -> Dict:
        """Main triage logic with error handling"""
        start_time = datetime.now()
        investigation_id = self.generate_investigation_id()
        
        try:
            # Log alert receipt
            self.logger.info(f"Processing alert {alert['id']}")
            self.active_investigations.inc()
            
            # Enrich with context
            enriched = await self.enrich_alert(alert)
            
            # Analyze threat
            analysis = await self.analyze_threat(enriched)
            
            # Generate response plan
            response = await self.plan_response(analysis)
            
            # Store results
            self.store_investigation(investigation_id, {
                'alert': alert,
                'enrichment': enriched,
                'analysis': analysis,
                'response': response,
                'timestamp': datetime.now().isoformat()
            })
            
            # Update metrics
            processing_duration = (datetime.now() - start_time).total_seconds()
            self.processing_time.labels(
                severity=alert.get('severity', 'unknown')
            ).observe(processing_duration)
            
            self.alerts_processed.labels(
                severity=alert.get('severity', 'unknown'),
                source=alert.get('source', 'unknown')
            ).inc()
            
            return {
                'investigation_id': investigation_id,
                'status': 'success',
                'summary': analysis['summary'],
                'recommended_actions': response['actions'],
                'confidence': analysis['confidence'],
                'processing_time': processing_duration
            }
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {str(e)}")
            return {
                'investigation_id': investigation_id,
                'status': 'error',
                'error': str(e)
            }
        finally:
            self.active_investigations.dec()
