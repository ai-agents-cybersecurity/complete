import pandas as pd
from flask import Flask, render_template, jsonify, request
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import sqlite3
import random
import os
from typing import Dict

@dataclass
class ModelHealthMetrics:
    timestamp: datetime
    model_id: str
    response_time_ms: float
    throughput_requests_per_min: float
    error_rate_percent: float
    accuracy_score: float
    drift_score: float
    token_usage_avg: int
    blocked_prompts_count: int
    policy_violations_count: int
    anomaly_detections_count: int
    memory_usage_mb: float
    cpu_utilization_percent: float
    gpu_utilization_percent: float

class ModelHealthDashboard:
    def __init__(self, db_path="model_health.db"):
        self.db_path = db_path
        self.app = Flask(__name__)
        self.init_database()
        self.setup_routes()
        self.thresholds = {
            'response_time_ms': 2000,
            'error_rate_percent': 5.0,
            'drift_score': 0.3,
            'accuracy_score': 0.85,
            'cpu_utilization_percent': 80
        }
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS model_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            model_id TEXT NOT NULL,
            response_time_ms REAL,
            throughput_requests_per_min REAL,
            error_rate_percent REAL,
            accuracy_score REAL,
            drift_score REAL,
            token_usage_avg INTEGER,
            blocked_prompts_count INTEGER,
            policy_violations_count INTEGER,
            anomaly_detections_count INTEGER,
            memory_usage_mb REAL,
            cpu_utilization_percent REAL,
            gpu_utilization_percent REAL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            model_id TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            current_value REAL,
            threshold_value REAL,
            severity TEXT NOT NULL,
            acknowledged BOOLEAN DEFAULT FALSE
        )''')
        conn.commit()
        conn.close()
    def record_metrics(self, metrics: ModelHealthMetrics):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        metrics_dict = asdict(metrics)
        metrics_dict['timestamp'] = metrics.timestamp.isoformat()
        cursor.execute('''INSERT INTO model_metrics (
            timestamp, model_id, response_time_ms, throughput_requests_per_min,
            error_rate_percent, accuracy_score, drift_score, token_usage_avg,
            blocked_prompts_count, policy_violations_count, anomaly_detections_count,
            memory_usage_mb, cpu_utilization_percent, gpu_utilization_percent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
            metrics_dict['timestamp'], metrics_dict['model_id'],
            metrics_dict['response_time_ms'], metrics_dict['throughput_requests_per_min'],
            metrics_dict['error_rate_percent'], metrics_dict['accuracy_score'],
            metrics_dict['drift_score'], metrics_dict['token_usage_avg'],
            metrics_dict['blocked_prompts_count'], metrics_dict['policy_violations_count'],
            metrics_dict['anomaly_detections_count'], metrics_dict['memory_usage_mb'],
            metrics_dict['cpu_utilization_percent'], metrics_dict['gpu_utilization_percent']
        ))
        conn.commit()
        conn.close()
        self.check_thresholds(metrics)
    def check_thresholds(self, metrics: ModelHealthMetrics):
        alerts_triggered = []
        if metrics.response_time_ms > self.thresholds['response_time_ms']:
            alerts_triggered.append(('HIGH_RESPONSE_TIME', 'response_time_ms', metrics.response_time_ms, self.thresholds['response_time_ms']))
        if metrics.error_rate_percent > self.thresholds['error_rate_percent']:
            alerts_triggered.append(('HIGH_ERROR_RATE', 'error_rate_percent', metrics.error_rate_percent, self.thresholds['error_rate_percent']))
        if metrics.drift_score > self.thresholds['drift_score']:
            alerts_triggered.append(('MODEL_DRIFT_DETECTED', 'drift_score', metrics.drift_score, self.thresholds['drift_score']))
        if metrics.accuracy_score < self.thresholds['accuracy_score']:
            alerts_triggered.append(('LOW_ACCURACY', 'accuracy_score', metrics.accuracy_score, self.thresholds['accuracy_score']))
        if metrics.cpu_utilization_percent > self.thresholds['cpu_utilization_percent']:
            alerts_triggered.append(('HIGH_CPU_USAGE', 'cpu_utilization_percent', metrics.cpu_utilization_percent, self.thresholds['cpu_utilization_percent']))
        for alert_type, metric_name, current_value, threshold_value in alerts_triggered:
            self.record_alert(metrics.model_id, alert_type, metric_name, current_value, threshold_value)
    def record_alert(self, model_id: str, alert_type: str, metric_name: str, current_value: float, threshold_value: float):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        severity = 'HIGH' if 'DRIFT' in alert_type or 'LOW_ACCURACY' in alert_type else 'MEDIUM'
        cursor.execute('''INSERT INTO alerts (timestamp, model_id, alert_type, metric_name, current_value, threshold_value, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)''', (datetime.now().isoformat(), model_id, alert_type, metric_name, current_value, threshold_value, severity))
        conn.commit()
        conn.close()
        print(f"🚨 ALERT: {alert_type} for model {model_id}")
        print(f"   Metric: {metric_name} = {current_value} (threshold: {threshold_value})")
    def get_dashboard_data(self, model_id: str, hours_back: int = 24) -> Dict:
        conn = sqlite3.connect(self.db_path)
        since_time = (datetime.now() - timedelta(hours=hours_back)).isoformat()
        df = pd.read_sql('''SELECT * FROM model_metrics WHERE model_id = ? AND timestamp > ? ORDER BY timestamp DESC''', conn, params=(model_id, since_time))
        if df.empty:
            return {"error": "No data found"}
        alerts_df = pd.read_sql('''SELECT * FROM alerts WHERE model_id = ? AND timestamp > ? ORDER BY timestamp DESC''', conn, params=(model_id, since_time))
        conn.close()
        latest_metrics = df.iloc[0] if not df.empty else None
        dashboard_data = {
            "model_id": model_id,
            "last_updated": datetime.now().isoformat(),
            "health_score": self.calculate_health_score(latest_metrics) if latest_metrics is not None else 0,
            "current_metrics": {
                "response_time_ms": latest_metrics["response_time_ms"] if latest_metrics is not None else 0,
                "error_rate_percent": latest_metrics["error_rate_percent"] if latest_metrics is not None else 0,
                "accuracy_score": latest_metrics["accuracy_score"] if latest_metrics is not None else 0,
                "drift_score": latest_metrics["drift_score"] if latest_metrics is not None else 0,
                "cpu_utilization_percent": latest_metrics["cpu_utilization_percent"] if latest_metrics is not None else 0
            },
            "trends": {
                "response_time": df['response_time_ms'].tolist()[-50:] if not df.empty else [],
                "error_rate": df['error_rate_percent'].tolist()[-50:] if not df.empty else [],
                "accuracy": df['accuracy_score'].tolist()[-50:] if not df.empty else [],
                "drift": df['drift_score'].tolist()[-50:] if not df.empty else [],
                "timestamps": df['timestamp'].tolist()[-50:] if not df.empty else []
            },
            "active_alerts": alerts_df[alerts_df['acknowledged'] == 0].to_dict('records') if not alerts_df.empty else [],
            "alert_count": len(alerts_df[alerts_df['acknowledged'] == 0]) if not alerts_df.empty else 0
        }
        return dashboard_data
    def calculate_health_score(self, metrics) -> float:
        if metrics is None:
            return 0.0
        health = 100.0
        if float(metrics["response_time_ms"]) > 1000:
            health -= min(30, (float(metrics["response_time_ms"]) - 1000) / 100)
        if float(metrics["error_rate_percent"]) > 1:
            health -= min(25, float(metrics["error_rate_percent"]) * 5)
        if float(metrics["drift_score"]) > 0.1:
            health -= min(30, float(metrics["drift_score"]) * 100)
        if float(metrics["accuracy_score"]) < 0.9:
            health -= min(20, (0.9 - float(metrics["accuracy_score"])) * 100)
        if float(metrics["cpu_utilization_percent"]) > 70:
            health -= min(15, (float(metrics["cpu_utilization_percent"]) - 70) / 2)
        return max(0, health)
    def setup_routes(self):
        @self.app.route('/')
        def dashboard():
            model_id = request.args.get('model_id', 'demo-model')
            return render_template('index.html', model_id=model_id)
        
        @self.app.route('/health')
        def health():
            return jsonify({"status": "ok", "time": datetime.now().isoformat()})

        @self.app.route('/api/dashboard/<model_id>')
        def api_dashboard(model_id: str):
            hours = int(request.args.get('hours', 24))
            data = self.get_dashboard_data(model_id, hours_back=hours)
            return jsonify(data)

        @self.app.route('/api/metrics', methods=['POST'])
        def api_metrics():
            data = request.get_json(silent=True) or {}
            try:
                ts_str = data.get('timestamp')
                ts = datetime.fromisoformat(ts_str) if ts_str else datetime.now()
                metrics = ModelHealthMetrics(
                    timestamp=ts,
                    model_id=data['model_id'],
                    response_time_ms=float(data.get('response_time_ms', 0.0)),
                    throughput_requests_per_min=float(data.get('throughput_requests_per_min', 0.0)),
                    error_rate_percent=float(data.get('error_rate_percent', 0.0)),
                    accuracy_score=float(data.get('accuracy_score', 0.0)),
                    drift_score=float(data.get('drift_score', 0.0)),
                    token_usage_avg=int(data.get('token_usage_avg', 0)),
                    blocked_prompts_count=int(data.get('blocked_prompts_count', 0)),
                    policy_violations_count=int(data.get('policy_violations_count', 0)),
                    anomaly_detections_count=int(data.get('anomaly_detections_count', 0)),
                    memory_usage_mb=float(data.get('memory_usage_mb', 0.0)),
                    cpu_utilization_percent=float(data.get('cpu_utilization_percent', 0.0)),
                    gpu_utilization_percent=float(data.get('gpu_utilization_percent', 0.0))
                )
            except (KeyError, ValueError, TypeError) as e:
                return jsonify({"error": f"invalid payload: {e}"}), 400
            self.record_metrics(metrics)
            return jsonify({"status": "success"})

        @self.app.route('/api/alerts/<model_id>')
        def api_alerts(model_id: str):
            hours = int(request.args.get('hours', 24))
            conn = sqlite3.connect(self.db_path)
            since_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            df = pd.read_sql(
                'SELECT * FROM alerts WHERE model_id = ? AND timestamp > ? AND acknowledged = 0 ORDER BY timestamp DESC',
                conn,
                params=(model_id, since_time)
            )
            conn.close()
            alerts = df.to_dict('records') if not df.empty else []
            return jsonify({"model_id": model_id, "count": len(alerts), "alerts": alerts})

        @self.app.route('/api/alerts/ack/<int:alert_id>', methods=['POST'])
        def ack_alert(alert_id: int):
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('UPDATE alerts SET acknowledged = 1 WHERE id = ?', (alert_id,))
            conn.commit()
            conn.close()
            return jsonify({"status": "acknowledged", "alert_id": alert_id})

        @self.app.route('/api/summary/<model_id>')
        def api_summary(model_id: str):
            hours = int(request.args.get('hours', 24))
            conn = sqlite3.connect(self.db_path)
            since_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            df = pd.read_sql(
                'SELECT * FROM model_metrics WHERE model_id = ? AND timestamp > ? ORDER BY timestamp DESC',
                conn,
                params=(model_id, since_time)
            )
            alerts_df = pd.read_sql(
                'SELECT * FROM alerts WHERE model_id = ? AND timestamp > ?',
                conn,
                params=(model_id, since_time)
            )
            conn.close()
            if df.empty:
                return jsonify({"error": "No data found"}), 404

            def metric_stats(series):
                s = pd.to_numeric(series, errors='coerce').dropna()
                if s.empty:
                    return {"avg": 0, "p95": 0, "min": 0, "max": 0}
                return {
                    "avg": round(float(s.mean()), 3),
                    "p95": round(float(s.quantile(0.95)), 3),
                    "min": round(float(s.min()), 3),
                    "max": round(float(s.max()), 3)
                }

            stats = {
                "response_time_ms": metric_stats(df["response_time_ms"]),
                "error_rate_percent": metric_stats(df["error_rate_percent"]),
                "accuracy_score": metric_stats(df["accuracy_score"]),
                "drift_score": metric_stats(df["drift_score"]),
                "cpu_utilization_percent": metric_stats(df["cpu_utilization_percent"])
            }
            alerts_by_type = {} if alerts_df.empty else alerts_df.groupby('alert_type').size().to_dict()
            severity_counts = {} if alerts_df.empty else alerts_df.groupby('severity').size().to_dict()

            return jsonify({
                "model_id": model_id,
                "since": since_time,
                "stats": stats,
                "alerts_by_type": alerts_by_type,
                "alert_severity_counts": severity_counts
            })

        @self.app.route('/demo/seed/<model_id>')
        def demo_seed(model_id: str):
            hours = int(request.args.get('hours', 6))
            interval = int(request.args.get('interval', 5))  # minutes
            total_minutes = hours * 60
            steps = max(1, total_minutes // interval)
            now = datetime.now()
            inserted = 0

            for step in range(int(steps)):
                minutes_ago = total_minutes - (step * interval)
                ts = now - timedelta(minutes=minutes_ago)

                # Generate synthetic but somewhat realistic values
                response_time_ms = max(50, random.gauss(600, 200))  # center ~600ms
                throughput = max(1.0, random.gauss(60, 15))         # req/min
                error_rate = max(0.0, min(20.0, abs(random.gauss(1.0, 1.0))))
                accuracy = max(0.5, min(1.0, random.gauss(0.93, 0.02)))
                drift = max(0.0, min(1.0, abs(random.gauss(0.08, 0.05))))
                token_usage = max(1, int(random.gauss(900, 250)))
                blocked = max(0, int(random.gauss(1, 1)))
                policy = max(0, int(random.gauss(0.3, 0.7)))
                anomalies = max(0, int(random.gauss(0.5, 0.9)))
                mem_mb = max(128.0, random.gauss(3072, 1024))
                cpu = max(0.0, min(100.0, random.gauss(55, 20)))
                gpu = max(0.0, min(100.0, random.gauss(30, 25)))

                metrics = ModelHealthMetrics(
                    timestamp=ts,
                    model_id=model_id,
                    response_time_ms=float(response_time_ms),
                    throughput_requests_per_min=float(throughput),
                    error_rate_percent=float(error_rate),
                    accuracy_score=float(accuracy),
                    drift_score=float(drift),
                    token_usage_avg=int(token_usage),
                    blocked_prompts_count=int(blocked),
                    policy_violations_count=int(policy),
                    anomaly_detections_count=int(anomalies),
                    memory_usage_mb=float(mem_mb),
                    cpu_utilization_percent=float(cpu),
                    gpu_utilization_percent=float(gpu)
                )
                self.record_metrics(metrics)
                inserted += 1

            return jsonify({
                "status": "seeded",
                "model_id": model_id,
                "inserted": inserted,
                "hours": hours,
                "interval_minutes": interval
            })

    def run(self, host: str = "0.0.0.0", port: int = 5000, debug: bool = True):
        self.app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    dashboard = ModelHealthDashboard()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug_env = os.environ.get("DEBUG", "1").lower()
    debug = debug_env in ("1", "true", "yes", "on")
    dashboard.run(host=host, port=port, debug=debug)
