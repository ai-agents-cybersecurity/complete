import asyncio
import json
import time
import numpy as np
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
import sqlite3
import matplotlib.pyplot as plt
import seaborn as sns
from flask import Flask, render_template, jsonify
import plotly.graph_objs as go
import plotly.utils

@dataclass
class ModelHealthMetrics:
    """Core metrics for AI model health monitoring"""
    model_name: str
    version: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    drift_score: float
    last_updated: datetime
    latency_ms: float
    throughput_qps: float
    error_rate: float
    incidents: int
    status: str

class ModelHealthDatabase:
    """SQLite-backed storage for model health metrics"""
    def __init__(self, db_path="model_health.db"):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()
    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS model_metrics (
            model_name TEXT, version TEXT, accuracy REAL, precision REAL, recall REAL, f1_score REAL,
            drift_score REAL, last_updated TEXT, latency_ms REAL, throughput_qps REAL, error_rate REAL,
            incidents INTEGER, status TEXT
        )''')
        self.conn.commit()
    def insert_metrics(self, metrics: ModelHealthMetrics):
        cur = self.conn.cursor()
        cur.execute('''INSERT INTO model_metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                metrics.model_name, metrics.version, metrics.accuracy, metrics.precision, metrics.recall,
                metrics.f1_score, metrics.drift_score, metrics.last_updated.isoformat(),
                metrics.latency_ms, metrics.throughput_qps, metrics.error_rate, metrics.incidents, metrics.status
            )
        )
        self.conn.commit()
    def get_latest_metrics(self, model_name: str) -> Optional[ModelHealthMetrics]:
        cur = self.conn.cursor()
        cur.execute('''SELECT * FROM model_metrics WHERE model_name=? ORDER BY last_updated DESC LIMIT 1''', (model_name,))
        row = cur.fetchone()
        if row:
            return ModelHealthMetrics(
                model_name=row[0], version=row[1], accuracy=row[2], precision=row[3], recall=row[4],
                f1_score=row[5], drift_score=row[6], last_updated=datetime.fromisoformat(row[7]),
                latency_ms=row[8], throughput_qps=row[9], error_rate=row[10], incidents=row[11], status=row[12]
            )
        return None
    def get_all_metrics(self) -> List[ModelHealthMetrics]:
        cur = self.conn.cursor()
        cur.execute('''SELECT * FROM model_metrics ORDER BY last_updated DESC''')
        rows = cur.fetchall()
        return [
            ModelHealthMetrics(
                model_name=row[0], version=row[1], accuracy=row[2], precision=row[3], recall=row[4],
                f1_score=row[5], drift_score=row[6], last_updated=datetime.fromisoformat(row[7]),
                latency_ms=row[8], throughput_qps=row[9], error_rate=row[10], incidents=row[11], status=row[12]
            ) for row in rows
        ]

# --- Simulated Model Monitoring ---
async def monitor_model_health(db: ModelHealthDatabase, model_name: str, version: str):
    while True:
        metrics = ModelHealthMetrics(
            model_name=model_name,
            version=version,
            accuracy=np.random.uniform(0.85, 0.99),
            precision=np.random.uniform(0.8, 0.99),
            recall=np.random.uniform(0.8, 0.99),
            f1_score=np.random.uniform(0.8, 0.99),
            drift_score=np.random.uniform(0, 0.2),
            last_updated=datetime.now(),
            latency_ms=np.random.uniform(30, 120),
            throughput_qps=np.random.uniform(10, 100),
            error_rate=np.random.uniform(0, 0.01),
            incidents=np.random.randint(0, 3),
            status="healthy"
        )
        db.insert_metrics(metrics)
        await asyncio.sleep(10)

# --- Flask Dashboard ---
app = Flask(__name__)
db = ModelHealthDatabase()

@app.route("/")
def dashboard():
    metrics = db.get_all_metrics()
    return render_template("dashboard.html", metrics=metrics)

@app.route("/api/metrics")
def api_metrics():
    metrics = db.get_all_metrics()
    return jsonify([asdict(m) for m in metrics])

@app.route("/api/metrics/<model_name>")
def api_model_metrics(model_name):
    metrics = db.get_latest_metrics(model_name)
    return jsonify(asdict(metrics) if metrics else {})

# --- Visualization Example (matplotlib, seaborn, plotly) ---
def plot_metrics(metrics: List[ModelHealthMetrics]):
    if not metrics:
        print("No metrics to plot.")
        return
    times = [m.last_updated for m in metrics]
    accuracy = [m.accuracy for m in metrics]
    drift = [m.drift_score for m in metrics]
    plt.figure(figsize=(12, 6))
    sns.lineplot(x=times, y=accuracy, label="Accuracy")
    sns.lineplot(x=times, y=drift, label="Drift Score")
    plt.title("Model Health Over Time")
    plt.xlabel("Time")
    plt.ylabel("Metric Value")
    plt.legend()
    plt.show()
    # Plotly interactive
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=times, y=accuracy, mode='lines', name='Accuracy'))
    fig.add_trace(go.Scatter(x=times, y=drift, mode='lines', name='Drift Score'))
    fig.update_layout(title="Model Health Over Time", xaxis_title="Time", yaxis_title="Value")
    fig.show()

# --- Entry Point ---
def main():
    # Start async monitoring in background
    loop = asyncio.get_event_loop()
    loop.create_task(monitor_model_health(db, "threat_detection_model", "v1.2"))
    # Start Flask app
    app.run(debug=True, use_reloader=False)

if __name__ == "__main__":
    main()
