# Architecture & Continuous Training for PAM Anomaly Detection (Wallix + Wazuh + Logstash)

This document provides a summary of the discussed architecture, continuous training pipeline, and implementation roadmap for Privileged Access Management (PAM) anomaly detection.

---

## 1. High-Level Real-Time Architecture

The system connects **Wallix PAM**, **Logstash**, an **ML Inference Service**, **Wazuh/Elasticsearch**, and **Kibana/Grafana** for end-to-end detection and alert handling.

```
[ Wallix PAM ] 
      │ (Syslog / API)
      ▼
 [ Logstash ] ──────► [ ML Inference API ] ──► (Anomaly Score)
      │                     (FastAPI / Model)
      ▼
 [ OpenSearch / Elasticsearch / Wazuh ]
      │
      ▼
 [ Kibana / Grafana Dashboard & Alerts ]
```

### Pipeline Flow:
1. **Ingestion:** Wallix streams session logs and command events to Logstash via Syslog or REST API.
2. **Parsing & Enrichment:** Logstash parses fields (Grok/JSON), extracts key features (connection time, command risk, session duration, source IP), and forwards them via an `http` filter to a FastAPI ML microservice.
3. **Inference:** The FastAPI service returns an anomaly score ($0.0$ to $1.0$) and a boolean flag (`is_anomaly: true/false`).
4. **Storage & Alerting:** The enriched log is indexed into Elasticsearch/OpenSearch. Wazuh monitors this index to trigger active response rules or SOC alerts when critical thresholds are exceeded.
5. **Visualization:** Kibana / OpenSearch Dashboards display raw logs, session timelines, and anomaly distributions.

---

## 2. Continuous Training (CT) Pipeline

To ensure the model adapts to evolving user behaviors without manual retraining, implement an automated continuous training feedback loop.

```
                      [ New Wallix Logs ]
                              │
                              ▼
           [ Elasticsearch / OpenSearch Storage ]
                              │
  Trigger: Scheduled / Data Drift / Wazuh Feedback
                              │
                              ▼
   ┌──────────────────────────────────────────────────────┐
   │         Continuous Training Worker / Job             │
   │  1. Extract latest clean baseline data               │
   │  2. Train & Evaluate anomaly model                   │
   │  3. Log artifacts & metrics to MLflow                │
   │  4. Generate Training Summary Report                 │
   └──────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
 [ Update Model Registry ]             [ Training Summary ]
 (Reload in FastAPI Service)           ├── Kibana / Wazuh Index
                                       └── Slack / Teams / Email Alert
```

### Key Components:
- **Orchestration:** Scheduled cron job, Airflow, or Prefect triggered periodically (e.g., weekly) or after $N$ new logs.
- **Model Registry & Tracking:** MLflow tracks training iterations, parameters (contamination rates, estimator count), baseline loss, and model artifacts.
- **Hot-Reloading:** The FastAPI inference service periodically polls the MLflow Model Registry for new versions tagged `Production` and reloads weights with zero downtime.

---

## 3. Training Summary Schema

Every automated retraining run should produce a structured summary payload saved to Elasticsearch and broadcasted to monitoring channels:

```json
{
  "timestamp": "2026-08-14T10:00:00Z",
  "run_id": "mlflow-run-abc123xyz",
  "model_version": "v1.4.0",
  "sample_count": 45200,
  "unique_users_profiled": 128,
  "mean_anomaly_score": -0.042,
  "score_std": 0.081,
  "drift_detected": false,
  "deployment_status": "SUCCESS_PROMOTED"
}
```

---

## 4. Python Implementation Reference (MLflow Continuous Training)

```python
import mlflow
from mlflow.tracking import MlflowClient
from sklearn.ensemble import IsolationForest
import datetime

def continuous_training_job():
    # 1. Fetch training data from Elasticsearch/OpenSearch
    X_train, raw_metadata = load_wallix_training_data(days=30)
    
    with mlflow.start_run() as run:
        # 2. Train Model
        contamination_rate = 0.02
        model = IsolationForest(n_estimators=150, contamination=contamination_rate, random_state=42)
        model.fit(X_train)
        
        # 3. Compute Summary Metrics
        scores = model.decision_function(X_train)
        summary = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "run_id": run.info.run_id,
            "sample_count": len(X_train),
            "users_profiled": raw_metadata["unique_users"],
            "mean_anomaly_score": float(scores.mean()),
            "score_std": float(scores.std()),
            "status": "SUCCESS_PROMOTED"
        }
        
        # 4. Log to MLflow
        mlflow.log_params({"contamination": contamination_rate, "n_estimators": 150})
        mlflow.log_metrics({"mean_score": summary["mean_anomaly_score"], "samples": summary["sample_count"]})
        mlflow.sklearn.log_model(model, "pam_anomaly_detector", registered_model_name="PAM-Detector")
        
        # 5. Push Summary to Elasticsearch & Alerts
        index_summary_to_elasticsearch(summary)
        send_slack_summary_notification(summary)

    return summary
```