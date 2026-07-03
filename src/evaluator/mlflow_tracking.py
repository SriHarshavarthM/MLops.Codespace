import mlflow
import os
from typing import Dict, Any


MLFLOW_TRACKING_URI = os.getenv("MLFLOW_TRACKING_URI", "./mlruns")
EXPERIMENT_NAME = os.getenv("MLFLOW_EXPERIMENT", "redmind_security_validation")


def initialize_mlflow():
    mlflow.set_tracking_uri(MLFLOW_TRACKING_URI)
    mlflow.set_experiment(EXPERIMENT_NAME)


def log_validation_run(params: Dict[str, Any], metrics: Dict[str, float], artifacts: Dict[str, str] | None = None):
    initialize_mlflow()
    with mlflow.start_run() as run:
        for key, value in params.items():
            mlflow.log_param(key, value)
        for key, value in metrics.items():
            mlflow.log_metric(key, float(value))
        if artifacts:
            for key, path in artifacts.items():
                if path:
                    mlflow.log_artifact(path, artifact_path=key)
        return run.info.run_id


def get_latest_run(experiment_name: str | None = None):
    initialize_mlflow()
    exp = mlflow.get_experiment_by_name(experiment_name or EXPERIMENT_NAME)
    if not exp:
        return None
    runs = mlflow.search_runs(exp.experiment_id, order_by=["metrics.security_trust_score DESC"], max_results=1)
    return runs.iloc[0] if not runs.empty else None
