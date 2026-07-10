import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, generate_latest

from src.attack_engine.executor import validate_model
from src.drift_detector.drift_detector import build_alert_payload, compare_security_scores
from src.evaluator.judge import evaluate_attack_results
from src.evaluator.mlflow_tracking import log_validation_run

try:
    import yaml
except ImportError:  # pragma: no cover - fallback for lightweight environments
    yaml = None


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("redmind.api")

ROOT_DIR = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT_DIR / "config"
DATA_DIR = ROOT_DIR / "data"

app = FastAPI(title="RedMind AI Security Validation API")

security_score_gauge = Gauge(
    "redmind_security_score",
    "Aggregated security trust score for the last validation run",
    ["model"],
)
attack_success_counter = Counter(
    "redmind_attack_success_total",
    "Count of successful adversarial attacks",
    ["category", "model"],
)
validation_runs_counter = Counter(
    "redmind_validation_runs_total",
    "Number of security validation runs executed",
    ["model"],
)


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _load_yaml_config(path: Path) -> dict[str, Any]:
    if yaml is None:
        return {}
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _build_model_catalog() -> list[dict[str, Any]]:
    config = _load_yaml_config(CONFIG_DIR / "model_endpoints.yaml")
    models = config.get("models", {}) or {}
    catalog = []
    for key, payload in models.items():
        if isinstance(payload, dict):
            catalog.append(
                {
                    "id": key,
                    "display_name": payload.get("display_name", key),
                    "api_model": payload.get("api_model", key),
                    "endpoint": payload.get("endpoint"),
                }
            )
    return catalog


def _build_scenario_catalog() -> list[dict[str, Any]]:
    config = _load_yaml_config(CONFIG_DIR / "attack_scenarios.yaml")
    scenarios = config.get("attack_scenarios", {}) or {}
    catalog = []
    for key, payload in scenarios.items():
        if isinstance(payload, dict):
            catalog.append(
                {
                    "id": key,
                    "description": payload.get("description", ""),
                    "severity": payload.get("severity", "unknown"),
                    "examples": payload.get("examples", []),
                }
            )
    return catalog


async def run_validation_pipeline(payload: dict[str, Any]) -> dict[str, Any]:
    model_name = payload.get("model_name")
    dataset_path = payload.get("dataset_path", "data/raw/attack_vectors.csv")
    temperature = _coerce_float(payload.get("temperature"), 0.2)
    baseline_score = _coerce_float(payload.get("baseline_score"), 90.0)
    threshold_drop = _coerce_float(payload.get("threshold_drop"), 10.0)

    if not model_name:
        raise ValueError("model_name is required")

    logger.info("Starting validation for model %s using %s", model_name, dataset_path)
    raw_results = await validate_model(model_name=model_name, dataset_path=dataset_path, temperature=temperature)
    evaluation = evaluate_attack_results(raw_results)
    metrics = evaluation["metrics"]

    for item in evaluation["scored_results"]:
        if item["attack_success"] > 0.0:
            attack_success_counter.labels(category=item["category"], model=model_name).inc()

    security_score_gauge.labels(model=model_name).set(metrics["security_trust_score"])
    validation_runs_counter.labels(model=model_name).inc()

    run_id = log_validation_run(
        params={
            "model_name": model_name,
            "temperature": temperature,
            "dataset_version": payload.get("dataset_version", "v1"),
        },
        metrics=metrics,
    )

    drift_result = compare_security_scores(
        metrics,
        {"security_trust_score": baseline_score},
        threshold_drop=threshold_drop,
    )
    alert_payload = None
    if drift_result["alert"]:
        alert_payload = build_alert_payload(metrics, {"security_trust_score": baseline_score}, model_name)

    return {
        "run_id": run_id,
        "metrics": metrics,
        "drift": drift_result,
        "alert_payload": alert_payload,
        "results_count": len(raw_results),
        "dataset_path": dataset_path,
        "model_name": model_name,
    }


@app.post("/api/v1/validate")
async def validate_endpoint(payload: dict[str, Any]):
    try:
        return await run_validation_pipeline(payload)
    except ValueError as exc:
        logger.warning("Rejected validation request: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        logger.warning("Validation input not found: %s", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.exception("Validation pipeline failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/v1/models")
def models_endpoint():
    return {"models": _build_model_catalog(), "count": len(_build_model_catalog())}


@app.get("/api/v1/scenarios")
def scenarios_endpoint():
    return {"scenarios": _build_scenario_catalog(), "count": len(_build_scenario_catalog())}


@app.get("/api/v1/status")
def status_endpoint():
    dataset_path = DATA_DIR / "raw" / "attack_vectors.csv"
    dataset_exists = dataset_path.exists()
    models = _build_model_catalog()
    scenarios = _build_scenario_catalog()
    return {
        "status": "ready" if dataset_exists and models else "degraded",
        "dataset_exists": dataset_exists,
        "dataset_path": str(dataset_path),
        "models_count": len(models),
        "scenarios_count": len(scenarios),
        "metrics_endpoint": "/api/v1/metrics",
    }


@app.get("/api/v1/metrics")
def metrics_endpoint():
    data = generate_latest()
    return PlainTextResponse(data.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/healthz")
def healthz():
    return {"status": "ok"}
