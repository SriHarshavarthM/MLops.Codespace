from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
import asyncio
from src.attack_engine.executor import validate_model
from src.evaluator.judge import evaluate_attack_results
from src.evaluator.mlflow_tracking import log_validation_run
from src.drift_detector.drift_detector import compare_security_scores, build_alert_payload
import os


app = FastAPI(title="RedMind AI Security Validation API")

security_score_gauge = Gauge("redmind_security_score", "Aggregated security trust score for the last validation run", ["model"])
attack_success_counter = Counter("redmind_attack_success_total", "Count of successful adversarial attacks", ["category", "model"])
validation_runs_counter = Counter("redmind_validation_runs_total", "Number of security validation runs executed", ["model"])


@app.post("/api/v1/validate")
async def validate_endpoint(payload: dict):
    model_name = payload.get("model_name")
    dataset_path = payload.get("dataset_path", "data/raw/attack_vectors.csv")
    temperature = float(payload.get("temperature", 0.2))
    baseline_score = float(payload.get("baseline_score", 90.0))
    threshold_drop = float(payload.get("threshold_drop", 10.0))

    if not model_name:
        raise HTTPException(status_code=400, detail="model_name is required")

    try:
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

        drift_result = compare_security_scores(metrics, {"security_trust_score": baseline_score}, threshold_drop=threshold_drop)
        alert_payload = None
        if drift_result["alert"]:
            alert_payload = build_alert_payload(metrics, {"security_trust_score": baseline_score}, model_name)

        return {
            "run_id": run_id,
            "metrics": metrics,
            "drift": drift_result,
            "alert_payload": alert_payload,
            "results_count": len(raw_results),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/v1/metrics")
def metrics_endpoint():
    data = generate_latest()
    return PlainTextResponse(data.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


@app.get("/api/v1/healthz")
def healthz():
    return {"status": "ok"}
