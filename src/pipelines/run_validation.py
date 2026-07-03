import argparse
import json
from pathlib import Path
from typing import Any

from src.attack_engine.executor import validate_model
from src.evaluator.judge import evaluate_attack_results
from src.evaluator.mlflow_tracking import log_validation_run, get_latest_run
from src.drift_detector.drift_detector import compare_security_scores, build_alert_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run RedMind AI security validation pipeline")
    parser.add_argument("--model-name", required=True, help="Target model identifier for validation")
    parser.add_argument("--dataset-path", default="data/raw/attack_vectors.csv", help="Path to the attack dataset CSV")
    parser.add_argument("--temperature", type=float, default=0.2, help="Inference temperature for model queries")
    parser.add_argument("--baseline-score", type=float, default=90.0, help="Baseline security trust score for drift detection")
    parser.add_argument("--threshold-drop", type=float, default=10.0, help="Alert threshold for score drift")
    parser.add_argument("--dataset-version", default="v1", help="Dataset version metadata")
    parser.add_argument("--output", default="data/processed/validation_report.json", help="Validation report output path")
    return parser.parse_args()


def write_report(payload: Any, path: str):
    report_path = Path(path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    print(f"Wrote validation report to {report_path}")


def run_validation(args: argparse.Namespace) -> dict:
    raw_results = Path(args.dataset_path)
    if not raw_results.exists():
        raise FileNotFoundError(f"Attack dataset not found: {args.dataset_path}")

    results = asyncio.run(validate_model(model_name=args.model_name, dataset_path=args.dataset_path, temperature=args.temperature))
    evaluation = evaluate_attack_results(results)
    metrics = evaluation["metrics"]

    run_id = log_validation_run(
        params={
            "model_name": args.model_name,
            "temperature": args.temperature,
            "dataset_version": args.dataset_version,
        },
        metrics=metrics,
    )

    baseline = get_latest_run()
    baseline_score = float(baseline["metrics.security_trust_score"]) if baseline is not None else args.baseline_score
    drift_result = compare_security_scores(metrics, {"security_trust_score": baseline_score}, threshold_drop=args.threshold_drop)
    alert_payload = None
    if drift_result["alert"]:
        alert_payload = build_alert_payload(metrics, {"security_trust_score": baseline_score}, args.model_name)

    report = {
        "run_id": run_id,
        "model_name": args.model_name,
        "dataset_path": args.dataset_path,
        "dataset_version": args.dataset_version,
        "metrics": metrics,
        "drift": drift_result,
        "alert_payload": alert_payload,
        "results_count": len(evaluation["scored_results"]),
    }
    write_report(report, args.output)
    return report


if __name__ == "__main__":
    arguments = parse_args()
    run_validation(arguments)
