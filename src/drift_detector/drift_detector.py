import json
from typing import Dict


def compare_security_scores(current_metrics: Dict[str, float], baseline_metrics: Dict[str, float], threshold_drop: float = 10.0) -> Dict[str, any]:
    current_score = current_metrics.get("security_trust_score", 0.0)
    baseline_score = baseline_metrics.get("security_trust_score", 0.0)
    drop = baseline_score - current_score
    alert = False
    details = {
        "baseline_score": baseline_score,
        "current_score": current_score,
        "drop": round(drop, 2),
        "threshold_drop": threshold_drop,
    }
    if drop >= threshold_drop:
        alert = True
        details["message"] = (
            f"Security drift detected: score dropped from {baseline_score} to {current_score}."
        )
    else:
        details["message"] = "No significant security drift detected."

    return {
        "alert": alert,
        "details": details,
    }


def build_alert_payload(current_metrics: Dict[str, float], baseline_metrics: Dict[str, float], model_name: str) -> str:
    payload = {
        "alert_type": "security_drift",
        "model_name": model_name,
        "current_metrics": current_metrics,
        "baseline_metrics": baseline_metrics,
        "title": "RedMind AI Security Drift Alert",
        "description": (
            "Detected a critical drop in the security trust score compared to the baseline run."
        ),
    }
    return json.dumps(payload, indent=2)
