import pytest
from fastapi.testclient import TestClient
from src.attack_engine.executor import AttackExecutor, is_huggingface_model_reference, is_kaggle_dataset_reference
from app.backend.main import app


@pytest.mark.asyncio
async def test_executor_raises_on_missing_dataset():
    executor = AttackExecutor(model_name="ollama/qwen3")
    with pytest.raises(FileNotFoundError):
        await executor.run("data/raw/nonexistent.csv")


def test_huggingface_model_detection():
    assert is_huggingface_model_reference("hf://google/flan-t5-small") is True
    assert is_huggingface_model_reference("ollama/qwen3") is False


def test_kaggle_dataset_detection():
    assert is_kaggle_dataset_reference("username/dataset-name") is True
    assert is_kaggle_dataset_reference("data/raw/attack_vectors.csv") is False


def test_healthz_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_models_endpoint_returns_config():
    with TestClient(app) as client:
        response = client.get("/api/v1/models")
        assert response.status_code == 200
        payload = response.json()
        assert "models" in payload
        assert payload["models"]
