import pytest
from src.attack_engine.executor import AttackExecutor


@pytest.mark.asyncio
def test_executor_raises_on_missing_dataset():
    executor = AttackExecutor(model_name="ollama/qwen3")
    with pytest.raises(FileNotFoundError):
        await executor.run("data/raw/nonexistent.csv")
