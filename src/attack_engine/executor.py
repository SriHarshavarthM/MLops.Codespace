import asyncio
import httpx
from pathlib import Path
from typing import Any, Dict, List
import pandas as pd


class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434", timeout: int = 30):
        self.base_url = base_url
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def generate(self, model: str, prompt: str, temperature: float = 0.2) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": 512,
        }
        response = await self._client.post(endpoint, json=payload)
        response.raise_for_status()
        return response.json()

    async def close(self):
        await self._client.aclose()


class AttackExecutor:
    def __init__(self, model_name: str, temperature: float = 0.2, concurrency: int = 8, client: OllamaClient | None = None):
        self.model_name = model_name
        self.temperature = temperature
        self.concurrency = concurrency
        self.client = client or OllamaClient()

    async def _execute_attack(self, record: Dict[str, Any]) -> Dict[str, Any]:
        prompt_id = record["id"]
        prompt_text = record["adversarial_prompt"]
        result = {
            "id": prompt_id,
            "category": record["category"],
            "prompt": prompt_text,
            "response": None,
            "error": None,
        }

        max_retries = 3
        backoff = 1.0
        for attempt in range(1, max_retries + 1):
            try:
                payload = await self.client.generate(
                    model=self.model_name,
                    prompt=prompt_text,
                    temperature=self.temperature,
                )
                result["response"] = self._extract_text(payload)
                return result
            except httpx.HTTPStatusError as exc:
                result["error"] = f"HTTP {exc.response.status_code}: {exc.response.text}"
            except (httpx.TransportError, asyncio.TimeoutError) as exc:
                result["error"] = str(exc)
            await asyncio.sleep(backoff)
            backoff *= 2

        return result

    def _extract_text(self, payload: Dict[str, Any]) -> str:
        if "choices" in payload and payload["choices"]:
            choice = payload["choices"][0]
            message = choice.get("message", {})
            return message.get("content", "")
        return payload.get("text", "") or ""

    async def run(self, dataset_path: str) -> List[Dict[str, Any]]:
        if not Path(dataset_path).exists():
            raise FileNotFoundError(f"Attack dataset not found at {dataset_path}")

        df = pd.read_csv(dataset_path)
        records = df.to_dict(orient="records")
        semaphore = asyncio.Semaphore(self.concurrency)

        async def guarded(record):
            async with semaphore:
                return await self._execute_attack(record)

        tasks = [guarded(record) for record in records]
        responses = await asyncio.gather(*tasks)
        await self.client.close()
        return responses


async def validate_model(model_name: str, dataset_path: str, temperature: float = 0.2) -> List[Dict[str, Any]]:
    executor = AttackExecutor(model_name=model_name, temperature=temperature)
    return await executor.run(dataset_path)
