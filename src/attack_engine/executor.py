import asyncio
import os
import re
from pathlib import Path
from typing import Any, Dict, List

import httpx
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


class HuggingFaceClient:
    def __init__(self, base_url: str | None = None, timeout: int = 30, api_token: str | None = None):
        self.base_url = base_url or os.getenv("HF_INFERENCE_API_URL", "https://api-inference.huggingface.co/models")
        self.timeout = timeout
        self.api_token = api_token or os.getenv("HF_API_TOKEN")
        self._client = httpx.AsyncClient(timeout=self.timeout)
        self._headers = {"Authorization": f"Bearer {self.api_token}"} if self.api_token else {}

    async def generate(self, model: str, prompt: str, temperature: float = 0.2) -> Dict[str, Any]:
        model_id = model.replace("hf://", "", 1).replace("huggingface://", "", 1)
        payload = {
            "inputs": prompt,
            "parameters": {
                "temperature": temperature,
                "max_new_tokens": 512,
                "return_full_text": False,
            },
        }
        response = await self._client.post(f"{self.base_url}/{model_id}", headers=self._headers, json=payload)
        response.raise_for_status()
        return response.json()

    async def close(self):
        await self._client.aclose()


def is_huggingface_model_reference(model_name: str) -> bool:
    normalized = model_name.strip()
    if normalized.startswith(("hf://", "huggingface://")):
        return True
    if normalized.startswith(("hf:", "hf/")):
        return True
    return bool(re.match(r"^[^/\s]+/[^/\s]+", normalized)) and not normalized.startswith("ollama/")


def is_kaggle_dataset_reference(value: str) -> bool:
    normalized = value.strip()
    if not normalized or normalized.startswith(("/", ".", "http://", "https://")):
        return False
    if Path(normalized).exists():
        return False
    if Path(normalized).suffix:
        return False
    return bool(re.match(r"^[^/\s]+/[^/\s]+$", normalized))


def resolve_dataset_path(dataset_path: str) -> str:
    if Path(dataset_path).exists():
        return dataset_path

    if is_kaggle_dataset_reference(dataset_path):
        try:
            import kagglehub
        except ImportError as exc:
            raise RuntimeError("Install kagglehub to download Kaggle datasets.") from exc

        try:
            download_dir = kagglehub.dataset_download(dataset_path)
        except Exception as exc:
            raise RuntimeError(f"Unable to download Kaggle dataset '{dataset_path}': {exc}") from exc

        csv_files = sorted(Path(download_dir).rglob("*.csv"))
        if csv_files:
            return str(csv_files[0])
        raise FileNotFoundError(f"Kaggle dataset '{dataset_path}' downloaded but no CSV files were found")

    return dataset_path


class AttackExecutor:
    def __init__(self, model_name: str, temperature: float = 0.2, concurrency: int = 8, client: OllamaClient | HuggingFaceClient | None = None):
        self.model_name = model_name
        self.temperature = temperature
        self.concurrency = concurrency
        self.client = client or self._build_client(model_name)

    def _build_client(self, model_name: str) -> OllamaClient | HuggingFaceClient:
        if is_huggingface_model_reference(model_name):
            return HuggingFaceClient()
        return OllamaClient()

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
        for _ in range(1, max_retries + 1):
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
        if isinstance(payload, dict) and "generated_text" in payload:
            return payload["generated_text"]
        if "choices" in payload and payload["choices"]:
            choice = payload["choices"][0]
            message = choice.get("message", {})
            return message.get("content", "")
        return payload.get("text", "") or ""

    async def run(self, dataset_path: str) -> List[Dict[str, Any]]:
        resolved_dataset_path = resolve_dataset_path(dataset_path)
        if not Path(resolved_dataset_path).exists():
            raise FileNotFoundError(f"Attack dataset not found at {resolved_dataset_path}")

        df = pd.read_csv(resolved_dataset_path)
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
