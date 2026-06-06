"""Qwen2.5-0.5B zero-shot 기반 2차 SQL Injection 검증 모듈"""

from __future__ import annotations

import asyncio

MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"


class QwenZeroShotVerifier:
    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds
        self._pipeline = None

    async def is_sqli(self, login_id: str, password: str) -> bool:
        try:
            label = await asyncio.wait_for(
                asyncio.to_thread(self._classify_sync, login_id, password),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            print("[monitor] LLM timeout 발생, normal 처리")
            return False
        except Exception as exc:
            print(f"[monitor] LLM 검증 실패, normal 처리: {exc}")
            return False

        if label == "sqli":
            return True
        if label == "normal":
            return False

        print(f"[monitor] LLM 출력 파싱 실패, normal 처리: {label}")
        return False

    def _classify_sync(self, login_id: str, password: str) -> str:
        pipeline = self._get_pipeline()
        prompt = (
            "Classify the following login input as either normal or sqli.\n"
            "Return only one token: normal or sqli.\n\n"
            f"id: {login_id}\n"
            f"password: {password}\n"
        )
        result = pipeline(
            prompt,
            max_new_tokens=3,
            do_sample=False,
            temperature=0.0,
            return_full_text=False,
        )
        text = result[0]["generated_text"].strip().lower()
        if "sqli" in text:
            return "sqli"
        if "normal" in text:
            return "normal"
        return text

    def _get_pipeline(self):
        if self._pipeline is None:
            from transformers import pipeline

            self._pipeline = pipeline(
                "text-generation",
                model=MODEL_NAME,
                torch_dtype="auto",
            )
        return self._pipeline
