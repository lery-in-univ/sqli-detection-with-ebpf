"""Qwen2.5-0.5B zero-shot 기반 2차 SQL Injection 검증 모듈"""

from __future__ import annotations

import asyncio

MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"


class QwenZeroShotVerifier:
    def __init__(self, timeout_seconds: float = 60.0) -> None:
        self.timeout_seconds = timeout_seconds
        self._tokenizer = None
        self._model = None

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
        tokenizer, model = self._get_model()
        prompt = self._build_prompt(tokenizer, login_id, password)
        normal_score = self._label_loss(tokenizer, model, prompt, "normal")
        sqli_score = self._label_loss(tokenizer, model, prompt, "sqli")
        label = "sqli" if sqli_score < normal_score else "normal"
        print(
            "[monitor] LLM label scores "
            f"normal={normal_score:.4f} sqli={sqli_score:.4f} selected={label}"
        )
        return label

    def _build_prompt(self, tokenizer, login_id: str, password: str) -> str:
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a strict SQL injection classifier. "
                    "Choose exactly one label: normal or sqli. "
                    "Inputs with OR 1=1, quoted tautologies, SQL comments, UNION SELECT, "
                    "or syntax-breaking quotes are sqli."
                ),
            },
            {"role": "user", "content": "id=alice\npassword=hello123\nlabel:"},
            {"role": "assistant", "content": "normal"},
            {"role": "user", "content": "id=admin OR 1=1\npassword=x\nlabel:"},
            {"role": "assistant", "content": "sqli"},
            {"role": "user", "content": "id=bob\npassword=' OR '1'='1\nlabel:"},
            {"role": "assistant", "content": "sqli"},
            {
                "role": "user",
                "content": (
                    f"id={login_id}\n"
                    f"password={password}\n"
                    "label:"
                ),
            },
        ]
        if getattr(tokenizer, "chat_template", None):
            return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)

        return (
            "Choose exactly one label: normal or sqli.\n"
            "id=alice\npassword=hello123\nlabel: normal\n\n"
            "id=admin OR 1=1\npassword=x\nlabel: sqli\n\n"
            "id=bob\npassword=' OR '1'='1\nlabel: sqli\n\n"
            f"id={login_id}\n"
            f"password={password}\n"
            "label:"
        )

    def _label_loss(self, tokenizer, model, prompt: str, label: str) -> float:
        import torch
        import torch.nn.functional as functional

        prompt_ids = tokenizer(prompt, return_tensors="pt").input_ids.to(model.device)
        label_ids = tokenizer(label, add_special_tokens=False, return_tensors="pt").input_ids.to(model.device)
        input_ids = torch.cat([prompt_ids, label_ids], dim=1)

        with torch.no_grad():
            logits = model(input_ids).logits

        start = prompt_ids.shape[1]
        losses = []
        for offset in range(label_ids.shape[1]):
            token_position = start + offset
            token_id = input_ids[0, token_position]
            token_logits = logits[0, token_position - 1]
            loss = functional.cross_entropy(token_logits.unsqueeze(0), token_id.unsqueeze(0))
            losses.append(loss.item())

        return sum(losses) / len(losses)

    def _get_model(self):
        if self._model is None or self._tokenizer is None:
            from transformers import AutoModelForCausalLM, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
            self._model = AutoModelForCausalLM.from_pretrained(MODEL_NAME, torch_dtype="auto")
            self._model.eval()
        return self._tokenizer, self._model
