"""Random Forest 기반 1차 SQL Injection 탐지 모듈"""

from __future__ import annotations

import json
from pathlib import Path

import joblib

from src.training.features import FEATURE_SCHEMA, feature_row

ROOT_DIR = Path(__file__).resolve().parents[2]


class RandomForestDetector:
    def __init__(self, threshold: float = 0.7) -> None:
        self.threshold = threshold
        self.model = None
        self.schema = FEATURE_SCHEMA
        self._load()

    @property
    def ready(self) -> bool:
        return self.model is not None

    def is_sqli(self, payload: str) -> tuple[bool, float]:
        if self.model is None:
            print("[monitor] RF 모델이 없어 normal 처리")
            return False, 0.0

        row = [feature_row(payload, self.schema)]
        probability = float(self.model.predict_proba(row)[0][1])
        return probability >= self.threshold, probability

    def is_login_sqli(self, login_id: str, password: str) -> tuple[bool, float]:
        id_result, id_probability = self.is_sqli(login_id)
        password_result, password_probability = self.is_sqli(password)
        return id_result or password_result, max(id_probability, password_probability)

    def _load(self) -> None:
        model_path = ROOT_DIR / "artifacts" / "rf_model.pkl"
        schema_path = ROOT_DIR / "artifacts" / "feature_schema.json"

        if not model_path.exists():
            return

        self.model = joblib.load(model_path)
        if schema_path.exists():
            self.schema = json.loads(schema_path.read_text(encoding="utf-8"))
