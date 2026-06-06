"""HttpParamsDataset 기반 Random Forest 학습 스크립트"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from src.training.features import FEATURE_SCHEMA, feature_row

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
ARTIFACTS_DIR = ROOT_DIR / "artifacts"
DATASET_PATH = DATA_DIR / "payload_full.csv"

PAYLOAD_COLUMNS = ["payload", "Payload", "value", "Value", "content", "Content", "param", "Parameter"]
ATTACK_TYPE_COLUMN = "attack_type"


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError("data/payload_full.csv 파일이 없습니다")

    df = pd.read_csv(DATASET_PATH)
    payload_col = _find_column(df, PAYLOAD_COLUMNS)

    if ATTACK_TYPE_COLUMN not in df.columns:
        raise RuntimeError("payload_full.csv에 attack_type 컬럼이 없습니다")

    attack_type = df[ATTACK_TYPE_COLUMN].astype(str).str.lower()
    filtered = df[attack_type.isin(["norm", "sqli"])].copy()
    filtered["target"] = (filtered[ATTACK_TYPE_COLUMN].astype(str).str.lower() == "sqli").astype(int)

    if filtered.empty:
        raise RuntimeError("norm/sqli attack_type을 가진 학습 데이터가 없습니다")

    x = [feature_row(payload) for payload in filtered[payload_col]]
    y = filtered["target"].to_numpy()

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    model.fit(x_train, y_train)

    preds = model.predict(x_test)
    report = classification_report(y_test, preds, target_names=["normal", "sqli"], output_dict=True)
    matrix = confusion_matrix(y_test, preds).tolist()

    ARTIFACTS_DIR.mkdir(exist_ok=True)
    joblib.dump(model, ARTIFACTS_DIR / "rf_model.pkl")
    (ARTIFACTS_DIR / "feature_schema.json").write_text(
        json.dumps(FEATURE_SCHEMA, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (ARTIFACTS_DIR / "metrics.json").write_text(
        json.dumps({"classification_report": report, "confusion_matrix": matrix}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"데이터셋: {DATASET_PATH}")
    print(f"정상 샘플 수: {(filtered['target'] == 0).sum()}")
    print(f"SQLi 샘플 수: {(filtered['target'] == 1).sum()}")
    print(f"학습 샘플 수: {len(x_train)}")
    print(f"테스트 샘플 수: {len(x_test)}")
    print(classification_report(y_test, preds, target_names=["normal", "sqli"]))
    print("모델 저장: artifacts/rf_model.pkl")

def _find_column(df: pd.DataFrame, candidates: list[str]) -> str:
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    raise RuntimeError(f"필요한 컬럼을 찾지 못했습니다. 후보={candidates}, 실제={list(df.columns)}")


if __name__ == "__main__":
    main()
