"""학습과 런타임에서 공유하는 payload 특징 추출 모듈"""

from __future__ import annotations

import re
from collections.abc import Iterable

SQL_KEYWORDS = [
    "select",
    "union",
    "where",
    "from",
    "insert",
    "update",
    "delete",
    "drop",
    "or",
    "and",
    "sleep",
    "benchmark",
    "information_schema",
]

FEATURE_SCHEMA = [
    "payload_length",
    "special_char_count",
    "special_char_ratio",
    "digit_count",
    "alpha_count",
    "quote_count",
    "double_quote_count",
    "semicolon_count",
    "dash_count",
    "comment_token_count",
    "sql_keyword_count",
    "url_encoding_count",
    "url_encoding_ratio",
    "space_count",
    "operator_count",
    "parenthesis_count",
]

URL_ENCODING_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
WORD_PATTERNS = {
    keyword: re.compile(rf"(?<![a-zA-Z0-9_]){re.escape(keyword)}(?![a-zA-Z0-9_])", re.IGNORECASE)
    for keyword in SQL_KEYWORDS
}


def extract_features(payload: object) -> dict[str, float]:
    text = "" if payload is None else str(payload)
    length = len(text)
    special_count = sum(1 for char in text if not char.isalnum() and not char.isspace())
    url_encoding_count = len(URL_ENCODING_PATTERN.findall(text))

    return {
        "payload_length": float(length),
        "special_char_count": float(special_count),
        "special_char_ratio": _ratio(special_count, length),
        "digit_count": float(sum(1 for char in text if char.isdigit())),
        "alpha_count": float(sum(1 for char in text if char.isalpha())),
        "quote_count": float(text.count("'")),
        "double_quote_count": float(text.count('"')),
        "semicolon_count": float(text.count(";")),
        "dash_count": float(text.count("-")),
        "comment_token_count": float(_count_comment_tokens(text)),
        "sql_keyword_count": float(_count_sql_keywords(text)),
        "url_encoding_count": float(url_encoding_count),
        "url_encoding_ratio": _ratio(url_encoding_count * 3, length),
        "space_count": float(sum(1 for char in text if char.isspace())),
        "operator_count": float(sum(1 for char in text if char in "=<>!+-*/")),
        "parenthesis_count": float(text.count("(") + text.count(")")),
    }


def feature_row(payload: object, schema: Iterable[str] = FEATURE_SCHEMA) -> list[float]:
    features = extract_features(payload)
    return [features[name] for name in schema]


def _ratio(value: int, total: int) -> float:
    if total == 0:
        return 0.0
    return float(value) / float(total)


def _count_comment_tokens(text: str) -> int:
    return text.count("--") + text.count("/*") + text.count("*/") + text.count("#")


def _count_sql_keywords(text: str) -> int:
    return sum(len(pattern.findall(text)) for pattern in WORD_PATTERNS.values())
