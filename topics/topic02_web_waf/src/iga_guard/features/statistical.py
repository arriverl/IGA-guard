"""Statistical payload features."""

from __future__ import annotations

import math
import re
from collections import Counter


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def extract_statistical(text: str) -> dict[str, float]:
    length = max(len(text), 1)
    digits = sum(c.isdigit() for c in text)
    specials = sum(not c.isalnum() for c in text)
    encoded_ratio = text.count("%") / length
    return {
        "length": float(length),
        "digit_ratio": digits / length,
        "special_ratio": specials / length,
        "entropy": shannon_entropy(text),
        "paren_count": float(text.count("(") + text.count(")")),
        "encoded_ratio": encoded_ratio,
        "upper_ratio": sum(c.isupper() for c in text) / length,
    }
