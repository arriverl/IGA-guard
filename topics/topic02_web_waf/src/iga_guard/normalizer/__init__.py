"""Payload normalization pipeline."""

from __future__ import annotations

from iga_guard.models import NormalizedPayload
from iga_guard.normalizer.ast_restore import restore_ast
from iga_guard.normalizer.decoder import decode_payload


def normalize_payload(
    raw: str,
    field_name: str = "",
    location: str = "query",
    max_decode_rounds: int = 5,
) -> NormalizedPayload:
    decoded, decode_chain = decode_payload(raw, max_rounds=max_decode_rounds)
    restored, ast_chain = restore_ast(decoded)
    return NormalizedPayload(
        raw_payload=raw,
        normalized_payload=restored,
        decode_chain=decode_chain + ast_chain,
        field_name=field_name,
        location=location,
    )
