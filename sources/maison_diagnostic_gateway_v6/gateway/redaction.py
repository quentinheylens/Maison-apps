"""Fail-closed redaction helpers for gateway responses."""

from __future__ import annotations

import re
from typing import Any


SENSITIVE_KEYS = {
    "access_token",
    "address",
    "api_key",
    "authorization",
    "client_secret",
    "coordinates",
    "credential",
    "email",
    "latitude",
    "longitude",
    "password",
    "phone",
    "picture",
    "refresh_token",
    "secret",
    "token",
    "user_id",
    "username",
}
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PRIVATE_IP_RE = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"
)
MAC_RE = re.compile(r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~-]{12,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def compact_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


COMPACT_SENSITIVE_KEYS = {compact_key(item) for item in SENSITIVE_KEYS}


def redact_text(value: str, redact_terms: tuple[str, ...] = ()) -> str:
    substitutions = (
        (JWT_RE, "[redacted-token]"),
        (BEARER_RE, "[redacted-authorization]"),
        (EMAIL_RE, "[redacted-email]"),
        (PRIVATE_IP_RE, "[redacted-private-ip]"),
        (MAC_RE, "[redacted-mac]"),
        (URL_RE, "[redacted-url]"),
    )
    result = value
    for pattern, replacement in substitutions:
        result = pattern.sub(replacement, result)
    for term in redact_terms:
        result = re.sub(re.escape(term), "[redacted-personal]", result, flags=re.IGNORECASE)
    return result


def sanitize(
    value: Any,
    *,
    key: str | None = None,
    redact_terms: tuple[str, ...] = (),
) -> Any:
    """Remove known sensitive fields and signatures from a nested response."""

    if key is not None and compact_key(key) in COMPACT_SENSITIVE_KEYS:
        return "[redacted]"
    if isinstance(value, dict):
        return {
            str(child_key): sanitize(
                child,
                key=str(child_key),
                redact_terms=redact_terms,
            )
            for child_key, child in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item, key=key, redact_terms=redact_terms) for item in value]
    if isinstance(value, str):
        return redact_text(value, redact_terms)
    return value
