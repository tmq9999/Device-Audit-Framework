"""Context-aware redaction for evidence written to disk."""

from __future__ import annotations

import re
from collections.abc import Iterable

_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_PHONE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:\+\d[\d().\- ]{7,}\d|\(\d{3}\)[ -]?\d{3}[ -]?\d{4}|\d{3}[ -.]\d{3}[ -.]\d{4})(?![A-Za-z0-9])"
)
_LABELED_IDENTIFIER_PATTERN = re.compile(
    r"(?i)(\b(?:m?imei(?:s)?|m?imsi|m?iccid|m?msisdn|m?subscriber(?:[ _-]?id)?|m?sim(?:[ _-]?serial)?|"
    r"android[ _-]?id|gaid|advertising[ _-]?id|line1(?:[ _-]?number)?|device[ _-]?id|"
    r"phone(?:[ _-]?number)?|serial(?:[ _-]?(?:no|number))?)\b\s*[:=]?\s*)"
    r"([A-Za-z0-9._:+-]{6,})"
)
_SENSITIVE_PROPERTY_PATTERN = re.compile(
    r"(?im)(^\[[^\]\r\n]*(?:serial|imei|imsi|iccid|msisdn|subscriber|sim[ _.-]?serial|"
    r"android[ _.-]?id|gaid|advertising[ _.-]?id|email|phone|line1|device[ _.-]?id)[^\]\r\n]*\]:\s*\[)([^\]\r\n]*)(\])"
)
_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?im)(^[^=\r\n]*(?:serial|imei|imsi|iccid|msisdn|subscriber|sim[ _.-]?serial|"
    r"android[ _.-]?id|gaid|advertising[ _.-]?id|email|phone|line1|device[ _.-]?id)[^=\r\n]*=)([^\r\n]*)$"
)


def redact_text(text: str, sensitive_values: Iterable[str] = ()) -> str:
    """Remove common sensitive identifiers while preserving unrelated numbers."""

    property_redacted = _SENSITIVE_PROPERTY_PATTERN.sub(r"\1<redacted>\3", text)
    assignment_redacted = _SENSITIVE_ASSIGNMENT_PATTERN.sub(r"\1<redacted>", property_redacted)
    without_emails = _EMAIL_PATTERN.sub("<redacted-email>", assignment_redacted)
    without_uuids = _UUID_PATTERN.sub("<redacted-uuid>", without_emails)
    without_phone_numbers = _PHONE_PATTERN.sub("<redacted-phone>", without_uuids)
    redacted = _LABELED_IDENTIFIER_PATTERN.sub(r"\1<redacted>", without_phone_numbers)
    for value in sorted({value for value in sensitive_values if value}, key=len, reverse=True):
        redacted = redacted.replace(value, "<redacted-serial>")
    return redacted


def redact_arguments(arguments: Iterable[str], serial: str | None = None) -> list[str]:
    """Return command arguments safe for persistence in evidence metadata."""

    redacted: list[str] = []
    for argument in arguments:
        value = "<redacted-serial>" if serial and argument == serial else redact_text(argument)
        redacted.append(value)
    return redacted
