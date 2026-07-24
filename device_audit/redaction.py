"""Context-aware redaction for evidence written to disk."""

from __future__ import annotations

import re
from collections.abc import Iterable

_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_MAC_PATTERN = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE)
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PHONE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:\+\d[\d().\- ]{7,}\d|\(\d{3}\)[ -]?\d{3}[ -]?\d{4}|\d{3}[ -.]\d{3}[ -.]\d{4})(?![A-Za-z0-9])"
)
_LABELED_IDENTIFIER_PATTERN = re.compile(
    r"(?i)(\b(?:m?imei(?:s)?|m?imsi|m?iccid|m?msisdn|m?subscriber(?:[ _-]?id)?|m?sim(?:[ _-]?serial)?|"
    r"android[ _-]?id|gaid|advertising[ _-]?id|line1(?:[ _-]?number)?|device[ _-]?id|"
    r"account(?:[ _-]?(?:id|name))?|client(?:[ _-]?(?:id|token))|auth(?:entication)?[ _-]?token|"
    r"access[ _-]?token|phone(?:[ _-]?number)?|serial(?:[ _-]?(?:no|number))?)\b\s*[:=]?\s*)"
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
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{12,}")
_WINDOWS_USER_PATH_PATTERN = re.compile(r"(?i)([A-Z]:\\Users\\)[^\\\r\n\s]+")
_POSIX_USER_PATH_PATTERN = re.compile(r"(?i)(/(?:home|Users)/)[^/\s]+")
_ANDROID_USER_PATH_PATTERN = re.compile(r"(?i)(/(?:data/user|storage/emulated)/)\d+(?=/)")
_ANDROID_PRIVATE_PATH_PATTERN = re.compile(
    r"(?i)(/(?:data/(?:data|user(?:_de)?/\d+)|storage/emulated/\d+/Android/(?:data|obb))/)[A-Za-z0-9_.-]+"
)
_CONTEXTUAL_PHASE4_IDENTIFIER_PATTERN = re.compile(
    r"(?im)(\b(?:battery serial|filesystem uuid|fs uuid|volume id|disk id|audio session(?: id)?|"
    r"binder client(?: id)?|client token)\b\s*[:=]\s*)([^\s,;]+)"
)
_CONTEXTUAL_PROCESS_IDENTIFIER_PATTERN = re.compile(r"(?im)(\b(?:pid|uid)\b\s*:\s*)(\d+)")


def redact_text(text: str, sensitive_values: Iterable[str] = ()) -> str:
    """Remove common sensitive identifiers while preserving unrelated numbers."""

    property_redacted = _SENSITIVE_PROPERTY_PATTERN.sub(r"\1<redacted>\3", text)
    assignment_redacted = _SENSITIVE_ASSIGNMENT_PATTERN.sub(r"\1<redacted>", property_redacted)
    without_emails = _EMAIL_PATTERN.sub("<redacted-email>", assignment_redacted)
    without_uuids = _UUID_PATTERN.sub("<redacted-uuid>", without_emails)
    without_macs = _MAC_PATTERN.sub("<redacted-mac>", without_uuids)
    without_ips = _IPV4_PATTERN.sub("<redacted-ip>", without_macs)
    without_phone_numbers = _PHONE_PATTERN.sub("<redacted-phone>", without_ips)
    without_bearer_tokens = _BEARER_TOKEN_PATTERN.sub(r"\1<redacted-token>", without_phone_numbers)
    without_windows_users = _WINDOWS_USER_PATH_PATTERN.sub(r"\1<redacted-user>", without_bearer_tokens)
    without_posix_users = _POSIX_USER_PATH_PATTERN.sub(r"\1<redacted-user>", without_windows_users)
    without_private_paths = _ANDROID_PRIVATE_PATH_PATTERN.sub(r"\1<redacted-package>", without_posix_users)
    without_android_users = _ANDROID_USER_PATH_PATTERN.sub(r"\1<redacted-user>", without_private_paths)
    without_phase4_ids = _CONTEXTUAL_PHASE4_IDENTIFIER_PATTERN.sub(r"\1<redacted>", without_android_users)
    without_process_ids = _CONTEXTUAL_PROCESS_IDENTIFIER_PATTERN.sub(r"\1<redacted>", without_phase4_ids)
    redacted = _LABELED_IDENTIFIER_PATTERN.sub(r"\1<redacted>", without_process_ids)
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
