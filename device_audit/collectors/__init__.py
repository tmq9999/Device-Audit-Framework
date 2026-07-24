"""Built-in read-only collectors shipped with the research release."""

from device_audit.collectors.builtin import (
    BUILTIN_COLLECTORS,
    DEFAULT_PACKAGES,
    DISPLAY_COMMANDS,
    MAGISK_COMMANDS,
    PHASE_ONE_COMMANDS,
    ROOT_RUNTIME_COMMANDS,
    RUNTIME_COMMANDS,
    TELEPHONY_COMMANDS,
    normalize_packages,
)

__all__ = [
    "BUILTIN_COLLECTORS",
    "DEFAULT_PACKAGES",
    "DISPLAY_COMMANDS",
    "MAGISK_COMMANDS",
    "PHASE_ONE_COMMANDS",
    "ROOT_RUNTIME_COMMANDS",
    "RUNTIME_COMMANDS",
    "TELEPHONY_COMMANDS",
    "normalize_packages",
]
