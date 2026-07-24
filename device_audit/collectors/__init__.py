"""Built-in read-only collectors shipped with the research release."""

from device_audit.collectors.builtin import (
    BUILTIN_COLLECTORS,
    CAMERA_COMMANDS,
    DEFAULT_PACKAGES,
    DISPLAY_COMMANDS,
    HAL_COMMANDS,
    MAGISK_COMMANDS,
    PHASE_ONE_COMMANDS,
    ROOT_RUNTIME_COMMANDS,
    RUNTIME_COMMANDS,
    SENSOR_COMMANDS,
    TELEPHONY_COMMANDS,
    normalize_packages,
)

__all__ = [
    "BUILTIN_COLLECTORS",
    "CAMERA_COMMANDS",
    "DEFAULT_PACKAGES",
    "DISPLAY_COMMANDS",
    "HAL_COMMANDS",
    "MAGISK_COMMANDS",
    "PHASE_ONE_COMMANDS",
    "ROOT_RUNTIME_COMMANDS",
    "RUNTIME_COMMANDS",
    "SENSOR_COMMANDS",
    "TELEPHONY_COMMANDS",
    "normalize_packages",
]
