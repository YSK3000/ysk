"""Platform selection."""
from __future__ import annotations

import sys
from typing import Optional

from kekkai.platforms.base import Platform

_instance: Optional[Platform] = None


def get_platform() -> Platform:
    global _instance
    if _instance is None:
        if sys.platform == "darwin":
            from kekkai.platforms.macos import MacOSPlatform
            _instance = MacOSPlatform()
        elif sys.platform.startswith("linux"):
            from kekkai.platforms.linux import LinuxPlatform
            _instance = LinuxPlatform()
        else:
            _instance = Platform()
    return _instance
