"""Where KEKKAI keeps its state. Works under sudo (keeps the invoking user's home)."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


def invoking_user_home() -> Path:
    """Home of the real user, even when running via sudo (sensor mode)."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except (KeyError, ImportError):
            pass
    return Path.home()


def data_dir() -> Path:
    env = os.environ.get("KEKKAI_HOME")
    if env:
        p = Path(env).expanduser()
    elif sys.platform == "darwin":
        p = invoking_user_home() / "Library" / "Application Support" / "KEKKAI"
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg and not os.environ.get("SUDO_USER") else invoking_user_home() / ".local" / "share"
        p = base / "kekkai"
    ensure_dir(p)
    return p


def sub(*parts: str) -> Path:
    p = data_dir().joinpath(*parts)
    ensure_dir(p.parent)
    return p


def ensure_dir(p: Path) -> None:
    if not p.exists():
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        chown_to_invoker(p)


def chown_to_invoker(p: Path) -> None:
    """Files created by `sudo kekkai sensor` must stay readable by the normal user."""
    uid: Optional[str] = os.environ.get("SUDO_UID")
    gid: Optional[str] = os.environ.get("SUDO_GID")
    if uid and gid and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            os.chown(str(p), int(uid), int(gid))
        except (OSError, ValueError):
            pass


def web_dir() -> Path:
    return Path(__file__).resolve().parent / "web"
