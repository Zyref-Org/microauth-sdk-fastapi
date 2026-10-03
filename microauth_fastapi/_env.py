"""Environment lookup with a ``.env`` fallback.

Real environment variables always win. When a ``MICROAUTH_*`` variable is
not set at all, the value from a ``.env`` file in the working directory is
used instead, so the setup shown in the dashboard works without
python-dotenv or extra server flags. Other variables in the file are ignored.
"""

from __future__ import annotations

import os
from pathlib import Path

_PREFIX = "MICROAUTH_"


def _parse(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        name = name.strip()
        if not sep or not name.startswith(_PREFIX):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            if value.startswith("#"):
                value = ""
            value = value.split(" #", 1)[0].rstrip()
        values[name] = value
    return values


def dotenv_values(directory: str | os.PathLike[str] | None = None) -> dict[str, str]:
    """Return the ``MICROAUTH_*`` entries of ``.env`` in ``directory``."""
    path = Path(directory if directory is not None else os.getcwd()) / ".env"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    return _parse(text)


def getenv(name: str, default: str | None = None) -> str | None:
    if name in os.environ:
        return os.environ[name]
    return dotenv_values().get(name, default)


def from_dotenv(name: str) -> bool:
    """Whether ``getenv(name)`` would come from ``.env`` rather than the environment."""
    return name not in os.environ and name in dotenv_values()
