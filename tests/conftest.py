from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolated_environment(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A developer's shell may point MICROAUTH_* at a local platform, and
    # MicroAuth() defaults to a journal in the user's state directory; tests
    # must see neither, nor each other's queued usage.
    for name in list(os.environ):
        if name.startswith("MICROAUTH_") and not name.startswith("MICROAUTH_TEST_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("MICROAUTH_JOURNAL_DIR", str(tmp_path_factory.mktemp("journal")))
