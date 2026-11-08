import shutil

import pytest

_real_which = shutil.which


@pytest.fixture(autouse=True)
def gh_on_path(monkeypatch):
    """Setup tests drive a fake gh, so they must not depend on the real binary being installed."""
    monkeypatch.setattr(shutil, "which", lambda name, *a, **k: "/usr/bin/gh" if name == "gh" else _real_which(name, *a, **k))
