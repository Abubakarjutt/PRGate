from __future__ import annotations

from .base import LanguagePlugin, TestFacts
from .python import PythonPlugin

PLUGINS: tuple[LanguagePlugin, ...] = (PythonPlugin(),)


def get_plugin(path: str) -> LanguagePlugin | None:
    return next((p for p in PLUGINS if p.handles(path)), None)


__all__ = ["LanguagePlugin", "TestFacts", "PLUGINS", "get_plugin"]
