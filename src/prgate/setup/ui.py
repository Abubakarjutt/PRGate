"""Prompting. `secret` never echoes its answer."""
from __future__ import annotations

import getpass
from typing import Protocol


class Prompter(Protocol):
    def say(self, text: str) -> None: ...
    def ask(self, q: str, default: str | None = None) -> str: ...
    def secret(self, q: str) -> str: ...
    def confirm(self, q: str, default: bool) -> bool: ...
    def choose(self, q: str, options: list[str], default: str) -> str: ...


class TerminalPrompter:
    def say(self, text: str) -> None:
        print(text, flush=True)

    def ask(self, q: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        answer = input(f"{q}{suffix}: ").strip()
        return answer or (default or "")

    def secret(self, q: str) -> str:
        return getpass.getpass(f"{q}: ")

    def confirm(self, q: str, default: bool) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            answer = input(f"{q} [{hint}]: ").strip().lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False

    def choose(self, q: str, options: list[str], default: str) -> str:
        self.say(q)
        for i, o in enumerate(options, 1):
            self.say(f"  {i}. {o}")
        while True:
            answer = input(f"Choice [{default}]: ").strip()
            if not answer:
                return default
            if answer in options:
                return answer
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return options[int(answer) - 1]
