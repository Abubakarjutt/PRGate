"""PR comment commands. This release has one: `/gate override <40-hex head sha> <reason>`."""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .config import Config
from .models import Outcome, Verdict
from .report import LIMIT, TITLE_MAX, escape, render

REASON_MAX = 300
_OVERRIDE = re.compile(r"/gate override ([0-9a-f]{40})[ \t]+(\S.*)")
_OVERRIDABLE = (Outcome.BLOCKED, Outcome.PERSON)


@dataclass(frozen=True)
class Command:
    kind: str  # only "override" in this release
    sha: str
    reason: str | None


def parse_command(body: object) -> Command | None:
    """The command on the comment's first line, or None. Only the full head SHA is accepted."""
    if not isinstance(body, str):
        return None
    first = body.split("\n", 1)[0][:2000].rstrip("\r").strip(" \t")
    m = _OVERRIDE.fullmatch(first)
    if not m:
        return None
    reason = m[2].strip()
    return Command("override", m[1], reason) if _has_text(reason) else None


def _has_text(reason: object) -> bool:
    """A reason must hold at least one letter or digit: not blank, zero-width or punctuation only."""
    return isinstance(reason, str) and any(ch.isalnum() for ch in reason)


def _login(value: str) -> str:
    return value.strip().lower()


def authorise(cmd: Command, sender: str, sender_is_bot: bool, pr_author: str | None, head_sha: str,
              config: Config, verdict: Verdict) -> tuple[bool, str]:
    """(allowed, why). The caller also checks: first run attempt, open PR, base is the default branch."""
    if cmd.kind != "override":
        return False, f"unknown command {cmd.kind!r}"
    if not config.valid:
        return False, "the policy config is invalid, so no one can override"
    who = _login(sender)
    if sender_is_bot or who.endswith("[bot]"):
        return False, "bots cannot override"
    if who in config.agent_identities:
        return False, "agent identities cannot override"
    if who not in config.overriders and who not in config.approvers:
        return False, "the sender is not an overrider or approver in the base config"
    if not isinstance(pr_author, str) or not pr_author.strip():
        return False, "the PR author is unknown, so the sender cannot be shown not to be the author"
    if who == _login(pr_author):
        return False, "the PR author cannot override their own PR"
    if cmd.sha != head_sha:
        return False, "the SHA is not the PR's current head"
    if verdict.head_sha != head_sha:
        return False, "the gate's verdict is not for the current head"
    if not _has_text(cmd.reason):
        return False, "an override needs a reason with at least one letter or digit"
    if verdict.outcome not in _OVERRIDABLE:
        return False, "the verdict is already cleared; there is nothing to override"
    return True, "override granted"


def override_report(verdict: Verdict, cmd: Command, sender: str) -> tuple[str, str]:
    """(title, body) for the check that records an override. The original verdict marker is kept."""
    orig_title, orig_body = render(verdict, ())
    title = f"Overridden by {sender[:39]}: {orig_title}"
    title = title.replace("<", "(").replace(">", ")").replace("@", "@​")
    if len(title) > TITLE_MAX:
        title = title[: TITLE_MAX - 1] + "…"
    head = [
        "## Overridden by a person",
        f"`/gate override` by {escape(sender, 100)} on commit `{verdict.head_sha}`.",
        f"**Reason:** {escape(cmd.reason or '', REASON_MAX)}",
        "",
        "The original report follows.",
        "",
    ]
    prefix = "\n".join(head)
    if len(prefix) + len(orig_body) > LIMIT:
        bare = replace(verdict, findings=(), question=None, explanation=None, reasons=verdict.reasons[:1])
        orig_body = render(bare, ())[1]
    return title, prefix + orig_body
