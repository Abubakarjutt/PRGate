"""Report rendering: Verdict -> check-run (title, body), and the inverse from the body's JSON marker."""
from __future__ import annotations

import json
import re

from dataclasses import replace

from .models import CheckResult, Finding, Outcome, RunStatus, Severity, Verdict

EXPERIMENTAL_LINE = "prgate is experimental and report-only: this check never blocks a merge."
LIMIT = 65000
TITLE_MAX = 120
_FIELD_MAX = 500
_MAX_REASONS = 20
_MARKER = re.compile(r"<!-- prgate-verdict:v1 (\{.*?\}) -->", re.S)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f  ]")
_MD = re.compile(r"([\\*_{}\[\]()#+!|~-])")
_LABEL = {Outcome.BLOCKED: "Blocked", Outcome.PERSON: "Sent to a person", Outcome.CLEARED: "Cleared"}


def _plain(text: str, limit: int = _FIELD_MAX) -> str:
    """UTF-8 safe, one-line-ish, no control characters or backticks, truncated."""
    t = str(text).encode("utf-8", "backslashreplace").decode("utf-8")
    t = _CTRL.sub(" ", t.replace("\r\n", "\n").replace("\n", " ")).replace("`", "'")
    return t if len(t) <= limit else t[: limit - 1] + "…"


def _esc(text: str, limit: int = _FIELD_MAX) -> str:
    """Escape PR-controlled text so it renders as inert plain text in markdown."""
    t = _plain(text, limit)
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = _MD.sub(r"\\\1", t)
    return t.replace("@", "@​")


def escape(text: str, limit: int = _FIELD_MAX) -> str:
    """Public form of the escaping used for PR-controlled text in report bodies."""
    return _esc(text, limit)


def _title(v: Verdict) -> str:
    suffix = f" ({v.head_sha[:7]})"
    head = f"{_LABEL[v.outcome]}: "
    reason = _plain(v.reasons[0] if v.reasons else "no reason given", TITLE_MAX)
    reason = reason.replace("<", "(").replace(">", ")").replace("@", "@​")
    room = TITLE_MAX - len(head) - len(suffix)
    if len(reason) > room:
        reason = reason[: room - 1] + "…"
    return head + reason + suffix


def _json(v: Verdict, n_reasons: int, n_findings: int) -> str:
    def cut(x):  # ensure_ascii below escapes control chars and lone surrogates, so this stays lossless
        return x if x is None or len(x) <= _FIELD_MAX else x[:_FIELD_MAX]

    s = cut
    data = {
        "outcome": v.outcome.value, "head_sha": v.head_sha,
        "reasons": [cut(r) for r in v.reasons[:n_reasons]], "question": s(v.question),
        "findings": [{"check": f.check, "severity": f.severity.value, "message": cut(f.message),
                      "path": s(f.path), "line": f.line, "question": s(f.question)}
                     for f in v.findings[:n_findings]],
        "would_clear": v.would_clear, "explanation": s(v.explanation),
    }
    out = json.dumps(data, separators=(",", ":"))
    return out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _finding_lines(f: Finding) -> list[str]:
    where = f" ({_esc(f.path)}{':' + str(f.line) if f.line else ''})" if f.path else ""
    llm = " (LLM-written, not verified)" if f.check == "behaviour" else ""
    lines = [f"- **{f.severity.value}** {_esc(f.check)}{llm}: {_esc(f.message)}{where}"]
    if f.question:
        lines.append(f"  - Question: {_esc(f.question)}")
    return lines


def _check_line(c: CheckResult) -> str:
    status = "ran" if c.status == RunStatus.RAN else (
        "could not run (timed out)" if c.status == RunStatus.TIMED_OUT else "could not run")
    detail = f" - {_esc(c.detail)}" if c.detail else ""
    return f"- {_esc(c.name)}: {status}{detail}"


def _body(v: Verdict, checks: tuple[CheckResult, ...], n_reasons: int, n_findings: int,
          n_checks: int | None = None) -> str:
    if n_checks is None:
        n_checks = len(checks)
    shown = checks[:n_checks]
    out = [f"## {_LABEL[v.outcome]}", f"Commit `{_plain(v.head_sha, 40)}`", ""]
    if v.reasons:
        out += [f"- {_esc(r)}" for r in v.reasons[:n_reasons]]
        if len(v.reasons) > n_reasons:
            out.append(f"- {len(v.reasons) - n_reasons} more reasons not shown")
        out.append("")
    if v.question:
        out += [f"**Question for a person:** {_esc(v.question)}", ""]
    if v.explanation:
        out += [f"**Explanation (LLM-written, not verified):** {_esc(v.explanation)}", ""]
    if v.findings:
        out.append("### Findings")
        for f in v.findings[:n_findings]:
            out += _finding_lines(f)
        if len(v.findings) > n_findings:
            out.append(f"- {len(v.findings) - n_findings} more findings not shown (report truncated)")
        out.append("")
    if checks:
        out.append("### Checks")
        out += [_check_line(c) for c in shown]
        if len(checks) > n_checks:
            out.append(f"- {len(checks) - n_checks} more checks not shown (report truncated)")
        unrun = [c.name for c in checks if c.status != RunStatus.RAN]
        if unrun:
            out.append(f"{len(unrun)} check(s) could not run, so the result may be incomplete.")
        out.append("")
    if v.outcome == Outcome.CLEARED:
        out += ["Cleared means these checks passed. It is not proof the change is correct.", ""]
    out += [EXPERIMENTAL_LINE, ""]
    if v.outcome == Outcome.BLOCKED:
        out += [f"Wrong? An approver can comment `/gate override {_plain(v.head_sha, 40)} <reason>`.", ""]
    out.append(f"<!-- prgate-verdict:v1 {_json(v, n_reasons, n_findings)} -->")
    return "\n".join(out)


def _largest_fitting(fits, hi: int) -> int:
    """Largest n in [0, hi] with fits(n), assuming fits is monotonic. Returns -1 if even 0 fails."""
    if not fits(0):
        return -1
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fits(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


def _fit(v: Verdict, checks: tuple[CheckResult, ...]) -> str:
    """Shrink findings, then checks, then reasons, until the body fits. Outcome and SHA are never cut."""
    def size(r, f, c):
        return len(_body(v, checks, r, f, c))

    n_r, n_f, n_c = min(_MAX_REASONS, len(v.reasons)), len(v.findings), len(checks)
    if size(n_r, n_f, n_c) <= LIMIT:
        return _body(v, checks, n_r, n_f, n_c)
    best = _largest_fitting(lambda n: size(n_r, n, n_c) <= LIMIT, n_f)
    if best >= 0:
        return _body(v, checks, n_r, best, n_c)
    best = _largest_fitting(lambda n: size(n_r, 0, n) <= LIMIT, n_c)
    if best >= 0:
        return _body(v, checks, n_r, 0, best)
    best = _largest_fitting(lambda n: size(n, 0, 0) <= LIMIT, n_r)
    if best >= 0:
        return _body(v, checks, best, 0, 0)
    bare = replace(v, reasons=(), question=None, explanation=None, findings=())
    out = [f"## {_LABEL[v.outcome]}", f"Commit `{_plain(v.head_sha, 40)}`", "",
           "Report truncated: too large to show.", "", EXPERIMENTAL_LINE, ""]
    if v.outcome == Outcome.BLOCKED:
        out += [f"Wrong? An approver can comment `/gate override {_plain(v.head_sha, 40)} <reason>`.", ""]
    out.append(f"<!-- prgate-verdict:v1 {_json(bare, 0, 0)} -->")
    return "\n".join(out)


def render(verdict: Verdict, checks: tuple[CheckResult, ...]) -> tuple[str, str]:
    return _title(verdict), _fit(verdict, checks)


def parse(body: str) -> Verdict:
    m = _MARKER.search(body)
    if not m:
        raise ValueError("no prgate verdict marker in body")
    d = json.loads(m.group(1))
    findings = tuple(Finding(f["check"], Severity(f["severity"]), f["message"], f["path"], f["line"],
                             f["question"]) for f in d["findings"])
    return Verdict(Outcome(d["outcome"]), d["head_sha"], tuple(d["reasons"]), d["question"], findings,
                   d["would_clear"], d["explanation"])
