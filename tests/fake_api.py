"""An in-memory GitHub REST API for tests, plugged into prgate.github.GitHub as its opener.

Nothing here touches the network. Every request is recorded with its URL and headers so tests
can check where the token went.
"""
from __future__ import annotations

import base64
import email.message
import io
import json
import re
import urllib.error
from dataclasses import dataclass, field
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

REPO = "o/r"
SLUG = "prgate-gate"


class _Response(io.BytesIO):
    def __init__(self, status: int, body: bytes):
        super().__init__(body)
        self.status = status
        self.headers = email.message.Message()


@dataclass
class FakeAPI:
    prs: dict = field(default_factory=dict)
    contents: dict = field(default_factory=dict)  # (path, ref) -> bytes
    runs: list = field(default_factory=list)
    comments: dict = field(default_factory=dict)
    fail: list = field(default_factory=list)  # (method, path regex, status)
    seen: list = field(default_factory=list)
    app_slug: str = SLUG

    # --- helpers for tests ---
    def add_run(self, head_sha, body, *, slug=SLUG, name="pr-gate", title="t"):
        run = {"id": len(self.runs) + 1, "name": name, "head_sha": head_sha, "status": "completed",
               "conclusion": "neutral", "app": {"slug": slug, "id": 7},
               "output": {"title": title, "summary": body}}
        self.runs.append(run)
        return run

    def posted(self):
        return [SimpleNamespace(head_sha=r["head_sha"], conclusion=r["conclusion"], title=r["output"]["title"],
                                body=r["output"]["summary"]) for r in self.runs if r.get("posted")]

    # --- opener protocol ---
    def open(self, req, timeout=None):
        url = urlparse(req.full_url)
        method = req.get_method()
        headers = {k.lower(): v for k, v in req.header_items()}
        self.seen.append((method, req.full_url, headers))
        for m, rx, status in self.fail:
            if m == method and re.search(rx, url.path):
                raise urllib.error.HTTPError(req.full_url, status, "fail", email.message.Message(),
                                             io.BytesIO(b'{"message": "nope"}'))
        status, body = self._route(method, url.path, parse_qs(url.query), req.data)
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "err", email.message.Message(),
                                         io.BytesIO(json.dumps(body).encode()))
        return _Response(status, json.dumps(body).encode())

    def _route(self, method, path, q, data):
        base = f"/repos/{REPO}"
        if m := re.fullmatch(base + r"/pulls/(\d+)", path):
            pr = self.prs.get(int(m[1]))
            return (200, pr) if pr else (404, {"message": "Not Found"})
        if method == "GET" and path == base + "/contents/.prgate.toml":
            raw = self.contents.get((".prgate.toml", q.get("ref", [""])[0]))
            if raw is None:
                return 404, {"message": "Not Found"}
            return 200, {"type": "file", "encoding": "base64", "content": base64.b64encode(raw).decode()}
        if m := re.fullmatch(base + r"/commits/([0-9a-f]{40})/check-runs", path):
            page = int(q.get("page", ["1"])[0])
            runs = [r for r in self.runs if r["head_sha"] == m[1]
                    and r["name"] == q.get("check_name", [r["name"]])[0]]
            return 200, {"total_count": len(runs), "check_runs": runs if page == 1 else []}
        if method == "POST" and path == base + "/check-runs":
            d = json.loads(data)
            try:  # GitHub refuses text that is not valid Unicode (lone surrogates)
                (d["output"]["title"] + d["output"]["summary"]).encode("utf-8")
            except UnicodeEncodeError:
                return 422, {"message": "invalid unicode"}
            run = {"id": len(self.runs) + 1, "name": d["name"], "head_sha": d["head_sha"], "status": d["status"],
                   "conclusion": d["conclusion"], "app": {"slug": self.app_slug, "id": 7},
                   "output": dict(d["output"]), "posted": True}
            self.runs.append(run)
            return 201, run
        if m := re.fullmatch(base + r"/issues/(\d+)/comments", path):
            return 200, self.comments.get(int(m[1]), []) if q.get("page", ["1"])[0] == "1" else []
        return 404, {"message": "Not Found"}
