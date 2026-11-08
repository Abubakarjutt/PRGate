"""A small GitHub REST client on urllib. The token goes only to https://api.github.com.

Every URL is built here from validated parts (repo name, full SHAs, PR numbers), so no caller
can steer the token to another host or path. Redirects are refused, because urllib would
forward the Authorization header to wherever a redirect points.
"""
from __future__ import annotations

import base64
import binascii
import http.client
import json
import re
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import quote, urlencode

from . import __version__

API_ROOT = "https://api.github.com"
USER_AGENT = f"prgate/{__version__}"
CHECK_NAME = "pr-gate"
TIMEOUT_S = 30
MAX_REPLY = 10 * 1024 * 1024
_MAX_PAGES = 10

_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_SHA = re.compile(r"[0-9a-f]{40}")
_TOKEN = re.compile(r"[\x21-\x7e]+")  # printable ASCII, no spaces: nothing that can split a header
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")


class GitHubError(Exception):
    """An API call failed. The message names the method, path and status, never the token."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError for the 3xx; the token is never re-sent


def build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect())


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def valid_repo(value: object) -> bool:
    return (isinstance(value, str) and _REPO.fullmatch(value) is not None
            and all(part not in (".", "..") for part in value.split("/")))


def _sha(value: object) -> str:
    if not valid_sha(value):
        raise ValueError("expected a full 40-character lowercase commit SHA")
    return value  # type: ignore[return-value]


def _number(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("expected a positive pull request number")
    return value


class GitHub:
    def __init__(self, token: str, repo: str, *, app_slug: str | None = None, opener: Any = None):
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise ValueError("the GitHub token is missing or has characters a token cannot have")
        if not valid_repo(repo):
            raise ValueError("the repository must be owner/name")
        if app_slug is not None and not (isinstance(app_slug, str) and _SLUG.fullmatch(app_slug)):
            raise ValueError("the App slug is not a valid slug")
        self._token = token
        self.repo = repo
        self.app_slug = app_slug
        self._opener = opener or build_opener()

    def __repr__(self) -> str:  # never show the token
        return f"GitHub(repo={self.repo!r}, app_slug={self.app_slug!r})"

    def _request(self, method: str, path: str, query: dict[str, Any] | None = None,
                 body: dict[str, Any] | None = None) -> Any:
        if not path.startswith(f"/repos/{self.repo}/"):
            raise ValueError("API paths are always inside this repository")
        url = API_ROOT + path + (f"?{urlencode(query)}" if query else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
            **({"Content-Type": "application/json"} if data is not None else {}),
        })
        where = f"{method} {path}"
        try:
            with self._opener.open(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read(MAX_REPLY + 1)
        except urllib.error.HTTPError as e:
            raise GitHubError(f"GitHub API {where} failed with HTTP {e.code}", e.code) from None
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
            raise GitHubError(f"GitHub API {where} failed ({type(e).__name__})") from None
        if len(raw) > MAX_REPLY:
            raise GitHubError(f"GitHub API {where} reply is too large")
        try:
            return json.loads(raw)
        except (ValueError, RecursionError):
            raise GitHubError(f"GitHub API {where} did not return JSON") from None

    def _repo_path(self, *parts: str) -> str:
        return f"/repos/{self.repo}/" + "/".join(parts)

    def create_check(self, head_sha: str, conclusion: str, title: str, body: str) -> dict:
        head = _sha(head_sha)
        return self._request("POST", self._repo_path("check-runs"), body={
            "name": CHECK_NAME, "head_sha": head, "status": "completed", "conclusion": conclusion,
            "output": {"title": title, "summary": body},
        })

    def latest_check(self, head_sha: str) -> dict | None:
        """This App's newest completed `pr-gate` check-run on exactly this commit, or None.

        Runs from any other app (GitHub Actions included) are ignored, so a check a PR forges
        can never be read back as the gate's verdict. Without a known App slug nothing is trusted.
        """
        head = _sha(head_sha)
        if self.app_slug is None:
            return None
        best: dict | None = None
        for page in range(1, _MAX_PAGES + 1):
            reply = self._request("GET", self._repo_path("commits", head, "check-runs"),
                                  {"check_name": CHECK_NAME, "filter": "all", "per_page": 100, "page": page})
            runs = reply.get("check_runs") if isinstance(reply, dict) else None
            if not isinstance(runs, list):
                raise GitHubError("GitHub API check-runs reply has no check_runs list")
            for run in runs:
                if not isinstance(run, dict) or not isinstance(run.get("app"), dict):
                    continue
                if (run.get("name") == CHECK_NAME and run.get("head_sha") == head
                        and run["app"].get("slug") == self.app_slug and run.get("status") == "completed"
                        and type(run.get("id")) is int and (best is None or run["id"] > best["id"])):
                    best = run
            if len(runs) < 100:
                break
        return best

    def pr(self, number: int) -> dict:
        reply = self._request("GET", self._repo_path("pulls", str(_number(number))))
        if not isinstance(reply, dict):
            raise GitHubError("GitHub API pull request reply is not an object")
        return reply

    def file(self, path: str, ref: str) -> bytes | None:
        """A file's bytes at commit `ref`, or None if it is absent there."""
        head = _sha(ref)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path) or ".." in path.split("/"):
            raise ValueError("unsafe file path")
        try:
            reply = self._request("GET", self._repo_path("contents", quote(path)), {"ref": head})
        except GitHubError as e:
            if e.status == 404:
                return None
            raise
        if not (isinstance(reply, dict) and reply.get("type") == "file" and reply.get("encoding") == "base64"
                and isinstance(reply.get("content"), str)):
            raise GitHubError(f"GitHub API contents reply for {path} is not a readable file")
        try:
            return base64.b64decode(reply["content"], validate=False)
        except (binascii.Error, ValueError):
            raise GitHubError(f"GitHub API contents reply for {path} is not valid base64") from None
