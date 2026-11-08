"""Create the gate's GitHub App through GitHub's App manifest flow, and wait for it to be installed.

The App's private key exists only in memory: it is returned in `AppCreds` (whose repr hides it)
and never written, logged, put in argv or put in an exception message. The conversion reply,
which also carries the webhook and client secrets, is never echoed.
"""
from __future__ import annotations

import html
import http.server
import json
import re
import secrets
import socket
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, quote, urlsplit

from prgate.setup.gh import Gh, GhError
from prgate.setup.preflight import RepoInfo
from prgate.setup.ui import Prompter

PROJECT_URL = "https://github.com/Abubakarjutt/PRGate"
HOST = "127.0.0.1"
MAX_NAME = 34
MAX_PREFIX = 26
GATE_PERMISSIONS = {"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}
CSP = "default-src 'none'; form-action https://github.com; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"

_CODE = re.compile(r"[A-Za-z0-9_-]{1,200}")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")
_POLL_S = 3.0
_MAX_PAGES = 10


@dataclass(frozen=True)
class AppCreds:
    app_id: int
    slug: str
    pem: str = field(repr=False)


def gate_manifest(info: RepoInfo, name: str, redirect_url: str) -> dict:
    return {
        "name": name,
        "url": PROJECT_URL,
        "description": f"prgate gate for {info.full_name}. Experimental and report-only: it posts a neutral pr-gate check.",
        "public": False,
        "redirect_url": redirect_url,
        "hook_attributes": {"url": PROJECT_URL, "active": False},
        "default_permissions": dict(GATE_PERMISSIONS),
        "default_events": [],
    }


def app_name(prefix: str, repo: str) -> str:
    """`<prefix>-<repo>-<6 hex>`, at most 34 characters; the repo part is cut first."""
    if len(prefix) > MAX_PREFIX:
        raise ValueError(f"the App name prefix must be at most {MAX_PREFIX} characters")
    suffix = secrets.token_hex(3)
    part = re.sub(r"-+", "-", re.sub(r"[^a-z0-9-]", "-", repo.lower())).strip("-")
    room = MAX_NAME - len(prefix) - len(suffix) - 2
    part = part[:max(room, 0)].rstrip("-")
    return f"{prefix}-{part}-{suffix}" if part else f"{prefix}-{suffix}"


def manifest_post_url(info: RepoInfo) -> str:
    if info.owner_is_org:
        return f"https://github.com/organizations/{quote(info.owner, safe='')}/settings/apps/new"
    return "https://github.com/settings/apps/new"


def _start_page(manifest: dict, action: str) -> bytes:
    value = html.escape(json.dumps(manifest), quote=True)
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>prgate: create the GitHub App</title></head><body>"
        f"<form id=\"f\" method=\"post\" action=\"{html.escape(action, quote=True)}\">"
        f"<input type=\"hidden\" name=\"manifest\" value=\"{value}\">"
        "<p>Sending the App manifest to GitHub. If nothing happens, press the button.</p>"
        "<button type=\"submit\">Create the GitHub App on GitHub</button></form>"
        "<script>document.getElementById(\"f\").submit()</script></body></html>"
    ).encode()


class _Handler(http.server.BaseHTTPRequestHandler):
    server: "_Httpd"
    server_version = "prgate"
    sys_version = ""
    timeout = 10  # an idle or slow client cannot hold its handler thread for long

    def log_message(self, format: str, *args: Any) -> None:  # the request line holds the code and state
        pass

    def _send(self, status: int, body: bytes = b"", content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _host_ok(self) -> bool:
        hosts = self.headers.get_all("Host") or []
        return len(hosts) == 1 and hosts[0] == f"{HOST}:{self.server.owner.port}"

    def do_GET(self) -> None:
        owner = self.server.owner
        if not self._host_ok():
            self._send(400, b"bad host\n")
            return
        parts = urlsplit(self.path)
        if parts.path.startswith("/start/"):
            page = owner._take_start(parts.path.removeprefix("/start/"))
            if page is None:
                self._send(404, b"not found\n")
            else:
                self._send(200, page, "text/html; charset=utf-8")
            return
        if parts.path != "/callback":
            self._send(404, b"not found\n")
            return
        query = parse_qs(parts.query, keep_blank_values=True)
        state, code = query.get("state", [""]), query.get("code", [""])
        if (len(state) != 1 or len(code) != 1 or not secrets.compare_digest(state[0].encode(), owner.state.encode())
                or not _CODE.fullmatch(code[0])):
            self._send(400, b"this link is not the one prgate is waiting for\n")
            return
        if not owner._accept(code[0]):  # the first valid callback wins and closes the listener
            self._send(409, b"prgate already has its callback\n")
            return
        try:
            self._send(200, b"The GitHub App was created. You can close this tab and return to prgate.\n")
            self.wfile.flush()
        finally:  # only now may prgate stop waiting and close the server, so the reply is never cut off
            owner._done.set()

    def _refuse(self) -> None:
        if not self._host_ok():
            self._send(400, b"bad host\n")
        else:
            self._send(405, b"method not allowed\n")

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):  # every other method, known or not, gets 405
            return self._refuse
        raise AttributeError(name)


class _Httpd(http.server.ThreadingHTTPServer):
    owner: "CallbackServer"
    allow_reuse_address = False
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Silent: the default prints a traceback to stderr. Only the exception type is kept."""
        import sys
        self.last_error = sys.exc_info()[0]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.last_error: type[BaseException] | None = None
        self._conns: set[socket.socket] = set()
        self._conns_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        with self._conns_lock:
            self._conns.add(request)
        super().process_request(request, client_address)

    def shutdown_request(self, request: Any) -> None:
        with self._conns_lock:
            self._conns.discard(request)
        super().shutdown_request(request)

    def drop_connections(self) -> None:
        with self._conns_lock:
            conns = list(self._conns)
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class CallbackServer:
    """A single-use HTTP server on 127.0.0.1 (a free port).

    It serves the start page once, at `/start/<token>` (a token distinct from `state`), and waits
    for one valid `/callback`. The first valid callback closes the listener.
    """

    def __init__(self, state: str) -> None:
        self.state = state
        self.host = HOST
        self.code: str | None = None
        self.error: BaseException | None = None
        self._start_token = secrets.token_urlsafe(32)
        self._start_page: bytes | None = None
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._stop = threading.Event()
        self._httpd = _Httpd((HOST, 0), _Handler)
        self._httpd.owner = self
        self._httpd.timeout = 0.05
        self.port: int = self._httpd.server_address[1]
        self.start_url = self.url(f"/start/{self._start_token}")
        self._thread = threading.Thread(target=self._serve, name="prgate-callback", daemon=True)
        self._thread.start()

    def url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def set_start(self, manifest: dict, post_url: str) -> None:
        page = _start_page(manifest, f"{post_url}?state={quote(self.state, safe='')}")
        with self._lock:
            self._start_page = page

    def _take_start(self, token: str) -> bytes | None:
        with self._lock:
            if self._start_page is None or not secrets.compare_digest(token.encode(), self._start_token.encode()):
                return None
            page, self._start_page = self._start_page, None
            return page

    def _accept(self, code: str) -> bool:
        with self._lock:
            if self.code is not None:
                return False
            self.code = code  # the handler sets _done once its reply has been written
            try:
                self._httpd.socket.close()
            except OSError:
                pass
            return True

    def _serve(self) -> None:
        try:
            while not self._finished():
                try:
                    self._httpd.handle_request()
                except (OSError, ValueError):
                    if self._finished():  # the listener was closed on purpose
                        break
                    raise
        except BaseException as e:  # recorded, so wait() returns at once instead of running out the clock
            self.error = e
        finally:
            self._httpd.server_close()
            if self.code is None:  # once a code is accepted, only its handler signals done, after replying
                self._done.set()

    def _finished(self) -> bool:
        return self.code is not None or self._done.is_set() or self._stop.is_set()

    def wait(self, timeout_s: float) -> str | None:
        self._done.wait(timeout_s)
        return self.code

    def close(self) -> None:
        self._stop.set()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
        self._httpd.server_close()
        self._httpd.drop_connections()


def _open(open_browser: Callable[[str], bool], url: str) -> bool:
    try:
        return bool(open_browser(url))
    except Exception:
        return False


def _creds(reply: object, info: RepoInfo, expected_name: object) -> AppCreds:
    """Trust the conversion reply only if it is the App this run asked for, owned by the repo's owner."""
    if not isinstance(reply, dict):
        raise GhError(None, "GitHub's reply to the App creation had no usable App id, slug and private key")
    app_id, slug, pem = reply.get("id"), reply.get("slug"), reply.get("pem")
    if not (type(app_id) is int and app_id > 0 and isinstance(slug, str) and _SLUG.fullmatch(slug) and isinstance(pem, str) and pem):
        raise GhError(None, "GitHub's reply to the App creation had no usable App id, slug and private key")
    owner = reply.get("owner")
    login = owner.get("login") if isinstance(owner, dict) else None
    if not (isinstance(owner, dict) and type(owner.get("id")) is int and owner["id"] == info.owner_id
            and isinstance(login, str) and login.lower() == info.owner.lower()
            and isinstance(expected_name, str) and reply.get("name") == expected_name
            and reply.get("permissions") == GATE_PERMISSIONS):
        raise GhError(None, "the created App is not the one prgate asked for (owner, name or permissions differ); "
                            "its key was not kept. Delete that App on GitHub and run prgate init again")
    return AppCreds(app_id, slug, pem)


def create_app(gh: Gh, info: RepoInfo, manifest: Callable[[str], dict], prompter: Prompter,
               open_browser: Callable[[str], bool] = webbrowser.open, timeout_s: float = 600) -> AppCreds:
    server = CallbackServer(secrets.token_urlsafe(32))
    try:
        wanted = manifest(server.url("/callback"))
        server.set_start(wanted, manifest_post_url(info))
        start = server.start_url
        if _open(open_browser, start):
            prompter.say(f"Your browser should now show GitHub's page to create the App. If it does not, open {start}")
        else:
            prompter.say(f"Open {start} in a browser on this machine to create the GitHub App. "
                         f"If you are connected over SSH, forward the port first: ssh -L {server.port}:127.0.0.1:{server.port} <this host>")
        code = server.wait(timeout_s)
        failed = server.error is not None
    finally:
        server.close()
    if code is None and failed:
        raise GhError(None, "the local callback server stopped unexpectedly while waiting for the GitHub App to be created")
    if code is None:
        raise GhError(None, "timed out waiting for the GitHub App to be created")
    return _creds(gh.api("POST", f"app-manifests/{code}/conversions"), info, wanted.get("name") if isinstance(wanted, dict) else None)


def _slug(slug: str) -> str:
    if not (isinstance(slug, str) and _SLUG.fullmatch(slug)):
        raise ValueError("not a valid GitHub App slug")
    return slug


def app_exists(gh: Gh, slug: str) -> bool:
    try:
        gh.api("GET", f"apps/{_slug(slug)}")
    except GhError as e:
        if e.status == 404:
            return False
        raise
    return True


def _pages(gh: Gh, path: str, key: str) -> list:
    out: list = []
    for page in range(1, _MAX_PAGES + 1):
        reply = gh.api("GET", f"{path}?per_page=100&page={page}")
        items = reply.get(key) if isinstance(reply, dict) else None
        if not isinstance(items, list):
            raise GhError(None, f"GitHub's reply to GET {path} had no {key} list")
        out.extend(i for i in items if isinstance(i, dict))
        if len(items) < 100:
            return out
    raise GhError(None, f"too many {key} to check (more than {_MAX_PAGES * 100}); install the App on this repository only")


def _installed(gh: Gh, slug: str, repo_id: int) -> bool:
    for inst in _pages(gh, "user/installations", "installations"):
        if inst.get("app_slug") == slug and type(inst.get("id")) is int:
            if any(r.get("id") == repo_id for r in _pages(gh, f"user/installations/{inst['id']}/repositories", "repositories")):
                return True
    return False


def is_installed(gh: Gh, slug: str, repo_id: int) -> bool:
    return _installed(gh, _slug(slug), repo_id)


def installed_app_slugs(gh: Gh, repo_id: int) -> list[str]:
    """Slugs of the Apps the user can see installed on the repo `repo_id`."""
    out: list[str] = []
    for inst in _pages(gh, "user/installations", "installations"):
        slug = inst.get("app_slug")
        if isinstance(slug, str) and _SLUG.fullmatch(slug) and type(inst.get("id")) is int:
            if any(r.get("id") == repo_id for r in _pages(gh, f"user/installations/{inst['id']}/repositories", "repositories")):
                out.append(slug)
    return out


def apps_settings_url(info: RepoInfo) -> str:
    """The list of Apps `create_app` registers under (the organization's for an organization repo)."""
    if info.owner_is_org:
        return f"https://github.com/organizations/{quote(info.owner, safe='')}/settings/apps"
    return "https://github.com/settings/apps"


def settings_url(info: RepoInfo, slug: str) -> str:
    """Where the App's owner deletes it."""
    return f"{apps_settings_url(info)}/{_slug(slug)}"


def ensure_installed(gh: Gh, info: RepoInfo, creds_slug: str, prompter: Prompter,
                     open_browser: Callable[[str], bool] = webbrowser.open, timeout_s: float = 600, poll_s: float = _POLL_S) -> None:
    slug = _slug(creds_slug)
    if _installed(gh, slug, info.repo_id):
        return
    url = f"https://github.com/apps/{slug}/installations/new"
    if _open(open_browser, url):
        prompter.say(f"Install the App on {info.full_name} in your browser. If it did not open, visit {url}")
    else:
        prompter.say(f"Open {url} and install the App on {info.full_name} (only that repository).")
    deadline = time.monotonic() + timeout_s
    while True:
        if _installed(gh, slug, info.repo_id):
            return
        if time.monotonic() >= deadline:
            raise GhError(None, f"timed out waiting for the GitHub App to be installed on {info.full_name}")
        time.sleep(min(poll_s, max(deadline - time.monotonic(), 0)))
