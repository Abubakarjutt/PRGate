import html
import http.client
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import pytest

from prgate.setup import apps
from prgate.setup.apps import (
    GATE_PERMISSIONS, AppCreds, CallbackServer, app_exists, app_name, create_app, ensure_installed, gate_manifest,
    manifest_post_url,
)
from prgate.setup.gh import GhError
from prgate.setup.preflight import RepoInfo
from tests.setup.fakes import FakeGh, ScriptedPrompter

NAME = "prgate-r-abc123"
PEM = "-----BEGIN RSA PRIVATE " + "KEY-----\nSECRETKEY\n-----END RSA PRIVATE KEY-----\n"


def info(owner: str = "o", owner_is_org: bool = False) -> RepoInfo:
    return RepoInfo(full_name=f"{owner}/r", owner=owner, owner_id=7, owner_is_org=owner_is_org, repo_id=100,
                    private=False, default_branch="main", plan="free")


def conv(owner: str = "o", **over) -> dict:
    """A conversion reply shaped like GitHub's documented one, for the App `manifest()` describes."""
    reply = {"id": 7, "slug": NAME, "name": NAME, "owner": {"login": owner, "id": 7, "type": "User"},
             "permissions": dict(GATE_PERMISSIONS), "events": [], "pem": PEM,
             "webhook_secret": "WHSECRET", "client_secret": "CLSECRET", "client_id": "Iv1.x"}
    reply.update(over)
    return reply


CONV = conv()


def manifest(u: str) -> dict:
    return gate_manifest(info(), NAME, u)


def org_manifest(u: str) -> dict:
    return gate_manifest(info(owner="acme", owner_is_org=True), NAME, u)


class Reply:
    def __init__(self, status: int, body: bytes, headers) -> None:
        self.status, self.body, self.headers = status, body, headers


def get(url: str) -> Reply:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return Reply(r.status, r.read(), r.headers)
    except urllib.error.HTTPError as e:
        return Reply(e.code, e.read(), e.headers)


def request(url: str, method: str) -> int:
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        conn.request(method, parts.path + (f"?{parts.query}" if parts.query else ""))
        return conn.getresponse().status
    finally:
        conn.close()


def raw(server: CallbackServer, target: str, host_lines: str) -> int:
    """Send a hand-written request, so the Host header can be wrong or missing."""
    with socket.create_connection((server.host, server.port), timeout=5) as s:
        s.sendall(f"GET {target} HTTP/1.0\r\n{host_lines}\r\n".encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    return int(data.split(b" ", 2)[1])


def _state_from(page: str) -> str:
    action = html.unescape(re.search(r'action="([^"]+)"', page)[1])
    return re.search(r"[?&]state=([^&]+)", action)[1]


def callback_with(code: str, pages: list | None = None):
    def opener(start_url: str) -> bool:
        page = get(start_url).body.decode()
        if pages is not None:
            pages.append(page)
        base = start_url.split("/start", 1)[0]
        assert get(f"{base}/callback?code={code}&state={_state_from(page)}").status == 200
        return True
    return opener


auto_callback = callback_with("c0de")


def no_browser_then_callback(start_url: str) -> bool:
    callback_with("c0de")(start_url)
    return False


def refuses_to_connect(url: str) -> bool:
    try:
        get(url)
    except OSError:
        return True
    return False


def threads_settle(baseline: int, within_s: float = 3.0) -> bool:
    end = time.monotonic() + within_s
    while time.monotonic() < end:
        if threading.active_count() <= baseline:
            return True
        time.sleep(0.02)
    return False


# --- manifest --------------------------------------------------------------------------------

def test_gate_manifest_has_no_more_than_the_needed_permissions():
    m = gate_manifest(info(), "prgate-r-abc123", "http://127.0.0.1:1/cb")
    assert m["default_permissions"] == {"checks": "write", "contents": "read", "pull_requests": "read", "metadata": "read"}
    assert m["hook_attributes"]["active"] is False and m["public"] is False


def test_gate_manifest_links_the_project_and_says_experimental():
    m = gate_manifest(info(), "prgate-r-abc123", "http://127.0.0.1:1/cb")
    assert m["url"] == "https://github.com/Abubakarjutt/PRGate" and "experimental" in m["description"].lower()


def test_gate_manifest_subscribes_to_no_events_and_redirects_to_the_callback():
    m = gate_manifest(info(), "prgate-r-abc123", "http://127.0.0.1:1/cb")
    assert m["default_events"] == [] and m["redirect_url"] == "http://127.0.0.1:1/cb" and m["name"] == "prgate-r-abc123"
    assert "report-only" in m["description"].lower()


def test_app_name_fits_and_is_unique():
    a, b = app_name("prgate", "x" * 60), app_name("prgate", "x" * 60)
    assert len(a) <= 34 and a != b


def test_app_name_keeps_a_short_repo_and_ends_in_six_hex():
    assert re.fullmatch(r"prgate-my-repo-[0-9a-f]{6}", app_name("prgate", "My_Repo"))


def test_app_name_truncates_the_repo_first():
    name = app_name("prgate", "abcdefghijklmnopqrstuvwxyz0123456789")
    assert name.startswith("prgate-abc") and len(name) == 34 and re.search(r"-[0-9a-f]{6}$", name)


def test_app_name_refuses_a_prefix_longer_than_26():
    assert len(app_name("p" * 26, "r")) <= 34
    with pytest.raises(ValueError):
        app_name("p" * 27, "r")


def test_org_repo_posts_to_org_settings():
    url = manifest_post_url(info(owner="acme", owner_is_org=True))
    assert url == "https://github.com/organizations/acme/settings/apps/new"


def test_personal_repo_posts_to_user_settings():
    assert manifest_post_url(info()) == "https://github.com/settings/apps/new"


# --- callback server -------------------------------------------------------------------------

def test_callback_binds_localhost_and_rejects_wrong_state():
    server = CallbackServer(state="good")
    try:
        assert server.host == "127.0.0.1"
        assert get(server.url("/callback?code=c&state=bad")).status == 400
        assert server.code is None
    finally:
        server.close()


def test_callback_rejects_missing_state_and_unsafe_code():
    server = CallbackServer(state="good")
    try:
        assert get(server.url("/callback?code=c")).status == 400
        assert get(server.url("/callback?code=..%2Fx&state=good")).status == 400
        assert get(server.url("/callback?state=good")).status == 400
        assert server.code is None
    finally:
        server.close()


def test_callback_is_single_use():
    server = CallbackServer(state="good")
    try:
        get(server.url("/callback?code=c&state=good"))
        with pytest.raises(OSError):
            get(server.url("/callback?code=c2&state=good"))
        assert server.code == "c"
    finally:
        server.close()


def test_callback_rejects_a_wrong_or_missing_host():
    server = CallbackServer(state="good")
    try:
        target = "/callback?code=c&state=good"
        assert raw(server, target, "Host: evil.example\r\n") == 400
        assert raw(server, target, f"Host: localhost:{server.port}\r\n") == 400
        assert raw(server, target, "") == 400
        assert raw(server, target, f"Host: 127.0.0.1:{server.port}\r\nHost: evil.example\r\n") == 400
        assert server.code is None
        assert raw(server, target, f"Host: 127.0.0.1:{server.port}\r\n") == 200
        assert server.code == "c"
    finally:
        server.close()


def test_start_page_rejects_a_wrong_host():
    server = CallbackServer(state="good")
    try:
        server.set_start({"x": 1}, "https://github.com/settings/apps/new")
        assert raw(server, urlsplit(server.start_url).path, "Host: evil.example\r\n") == 400
        assert get(server.start_url).status == 200  # the rejected request did not use up the page
    finally:
        server.close()


def test_idle_socket_does_not_block_the_callback_and_close_leaves_no_thread():
    baseline = threading.active_count()
    server = CallbackServer(state="good")
    idle = socket.create_connection((server.host, server.port), timeout=5)
    try:
        time.sleep(0.1)  # let the server pick up the idle connection
        started = time.monotonic()
        assert get(server.url("/callback?code=c&state=good")).status == 200
        assert time.monotonic() - started < 2 and server.code == "c"
    finally:
        server.close()
        idle.close()
    assert threads_settle(baseline)


OK_BODY = b"The GitHub App was created. You can close this tab and return to prgate.\n"


def test_callback_reply_arrives_in_full_before_the_server_closes(capfd):
    for _ in range(50):
        replies: list = []
        threads: list = []

        def browser(start_url: str) -> bool:
            page = get(start_url).body.decode()
            base = start_url.split("/start", 1)[0]

            def hit() -> None:  # like a real browser: the callback arrives from elsewhere while prgate waits
                try:
                    replies.append(get(f"{base}/callback?code=c0de&state={_state_from(page)}"))
                except Exception as e:  # noqa: BLE001 - a reset or truncated reply is the failure under test
                    replies.append(e)

            t = threading.Thread(target=hit)
            t.start()
            threads.append(t)
            return True

        create_app(FakeGh(conversion=CONV), info(), manifest, ScriptedPrompter({}), open_browser=browser, timeout_s=5)
        threads[0].join(5)
        assert len(replies) == 1 and isinstance(replies[0], Reply), replies
        assert replies[0].status == 200 and replies[0].body == OK_BODY
    out, err = capfd.readouterr()
    assert "Traceback" not in err and "Traceback" not in out and "BrokenPipe" not in err


def test_a_second_valid_callback_on_an_open_connection_gets_409():
    server = CallbackServer(state="good")
    a = http.client.HTTPConnection(server.host, server.port, timeout=5)
    b = http.client.HTTPConnection(server.host, server.port, timeout=5)
    try:
        a.connect(); b.connect()
        time.sleep(0.3)  # both connections are accepted before the listener closes
        a.request("GET", "/callback?code=first&state=good")
        ra = a.getresponse()
        assert ra.status == 200 and ra.read() == OK_BODY
        b.request("GET", "/callback?code=second&state=good")
        assert b.getresponse().status == 409
        assert server.code == "first"
    finally:
        a.close(); b.close()
        server.close()


def test_only_get_on_start_and_callback_is_served():
    server = CallbackServer(state="good")
    try:
        assert get(server.url("/elsewhere")).status == 404
        assert request(server.url("/callback?code=c&state=good"), "POST") in (404, 405)
        assert request(server.url("/start"), "PUT") in (404, 405)
        assert request(server.url("/start"), "BREW") in (404, 405)
        assert server.code is None
    finally:
        server.close()


def test_start_page_auto_posts_the_escaped_manifest_with_no_store_and_csp():
    server = CallbackServer(state="st4te")
    try:
        manifest = {"name": "a\"b<c>&'", "redirect_url": server.url("/callback")}
        server.set_start(manifest, "https://github.com/settings/apps/new")
        r = get(server.start_url)
        page = r.body.decode()
        assert r.status == 200
        assert r.headers["Cache-Control"] == "no-store"
        csp = r.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "form-action https://github.com" in csp and "script-src 'unsafe-inline'" in csp
        assert 'method="post"' in page and 'action="https://github.com/settings/apps/new?state=st4te"' in page
        value = re.search(r'name="manifest" value="([^"]*)"', page)[1]
        assert "<" not in value and json.loads(html.unescape(value)) == manifest
        assert ".submit()" in page
    finally:
        server.close()


def test_start_page_lives_at_an_unguessable_path_and_is_served_once():
    server = CallbackServer(state="st4te")
    try:
        server.set_start({"x": 1}, "https://github.com/settings/apps/new")
        token = urlsplit(server.start_url).path.removeprefix("/start/")
        assert len(token) >= 40 and "st4te" not in token
        assert get(server.url("/start")).status == 404
        assert get(server.url("/start/" + "A" * len(token))).status == 404
        assert get(server.url("/start/")).status == 404
        assert get(server.start_url).status == 200
        assert get(server.start_url).status == 404
    finally:
        server.close()


def test_start_token_differs_from_the_state():
    a, b = CallbackServer(state="s"), CallbackServer(state="s")
    try:
        assert a.start_url != b.start_url
    finally:
        a.close(); b.close()


def test_start_page_is_404_until_a_manifest_is_set():
    server = CallbackServer(state="good")
    try:
        assert get(server.start_url).status == 404
    finally:
        server.close()


def test_close_frees_the_port():
    server = CallbackServer(state="good")
    url = server.url("/start")
    server.close()
    assert refuses_to_connect(url)


# --- create_app ------------------------------------------------------------------------------

def test_key_is_returned_in_memory_and_never_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path); monkeypatch.setenv("HOME", str(tmp_path))
    creds = create_app(FakeGh(conversion=conv(pem="KEY")), info(), manifest, ScriptedPrompter({}), open_browser=auto_callback)
    assert creds.pem == "KEY" and "KEY" not in repr(creds) and not any(tmp_path.rglob("*"))


def test_no_browser_prints_url_and_ssh_hint():
    p = ScriptedPrompter({})
    create_app(FakeGh(conversion=CONV), info(), manifest, p, open_browser=no_browser_then_callback)
    assert any("http://127.0.0.1:" in s and "ssh -L" in s for s in p.said)


def test_ssh_hint_names_the_listening_port_and_the_tokened_start_url():
    p = ScriptedPrompter({})
    opened = []

    def opener(url: str) -> bool:
        opened.append(url)
        return no_browser_then_callback(url)

    create_app(FakeGh(conversion=CONV), info(), manifest, p, open_browser=opener)
    hint = next(s for s in p.said if "ssh -L" in s)
    port = re.search(r"http://127\.0\.0\.1:(\d+)/start/", hint)[1]
    assert f"ssh -L {port}:127.0.0.1:{port}" in hint and opened[0] in hint
    assert re.fullmatch(r"http://127\.0\.0\.1:\d+/start/[A-Za-z0-9_-]{40,}", opened[0])


def test_browser_that_raises_counts_as_not_opened():
    p = ScriptedPrompter({})

    def broken(url: str) -> bool:
        callback_with("c0de")(url)
        raise RuntimeError("no display")

    assert create_app(FakeGh(conversion=CONV), info(), manifest, p, open_browser=broken).app_id == 7
    assert any("ssh -L" in s for s in p.said)


def test_create_app_exchanges_the_code_and_returns_the_creds():
    gh = FakeGh(conversion=CONV)
    seen = []
    creds = create_app(gh, info(), lambda u: seen.append(u) or manifest(u), ScriptedPrompter({}),
                       open_browser=callback_with("abc123"))
    assert creds == AppCreds(7, NAME, PEM)
    assert ("POST", "app-manifests/abc123/conversions") in gh.writes
    assert seen and seen[0].startswith("http://127.0.0.1:") and seen[0].endswith("/callback")


def test_create_app_never_says_the_conversion_secrets():
    p = ScriptedPrompter({})
    create_app(FakeGh(conversion=CONV), info(), manifest, p, open_browser=no_browser_then_callback)
    said = "\n".join(p.said)
    assert "SECRETKEY" not in said and "WHSECRET" not in said and "CLSECRET" not in said


def test_start_page_posts_to_org_settings_for_an_org_repo():
    pages: list = []
    org = info(owner="acme", owner_is_org=True)
    create_app(FakeGh(conversion=conv(owner="acme")), org, org_manifest, ScriptedPrompter({}), open_browser=callback_with("c0de", pages))
    assert 'action="https://github.com/organizations/acme/settings/apps/new?state=' in pages[0]


def test_org_owner_login_is_compared_without_case():
    org = info(owner="Acme", owner_is_org=True)
    creds = create_app(FakeGh(conversion=conv(owner="acme")), org, org_manifest, ScriptedPrompter({}), open_browser=auto_callback)
    assert creds.app_id == 7


def test_create_app_times_out_naming_the_step_and_closes_the_server():
    urls = []
    with pytest.raises(GhError, match="timed out waiting for the GitHub App to be created"):
        create_app(FakeGh(conversion=CONV), info(), manifest, ScriptedPrompter({}),
                   open_browser=lambda u: urls.append(u) or True, timeout_s=0.3)
    assert refuses_to_connect(urls[0])


def test_create_app_fails_fast_when_the_listener_dies(monkeypatch):
    def boom(self):
        raise RuntimeError("listener broke")

    monkeypatch.setattr(apps._Httpd, "handle_request", boom)
    started = time.monotonic()
    with pytest.raises(GhError, match="callback server stopped") as e:
        create_app(FakeGh(conversion=CONV), info(), manifest, ScriptedPrompter({}), open_browser=lambda u: True, timeout_s=30)
    assert time.monotonic() - started < 5 and "GitHub App to be created" in str(e.value)


def test_create_app_closes_the_server_when_the_exchange_fails():
    urls = []

    def opener(url: str) -> bool:
        urls.append(url)
        return auto_callback(url)

    gh = FakeGh(conversion=CONV, fail_once={("POST", "app-manifests/c0de/conversions"): 422})
    with pytest.raises(GhError):
        create_app(gh, info(), manifest, ScriptedPrompter({}), open_browser=opener)
    assert refuses_to_connect(urls[0])


@pytest.mark.parametrize("bad", [{"id": 7, "slug": "s", "webhook_secret": "PEMVALUE"}, {"id": "7", "slug": "s", "pem": "PEMVALUE"},
                                 {"id": 7, "slug": "", "pem": "PEMVALUE"}, {"id": 7, "slug": "s", "pem": ""}, ["PEMVALUE"], "PEMVALUE"])
def test_malformed_conversion_is_refused_without_echoing_it(bad):
    with pytest.raises(GhError) as e:
        create_app(FakeGh(conversion=bad), info(), manifest, ScriptedPrompter({}), open_browser=auto_callback)
    assert "PEMVALUE" not in str(e.value) and "PEMVALUE" not in repr(e.value)


@pytest.mark.parametrize("over", [
    {"owner": {"login": "o", "id": 8, "type": "User"}},
    {"owner": {"login": "mallory", "id": 7, "type": "User"}},
    {"owner": None},
    {"name": "prgate-other-abc123"},
    {"name": None},
    {"permissions": {**GATE_PERMISSIONS, "administration": "write"}},
    {"permissions": {**GATE_PERMISSIONS, "contents": "write"}},
    {"permissions": None},
])
def test_conversion_for_a_different_app_is_refused_without_echoing_the_key(over):
    with pytest.raises(GhError, match="created App") as e:
        create_app(FakeGh(conversion=conv(**over)), info(), manifest, ScriptedPrompter({}), open_browser=auto_callback)
    assert "SECRETKEY" not in str(e.value) and "BEGIN" not in str(e.value) and "mallory" not in str(e.value)


def test_conversion_without_a_permissions_field_is_refused():
    reply = conv()
    del reply["permissions"]
    with pytest.raises(GhError, match="created App"):
        create_app(FakeGh(conversion=reply), info(), manifest, ScriptedPrompter({}), open_browser=auto_callback)


def test_app_creds_repr_hides_the_key():
    assert "SECRET" not in repr(AppCreds(1, "s", "SECRET")) and "SECRET" not in str(AppCreds(1, "s", "SECRET"))


# --- app_exists / ensure_installed -----------------------------------------------------------

def test_app_exists_reads_apps_slug():
    gh = FakeGh(apps={"prgate-r-abc123": {"slug": "prgate-r-abc123", "id": 7}})
    assert app_exists(gh, "prgate-r-abc123") is True
    assert app_exists(gh, "other") is False


def test_app_exists_raises_on_other_errors():
    gh = FakeGh(fail_once={("GET", "apps/s"): 500})
    with pytest.raises(GhError):
        app_exists(gh, "s")


def test_app_exists_refuses_an_unsafe_slug():
    with pytest.raises(ValueError):
        app_exists(FakeGh(), "../user")


def test_ensure_installed_returns_at_once_when_already_installed():
    gh = FakeGh(installations=[{"id": 5, "app_slug": "s"}], installation_repos={5: [100]})
    ensure_installed(gh, info(), "s", ScriptedPrompter({}), open_browser=lambda u: pytest.fail("opened a browser"), timeout_s=1)


def test_ensure_installed_finds_the_repo_on_a_later_page():
    gh = FakeGh(installations=[{"id": 5, "app_slug": "s"}], installation_repos={5: [*range(1000, 1120), 100]})
    ensure_installed(gh, info(), "s", ScriptedPrompter({}), open_browser=lambda u: pytest.fail("opened a browser"), timeout_s=1)


def test_ensure_installed_refuses_more_pages_than_it_can_check():
    gh = FakeGh(installations=[{"id": 5, "app_slug": "s"}], installation_repos={5: list(range(1000, 2000))})
    with pytest.raises(GhError, match="too many"):
        ensure_installed(gh, info(), "s", ScriptedPrompter({}), open_browser=lambda u: True, timeout_s=1, poll_s=0.01)


def test_ensure_installed_opens_the_install_page_and_waits_for_the_repo():
    gh = FakeGh(installations=[{"id": 4, "app_slug": "other"}], installation_repos={4: [100]})
    opened = []

    def install(url: str) -> bool:
        opened.append(url)
        gh.installations.append({"id": 5, "app_slug": "s"})
        gh.installation_repos[5] = [99, 100]
        return True

    ensure_installed(gh, info(), "s", ScriptedPrompter({}), open_browser=install, timeout_s=2, poll_s=0.01)
    assert opened == ["https://github.com/apps/s/installations/new"]


def test_ensure_installed_prints_the_url_when_no_browser():
    gh = FakeGh()
    p = ScriptedPrompter({})

    def install(url: str) -> bool:
        gh.installations.append({"id": 5, "app_slug": "s"})
        gh.installation_repos[5] = [100]
        return False

    ensure_installed(gh, info(), "s", p, open_browser=install, timeout_s=2, poll_s=0.01)
    assert any("https://github.com/apps/s/installations/new" in s for s in p.said)


def test_ensure_installed_times_out_naming_the_step():
    gh = FakeGh(installations=[{"id": 5, "app_slug": "s"}], installation_repos={5: [99]})
    with pytest.raises(GhError, match="timed out waiting for the GitHub App to be installed"):
        ensure_installed(gh, info(), "s", ScriptedPrompter({}), open_browser=lambda u: True, timeout_s=0.2, poll_s=0.01)
