import http.client
import http.server
import json
import threading
import urllib.error

import pytest

import prgate
from fake_api import REPO, SLUG, FakeAPI
from prgate import github
from prgate.github import API_ROOT, GitHub, GitHubError

TOKEN = "ghs_SECRETVALUE"
H = "a" * 40


def gh(api=None, slug=SLUG):
    return GitHub(TOKEN, REPO, app_slug=slug, opener=api or FakeAPI())


def test_requests_go_to_the_api_host_with_a_generic_agent():
    api = FakeAPI()
    gh(api).create_check(H, "neutral", "title", "body")
    [(method, url, headers)] = api.seen
    assert method == "POST" and url == f"{API_ROOT}/repos/{REPO}/check-runs"
    assert API_ROOT == "https://api.github.com"
    assert headers["authorization"] == f"Bearer {TOKEN}"
    assert headers["user-agent"] == f"prgate/{prgate.__version__}"
    assert prgate.__version__ == "0.0.1"


def test_create_check_posts_a_completed_pr_gate_run():
    api = FakeAPI()
    gh(api).create_check(H, "neutral", "t", "b")
    [run] = api.runs
    assert (run["name"], run["head_sha"], run["status"], run["conclusion"]) == ("pr-gate", H, "completed", "neutral")
    assert run["output"] == {"title": "t", "summary": "b"}


@pytest.mark.parametrize("token", ["", "a\nb", "a\rb", "tok en", None, 3])
def test_unsafe_tokens_are_refused(token):
    with pytest.raises(ValueError) as e:
        GitHub(token, REPO, opener=FakeAPI())
    if isinstance(token, str) and len(token) > 1:
        assert token not in str(e.value)


@pytest.mark.parametrize("repo", ["", "o", "o/r/x", "../r", "o/..", "o/r?x", "o/r#", "o r/x", "o/r\n"])
def test_unsafe_repo_names_are_refused(repo):
    with pytest.raises(ValueError):
        GitHub(TOKEN, repo, opener=FakeAPI())


@pytest.mark.parametrize("bad", ["abc", "A" * 40, "../" + "a" * 37, None])
def test_methods_refuse_bad_shas_without_a_request(bad):
    api = FakeAPI()
    with pytest.raises(ValueError):
        gh(api).latest_check(bad)
    with pytest.raises(ValueError):
        gh(api).create_check(bad, "neutral", "t", "b")
    assert api.seen == []


def test_pr_number_must_be_a_positive_int():
    api = FakeAPI()
    for bad in ("5", -1, 0, True, "5/../x"):
        with pytest.raises(ValueError):
            gh(api).pr(bad)
    assert api.seen == []


def test_api_errors_carry_the_status_but_never_the_token():
    api = FakeAPI(fail=[("GET", r"/pulls/", 500)])
    with pytest.raises(GitHubError) as e:
        gh(api).pr(5)
    assert e.value.status == 500 and TOKEN not in str(e.value)


def test_latest_check_is_the_newest_from_this_app_by_name_and_head():
    api = FakeAPI()
    api.add_run(H, "mine-old")
    api.add_run(H, "other-app", slug="github-actions")
    api.add_run(H, "mine-new")
    api.add_run(H, "other-name", name="pr-gate-x")
    api.add_run("b" * 40, "other-head")
    assert gh(api).latest_check(H)["output"]["summary"] == "mine-new"


def test_latest_check_ignores_runs_from_other_apps_only():
    api = FakeAPI()
    api.add_run(H, "forged", slug="evil-app")
    assert gh(api).latest_check(H) is None


def test_latest_check_without_a_known_app_trusts_nothing():
    api = FakeAPI()
    api.add_run(H, "mine")
    assert gh(api, slug=None).latest_check(H) is None and api.seen == []


def test_file_reads_base64_content_and_404_is_absent():
    api = FakeAPI()
    api.contents[(".prgate.toml", H)] = b"clear_docs = true\n"
    assert gh(api).file(".prgate.toml", H) == b"clear_docs = true\n"
    assert gh(api).file(".prgate.toml", "b" * 40) is None


def test_the_gate_client_cannot_read_comments():
    # The verdict never reads PR comments, so the App token has no comment-listing call.
    assert not hasattr(gh(FakeAPI()), "comments")


def test_non_json_reply_is_an_api_error():
    from fake_api import _Response

    class Bad(FakeAPI):
        def open(self, req, timeout=None):
            return _Response(200, b"<html>")

    with pytest.raises(GitHubError):
        gh(Bad()).pr(5)


class _Redirector(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", type(self).target)
        self.end_headers()

    def log_message(self, *a):
        pass


class _Sink(http.server.BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        type(self).hits.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


@pytest.fixture
def servers():
    sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    redir = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Redirector)
    _Redirector.target = f"http://127.0.0.1:{sink.server_port}/steal"
    _Sink.hits = []
    for s in (sink, redir):
        threading.Thread(target=lambda s=s: s.serve_forever(0.01), daemon=True).start()
    yield redir
    for s in (sink, redir):
        s.shutdown()
        s.server_close()


def test_the_real_opener_refuses_redirects(servers):
    import urllib.request

    req = urllib.request.Request(f"http://127.0.0.1:{servers.server_port}/x",
                                 headers={"Authorization": f"Bearer {TOKEN}"})
    with pytest.raises(urllib.error.HTTPError) as e:
        github.build_opener().open(req, timeout=5)
    assert e.value.code == 302
    assert _Sink.hits == []


def test_a_redirect_reply_is_an_api_error():
    api = FakeAPI(fail=[("GET", r"/pulls/", 301)])
    with pytest.raises(GitHubError):
        gh(api).pr(5)


def test_oversized_reply_is_an_api_error(monkeypatch):
    monkeypatch.setattr(github, "MAX_REPLY", 10)
    api = FakeAPI()
    api.prs[5] = {"number": 5, "pad": "x" * 100}
    with pytest.raises(GitHubError):
        gh(api).pr(5)


def test_api_root_is_fixed():
    assert json.dumps(github.API_ROOT) == '"https://api.github.com"'
    with pytest.raises(TypeError):
        GitHub(TOKEN, REPO, opener=FakeAPI(), root="http://127.0.0.1")


@pytest.mark.parametrize("exc", [http.client.IncompleteRead(b""), http.client.BadStatusLine("x"),
                                 http.client.LineTooLong("header")])
def test_a_truncated_or_malformed_reply_is_an_api_error(exc):
    from fake_api import _Response

    class Broken(FakeAPI):
        def open(self, req, timeout=None):
            r = _Response(200, b"{}")

            def read(*a):
                raise exc
            r.read = read
            return r

    with pytest.raises(GitHubError) as e:
        gh(Broken()).pr(5)
    assert TOKEN not in str(e.value)


def test_a_malformed_status_line_from_open_is_an_api_error():
    class Broken(FakeAPI):
        def open(self, req, timeout=None):
            raise http.client.BadStatusLine("garbage")

    with pytest.raises(GitHubError):
        gh(Broken()).file(".prgate.toml", H)
