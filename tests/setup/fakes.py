"""In-memory stand-ins for `Gh` and `Prompter`. Later tasks add constructor keywords as needed."""
from __future__ import annotations

import base64
import copy
import hashlib
import html
import json
import re
import time
import urllib.request
from urllib.parse import parse_qs, quote, unquote
from typing import Any

from prgate.setup.gh import GhError


class FakeGh:
    """Repo state: info, rulesets, environments (with branch policies), secret names, apps,
    installations, refs, contents and PRs. Every write is recorded in `writes`, every GET in `reads`.

    `contents` maps a path to its text (or bytes) on the default branch. It is served by the contents API
    (files base64-encoded like GitHub, directories as listings) and changed only by a Git Data API commit
    that moves the default branch. `protected=True` (or `(status, message)`) refuses that ref update.
    `undecodable` paths come back the way GitHub returns files over 1 MB (no base64 content).
    `fail_secret=True` makes `set_env_secret` fail with an error that echoes the value, as a careless CLI might.
    `empty=True` (or 404/409) is a repo with no commits: reading the default-branch ref fails with that status.
    `entry_types` marks contents paths as `symlink` or `submodule` (listed as such, never served as files).
    `policy_race` / `pr_race` make another actor create the policy / PR just before ours, so ours gets a 422.
    `pr_without_url` makes POST pulls reply without `html_url`. `commits` may be preset (sha -> tree, parents,
    message); `compare/{base}...{head}` answers from their parent links. Default-branch ref updates are recorded in `default_ref_bodies`; a forced one is refused.

    With `conversion=None` the App conversion answers for the App the browser asked for: `browse` is a stand-in
    browser that reads the manifest name from the start page and calls back with that name as the code, and it
    installs an App when sent to its install page. `merge_after_s` merges the open `prgate-setup` PR that many
    seconds after it was opened (None: never). `check_on_selftest` is the pr-gate check posted when a self-test
    PR opens: "auto" (from the newest App, neutral), None (nothing) or {"name", "app_id"[, "conclusion"]}."""

    PEM_MARK = "FAKEPEMBODY"

    def __init__(self, *, repo: str = "o/r", login: str = "owner", scopes: frozenset[str] | None = frozenset({"repo", "workflow"}),
                 default_branch: str = "main", private: bool = False, plan: str | None = "free",
                 protection_probe: int = 404, permissions: dict | None = None, owner_is_org: bool = False,
                 org_role: str = "admin", org_state: str = "active",
                 org_membership_error: int | None = None, org_plan_error: int | None = None, fail_once: dict[tuple[str, str], int] | None = None,
                 conversion: Any = None, **state: Any) -> None:
        self.repo = repo
        self._login = login
        self._scopes = frozenset(scopes) if scopes is not None else None
        owner = repo.split("/")[0] if owner_is_org else login
        self.plan = plan
        self.protection_probe = protection_probe  # status of GET .../protection: 200, 404 (not protected) or an error
        self.owner_is_org = owner_is_org
        self.org_role = org_role
        self.org_state = org_state
        self.org_membership_error = org_membership_error
        self.org_plan_error = org_plan_error
        self.info: dict = {"full_name": repo, "default_branch": default_branch, "private": private, "id": 100,
                           "owner": {"login": owner, "id": 7, "type": "Organization" if owner_is_org else "User"},
                           "permissions": permissions if permissions is not None else {"admin": True, "push": True}}
        self.rulesets: list[dict] = []
        self.environments: dict[str, dict] = {}  # name -> {"branch_policies": [names]}
        self.secrets: dict[str, set[str]] = {}  # env -> secret names
        self.apps: dict[str, dict] = {}
        self.installations: list[dict] = []
        self.installation_repos: dict[int, list[int]] = {}  # installation id -> repo ids it can reach
        self.conversion = conversion  # reply to POST app-manifests/{code}/conversions
        self.refs: dict[str, str] = {f"heads/{default_branch}": "0" * 40}
        self.contents: dict[str, str] = {}
        self.prs: list[dict] = []
        self.check_runs: dict[str, list[str]] = {}  # commit sha -> check names; dict order is newest first
        self.fail_once = dict(fail_once or {})  # (method, path) -> status
        self.writes: list[tuple[str, str]] = []
        self.reads: list[str] = []
        self.protected: bool | tuple[int, str] = False
        self.fail_secret = False
        self.undecodable: set[str] = set()
        self.commit_count = 0
        self.empty: bool | int = False
        self.entry_types: dict[str, str] = {}
        self.policy_race = False
        self.pr_race = False
        self.pr_without_url = False
        self.default_ref_bodies: list[dict] = []
        self.merge_after_s: float | None = None
        self.close_setup_pr = False  # the open prgate-setup PR gets closed without merging
        self.check_on_selftest: Any = "auto"
        self.selftest_checks: dict[str, list[dict]] = {}  # commit sha -> check runs with app and conclusion
        self._pr_opened: dict[int, float] = {}
        self.blob_paths: list[str] = []  # paths of the blobs written, in tree order, filled at tree creation
        self.blobs: dict[str, str | bytes] = {}
        self.trees: dict[str, dict[str, str | bytes]] = {}
        self.commits: dict[str, dict] = {}
        self._policy_ids: dict[str, list[int]] = {}
        self._next_id = 1000
        for k, v in state.items():
            if not hasattr(self, k):
                raise TypeError(f"unknown FakeGh state {k!r}")
            setattr(self, k, v)
        if self.empty:
            self.refs.pop(f"heads/{default_branch}", None)

    @classmethod
    def fully_set_up(cls, **kw: Any) -> "FakeGh":
        """A repo where every init step finds nothing to do: environment, secrets, gate files, App, install."""
        import prgate
        from prgate.setup.files import SetupAnswers, render_config, render_workflow

        gh = cls(**kw)
        gh.environments["prgate-verdict"] = {"branch_policies": [gh.info["default_branch"]],
                                             "deployment_branch_policy": {"protected_branches": False,
                                                                          "custom_branch_policies": True}}
        gh.secrets["prgate-verdict"] = {"PRGATE_APP_ID", "PRGATE_APP_KEY"}
        gh.contents[".github/workflows/pr-gate.yml"] = render_workflow(f"Abubakarjutt/PRGate@v{prgate.__version__}")
        gh.contents[".prgate.toml"] = render_config(SetupAnswers(language="python", ci_checks=(), approvers=(gh._login,)))
        gh.apps["prgate"] = {"slug": "prgate", "id": 1, "owner": copy.deepcopy(gh.info["owner"])}
        gh.installations.append({"id": 1, "app_slug": "prgate"})
        gh.installation_repos[1] = [gh.info["id"]]
        return gh

    @classmethod
    def resume(cls, old: "FakeGh") -> "FakeGh":
        new = copy.deepcopy(old)
        new.fail_once = {}
        return new

    @property
    def open_prs(self) -> list[dict]:
        return [p for p in self.prs if p.get("state", "open") == "open"]

    @property
    def branches(self) -> list[str]:
        return [r.removeprefix("heads/") for r in self.refs if r.startswith("heads/")]

    def browse(self, url: str) -> bool:
        """A browser for the App manifest flow: callback with the manifest's name as the code, or install."""
        if url.startswith("http://127.0.0.1:"):
            with urllib.request.urlopen(url, timeout=5) as r:
                page = r.read().decode()
            manifest = json.loads(html.unescape(re.search(r'name="manifest" value="([^"]*)"', page)[1]))
            action = html.unescape(re.search(r'action="([^"]+)"', page)[1])
            state = re.search(r"[?&]state=([^&]+)", action)[1]
            base = url.split("/start", 1)[0]
            with urllib.request.urlopen(f"{base}/callback?code={quote(manifest['name'])}&state={state}", timeout=5) as r:
                assert r.status == 200
            return True
        m = re.fullmatch(r"https://github\.com/apps/([^/]+)/installations/new", url)
        if m:
            self._next_id += 1
            self.installations.append({"id": self._next_id, "app_slug": m[1]})
            self.installation_repos[self._next_id] = [self.info["id"]]
            return True
        return False

    def add_app(self, slug: str, app_id: int, owner: dict | None = None, installed: bool = True) -> None:
        """An App on GitHub (owned by the repo owner unless `owner` is given), installed on this repo by default."""
        self.apps[slug] = {"slug": slug, "id": app_id, "owner": copy.deepcopy(owner or self.info["owner"])}
        if installed:
            self._next_id += 1
            self.installations.append({"id": self._next_id, "app_slug": slug})
            self.installation_repos[self._next_id] = [self.info["id"]]

    def _maybe_merge(self) -> None:
        if self.close_setup_pr:
            for pr in self.open_prs:
                if pr.get("head") == "prgate-setup":
                    pr["state"] = "closed"
                    pr["merged"] = False
        if self.merge_after_s is None:
            return
        for pr in self.open_prs:
            opened = self._pr_opened.get(pr["number"])
            if pr.get("head") == "prgate-setup" and opened is not None and time.monotonic() - opened >= self.merge_after_s:
                sha = self.refs["heads/prgate-setup"]
                self.contents = dict(self.trees[self.commits[sha]["tree"]])
                self.refs[f"heads/{self.info['default_branch']}"] = sha
                pr["state"] = "closed"
                pr["merged"] = True

    def _selftest_check(self, head: str) -> None:
        sha = self.refs.get(f"heads/{head}")
        want = self.check_on_selftest
        if sha is None or want is None:
            return
        if want == "auto":
            if not self.apps:
                return
            want = {"name": "pr-gate", "app_id": list(self.apps.values())[-1]["id"]}
        self.selftest_checks.setdefault(sha, []).append(
            {"name": want["name"], "head_sha": sha, "status": "completed", "app": {"id": want["app_id"]},
             "conclusion": want.get("conclusion", "neutral")})

    def login(self) -> str:
        return self._login

    def scopes(self) -> frozenset[str] | None:
        return self._scopes

    def set_env_secret(self, repo: str, env: str, name: str, value: str) -> None:
        if self.fail_secret:
            raise GhError(500, f"failed to set secret {name} to {value} (HTTP 500)")
        self._maybe_fail("PUT", f"secret/{env}/{name}")
        self.writes.append(("SECRET", f"{repo}/{env}/{name}"))  # never the value
        self.secrets.setdefault(env, set()).add(name)

    def _maybe_fail(self, method: str, path: str) -> None:
        status = self.fail_once.pop((method, path), None)
        if status is not None:
            raise GhError(status, f"injected failure (HTTP {status})")

    # --- contents and Git Data API helpers ---

    def _file_reply(self, path: str) -> dict:
        data = self.contents[path]
        raw = data.encode() if isinstance(data, str) else data
        name = path.rsplit("/", 1)[-1]
        if path in self.undecodable:
            return {"type": "file", "name": name, "path": path, "encoding": "none", "content": "", "size": len(raw)}
        b64 = base64.b64encode(raw).decode()
        wrapped = "\n".join(b64[i:i + 60] for i in range(0, len(b64), 60)) + "\n"  # GitHub wraps base64 at 60
        return {"type": "file", "name": name, "path": path, "encoding": "base64", "content": wrapped, "size": len(raw)}

    def _contents_get(self, rest: str) -> Any:
        target, _, query = rest.partition("?")
        target = unquote(target)
        ref = parse_qs(query).get("ref", [self.info["default_branch"]])[0]
        if ref != self.info["default_branch"]:
            raise GhError(404, "No commit found for the ref (HTTP 404)")
        if target in self.entry_types:
            kind = self.entry_types[target]
            name = target.rsplit("/", 1)[-1]
            if kind == "symlink":
                return {"type": "symlink", "name": name, "path": target, "target": "../elsewhere"}
            return {"type": kind, "name": name, "path": target, "submodule_git_url": "https://example.invalid/x.git"}
        if target in self.contents:
            return self._file_reply(target)
        prefix = target.rstrip("/") + "/"
        children: dict[str, str] = {}
        for p in self.contents:
            if p.startswith(prefix):
                head, sep, _ = p[len(prefix):].partition("/")
                children[head] = "dir" if sep else self.entry_types.get(p, "file")
        if not children:
            raise GhError(404, "Not Found (HTTP 404)")
        return [{"name": n, "path": prefix + n, "type": t} for n, t in sorted(children.items())]

    def _new_sha(self, *parts: Any) -> str:
        self._next_id += 1
        return hashlib.sha1(repr((self._next_id, *parts)).encode()).hexdigest()

    def _is_ancestor(self, older: str, newer: str) -> bool:
        seen, todo = set(), [newer]
        while todo:
            sha = todo.pop()
            if sha in seen:
                continue
            seen.add(sha)
            parents = self.commits.get(sha, {}).get("parents", [])
            if older in parents:
                return True
            todo.extend(parents)
        return False

    def _tree_of(self, commit_sha: str) -> str:
        if self.commits.get(commit_sha, {}).get("tree"):
            return self.commits[commit_sha]["tree"]
        sha = hashlib.sha1(f"tree-of-{commit_sha}".encode()).hexdigest()  # a commit made before the fake existed
        self.trees.setdefault(sha, dict(self.contents))
        return sha

    def _policies(self, env: str) -> list[str]:
        names = self.environments.setdefault(env, {"branch_policies": []}).setdefault("branch_policies", [])
        ids = self._policy_ids.get(env)
        if ids is None or len(ids) != len(names):
            ids = self._policy_ids[env] = []
            for _ in names:
                self._next_id += 1
                ids.append(self._next_id)
        return names

    def api(self, method: str, path: str, body: dict | None = None) -> Any:
        method = method.upper()
        self._maybe_merge()
        self._maybe_fail(method, path)
        if method != "GET":
            self.writes.append((method, path))
        else:
            self.reads.append(path)
        base = f"repos/{self.repo}"
        if method == "GET":
            if path == base:
                return copy.deepcopy(self.info)
            if path == "user":
                return {"login": self._login, "id": 7, "plan": {"name": self.plan} if self.plan else None}
            if self.owner_is_org and path == f"orgs/{self.info['owner']['login']}":
                if self.org_plan_error:
                    raise GhError(self.org_plan_error, f"error (HTTP {self.org_plan_error})")
                return {"login": self.info["owner"]["login"], "plan": {"name": self.plan} if self.plan else None}
            if self.owner_is_org and path == f"user/memberships/orgs/{self.info['owner']['login']}":
                if self.org_membership_error:
                    raise GhError(self.org_membership_error, f"Resource not accessible (HTTP {self.org_membership_error})")
                return {"role": self.org_role, "state": self.org_state}
            if path == f"{base}/branches/{self.info['default_branch']}/protection":
                if self.protection_probe == 200:
                    return {}
                if self.protection_probe == 404:
                    raise GhError(404, "Branch not protected (HTTP 404)")
                raise GhError(self.protection_probe, f"Upgrade to GitHub Pro or make this repository public to enable this feature. (HTTP {self.protection_probe})"
                              if self.protection_probe == 403 else f"error (HTTP {self.protection_probe})")
            if path == f"{base}/rulesets":
                return copy.deepcopy(self.rulesets)
            m = re.fullmatch(rf"{base}/environments/([^/]+)/secrets\?per_page=100&page=(\d+)", path)
            if m:
                env = unquote(m[1])
                if env not in self.environments:
                    raise GhError(404, "Not Found (HTTP 404)")
                names = sorted(self.secrets.get(env, set()))[(int(m[2]) - 1) * 100: int(m[2]) * 100]
                return {"total_count": len(self.secrets.get(env, set())), "secrets": [{"name": n} for n in names]}
            m = re.fullmatch(rf"{base}/commits/([0-9a-f]+)/check-runs\?check_name=pr-gate&per_page=100", path)
            if m:
                runs = [r for r in self.selftest_checks.get(m[1], []) if r["name"] == "pr-gate"]
                return {"total_count": len(runs), "check_runs": copy.deepcopy(runs)}
            m = re.fullmatch(rf"{base}/environments/([^/]+)", path)
            if m:
                if m[1] not in self.environments:
                    raise GhError(404, "Not Found (HTTP 404)")
                return {"name": m[1], **copy.deepcopy(self.environments[m[1]])}
            m = re.fullmatch(rf"{base}/contents/(.+)", path)
            if m:
                return self._contents_get(m[1])
            m = re.fullmatch(rf"{base}/environments/([^/]+)/deployment-branch-policies\?per_page=(\d+)&page=(\d+)", path)
            if m:
                env, per, page = unquote(m[1]), int(m[2]), int(m[3])
                if env not in self.environments:
                    raise GhError(404, "Not Found (HTTP 404)")
                names = self._policies(env)
                items = [{"id": i, "name": n, "type": "branch"} for i, n in zip(self._policy_ids[env], names)]
                return {"total_count": len(items), "branch_policies": items[(page - 1) * per: page * per]}
            m = re.fullmatch(rf"{base}/compare/([0-9a-f]+)\.\.\.([0-9a-f]+)", path)
            if m:
                b, h = m[1], m[2]
                if b == h:
                    return {"status": "identical"}
                if self._is_ancestor(b, h):
                    return {"status": "ahead"}
                if self._is_ancestor(h, b):
                    return {"status": "behind"}
                return {"status": "diverged"}
            m = re.fullmatch(rf"{base}/git/commits/([0-9a-f]+)", path)
            if m:
                c = self.commits.get(m[1], {})
                return {"sha": m[1], "tree": {"sha": self._tree_of(m[1])}, "message": c.get("message", ""),
                        "parents": [{"sha": x} for x in c.get("parents", [])]}
            if path == f"{base}/pulls":
                return copy.deepcopy(self.prs)
            m = re.fullmatch(rf"{base}/pulls/(\d+)", path)
            if m:
                pr = next((p for p in self.prs if p.get("number") == int(m[1])), None)
                if pr is None:
                    raise GhError(404, "Not Found (HTTP 404)")
                return {"merged": False, **copy.deepcopy(pr)}
            m = re.fullmatch(rf"{base}/pulls\?(.+)", path)
            if m:
                q = parse_qs(m[1])
                head = q.get("head", [""])[0].partition(":")[2]
                return [copy.deepcopy(p) for p in self.prs
                        if p.get("head") == head and p.get("base") == q.get("base", [None])[0] and p.get("state", "open") == "open"]
            m = re.fullmatch(rf"{base}/commits\?sha=([^&]+)&per_page=(\d+)", path)
            if m:
                if unquote(m[1]) != self.info["default_branch"]:
                    return []
                return [{"sha": sha} for sha in list(self.check_runs)[: int(m[2])]]
            m = re.fullmatch(rf"{base}/commits/([^/]+)/check-runs\?per_page=100", path)
            if m:
                if m[1] not in self.check_runs:
                    raise GhError(404, "Not Found (HTTP 404)")
                names = self.check_runs[m[1]]
                return {"total_count": len(names), "check_runs": [{"name": n} for n in names]}
            m = re.fullmatch(rf"{base}/git/ref/(.+)", path)
            if m:
                if self.empty and unquote(m[1]) == f"heads/{self.info['default_branch']}":
                    status = 409 if self.empty is True else int(self.empty)
                    raise GhError(status, f"Git Repository is empty. (HTTP {status})")
                if m[1] not in self.refs:
                    raise GhError(404, "Not Found (HTTP 404)")
                return {"ref": f"refs/{m[1]}", "object": {"sha": self.refs[m[1]]}}
            m = re.fullmatch(r"user/installations(?:\?per_page=100&page=(\d+))?", path)
            if m:
                page = int(m[1] or 1)
                return {"total_count": len(self.installations), "installations": copy.deepcopy(self.installations[(page - 1) * 100: page * 100])}
            m = re.fullmatch(r"user/installations/(\d+)/repositories\?per_page=100&page=(\d+)", path)
            if m:
                ids = self.installation_repos.get(int(m[1]), [])
                page = int(m[2])
                return {"total_count": len(ids), "repositories": [{"id": i} for i in ids[(page - 1) * 100: page * 100]]}
            m = re.fullmatch(r"apps/([^/?]+)", path)
            if m:
                if m[1] not in self.apps:
                    raise GhError(404, "Not Found (HTTP 404)")
                return copy.deepcopy(self.apps[m[1]])
            raise GhError(404, f"Not Found (HTTP 404): {path}")
        if method == "PUT":
            m = re.fullmatch(rf"{base}/environments/([^/]+)", path)
            if m:
                env = self.environments.setdefault(unquote(m[1]), {"branch_policies": []})
                if body and "deployment_branch_policy" in body:
                    env["deployment_branch_policy"] = copy.deepcopy(body["deployment_branch_policy"])
                return {"name": m[1]}
            m = re.fullmatch(rf"{base}/contents/(.+)", path)
            if m:
                self.contents[m[1]] = (body or {}).get("content", "")
                return {"content": {"path": m[1]}}
        if method == "POST":
            m = re.fullmatch(r"app-manifests/([^/]+)/conversions", path)
            if m and self.conversion is None:
                from prgate.setup.apps import GATE_PERMISSIONS
                self._next_id += 1
                name = unquote(m[1])
                reply = {"id": self._next_id, "slug": name, "name": name, "owner": copy.deepcopy(self.info["owner"]),
                         "permissions": dict(GATE_PERMISSIONS), "events": [], "webhook_secret": "WHSECRET",
                         "pem": "-----BEGIN RSA PRIVATE " + f"KEY-----\n{self.PEM_MARK}{self._next_id}\n-----END RSA PRIVATE KEY-----\n"}
                self.apps[name] = {"slug": name, "id": self._next_id, "owner": copy.deepcopy(self.info["owner"])}
                return reply
            if m:
                reply = copy.deepcopy(self.conversion)
                if isinstance(reply, dict) and isinstance(reply.get("slug"), str):
                    self.apps[reply["slug"]] = {"slug": reply["slug"], "id": reply.get("id"),
                                                "owner": copy.deepcopy(reply.get("owner"))}
                return reply
            m = re.fullmatch(rf"{base}/environments/([^/]+)/deployment-branch-policies", path)
            if m:
                env = unquote(m[1])
                names = self._policies(env)
                name = (body or {}).get("name")
                if self.policy_race and name not in names:
                    names.append(name)
                    self._next_id += 1
                    self._policy_ids[env].append(self._next_id)
                if name in names:
                    raise GhError(422, "Validation Failed: name already exists (HTTP 422)")
                names.append(name)
                self._next_id += 1
                self._policy_ids[env].append(self._next_id)
                return {"id": self._next_id, "name": (body or {}).get("name"), "type": "branch"}
            if path == f"{base}/pulls":
                head, target = (body or {}).get("head"), (body or {}).get("base")
                if self.pr_race:
                    self.pr_race = False
                    n = len(self.prs) + 1
                    self.prs.append({"number": n, "state": "open", "head": head, "base": target,
                                     "html_url": f"https://github.com/{self.repo}/pull/{n}"})
                if any(p.get("head") == head and p.get("base") == target and p.get("state", "open") == "open"
                       for p in self.prs):
                    raise GhError(422, "Validation Failed: A pull request already exists for o:prgate-setup. (HTTP 422)")
                if self.pr_without_url:
                    self.prs.append({"number": len(self.prs) + 1, "state": "open", **(body or {})})
                    return {"number": len(self.prs)}
                n = len(self.prs) + 1
                pr = {"number": n, "state": "open", "html_url": f"https://github.com/{self.repo}/pull/{n}", **(body or {})}
                self.prs.append(pr)
                self._pr_opened[n] = time.monotonic()
                if isinstance(head, str) and head.startswith("prgate-selftest-"):
                    self._selftest_check(head)
                return copy.deepcopy(pr)
            if path == f"{base}/git/blobs":
                sha = self._new_sha("blob", (body or {}).get("content"))
                self.blobs[sha] = (body or {})["content"]
                return {"sha": sha}
            if path == f"{base}/git/trees":
                files = dict(self.trees[(body or {})["base_tree"]])
                for entry in (body or {})["tree"]:
                    files[entry["path"]] = self.blobs[entry["sha"]]
                    self.blob_paths.append(entry["path"])
                sha = self._new_sha("tree")
                self.trees[sha] = files
                return {"sha": sha}
            if path == f"{base}/git/commits":
                sha = self._new_sha("commit")
                self.commits[sha] = {"tree": (body or {})["tree"], "parents": list((body or {})["parents"]),
                                     "message": (body or {}).get("message", "")}
                self.commit_count += 1
                return {"sha": sha, "html_url": f"https://github.com/{self.repo}/commit/{sha}"}
            if path == f"{base}/git/refs":
                ref = (body or {})["ref"].removeprefix("refs/")
                if ref in self.refs:
                    raise GhError(422, "Reference already exists (HTTP 422)")
                self.refs[ref] = (body or {}).get("sha", "0" * 40)
                return body
        if method == "PATCH":
            m = re.fullmatch(rf"{base}/pulls/(\d+)", path)
            if m:
                pr = next((p for p in self.prs if p.get("number") == int(m[1])), None)
                if pr is None:
                    raise GhError(404, "Not Found (HTTP 404)")
                if (body or {}).get("state") in ("open", "closed"):
                    pr["state"] = body["state"]
                return copy.deepcopy(pr)
            m = re.fullmatch(rf"{base}/git/refs/(.+)", path)
            if m:
                ref = unquote(m[1])
                if ref not in self.refs:
                    raise GhError(422, "Reference does not exist (HTTP 422)")
                sha = (body or {})["sha"]
                if ref == f"heads/{self.info['default_branch']}":
                    self.default_ref_bodies.append(copy.deepcopy(body or {}))
                    if (body or {}).get("force") is not False:
                        raise GhError(422, "the fake refuses a default-branch update that is not force: false (HTTP 422)")
                    if self.protected:
                        status, msg = self.protected if isinstance(self.protected, tuple) else (
                            422, "Protected branch update failed for refs/heads/main.")
                        raise GhError(status, f"{msg} (HTTP {status})")
                    if self.commits.get(sha, {}).get("parents") != [self.refs[ref]]:
                        raise GhError(422, "Update is not a fast forward (HTTP 422)")
                    self.contents = dict(self.trees[self.commits[sha]["tree"]])
                self.refs[ref] = sha
                return {"ref": f"refs/{ref}", "object": {"sha": sha}}
        if method == "DELETE":
            m = re.fullmatch(rf"{base}/git/refs/(heads/.+)", path)
            if m:
                ref = unquote(m[1])
                if ref not in self.refs:
                    raise GhError(422, "Reference does not exist (HTTP 422)")
                if ref == f"heads/{self.info['default_branch']}":
                    raise GhError(422, "the fake refuses to delete the default branch (HTTP 422)")
                del self.refs[ref]
                return None
            m = re.fullmatch(rf"{base}/environments/([^/]+)/deployment-branch-policies/(\d+)", path)
            if m:
                env = unquote(m[1])
                names = self._policies(env)
                ids = self._policy_ids[env]
                i = ids.index(int(m[2]))
                del names[i], ids[i]
                return None
        raise GhError(404, f"Not Found (HTTP 404): {method} {path}")


class UnansweredQuestion(BaseException):
    """Not an Exception, so a broad `except Exception` in the code under test cannot swallow it."""


class ScriptedPrompter:
    """`answers` maps a substring of the question to its answer. An unanswered question raises."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.said: list[str] = []
        self.secret_questions: list[str] = []

    def _answer(self, q: str) -> Any:
        for key, value in self.answers.items():
            if key in q:
                return value
        raise UnansweredQuestion(f"no scripted answer for question: {q!r}")

    def say(self, text: str) -> None:
        self.said.append(text)

    def ask(self, q: str, default: str | None = None) -> str:
        return self._answer(q)

    def secret(self, q: str) -> str:
        self.secret_questions.append(q)
        return self._answer(q)

    def confirm(self, q: str, default: bool) -> bool:
        return self._answer(q)

    def choose(self, q: str, options: list[str], default: str) -> str:
        return self._answer(q)
