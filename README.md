> **Experimental, report-only.** prgate never blocks a merge yet. Read what it checks before relying on it.

# prgate

prgate is a GitHub pull-request gate. For each pull request it reads the diff and the changed files as git objects, decides one of three outcomes, and posts the result as a check named `pr-gate` with a short report. It uses no LLM and runs no tests. The check always ends as `neutral`, so it never stops a merge. The verdict is advice for the person who reviews the pull request.

## Install

```
uvx prgate init
```

or

```
pipx install prgate
prgate init
```

Run it inside a clone of your repository. `prgate init` walks you through setup. [docs/setup.md](https://github.com/Abubakarjutt/PRGate/blob/main/docs/setup.md) lists every step, and every manual alternative.

## Requirements

- The `gh` command-line tool, logged in as an admin of the repository.
- Python 3.12 or newer.
- A public repository, or a paid GitHub plan for a private one. Private repositories on the free plan are refused, because environment secrets are not available there.

## What each verdict means

**Blocked.** Only on proof anyone can check:
- a test was deleted, a test newly became skipped, or a test's asserts dropped to zero. Each one is named;
- a secret of a well-known format was added, such as an AWS key ID, an `sk_live_` key, an `xoxb-` token or a private key with its key body. The report never repeats the secret;
- a dependency newly declared in `pyproject.toml`, `requirements*.txt`, `setup.cfg` or `setup.py` has a name that PyPI does not know (404).

When prgate is unsure, it does not say Blocked. A moved, renamed or merged test, a test whose checks may live in a helper or fixture, fewer asserts that are still above zero, an unknown import, a `ghp_` token, a private-key header with no key body, an example secret value, a secret-like string in a test directory, a dependency in a repository that mentions another package index, a very new package, or an unreachable registry all go to a person.

The names of newly declared dependencies are sent to pypi.org from the runner, private repositories included. A package index set only outside the repository, such as an organisation-level CI secret, is invisible to prgate, so a private package can still be reported as not on PyPI. Use `/gate override` for that.

A test that is renamed, changed and moved to another file in the same pull request can still be reported as deleted, because nothing ties the old test to the new one. Use `/gate override` for that too, or make the move in its own pull request.

**Sent to a person.** The report asks one specific question. This covers code changes in general, areas that always need a human (authentication, payments, migrations, CI configuration), agent instruction files, config without a rollout marker, dependency changes, files prgate does not recognise, and any check that could not run.

**Cleared.** Documentation-only changes on a short, strict list. Cleared means those checks passed. It is not proof that the change is correct.

Every Blocked report says how to override it. An approver named in `.prgate.toml` comments `/gate override <40-character head sha> <reason>`. The next report on that head shows the override. For now this only records the decision, because nothing is enforced. There is no enforce mode yet.

## What it never does

- It never runs code from a pull request. No job installs, imports or executes anything from the pull request.
- It never posts a secret, and never repeats one it finds.
- It never blocks a merge. The `pr-gate` check always concludes `neutral`.

It checks Python tests only. Secrets and change types are checked for any language. Pull requests into a branch other than the default branch get no report, and the Actions run for such a pull request may show the verdict job as failed or blocked. That is expected.

## Check your setup

```
prgate doctor
```

It checks the files, the workflow, the App, the install, the environment and the secrets (by name only) without changing anything. It does not re-run the self-test. It prints one line per step and gives a fix for each step that is not in place. Run it again after you change any workflow file.

## Remove it

Delete `.github/workflows/pr-gate.yml` and `.prgate.toml`, delete the `prgate-verdict` environment in the repository settings, and delete the GitHub App that `prgate init` created. [docs/setup.md](https://github.com/Abubakarjutt/PRGate/blob/main/docs/setup.md#removing-prgate) has the details.

## More

- [docs/setup.md](https://github.com/Abubakarjutt/PRGate/blob/main/docs/setup.md): setup, the security boundary, and manual steps.
- [SECURITY.md](https://github.com/Abubakarjutt/PRGate/blob/main/SECURITY.md): how to report a vulnerability.
- [CONTRIBUTING.md](https://github.com/Abubakarjutt/PRGate/blob/main/CONTRIBUTING.md): how to contribute.

## Licence

MIT. See [LICENSE](https://github.com/Abubakarjutt/PRGate/blob/main/LICENSE).
