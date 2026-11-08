# Setting up prgate

prgate is experimental and report-only. The `pr-gate` check always concludes `neutral`, so it never blocks a merge. There is no enforce mode yet.

This page says what `prgate init` does, step by step, what protects the gate App's key, and how to do each step by hand.

## Before you start

- Install the `gh` command-line tool and log in as an admin of the repository. Your token needs the `workflow` scope (`gh auth refresh -s workflow`).
- Use Python 3.12 or newer.
- Use a public repository, or a private one on a paid plan. On the free plan, private repositories have no environment secrets, so `init` refuses them.
- For an organisation repository, an organisation owner must run `init`, because only an owner can create the organisation's GitHub App.
- Run it from a clone of the repository, so `init` can read its `origin` remote.

## What `prgate init` does

`init` only does the steps that are not already done. You can run it again at any time.

1. **Preflight.** Read-only. It checks that `gh` is installed and logged in, that you are an admin, that your token can write workflow files, and that the plan supports environment secrets.
2. **Questions.** It looks at the project. If it is not a Python project, it warns that prgate checks Python tests only and asks whether to continue. It then asks which CI checks the report should list (it suggests the ones that ran on recent commits of the default branch), and which GitHub logins may override the gate. The default approver is you.
3. **Files.** It writes `.prgate.toml` (with `mode = "silent"`) and `.github/workflows/pr-gate.yml` to the default branch in one commit. If the default branch is protected, it opens a pull request instead and waits up to 15 minutes for you to merge it. If you do not merge in time, merge it and run `prgate init` again. If a file already exists with different content, `init` shows the difference and asks before replacing it, whoever wrote it. If you answer no, `init` stops and changes nothing more. A file that is already identical is left alone without a question.
4. **Workflow check.** Before it creates any App, `init` reads the workflow files on the default branch and requires two things:
   - `.github/workflows/pr-gate.yml` is exactly what `init` rendered. A single trailing newline is ignored.
   - No other workflow file on the default branch refers to `prgate-verdict`. This includes references written with YAML escapes, because prgate decodes `\x`, `\u` and `\U` escapes before it matches. It also covers quotes and whitespace inside the name.

   If either is not true, `init` stops and names the file.
5. **Environment.** It creates the environment `prgate-verdict` and allows only the default branch to deploy to it. This is done before the key exists.
6. **Gate App.** It opens your browser to GitHub's page for creating a GitHub App from a manifest. You click Create. The App is named `prgate-<repo>-<6 hex>`, is private, has no webhook and subscribes to no events. Its permissions are:
   - Checks: write
   - Contents: read
   - Pull requests: read
   - Metadata: read

   GitHub shows an App's private key only once, so `init` stores the App id and key in the `prgate-verdict` environment secrets (`PRGATE_APP_ID` and `PRGATE_APP_KEY`) as soon as it has them. The key is never printed, logged or written to a file.
7. **Install.** It asks you to install the App on this repository only, and waits.
8. **Self-test.** It opens a pull request that adds `prgate-selftest.txt`, waits for a `neutral` `pr-gate` check from the gate App on that pull request, and then closes the pull request and deletes its branch. It does this even if you press Ctrl-C. If the report does not arrive, `init` says so and exits with an error.
9. **Summary.** It prints the state of every setup step, including the self-test result. Run `prgate doctor` to check the setup again.

### What is kept on your machine

`init` stores only the App id and slug, in `~/.config/prgate/<owner>__<repo>/state.json`, with mode 0600. It never stores the key. If this file is lost, `doctor` finds the App by its installation.

### Which App `init` trusts

`init` and `doctor` trust a gate App only if it is owned by the repository's owner (the organisation, for an organisation repository). Anyone can name an App `prgate-...`, so the name alone is not enough. If the environment already holds an App id and key but `init` cannot confirm a matching App, or if several gate Apps are installed, `init` asks before it creates a new App and replaces the stored secrets. Answer no and nothing more changes. The files and the environment already exist by then.

## The security boundary

The gate App's key is stored in the `prgate-verdict` environment. Two things protect it:

1. **Who can merge into the default branch.** The environment allows only the default branch. A workflow on the default branch can use the key, so anyone who can put a workflow there can read it.
2. **The environment's deployment policy,** which allows the default branch only. Workflows running on any other branch cannot use the key.

The workflow check in `init` is a one-time check. It is not the boundary. It confirms that, when you set up, the default branch held the exact workflow `init` wrote and no other workflow named the environment. A workflow merged later is not checked by `init`.

So, after you change any workflow file, run:

```
prgate doctor
```

`doctor` repeats the workflow check and reports the same problems. It checks the files, the workflow, the App, the install, the environment and the secrets (secrets by name only), but not the self-test. Protect the default branch, and limit who can merge to it.

### Warnings

The check also looks for two things it cannot settle. These are warnings, not failures:

- **A workflow sets `environment:` from an expression** (`${{ ... }}`). prgate cannot tell what value it will have. Check that it can never be `prgate-verdict`.
- **A workflow calls a reusable workflow from another repository.** prgate cannot read that workflow. Check that it never uses `prgate-verdict`.

A warning does not stop `init`. It also does not excuse anything: the files that prgate can read must still pass.

## Pull requests into other branches

The gate only reports on pull requests that target the default branch. The App key is available only to workflows running on the default branch, so a pull request into any other branch gets no `pr-gate` report. The Actions run for such a pull request may show the verdict job as failed or blocked. That is expected.

## Interrupted setup

If setup is interrupted, run `prgate init` again. It picks up from what is already done.

If it was interrupted after you clicked Create on GitHub, the App may exist without a stored key. GitHub shows a key only once, so `init` cannot recover it. `init` prints a link to the App's settings page. Delete that App, then run `prgate init` again.

## Removing prgate

1. Delete `.github/workflows/pr-gate.yml` and `.prgate.toml` from the default branch. If the default branch is protected, do this through a pull request.
2. Delete the `prgate-verdict` environment (Settings, then Environments). Its secrets go with it.
3. Delete the gate App (Settings, then Developer settings, then GitHub Apps, for the owner of the repository, then Advanced, then Delete).
4. Optionally delete `~/.config/prgate/<owner>__<repo>/`.

## Appendix: doing each step by hand

Every step above can be done without `init`. `prgate doctor` checks the result, but not the self-test.

**1. Preflight.** Run `gh auth status` and `gh auth refresh -s workflow`. Check that you are an admin of the repository.

**2. Questions.** Choose your approvers and the CI check names to list. These go into `.prgate.toml`.

**3. Files.** Create `.prgate.toml`:

```toml
mode = "silent"
clear_docs = true
approvers = ["your-login"]
ci_checks = ["tests"]
language = "python"
```

Create `.github/workflows/pr-gate.yml`. The simplest route is to run `prgate init` once and copy what it writes. To build it by hand, take `src/prgate/templates/pr-gate.yml` from the prgate package and replace both `__PRGATE_ACTION_REF__` with `Abubakarjutt/PRGate@v<version>` for the version you installed. Then make the first line of the file exactly:

```
# Written by prgate init. Edit freely; re-running init will ask before replacing.
```

followed by the template. `init` and `doctor` require the file to match what `init` renders byte for byte, apart from one trailing newline. Use the same first line in `.prgate.toml`. Commit both files to the default branch, or merge them through a pull request.

**4. Workflow check.** Read every file in `.github/workflows/` on the default branch. None except `pr-gate.yml` may mention `prgate-verdict`, in any spelling. Do this before step 6, and again after you change workflows.

**5. Environment.** In Settings, then Environments, create `prgate-verdict`. Under "Deployment branches and tags", choose "Selected branches and tags" and add only the default branch by exact name. Or with `gh`:

```
gh api -X PUT repos/OWNER/REPO/environments/prgate-verdict \
  -F 'deployment_branch_policy[protected_branches]=false' \
  -F 'deployment_branch_policy[custom_branch_policies]=true'
gh api -X POST repos/OWNER/REPO/environments/prgate-verdict/deployment-branch-policies \
  -f name=main -f type=branch
```

Use your default branch's name instead of `main`. Remove any other branch policy. If the branch name contains any of `* ? [ ] { }`, GitHub reads it as a pattern that could match other branches, and prgate refuses it.

**6. Gate App.** In the settings of the repository's owner, open Developer settings, then GitHub Apps, then New GitHub App. Give it a name beginning `prgate`, any homepage URL, and untick "Active" under Webhook. Set the repository permissions to Checks: read and write, Contents: read-only, Pull requests: read-only, and Metadata: read-only. Subscribe to no events. Choose "Only on this account". Create the App, note its App ID, and generate a private key. GitHub downloads the key once.

**7. Install.** On the App's page, choose Install App and select only this repository.

**8. Secrets.** Store the App id and key in the environment, not in the repository secrets:

```
gh secret set PRGATE_APP_ID --env prgate-verdict --repo OWNER/REPO
gh secret set PRGATE_APP_KEY --env prgate-verdict --repo OWNER/REPO < key.pem
```

Then delete `key.pem`. Optionally write the App id and slug to `~/.config/prgate/<owner>__<repo>/state.json` as `{"gate_app_id": 123, "gate_app_slug": "prgate-..."}` with mode 0600. `doctor` finds the App without it.

**9. Self-test.** Open a pull request into the default branch that changes any file. Wait for a `pr-gate` check with the conclusion `neutral`, posted by the gate App. Then close the pull request and delete its branch.
