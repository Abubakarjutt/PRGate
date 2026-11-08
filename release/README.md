# Releasing prgate

The action installs exactly one wheel: the one whose sha256 is pinned in `action-requirements.txt`.
A release pins that hash first, then tags. The release workflow rebuilds the wheel from the tagged
commit, refuses to publish unless the rebuild has the pinned hash, and publishes that wheel by
trusted publishing. No token is involved anywhere.

## Once, before the first release

1. **Trusted publishers.** On both PyPI (pypi.org) and TestPyPI (test.pypi.org), register a trusted
   publisher (a "pending publisher" until the project exists) with: project `prgate`, owner
   `Abubakarjutt`, repository `PRGate`, workflow `release.yml`, environment `pypi`.
2. **GitHub environment.** In `Abubakarjutt/PRGate` → Settings → Environments, create `pypi`. Under
   deployment branches and tags, allow only the tag rule `v*`, and add yourself as a required reviewer,
   so nothing publishes without your approval.

## Every release

Run these steps in the clone of the repo that will carry the tag (the public `Abubakarjutt/PRGate`).
`SOURCE_DATE_EPOCH` comes from that repo's history, so a hash computed in another clone with a
different history will not match. The hash script needs git 2.40 or later, because it runs
`git check-attr --source`.

0. Bring this repo up to date and commit that first. An update may reset `action-requirements.txt`
   to the all-zeros placeholder, so **re-run the hash script after every update, inside this clone**.
1. Make sure `src/prgate/__init__.py` has the version you are releasing (`__version__ = "<version>"`),
   and that everything that goes into the wheel (`src/`, `pyproject.toml`, `setup.py`, `README.md`,
   `LICENSE`) is committed. The script refuses uncommitted changes to those files.
2. Pin the hash:

   ```
   python3.12 release/hash_release.py <version>
   ```

   It builds the wheel from `HEAD` in a fresh venv with the exact tools in
   `release/build-requirements.txt`, rewrites the pin line of `action-requirements.txt` as
   `prgate==<version> --hash=sha256:<hex>` (the comment line stays), and prints the hash. It exits 1,
   writing nothing, if `<version>` is not `__version__`.
3. Commit only `action-requirements.txt`:

   ```
   git add action-requirements.txt
   git commit -m "release: pin prgate <version>"
   ```

   Committing it does not change the hash: that file is not a wheel input.
4. Tag and push the tag:

   ```
   git tag v<version>
   git push origin v<version>
   ```

5. Let the workflow run. It fails if `action-requirements.txt` still holds the all-zeros placeholder,
   if the tag is not `v<__version__>`, or if the rebuilt wheel's sha256 differs from the pin. Only then
   does the `publish` job (environment `pypi`) upload the wheel: `v0.0.*` tags go to TestPyPI, every
   other tag to PyPI.

## If the workflow reports a different hash

Do not simply re-pin to the workflow's hash: the point of the check is that anyone can rebuild the
published wheel. First check that the tag is on the commit you pinned and that nothing but
`action-requirements.txt` changed since. Then rebuild on Linux with the same script, from the public
clone, and compare:

```
docker run --rm -v "$PWD":/repo -w /repo python:3.12-slim \
  sh -c 'apt-get update -qq && apt-get install -y -qq git >/dev/null &&
         git config --global --add safe.directory /repo &&
         python release/hash_release.py --check <version>'
```

If that container build matches the workflow but not your machine, pin from the container
(`python release/hash_release.py <version>` in the same command), commit, delete the tag, and tag again.
