# Publishing agentsec to PyPI

The package is installable from a git checkout today:

```sh
pip install git+https://github.com/dunkleschitz/agentsec.git
# or, from a clone:
pip install .
agentsec --list
```

It is **not** on PyPI until someone with the PyPI project publishes it. This
file is the exact checklist. The GitHub Actions workflow at
`.github/workflows/publish.yml` is **manual-only** (`workflow_dispatch`) and
will not upload anything unless you type `publish` when you start the run.

## 1. Create the PyPI project (once)

1. Sign in (or create an account) at [pypi.org](https://pypi.org/).
2. Open **Publishing** → **Trusted publishers** → **Add a new pending publisher**
   ([direct link](https://pypi.org/manage/account/publishing/)):
   - **PyPI project name:** `agentsec`
   - **Owner:** `dunkleschitz`
   - **Repository:** `agentsec`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`
3. The first successful trusted-publish creates the project. You do not need an
   API token if trusted publishing is configured.

Test uploads use [test.pypi.org](https://test.pypi.org/) and a second pending
publisher with the same workflow and environment name, or a separate workflow
input (not wired up here).

## 2. Create the GitHub environment (once)

In the repo: **Settings → Environments → New environment**, name it exactly
`pypi`. Optional but recommended:

- Required reviewers (so a workflow_dispatch cannot publish unattended).
- No protection rules that block the `id-token: write` permission.

## 3. Build locally (optional smoke test)

From a clean checkout, with Python 3.10+:

```sh
python3 -m venv /tmp/agentsec-build
/tmp/agentsec-build/bin/pip install -U pip build
/tmp/agentsec-build/bin/python -m build
# artifacts: dist/agentsec-0.39.0.tar.gz and dist/agentsec-0.39.0-py3-none-any.whl

python3 -m venv /tmp/agentsec-verify
/tmp/agentsec-verify/bin/pip install dist/agentsec-*.whl
/tmp/agentsec-verify/bin/agentsec --version
/tmp/agentsec-verify/bin/agentsec --list
/tmp/agentsec-verify/bin/agentsec resultguard --help
```

Do **not** run `twine upload` (or `python -m twine upload`) until the PyPI
project and trusted publisher above exist, and you intend to release.

## 4. Publish a tagged release

1. Land the commits you want on `main`. CI must be green.
2. Tag and push (example):

   ```sh
   git tag -a v0.39.0 -m "agentsec v0.39.0"
   git push origin v0.39.0
   gh release create v0.39.0 --verify-tag --title "v0.39.0" --notes-file RELEASE-NOTES.md
   ```

3. In GitHub: **Actions → Publish to PyPI → Run workflow**.
   - Branch: the tag or `main` at the tag.
   - Confirmation prompt: type `publish`.
4. Confirm the run used the `pypi` environment and finished without errors.
5. Check [pypi.org/project/agentsec](https://pypi.org/project/agentsec/).

After the first publish, people can run:

```sh
pip install agentsec
agentsec mcpposture ~/.cursor/mcp.json
```

## 5. Why the workflow is disabled by default

`publish.yml` has no `push` or `release` trigger. A typo in a GitHub token, a
fork PR, or a tag push cannot publish. The job also has

```yaml
if: github.event.inputs.confirm == 'publish'
```

so a dispatch that is started without that exact confirmation is a no-op.

## Versioning

The version in `pyproject.toml` and `agentsec/__init__.py` must match the git
tag (`vX.Y.Z`). Bump both in the same commit before tagging.
