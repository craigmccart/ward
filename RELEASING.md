# Releasing Ward

Ward's release workflow (`.github/workflows/release.yml`) builds the wheel
and can publish to PyPI on a `v*.*.*` tag. The PyPI publish job is gated
behind a repo variable so tag pushes never fail before PyPI is configured.

## One-time PyPI setup (maintainer)

These steps need your PyPI login and can't be scripted from here.

1. **Create the project on PyPI.**
   - Go to <https://pypi.org> and sign in (enable 2FA if you haven't).
   - The distribution name is `ward-scanner` (set in `pyproject.toml`).
   - You don't upload anything by hand - the trusted publisher does it.

2. **Add a Trusted Publisher (OIDC, no API token needed).**
   - PyPI → your account → *Publishing* → *Add a pending publisher*.
   - Fill in:
     - PyPI Project Name: `ward-scanner`
     - Owner: `Sonofg0tham`
     - Repository name: `ward`
     - Workflow name: `release.yml`
     - Environment name: `pypi`
   - Save. This lets GitHub Actions publish without a stored password.

3. **Flip the gate on GitHub** (this part I can run for you):
   ```bash
   gh variable set PYPI_READY --body true -R craigmccart/ward
   ```
   Until this variable is `true`, the `publish-pypi` job is skipped.

## Cutting a release

Once the trusted publisher exists and `PYPI_READY=true`:

1. Bump the version everywhere it appears. `tests/test_version_consistency.py`
   fails until all five agree, so `pytest` is the checklist:
   - `pyproject.toml` → `[project].version`
   - `src/ward/__init__.py` → `__version__`
   - `action.yml` → the `ward-scanner>=X.Y.Z,<MAJOR.MINOR+1` pip pin
   - `.pre-commit-hooks.yaml` → the `rev:` in the usage comment
   - `README.md` → `uses: craigmccart/ward@vX.Y.Z` and the pre-commit `rev:`
2. Move the `## [Unreleased]` entries in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading and add the compare link at the
   bottom. The same test asserts a section exists for the current version.
3. Regenerate the benchmark reports and commit them (keeps the detection
   envelope auditable per release):
   ```bash
   ward bench --no-cache --output benchmark/vX.Y.Z-smoke.md
   ward bench --no-cache --format json --output benchmark/vX.Y.Z-smoke.json
   ward bench --download lakera_ignore_instructions \
              --download deepset_prompt_injections \
              --download spikee_jailbreaks \
              --download advbench_harmful_behaviors \
              --output benchmark/vX.Y.Z-full.md   # repeat with --format json
   ```
   `--no-cache` matters: without it, a machine that has ever run
   `--download` silently scores the full corpora and labels them smoke.
4. Commit, push, then tag and push the tag:
   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
5. The release workflow builds the wheel and, with the gate on, publishes to
   PyPI via the trusted publisher. It also creates a GitHub Release.
6. Verify:
   ```bash
   pipx install ward-scanner==X.Y.Z
   pipx install "ward-scanner[judge]"     # with the optional LLM judge tier
   ward version
   ```

## GitHub Marketplace (the Action)

The Action metadata lives at `action.yml` in the repo root (Marketplace
requires it there). To list it:

1. Open the release you just created on GitHub.
2. Tick **"Publish this Action to the GitHub Marketplace"**.
3. Pick a category (Security is the right one) and accept the terms.

Users then reference it as `uses: craigmccart/ward@vX.Y.Z`.

## Notes

- Ward ships **zero telemetry**. The only outbound calls the core makes are
  the GitHub API requests `ward scan-pr` triggers. The optional `[judge]`
  extra makes calls to your configured LLM provider only when you enable it.
- Coverage must stay ≥ 75% (enforced by `pyproject.toml`).
- All four gates must pass before tagging: `pytest`, `ruff check`,
  `ruff format --check`, `mypy src/ward`.
