"""Ward's version is written in five places. This keeps them honest.

Releasing means bumping `pyproject.toml`, `src/ward/__init__.py`, the pip pin
in `action.yml`, and the two usage examples pinned by tag. Doing that by hand
has already drifted once (`.pre-commit-hooks.yaml` sat on `v0.1.0` through
eight releases), so it is a test rather than a line in RELEASING.md.

These tests are skipped when the repo files are not present, so they do not
fail for anyone running the suite against an installed wheel.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from ward import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / "pyproject.toml").is_file(),
    reason="not running from a source checkout",
)


def _read(name: str) -> str:
    path = REPO_ROOT / name
    if not path.is_file():
        pytest.skip(f"{name} not present in this checkout")
    return path.read_text(encoding="utf-8")


def test_version_is_valid_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), (
        f"__version__ {__version__!r} is not MAJOR.MINOR.PATCH"
    )


def test_pyproject_matches_dunder_version():
    data = tomllib.loads(_read("pyproject.toml"))
    assert data["project"]["version"] == __version__, (
        "pyproject.toml and src/ward/__init__.py disagree. Bump both."
    )


def test_action_pins_the_current_version():
    """action.yml installs `ward-scanner>=X.Y.Z,<NEXT_MAJOR_MINOR`."""
    text = _read("action.yml")
    match = re.search(r"ward-scanner>=(\d+\.\d+\.\d+),<(\d+\.\d+)", text)
    assert match, "could not find the ward-scanner pip pin in action.yml"
    assert match.group(1) == __version__, (
        f"action.yml pins ward-scanner>={match.group(1)} but Ward is {__version__}. "
        "Users of the action would install an older build than the tag they referenced."
    )
    major, minor, _ = __version__.split(".")
    expected_ceiling = f"{major}.{int(minor) + 1}"
    assert match.group(2) == expected_ceiling, (
        f"action.yml upper bound is <{match.group(2)}, expected <{expected_ceiling}"
    )


def test_pre_commit_hooks_example_uses_the_current_tag():
    text = _read(".pre-commit-hooks.yaml")
    revs = re.findall(r"rev:\s*v(\d+\.\d+\.\d+)", text)
    assert revs, "no `rev: vX.Y.Z` example found in .pre-commit-hooks.yaml"
    for rev in revs:
        assert rev == __version__, (
            f".pre-commit-hooks.yaml documents rev v{rev} but Ward is {__version__}"
        )


def test_readme_pins_the_current_tag():
    text = _read("README.md")
    pins = re.findall(r"craigmccart/ward@v(\d+\.\d+\.\d+)", text)
    pins += re.findall(r"rev:\s*v(\d+\.\d+\.\d+)", text)
    assert pins, "README documents no pinned version"
    for pin in pins:
        assert pin == __version__, (
            f"README pins v{pin} but Ward is {__version__}. Copy-pasting the README "
            "would give users a stale release."
        )


# CHANGELOG.md is historical by definition - old versions are the point there.
# Everything else that shows a user a copy-pasteable pin must be current.
_PIN_EXEMPT = {"CHANGELOG.md"}


def test_no_doc_shows_a_stale_copy_pasteable_pin():
    docs = [REPO_ROOT / "README.md", *sorted((REPO_ROOT / "docs").glob("*.md"))]
    checked = 0
    for path in docs:
        if not path.is_file() or path.name in _PIN_EXEMPT:
            continue
        text = path.read_text(encoding="utf-8")
        for pin in re.findall(r"craigmccart/ward@v(\d+\.\d+\.\d+)", text):
            checked += 1
            rel = path.relative_to(REPO_ROOT).as_posix()
            assert pin == __version__, (
                f"{rel} tells readers to use ward@v{pin}, but Ward is {__version__}."
            )
    assert checked, "no action pins found to check - has the usage example moved?"


def test_changelog_has_an_entry_for_the_current_version():
    text = _read("CHANGELOG.md")
    assert f"## [{__version__}]" in text, (
        f"CHANGELOG.md has no `## [{__version__}]` section. Add one before tagging."
    )
