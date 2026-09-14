"""Tests for the GitHub REST client.

Parsing is covered as pure functions; the fetch path runs against an
``httpx.MockTransport`` so no network is touched.
"""

from __future__ import annotations

import httpx
import pytest

from ward.core.github_api import (
    GitHubError,
    _headers,
    fetch_pr_metadata,
    parse_pr_ref,
)


def test_parse_pr_ref_happy_path():
    assert parse_pr_ref("craigmccart/ward#42") == ("craigmccart", "ward", 42)


def test_parse_pr_ref_allows_dots_and_underscores_in_repo():
    assert parse_pr_ref("acme/my.repo_name-1#7") == ("acme", "my.repo_name-1", 7)


@pytest.mark.parametrize(
    "ref",
    [
        "missing-hash",
        "no/repo",
        "owner/repo#not-a-number",
        "#42",
        "owner#42",
    ],
)
def test_parse_pr_ref_rejects_bad_input(ref: str):
    with pytest.raises(ValueError):
        parse_pr_ref(ref)


@pytest.mark.parametrize(
    "ref",
    [
        # Path traversal: httpx normalises the URL, so "a/../../evil" would
        # otherwise resolve to https://api.github.com/evil/pulls/1 with the
        # caller's token attached.
        "a/../../evil#1",
        "../x/repo#1",
        "owner/../../../users/victim#1",
        # Percent-encoded separators aiming at the same trick.
        "x%2f..%2f/y#2",
        "owner/re%2fpo#3",
        # Owners cannot start or end with a hyphen, or hold slashes.
        "-bad/repo#1",
        "bad-/repo#1",
        # Non-positive PR numbers are never valid.
        "owner/repo#0",
        "owner/repo#-5",
        # Bare relative path segments as the repo.
        "owner/.#1",
        "owner/..#1",
    ],
)
def test_parse_pr_ref_rejects_path_traversal_and_bad_names(ref: str):
    with pytest.raises(ValueError):
        parse_pr_ref(ref)


def test_owner_length_capped_at_github_limit():
    with pytest.raises(ValueError):
        parse_pr_ref(f"{'a' * 40}/repo#1")
    # 39 characters is GitHub's actual maximum and must still parse.
    owner, repo, number = parse_pr_ref(f"{'a' * 39}/repo#1")
    assert owner == "a" * 39
    assert (repo, number) == ("repo", 1)


# --- header / auth ----------------------------------------------------------


def test_headers_include_token_when_set(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_example")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert _headers()["Authorization"] == "Bearer ghp_example"


def test_headers_omit_authorization_when_no_token(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert "Authorization" not in _headers()


# --- fetch path -------------------------------------------------------------


def _install_transport(monkeypatch: pytest.MonkeyPatch, handler) -> list[str]:
    """Route every httpx.Client through a MockTransport. Returns the path log."""
    seen: list[str] = []
    real_client = httpx.Client

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return handler(request)

    def factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    return seen


def test_fetch_pr_metadata_maps_every_surface(monkeypatch: pytest.MonkeyPatch):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/commits"):
            return httpx.Response(
                200,
                json=[
                    {"sha": "abc123", "commit": {"message": "fix: tidy up"}},
                    {"malformed": True},  # skipped, no sha/commit
                ],
            )
        if path.endswith("/files"):
            return httpx.Response(
                200,
                json=[{"filename": "src/app.py"}, {"no_filename": True}],
            )
        return httpx.Response(
            200,
            json={
                "title": "Add feature",
                "body": None,  # GitHub returns null for an empty body
                "head": {"ref": "feat/x", "sha": "deadbeefcafe"},
                "base": {"ref": "main"},
            },
        )

    paths = _install_transport(monkeypatch, handler)
    meta = fetch_pr_metadata("acme", "widget", 42)

    assert meta.title == "Add feature"
    assert meta.body == ""  # null body normalises to empty string, never "None"
    assert meta.head_ref == "feat/x"
    assert meta.base_ref == "main"
    assert meta.head_sha == "deadbeefcafe"
    assert meta.commit_messages == (("abc123", "fix: tidy up"),)
    assert meta.changed_file_paths == ("src/app.py",)
    assert paths == [
        "/repos/acme/widget/pulls/42",
        "/repos/acme/widget/pulls/42/commits",
        "/repos/acme/widget/pulls/42/files",
    ]


def test_fetch_pr_metadata_raises_on_non_2xx(monkeypatch: pytest.MonkeyPatch):
    _install_transport(monkeypatch, lambda _r: httpx.Response(404, text="Not Found"))
    with pytest.raises(GitHubError) as excinfo:
        fetch_pr_metadata("acme", "widget", 42)
    assert "404" in str(excinfo.value)


# --- pagination -------------------------------------------------------------
#
# Ward used to read one page of commits and one page of files and stop.
# GitHub's default page size is 30, so an attacker only had to push thirty
# unremarkable commits before the payload for scan-pr to never see it - and
# report PASS.


def _paged_handler(n_commits: int, n_files: int, *, declared: tuple[int, int] | None = None):
    """A PR whose list endpoints honour per_page and emit Link headers."""
    commits = [
        {"sha": f"sha{i:04d}", "commit": {"message": f"commit {i}"}} for i in range(n_commits)
    ]
    files = [{"filename": f"file{i:04d}.py"} for i in range(n_files)]
    said_commits, said_files = declared or (n_commits, n_files)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        page = int(request.url.params.get("page", 1))
        per_page = int(request.url.params.get("per_page", 30))
        items = commits if path.endswith("/commits") else files if path.endswith("/files") else None
        if items is None:
            return httpx.Response(
                200,
                json={
                    "title": "t",
                    "body": "b",
                    "head": {"ref": "feat/x", "sha": "s"},
                    "base": {"ref": "main"},
                    "commits": said_commits,
                    "changed_files": said_files,
                },
            )
        start = (page - 1) * per_page
        chunk = items[start : start + per_page]
        headers = {}
        if start + per_page < len(items):
            nxt = request.url.copy_set_param("page", page + 1)
            headers["Link"] = f'<{nxt}>; rel="next"'
        return httpx.Response(200, json=chunk, headers=headers)

    return handler


def test_commits_beyond_the_first_page_are_scanned(monkeypatch: pytest.MonkeyPatch):
    """Must exceed per_page, not merely GitHub's 30-item default.

    The first version of this test used 35 commits, which exposed the
    original bug but stopped discriminating the moment the fix asked for
    per_page=100 - 35 items fit on one page, so no Link header is emitted and
    the paging loop is never exercised. Mutation testing caught it: breaking
    the loop left this test green. 150 forces a genuine second request.
    """
    _install_transport(monkeypatch, _paged_handler(150, 1))
    meta = fetch_pr_metadata("acme", "widget", 42)
    assert len(meta.commit_messages) == 150, "commits past the first page were dropped"
    assert meta.commit_messages[-1] == ("sha0149", "commit 149")


def test_changed_files_beyond_the_first_page_are_scanned(monkeypatch: pytest.MonkeyPatch):
    _install_transport(monkeypatch, _paged_handler(1, 250))
    meta = fetch_pr_metadata("acme", "widget", 42)
    assert len(meta.changed_file_paths) == 250
    assert "file0249.py" in meta.changed_file_paths


def test_pagination_requests_the_largest_page_size(monkeypatch: pytest.MonkeyPatch):
    """100 is GitHub's maximum. Asking for fewer means more round trips."""
    seen: list[str] = []
    real_client = httpx.Client

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return _paged_handler(5, 5)(request)

    def factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    fetch_pr_metadata("acme", "widget", 42)
    listed = [u for u in seen if u.endswith(("commits?per_page=100", "files?per_page=100"))]
    assert len(listed) == 2, f"list endpoints did not request per_page=100: {seen}"


def test_a_truncated_pr_fails_closed_rather_than_reporting_pass(monkeypatch: pytest.MonkeyPatch):
    """GitHub caps commits at 250 and files at 3000, whatever the page size.

    Past that, Ward genuinely cannot see the whole PR. Reporting a verdict on
    the part it did see would be a PASS on an unscanned commit, so it must
    refuse instead - the PR object states its own totals, which is a more
    reliable signal than guessing at where the cap is.
    """
    # 250 commits returned, but the PR says it has 400.
    _install_transport(monkeypatch, _paged_handler(250, 1, declared=(400, 1)))
    with pytest.raises(GitHubError) as exc:
        fetch_pr_metadata("acme", "widget", 42)
    assert "250 of 400" in str(exc.value)
    assert "scan-local" in str(exc.value), "the error must say what to do instead"


def test_pagination_will_not_follow_a_link_off_github(monkeypatch: pytest.MonkeyPatch):
    """The next URL arrives in a response header, carrying the caller's token.

    A proxy that rewrites Link could otherwise redirect paging to its own
    host and be handed the Authorization header.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/commits"):
            return httpx.Response(
                200,
                json=[{"sha": "a", "commit": {"message": "m"}}],
                headers={"Link": '<https://evil.example/collect?page=2>; rel="next"'},
            )
        return httpx.Response(200, json={"head": {}, "base": {}})

    _install_transport(monkeypatch, handler)
    with pytest.raises(GitHubError, match="refusing to follow pagination"):
        fetch_pr_metadata("acme", "widget", 42)
