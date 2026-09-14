<!-- ward-allow-file: io.*, role.*, exf.*, tool.*, ait.*, obf.* -->

# Contributing to Ward

Thanks for taking a look. Ward is a small, focused security tool and
contributions are welcome - especially new detection rules and honest
false-positive reports.

## Before you start

- **Security issues do not go in the issue tracker.** Report them privately
  via [GitHub Security Advisories](https://github.com/craigmccart/ward/security/advisories/new).
  See [SECURITY.md](SECURITY.md).
- For anything larger than a bug fix, open an issue first so we can agree
  the shape before you write code.

## Setup

```bash
git clone https://github.com/craigmccart/ward
cd ward
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Python 3.11 or newer is required.

## The four gates

All four must pass before a PR can merge. CI runs them on Linux, macOS and
Windows across Python 3.11, 3.12 and 3.13.

```bash
pytest                       # coverage must stay >= 75%
ruff check src tests
ruff format --check src tests
mypy src/ward                # strict mode
```

Run `ruff format src tests` to fix formatting rather than hand-editing.

## Adding a detection rule

This is the most useful contribution, and it has a fixed shape.

1. **Add the rule** to the right pack in `src/ward/rules/*.yaml`. Rule ids
   are `<category-prefix>.<name>` - `io.` instruction override, `role.`
   role manipulation, `obf.` obfuscation, `tool.` tool-call injection,
   `exf.` exfiltration, `ait.` AI-tool-specific. Ids must be unique across
   the whole pack; the loader rejects duplicates.

2. **Add an attack fixture** under `tests/fixtures/` as the next number in
   sequence. It must fail:

   ```yaml
   description: "What the attack does, in one line"
   expect_verdict: fail
   expect_rule_ids: [io.your_new_rule]
   inputs:
     - surface: pr_body
       text: "the payload"
   ```

3. **Add a clean fixture** under `tests/fixtures/clean/` proving the rule
   does not fire on legitimate text that looks similar. This is not
   optional for anything phrase-based. Ward's headline claim is a 0.0%
   false-positive rate on 343 benign rows, and that only stays true if
   every new rule is tested against the benign case.

4. **Choose surfaces deliberately.** A rule with no `surfaces:` key applies
   everywhere, which is usually wrong. A branch name and a Markdown
   document have very different base rates for the same string.

5. **Run the benchmark** and check you have not moved the false-positive
   rate:

   ```bash
   ward bench --no-cache
   ```

   Recall going up is good. FPR going above 0.0% needs a very good reason.

## Conventions

- Ruff, line length 100, target py311. Mypy strict.
- **RUF001-003 are deliberately ignored** in the homoglyph-handling files
  (`normalise.py`, `obfuscation.py`, `demo.py`, `selftest.py` and their
  tests). Never "fix" the Cyrillic or ambiguous Unicode there - it is the
  test payload. If you add a file that carries homoglyph payloads, add it
  to the per-file ignore list in `pyproject.toml`.
- `class Foo(str, Enum)` is intentional. Do not convert to `StrEnum`; it
  changes `str()` output and Ward leans on the current semantics.
- UK English in prose and comments.
- **Fail closed.** Ward is a security gate. Any new code path that could
  end with "nothing was scanned" must raise, not return a clean result.
  There are tests in `tests/test_rules.py` guarding this for the rule
  loader; extend that pattern rather than working around it.

## Commit and PR

- One logical change per PR. A new rule plus its two fixtures is one change.
- Write commit messages in the imperative: "Add rule for X", not "Added".
- Add an entry to [CHANGELOG.md](CHANGELOG.md) under `## [Unreleased]`.
- CI reports what your change did to recall and FPR. For a branch on this
  repo that arrives as a sticky PR comment; from a fork it is in the
  `bench-diff` job log and the uploaded artifact, because a fork's token
  cannot comment. Either way, read it.

Note that Ward scans its own repository in CI, and this file is scanned as
documentation. If you need to write out an attack string in prose, the
`ward-allow-file` directive at the top of this file already covers the
standard categories.

## Releasing

Maintainer-only. See [RELEASING.md](RELEASING.md).

## Licence

By contributing you agree that your contributions are licensed under the
MIT Licence, the same as the rest of the project.
