"""SARIF 2.1.0 report for the GitHub Code Scanning tab.

The schema is the SARIF 2.1.0 spec as accepted by GitHub Advanced Security.
We produce a single ``runs[0]`` with ``tool.driver.rules`` populated from
the actual fired findings, and one ``results`` entry per finding.
"""

from __future__ import annotations

import json
from urllib.parse import quote

from ..core.models import Finding, ScanReport, Severity

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

_SEVERITY_SCORE = {
    Severity.INFO: "2.0",
    Severity.LOW: "3.5",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}


def _rule_descriptor(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.replace(".", "_"),
        "shortDescription": {"text": finding.message[:120]},
        "fullDescription": {"text": finding.message},
        "helpUri": finding.references[0]
        if finding.references
        else "https://github.com/craigmccart/ward",
        "help": {
            "text": finding.remediation or "Reject the metadata and review the source.",
        },
        "properties": {
            "category": finding.category,
            "tags": ["security", "prompt-injection", finding.category],
            "security-severity": _SEVERITY_SCORE[finding.severity],
        },
        "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
    }


# Surfaces that genuinely correspond to a file on disk.
_FILE_SURFACES = frozenset({"file_name", "directory_name", "file_content", "code_comment"})

# Where a non-file finding is anchored instead.
#
# A branch name is not a file, so the obvious move is to describe it with
# logicalLocations alone and no physicalLocation - which is what the previous
# version of this file did, and it was wrong in a way the SARIF spec does not
# catch. The spec permits a location carrying either kind, so the document
# validates; GitHub's code-scanning ingest is stricter and documents
# physicalLocation as REQUIRED, noting that at least one location is needed
# for a result to be displayed. Results without one are not rendered as
# alerts, and github/codeql-action#1738 shows the harsher outcome where the
# whole upload is rejected for "expected at least one location" - which would
# take the file findings down with the rest.
#
# So four of the five surfaces scan-pr produces became invisible in the Code
# Scanning tab. The exit code stayed correct and the job still went red, but
# the maintainer clicked through to an empty tab. That is a worse trade than
# the schema-invalid URI it was fixing.
#
# Both are emitted now: a stable synthetic path per surface so GitHub has
# something to anchor to, and the logicalLocation alongside it carrying the
# real branch or PR reference. The synthetic paths live under .ward/ and are
# not expected to exist in the repository - GitHub annotates what it can and
# still lists the alert either way.
_SURFACE_ANCHOR = ".ward"


def _artifact_uri(location: str) -> str:
    """Turn a filesystem path into a valid SARIF artifact URI.

    The raw string used to go straight into ``artifactLocation.uri``, which
    fails official schema validation for perfectly ordinary paths. On Windows
    ``scan-local`` yields ``docs\\release notes.md``: backslashes are not path
    separators in a URI reference, and a literal space is not permitted at
    all. GitHub's code-scanning ingest is stricter than the CLI is, so the
    upload step failed on repos that were otherwise scanning fine.
    """
    return quote(location.replace("\\", "/"), safe="/")


def _location(finding: Finding, *, target: str) -> dict[str, object]:
    raw = finding.location or target or "untrusted-metadata"
    if finding.surface in _FILE_SURFACES:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": _artifact_uri(raw)},
                "region": {"startLine": 1},
            }
        }
    # Every result carries a physicalLocation, because GitHub will not display
    # one that does not. The anchor is a synthetic per-surface path rather
    # than the branch name itself: annotating line 1 of a file called
    # "feat/ignore-previous-instructions" pointed at a path that was never in
    # the repository, which is the thing this stopped doing.
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": f"{_SURFACE_ANCHOR}/{finding.surface}"},
            "region": {"startLine": 1},
        },
        # The real reference lives here, where it cannot be mistaken for a path.
        "logicalLocations": [
            {
                "name": raw,
                "kind": "member",
                "fullyQualifiedName": f"{finding.surface}:{raw}",
            }
        ],
    }


def _result(finding: Finding, *, target: str) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {
            "text": (f"{finding.message}\nsurface: {finding.surface}\nevidence: {finding.evidence}")
        },
        "locations": [_location(finding, target=target)],
        "properties": {
            "surface": finding.surface,
            "category": finding.category,
        },
    }


def render_sarif(report: ScanReport) -> str:
    """Produce a valid SARIF 2.1.0 document as a JSON string."""
    # The descriptor describes the rule across the WHOLE run, so it takes the
    # highest severity that rule reached - not whichever finding happened to
    # come first. Findings arrive in file order and one rule can carry two
    # severities in a run (the demotion path produces exactly that), so
    # `setdefault` meant the number GitHub Code Scanning displays depended on
    # filenames. Code Scanning alerts off security-severity, so a HIGH shown
    # as MEDIUM is an alert somebody does not get.
    worst: dict[str, Finding] = {}
    for finding in report.findings:
        current = worst.get(finding.rule_id)
        if current is None or finding.severity.rank > current.severity.rank:
            worst[finding.rule_id] = finding
    seen: dict[str, dict[str, object]] = {
        rule_id: _rule_descriptor(f) for rule_id, f in worst.items()
    }

    rules = list(seen.values())
    results = [_result(f, target=report.target) for f in report.findings]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ward",
                        "version": _ward_version(),
                        "informationUri": "https://github.com/craigmccart/ward",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "verdict": report.verdict.value,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _ward_version() -> str:
    from .. import __version__

    return __version__
