"""Behaviour tests for the repo-security-audit skill's findings normalizer.

The normalizer is the deterministic core of SEC-AUDIT Phase 2. These tests
assert its behavioural contracts, not a snapshot of its output:

* secret values never propagate into findings (the highest-stakes guarantee)
* nothing is silently dropped - every dismissal is logged
* location classification downgrades but never deletes, and never downgrades
  a secret
* dedup merges on (file, line, cwe) and unions sources
* output is deterministic for identical input

Stdlib + pytest only, no network. The module is loaded by path because it
lives in the user's skills tree, not in the hermes-agent package.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


def _skill_roots() -> list[Path]:
    """Candidate skills roots, most explicit first.

    Robustness note: this test file exercises a script that lives in the user's
    skills tree, not in this repo. Locating it has to survive two hostile
    conditions that the CI-parity runner creates:

    * ``HERMES_HOME`` is redirected to a temp dir by the ``_isolate_hermes_home``
      autouse fixture, so it must NOT be the only lookup path;
    * ``scripts/run_tests.sh`` re-execs under ``env -i``, where a non-ASCII home
      path can arrive mojibake-encoded and ``Path.home()`` yields a directory
      that does not exist.

    So: an explicit override wins, then real env vars, then ``Path.home()`` as a
    best-effort last resort - each guarded, and the whole thing skips cleanly
    rather than erroring when the skill simply is not installed.
    """
    roots: list[Path] = []

    def add(value: str | None, *parts: str) -> None:
        if not value:
            return
        try:
            candidate = Path(value).joinpath(*parts)
        except (OSError, ValueError):
            return
        if candidate not in roots:
            roots.append(candidate)

    # Explicit override for anyone running the suite outside a normal profile.
    add(os.environ.get("HERMES_SKILL_TEST_ROOT"))
    add(os.environ.get("HERMES_HOME"))
    for var in ("USERPROFILE", "HOME"):
        add(os.environ.get(var), ".hermes")
        add(os.environ.get(var), "AppData", "Local", "hermes")
    try:
        home = Path.home()
    except (RuntimeError, OSError):
        home = None
    if home is not None:
        add(str(home), ".hermes")
        add(str(home), "AppData", "Local", "hermes")
    return roots


def _skill_script() -> Path:
    """Locate normalize_findings.py in whichever skills root is active."""
    rel = Path("skills/software-development/repo-security-audit/scripts")
    for root in _skill_roots():
        candidate = root / rel / "normalize_findings.py"
        try:
            if candidate.is_file():
                return candidate
        except OSError:  # unreadable / malformed path component
            continue
    pytest.skip("repo-security-audit skill is not installed in this profile")


@pytest.fixture(scope="module")
def nf():
    """Import the normalizer module from its on-disk path."""
    path = _skill_script()
    spec = importlib.util.spec_from_file_location("_sec_audit_normalize", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_sec_audit_normalize"] = mod
    spec.loader.exec_module(mod)
    return mod


def _run_dir(tmp_path: Path) -> Path:
    raw = tmp_path / "raw"
    raw.mkdir(parents=True)
    return tmp_path


def _write(run_dir: Path, name: str, payload: object) -> None:
    (run_dir / "raw" / name).write_text(
        json.dumps(payload), encoding="utf-8", newline="\n"
    )


# ---------------------------------------------------------------------------
# Secret redaction - the highest-stakes contract
# ---------------------------------------------------------------------------

LIVE_SECRET = "AKIAIOSFODNN7EXAMPLE_supersecret_value_42"


def test_gitleaks_secret_value_never_appears_in_output(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "gitleaks.json",
        [
            {
                "RuleID": "aws-access-token",
                "File": "src/config.py",
                "StartLine": 12,
                "Secret": LIVE_SECRET,
                "Match": f"AWS_KEY = '{LIVE_SECRET}'",
            }
        ],
    )

    result = nf.normalize(run_dir)
    blob = json.dumps(result)

    assert LIVE_SECRET not in blob, "secret value leaked into normalized output"
    assert result["total"] == 1
    finding = result["findings"][0]
    assert finding["category"] == "secret"
    assert finding["severity"] == "critical"
    assert finding["evidence"]["file"] == "src/config.py"
    assert finding["evidence"]["line"] == 12
    assert nf.REDACTED in finding["evidence"]["snippet_redacted"]


def test_secret_value_absent_from_written_files(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "gitleaks.json",
        [{"RuleID": "generic", "File": "a.py", "StartLine": 1, "Secret": LIVE_SECRET}],
    )

    assert nf.main([str(run_dir)]) == 0

    for name in ("findings.json", "triage-log.md"):
        text = (run_dir / name).read_text(encoding="utf-8")
        assert LIVE_SECRET not in text, f"secret leaked into {name}"


def test_redact_masks_assignment_style_secrets(nf):
    out = nf.redact("password = 'hunter2hunter2'")
    assert "hunter2hunter2" not in out
    assert nf.REDACTED in out


def test_redact_force_replaces_entire_snippet(nf):
    assert nf.redact("anything at all", force=True) == nf.REDACTED


# ---------------------------------------------------------------------------
# Location classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("tests/test_login.py", "test"),
        ("src/__tests__/foo.ts", "test"),
        ("pkg/fixtures/data.json", "fixture"),
        ("node_modules/left-pad/index.js", "vendored"),
        ("dist/app.min.js", "generated"),
        ("examples/demo.py", "example"),
        ("src/server/auth.ts", "production"),
    ],
)
def test_classify_location(nf, path, expected):
    assert nf.classify_location(path)[0] == expected


def test_windows_backslash_paths_classify_the_same(nf):
    assert nf.classify_location(r"src\__tests__\foo.ts")[0] == "test"


def test_test_location_downgrades_sast_severity(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "semgrep.json",
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "tests/test_eval.py",
                    "start": {"line": 3},
                    "extra": {
                        "message": "eval() detected",
                        "severity": "ERROR",
                        "metadata": {"cwe": "CWE-95: Eval Injection"},
                    },
                }
            ]
        },
    )

    finding = nf.normalize(run_dir)["findings"][0]
    assert finding["original_severity"] == "high"
    assert finding["severity"] == "low"  # high -> 2 steps down
    assert finding["location_class"] == "test"
    assert finding["cwe"] == "CWE-95"


def test_secret_in_test_path_is_not_downgraded(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "gitleaks.json",
        [{"RuleID": "aws", "File": "tests/fixtures/creds.json", "StartLine": 2}],
    )

    finding = nf.normalize(run_dir)["findings"][0]
    assert finding["severity"] == "critical", "secrets must never be downgraded by location"


def test_vendored_sast_hit_is_dismissed_with_a_reason(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "semgrep.json",
        {
            "results": [
                {
                    "check_id": "js.audit.detect-eval",
                    "path": "node_modules/evil/index.js",
                    "start": {"line": 9},
                    "extra": {"message": "eval", "severity": "ERROR", "metadata": {}},
                }
            ]
        },
    )

    result = nf.normalize(run_dir)
    assert result["total"] == 0
    reasons = " ".join(d["reason"] for d in result["_dismissals"])
    assert "vendored" in reasons


# ---------------------------------------------------------------------------
# Nothing silently dropped
# ---------------------------------------------------------------------------


def test_unrecognized_raw_file_is_logged_not_ignored(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(run_dir, "mystery-output.json", {"totally": "unknown shape"})

    result = nf.normalize(run_dir)
    assert result["skipped_files"], "unparseable input must be recorded"
    assert any("no parser" in d["reason"] for d in result["_dismissals"])


def test_triage_log_is_appended_not_truncated(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(run_dir, "unknown.json", {"x": 1})

    nf.main([str(run_dir)])
    first = (run_dir / "triage-log.md").read_text(encoding="utf-8")
    nf.main([str(run_dir)])
    second = (run_dir / "triage-log.md").read_text(encoding="utf-8")

    assert len(second) > len(first)
    assert second.startswith("# Triage Log")
    assert second.count("normalize_findings.py pass") == 2


def test_malformed_json_does_not_crash_the_run(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    (run_dir / "raw" / "broken.json").write_text("{not json", encoding="utf-8")
    _write(run_dir, "bandit.json", {"results": []})

    result = nf.normalize(run_dir)  # must not raise
    assert result["total"] == 0


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_dedup_merges_same_file_line_cwe_and_unions_sources(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "semgrep.json",
        {
            "results": [
                {
                    "check_id": "sql-injection",
                    "path": "src/db.py",
                    "start": {"line": 40},
                    "extra": {
                        "message": "SQL injection",
                        "severity": "WARNING",
                        "metadata": {"cwe": "CWE-89"},
                    },
                }
            ]
        },
    )
    _write(
        run_dir,
        "bandit.json",
        {
            "results": [
                {
                    "test_id": "B608",
                    "issue_text": "possible SQL injection",
                    "issue_severity": "HIGH",
                    "issue_cwe": {"id": 89},
                    "filename": "src/db.py",
                    "line_number": 40,
                    "code": "query = 'SELECT ' + user_input",
                }
            ]
        },
    )

    result = nf.normalize(run_dir)
    assert result["total"] == 1, "same (file,line,cwe) from two tools must merge"
    finding = result["findings"][0]
    assert len(finding["sources"]) == 2
    assert finding["severity"] == "high", "merged finding keeps the strongest severity"
    assert any("duplicate" in d["reason"] for d in result["_dismissals"])


def test_different_lines_are_not_merged(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "bandit.json",
        {
            "results": [
                {
                    "test_id": "B608",
                    "issue_text": "sql",
                    "issue_severity": "HIGH",
                    "issue_cwe": {"id": 89},
                    "filename": "src/db.py",
                    "line_number": n,
                    "code": "q",
                }
                for n in (10, 20)
            ]
        },
    )
    assert nf.normalize(run_dir)["total"] == 2


# ---------------------------------------------------------------------------
# Determinism and schema
# ---------------------------------------------------------------------------


def test_identical_input_produces_identical_output(nf, tmp_path):
    payload = {
        "results": [
            {
                "check_id": f"rule-{i}",
                "path": f"src/mod{i}.py",
                "start": {"line": i},
                "extra": {"message": f"m{i}", "severity": "WARNING", "metadata": {}},
            }
            for i in range(6)
        ]
    }

    outputs = []
    for name in ("a", "b"):
        run_dir = _run_dir(tmp_path / name)
        _write(run_dir, "semgrep.json", payload)
        result = nf.normalize(run_dir)
        result.pop("run_dir")
        result.pop("_dismissals")
        outputs.append(json.dumps(result, sort_keys=True))

    assert outputs[0] == outputs[1]


def test_findings_sorted_by_severity_and_ids_follow_that_order(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "gitleaks.json",
        [{"RuleID": "aws", "File": "src/z.py", "StartLine": 1}],
    )
    _write(
        run_dir,
        "semgrep.json",
        {
            "results": [
                {
                    "check_id": "low-thing",
                    "path": "src/a.py",
                    "start": {"line": 1},
                    "extra": {"message": "m", "severity": "INFO", "metadata": {}},
                }
            ]
        },
    )

    findings = nf.normalize(run_dir)["findings"]
    ranks = [nf.SEVERITY_RANK[f["severity"]] for f in findings]
    assert ranks == sorted(ranks), "findings must be severity-ordered"
    assert findings[0]["id"] == "SEC-001"
    assert findings[0]["category"] == "secret"


def test_every_finding_carries_the_full_schema(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "semgrep.json",
        {
            "results": [
                {
                    "check_id": "r",
                    "path": "src/a.py",
                    "start": {"line": 1},
                    "extra": {"message": "m", "severity": "ERROR", "metadata": {}},
                }
            ]
        },
    )

    required = {
        "id",
        "title",
        "severity",
        "category",
        "cwe",
        "status",
        "confidence",
        "evidence",
        "related_locations",
        "sources",
        "exploit_scenario",
        "remediation",
        "verification_recipe",
        "effort",
        "adjudication",
        "hap_task_id",
        "business_impact",
        "scanner_report_ref",
    }
    finding = nf.normalize(run_dir)["findings"][0]
    assert required <= set(finding), f"missing: {required - set(finding)}"
    assert finding["status"] == "open"
    assert finding["confidence"] == "assumption", (
        "the normalizer may not claim verification; only Phase 3/4 can raise confidence"
    )
    assert finding["scanner_report_ref"] == "raw/semgrep.json"


def test_schema_version_is_declared(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    assert nf.normalize(run_dir)["schema_version"] == nf.SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Additional parsers
# ---------------------------------------------------------------------------


def test_osv_dependency_finding(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "osv.json",
        {
            "results": [
                {
                    "source": {"path": "package-lock.json"},
                    "packages": [
                        {
                            "package": {"name": "lodash", "version": "4.17.20"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-xxxx",
                                    "database_specific": {
                                        "severity": "high",
                                        "cwe_ids": ["CWE-1321"],
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )

    finding = nf.normalize(run_dir)["findings"][0]
    assert finding["category"] == "dependency"
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-1321"
    assert "lodash" in finding["title"]


@pytest.mark.parametrize(
    "ghsa_severity,expected",
    [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MODERATE", "medium"),  # GHSA's spelling of medium - must not fall through
        ("moderate", "medium"),
        ("LOW", "low"),
    ],
)
def test_osv_ghsa_severity_vocabulary_is_mapped(nf, ghsa_severity, expected):
    """OSV/GHSA use MODERATE, which is not in our severity vocabulary.

    Regression guard: a real EXZ scan of 145 CVEs surfaced 51 MODERATE and 47
    unlabelled records. Before the fix every MODERATE silently fell through to
    the default, so the mapping has to be asserted per vocabulary word.
    """
    vuln = {"id": "GHSA-x", "database_specific": {"severity": ghsa_severity}}
    assert nf._osv_severity(vuln) == expected


def test_osv_falls_back_to_cvss_score_when_no_word_severity(nf):
    assert nf._osv_severity({"severity": [{"score": 9.8}]}) == "critical"
    assert nf._osv_severity({"severity": [{"score": 7.5}]}) == "high"
    assert nf._osv_severity({"severity": [{"score": 5.0}]}) == "medium"
    assert nf._osv_severity({"severity": [{"score": 2.0}]}) == "low"


def test_osv_with_no_severity_information_defaults_to_medium(nf):
    assert nf._osv_severity({"id": "GHSA-y"}) == "medium"


def test_sarif_is_parsed(nf, tmp_path):
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "trivy.sarif",
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Trivy",
                            "rules": [
                                {
                                    "id": "AVD-001",
                                    "shortDescription": {"text": "Root user"},
                                    "properties": {"tags": ["CWE-250"]},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "AVD-001",
                            "level": "error",
                            "message": {"text": "Container runs as root"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "Dockerfile"},
                                        "region": {"startLine": 4},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )

    finding = nf.normalize(run_dir)["findings"][0]
    assert finding["severity"] == "high"
    assert finding["evidence"]["file"] == "Dockerfile"
    assert finding["evidence"]["line"] == 4
    assert finding["cwe"] == "CWE-250"
    assert finding["sources"][0].startswith("trivy:")


def test_empty_raw_dir_yields_zero_findings(nf, tmp_path):
    result = nf.normalize(_run_dir(tmp_path))
    assert result["total"] == 0
    assert result["findings"] == []
    assert result["counts"]["critical"] == 0


def test_missing_run_dir_exits_with_usage_error(nf, tmp_path):
    assert nf.main([str(tmp_path / "does-not-exist")]) == 2


# ---------------------------------------------------------------------------
# record_tracks.py - scanner provenance
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rt():
    """Import record_tracks.py from the installed skill."""
    path = _skill_script().parent / "record_tracks.py"
    if not path.is_file():
        pytest.skip("record_tracks.py not present in this skill install")
    spec = importlib.util.spec_from_file_location("_sec_audit_tracks", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_sec_audit_tracks"] = mod
    spec.loader.exec_module(mod)
    return mod


def _tb_report(run_dir: Path, task: str, status: str, exit_code: int) -> None:
    (run_dir / "logs").mkdir(exist_ok=True)
    (run_dir / "logs" / f"tb-{task}.json").write_text(
        json.dumps(
            {
                "task_id": f"secaudit-{task}",
                "final_status": status,
                "exit_code": exit_code,
                "duration_seconds": 1.0,
                "execution_class": "batch",
            }
        ),
        encoding="utf-8",
    )


def test_nonzero_exit_with_output_is_not_a_failure(rt, tmp_path):
    """Scanners exit non-zero WHEN THEY FIND SOMETHING.

    gitleaks, osv-scanner, checkov and semgrep all exit 1 on findings. Treating
    a non-zero exit as failure makes the provenance tool cry wolf on every
    successful scan - and a gate that cries wolf gets ignored. The real signal
    is whether a parsable output file was produced.
    """
    run_dir = _run_dir(tmp_path)
    _write(run_dir, "osv.json", {"results": []})
    _tb_report(run_dir, "osv", "FAILED", 1)  # findings-were-found exit

    tracks = rt.build_tracks(run_dir)
    assert tracks["attempts_without_output"] == [], (
        "a scanner that produced output must not be reported as a failure"
    )
    assert "1C-dependencies" in tracks["tracks_with_coverage"]


def test_attempt_with_no_output_is_flagged(rt, tmp_path):
    """The dangerous case: a run that produced nothing looks clean otherwise."""
    run_dir = _run_dir(tmp_path)
    _tb_report(run_dir, "semgrep", "RUNNER_ERROR", 2)

    tracks = rt.build_tracks(run_dir)
    assert len(tracks["attempts_without_output"]) == 1
    entry = tracks["attempts_without_output"][0]
    assert entry["task_id"] == "secaudit-semgrep"
    assert "runner could not execute" in entry["reason"]
    assert tracks["tracks_with_coverage"] == []


def test_success_status_without_output_is_still_flagged(rt, tmp_path):
    run_dir = _run_dir(tmp_path)
    _tb_report(run_dir, "bandit", "SUCCEEDED", 0)

    tracks = rt.build_tracks(run_dir)
    assert len(tracks["attempts_without_output"]) == 1
    assert "wrote no parsable output" in tracks["attempts_without_output"][0]["reason"]


def test_history_track_is_distinguished_from_tree_track(rt):
    """Longest-fragment match: 'gitleaks-history' must not collapse to 'gitleaks'."""
    assert rt.track_for("gitleaks-history.json") == "1A-secrets-history"
    assert rt.track_for("gitleaks.json") == "1A-secrets-tree"
    assert rt.track_for("semgrep-broad.json") == "1B-sast-broad"
    assert rt.track_for("semgrep.json") == "1B-sast"


def test_osv_nested_records_are_counted(rt, tmp_path):
    """osv-scanner nests vulnerabilities two levels deep; a naive len() is wrong."""
    run_dir = _run_dir(tmp_path)
    _write(
        run_dir,
        "osv.json",
        {
            "results": [
                {
                    "source": {"path": "package-lock.json"},
                    "packages": [
                        {
                            "package": {"name": "a", "version": "1"},
                            "vulnerabilities": [{"id": "X"}, {"id": "Y"}],
                        },
                        {
                            "package": {"name": "b", "version": "2"},
                            "vulnerabilities": [{"id": "Z"}],
                        },
                    ],
                }
            ]
        },
    )
    assert rt.count_records(run_dir / "raw" / "osv.json") == 3


def test_unparsable_output_is_reported(rt, tmp_path):
    run_dir = _run_dir(tmp_path)
    (run_dir / "raw" / "gitleaks.json").write_text("{broken", encoding="utf-8")

    tracks = rt.build_tracks(run_dir)
    assert tracks["unparsable_outputs"] == ["raw/gitleaks.json"]
    assert "1A-secrets-tree" not in tracks["tracks_with_coverage"]


# ---------------------------------------------------------------------------
# verify_history_clean.py - "did a secret ever reach git?" verification
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def vhc():
    path = _skill_script().parent / "verify_history_clean.py"
    if not path.is_file():
        pytest.skip("verify_history_clean.py not present in this skill install")
    spec = importlib.util.spec_from_file_location("_sec_audit_hist", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_sec_audit_hist"] = mod
    spec.loader.exec_module(mod)
    return mod


def _git_repo(path: Path) -> None:
    import subprocess

    path.mkdir(parents=True, exist_ok=True)
    for args in (
        ["init", "-q", "."],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
        ["config", "commit.gpgsign", "false"],
    ):
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


def _git(path: Path, *args: str) -> None:
    import subprocess

    subprocess.run(["git", *args], cwd=path, check=True, capture_output=True)


def _seed_scan(run_dir: Path, secret: str) -> None:
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "raw" / "gitleaks.json").write_text(
        json.dumps([{"Secret": secret, "File": "cfg.env", "StartLine": 1,
                     "RuleID": "aws", "Description": "k"}]),
        encoding="utf-8",
    )


SECRET = "AKIAQ7X9TESTONLYVALUE42"


def test_clean_repo_reports_clean(vhc, tmp_path):
    repo, run = tmp_path / "repo", tmp_path / "run"
    _git_repo(repo)
    (repo / "a.txt").write_text("nothing here\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    _seed_scan(run, SECRET)

    assert vhc.main([str(run), str(repo)]) == 0


def test_secret_committed_then_removed_is_found(vhc, tmp_path):
    repo, run = tmp_path / "repo", tmp_path / "run"
    _git_repo(repo)
    (repo / "cfg.env").write_text(f"API_KEY={SECRET}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "oops")
    (repo / "cfg.env").write_text("API_KEY=redacted\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "redact")
    _seed_scan(run, SECRET)

    assert vhc.main([str(run), str(repo)]) == 1


def test_secret_amended_away_is_still_found(vhc, tmp_path):
    """The regression this tool exists for.

    A secret introduced and then dropped via ``commit --amend`` is unreachable
    from every ref, so ``git log -S``, ``rev-list --all`` and every
    commit-walking scanner (gitleaks included) report clean. It is ALSO not
    listed by ``fsck --unreachable``, because the superseded commit is still
    reachable from the reflog. Only enumerating the object database itself
    finds it -- and a false "clean" here means a real credential leak gets a
    "no rotation required" recommendation.
    """
    import subprocess

    repo, run = tmp_path / "repo", tmp_path / "run"
    _git_repo(repo)
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")

    # commit carries BOTH a real change and the secret, so amending to drop
    # only the secret still leaves a non-empty commit
    (repo / "cfg.env").write_text(f"API_KEY={SECRET}\n", encoding="utf-8")
    (repo / "b.txt").write_text("y\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "feature + oops")
    (repo / "cfg.env").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--amend", "-m", "feature only")

    # precondition: commit-walking really is blind to it
    out = subprocess.run(
        ["git", "log", "--all", "-S", SECRET, "--oneline"],
        cwd=repo, capture_output=True, text=True,
    )
    assert out.stdout.strip() == "", "fixture invalid: secret still ref-reachable"

    _seed_scan(run, SECRET)
    assert vhc.main([str(run), str(repo)]) == 1


def test_enumeration_covers_more_than_reachable_objects(vhc, tmp_path):
    """Contract: the object-DB enumeration is a superset of ref-reachable."""
    import subprocess

    repo = tmp_path / "repo"
    _git_repo(repo)
    (repo / "a.txt").write_text("x\n", encoding="utf-8")
    (repo / "gone.txt").write_text("dropped content\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    (repo / "gone.txt").unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--amend", "-m", "base only")

    all_blobs = set(vhc.all_object_shas(repo))
    reach = subprocess.run(
        ["git", "rev-list", "--all", "--objects"],
        cwd=repo, capture_output=True, text=True,
    ).stdout.splitlines()
    reachable = {ln.split(" ", 1)[0] for ln in reach if ln[:40].strip()}

    assert all_blobs - reachable, (
        "object-DB enumeration must find blobs that rev-list --all misses"
    )


def test_no_secret_value_is_ever_printed(vhc, tmp_path, capsys):
    repo, run = tmp_path / "repo", tmp_path / "run"
    _git_repo(repo)
    (repo / "cfg.env").write_text(f"API_KEY={SECRET}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "oops")
    _seed_scan(run, SECRET)

    vhc.main([str(run), str(repo)])
    out = capsys.readouterr().out
    assert SECRET not in out, "the tool must never print a secret value"
    assert "ROTATION REQUIRED" in out


def test_placeholder_values_are_not_treated_as_secrets(vhc, tmp_path):
    """Short/low-entropy placeholders must not drive a rotation recommendation."""
    repo, run = tmp_path / "repo", tmp_path / "run"
    _git_repo(repo)
    (repo / "cfg.env").write_text("API_KEY=SECRET\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "placeholder")
    _seed_scan(run, "SECRET")

    assert vhc.main([str(run), str(repo)]) == 0


def test_non_repo_path_is_a_usage_error(vhc, tmp_path):
    run = tmp_path / "run"
    _seed_scan(run, SECRET)
    assert vhc.main([str(run), str(tmp_path / "not-a-repo")]) == 2


def test_redacted_scan_refuses_to_certify_clean(vhc, tmp_path):
    """A --redact'ed scan must FAIL the gate, not silently report clean.

    Redaction strips the values this check needs, so the scan verifies nothing.
    Returning 0 there would print a no-rotation-required conclusion having
    checked zero values - the exact silent failure this gate exists to prevent.
    Exit 2 = cannot verify, which is distinct from 0 = verified clean and
    1 = secret found in history.
    """
    repo, run = tmp_path / "repo", tmp_path / "run"
    _git_repo(repo)
    (repo / "cfg.env").write_text(f"API_KEY={SECRET}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "seed")
    _seed_scan(run, "REDACTED")

    assert vhc.main([str(run), str(repo)]) == 2
