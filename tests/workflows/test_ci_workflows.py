"""The CI privilege split, the secret scan, CodeQL and Dependabot configuration.

A workflow edit can grant the *next* run privilege the *current* task never held, so the
workflows' privileges are checked rather than trusted to review. Each workflow is parsed
into its semantic model (triggers, permissions, jobs, steps) and the checks are functions
of that model, so each negative case drives the same code on a mutated copy of the parsed
document instead of asserting only that today's file happens to be clean. PyYAML is a
development-time dependency of this test only (requirements-dev.txt).
"""

from __future__ import annotations

import copy
import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
VALIDATION = WORKFLOWS / "ci.yml"
CODEQL = WORKFLOWS / "codeql.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
GITLEAKS_CONFIG = ROOT / ".gitleaks.toml"

#: Allowance keys that widen a scan past one named value. An allowance names a value.
_FORBIDDEN_ALLOWANCE_KEYS = ("paths", "commits", "targetRules", "stopwords")

#: A third-party action is pinned to a full commit SHA; a tag can be moved.
_PINNED = re.compile(r"[^@\s]+@[0-9a-f]{40}")

#: The one job allowed to hold a write permission, and the one write it may hold.
_SECURITY_EVENTS_JOB = ("codeql.yml", "analyze")


def load_workflow(text: str) -> dict[str, Any]:
    """The workflow as GitHub reads it: YAML 1.1 turns the `on` key into boolean True."""
    document = yaml.safe_load(text)
    if True in document:
        document["on"] = document.pop(True)
    return document


def _triggers(workflow: dict[str, Any]) -> set[str]:
    on = workflow.get("on") or {}
    if isinstance(on, str):
        return {on}
    return set(on)


def _permission_maps(workflow: dict[str, Any]) -> Iterator[tuple[str, Any]]:
    yield "workflow", workflow.get("permissions")
    for name, job in (workflow.get("jobs") or {}).items():
        yield f"job `{name}`", job.get("permissions")


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _steps(workflow: dict[str, Any], job: str) -> list[dict[str, Any]]:
    return list(workflow["jobs"][job].get("steps") or [])


def _all_steps(workflow: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for job in (workflow.get("jobs") or {}).values():
        yield from job.get("steps") or []


def validation_violations(workflow: dict[str, Any]) -> list[str]:
    """What the validation workflow holds that a pull request must not be able to reach."""
    found = []
    if workflow.get("permissions") != {"contents": "read"}:
        found.append("top-level permissions are not exactly `contents: read`")
    for scope, permissions in _permission_maps(workflow):
        if not isinstance(permissions, dict):
            continue
        for name, level in permissions.items():
            if level in ("write", "admin"):
                found.append(f"write permission `{name}: {level}` in {scope}")
    for text in _strings(workflow.get("jobs")):
        for match in re.finditer(r"\bsecrets\.[A-Za-z_]+|\bsecrets\[", text):
            found.append(f"secret reference `{match.group(0)}`")
    for job in (workflow.get("jobs") or {}).values():
        if "secrets" in job:
            found.append("job passes `secrets` to a called workflow")
    if "pull_request_target" in _triggers(workflow):
        found.append("`pull_request_target` trigger")
    return found


def hygiene_violations(workflow: dict[str, Any]) -> list[str]:
    """Every workflow declares its token, pins its actions and keeps no checkout credential."""
    found = []
    if not isinstance(workflow.get("permissions"), dict):
        found.append("no top-level `permissions` block")
    elif workflow["permissions"].get("contents") != "read":
        found.append("top-level `contents` is not `read`")
    if "pull_request_target" in _triggers(workflow):
        found.append("`pull_request_target` trigger")
    for step in _all_steps(workflow):
        uses = str(step.get("uses", ""))
        if not uses or uses.startswith("./"):
            continue
        if not _PINNED.fullmatch(uses):
            found.append(f"action `{uses}` is not pinned to a full commit SHA")
        if uses.startswith("actions/checkout@") and (step.get("with") or {}).get(
            "persist-credentials"
        ) is not False:
            found.append("checkout keeps its credentials (`persist-credentials` is not false)")
    return found


def secret_scan_violations(workflow: dict[str, Any]) -> list[str]:
    """The secret-scan job must exist, be pinned to a version and a checksum, and fail."""
    if "secret-scan" not in (workflow.get("jobs") or {}):
        return ["no `secret-scan` job"]
    steps = _steps(workflow, "secret-scan")
    env: dict[str, Any] = {}
    for step in steps:
        env.update(step.get("env") or {})
    runs = [str(step["run"]) for step in steps if "run" in step]
    checkouts = [
        step.get("with") or {}
        for step in steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    found = []
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(env.get("GITLEAKS_VERSION", ""))):
        found.append("scanner version is not pinned to an exact release")
    if not re.fullmatch(r"[0-9a-f]{64}", str(env.get("GITLEAKS_SHA256", ""))):
        found.append("scanner archive has no recorded SHA-256")
    if not any(
        re.search(r"^\s*echo\b.*\|\s*sha256sum --check\b", line)
        for run in runs
        for line in run.splitlines()
    ):
        found.append("scanner archive is not verified before it runs")
    if not any(re.search(r"\bgitleaks\b.*--exit-code 1\b", run, re.DOTALL) for run in runs):
        found.append("a finding does not fail the job")
    if not any(with_.get("fetch-depth") == 0 for with_ in checkouts):
        found.append("history is not fully fetched, so only the tip would be scanned")
    return found


def codeql_violations(workflow: dict[str, Any]) -> list[str]:
    """CodeQL writes security events and nothing else, and only on its analyze job."""
    found = []
    jobs = workflow.get("jobs") or {}
    if _SECURITY_EVENTS_JOB[1] not in jobs:
        return ["no `analyze` job"]
    for scope, permissions in _permission_maps(workflow):
        if not isinstance(permissions, dict):
            continue
        for name, level in permissions.items():
            if level in ("write", "admin") and not (
                scope == f"job `{_SECURITY_EVENTS_JOB[1]}`" and (name, level) == ("security-events", "write")
            ):
                found.append(f"unexpected write permission `{name}: {level}` in {scope}")
    analyze = jobs[_SECURITY_EVENTS_JOB[1]]
    permissions = analyze.get("permissions") or {}
    if permissions.get("security-events") != "write":
        found.append("the analyze job cannot upload results (`security-events: write`)")
    for name in ("contents", "actions"):
        if permissions.get(name) != "read":
            found.append(f"the analyze job does not hold `{name}: read`")
    steps = _steps(workflow, _SECURITY_EVENTS_JOB[1])
    uses = [str(step.get("uses", "")) for step in steps]
    for action in ("init", "analyze"):
        if not any(item.startswith(f"github/codeql-action/{action}@") for item in uses):
            found.append(f"no `codeql-action/{action}` step")
    languages = (analyze.get("strategy") or {}).get("matrix", {}).get("language")
    if "javascript-typescript" not in (languages or []):
        found.append("`javascript-typescript` is not analyzed")
    if not _triggers(workflow) & {"push", "pull_request"}:
        found.append("CodeQL does not run on pushes or pull requests")
    return found


def allowance_violations(config_text: str) -> list[str]:
    """An allowance must name one value (an anchored regex), never a path, rule or commit."""
    config = tomllib.loads(config_text)
    found = []
    if config.get("extend", {}).get("useDefault") is not True:
        found.append("the default ruleset is not extended")
    allowances = list(config.get("allowlists", []))
    if "allowlist" in config:
        allowances.append(config["allowlist"])
    for entry in allowances:
        label = entry.get("description", "<undescribed allowance>")
        for key in _FORBIDDEN_ALLOWANCE_KEYS:
            if key in entry:
                found.append(f"allowance `{label}` uses `{key}`")
        if not entry.get("regexes"):
            found.append(f"allowance `{label}` names no value")
        for pattern in entry.get("regexes", []):
            if not (pattern.startswith("^") and pattern.endswith("$")):
                found.append(f"allowance `{label}` has an unanchored regex `{pattern}`")
    return found


def dependabot_violations(config: dict[str, Any]) -> list[str]:
    """Dependabot watches the actions the workflows use and the npm lockfile."""
    watched = {update.get("package-ecosystem") for update in config.get("updates") or []}
    return [
        f"Dependabot does not watch `{ecosystem}`"
        for ecosystem in ("github-actions", "npm")
        if ecosystem not in watched
    ]


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOWS.glob("*.yml"))


def _validation() -> dict[str, Any]:
    return load_workflow(VALIDATION.read_text())


def _codeql() -> dict[str, Any]:
    return load_workflow(CODEQL.read_text())


def _step(workflow: dict[str, Any], job: str, name: str) -> dict[str, Any]:
    (step,) = [s for s in _steps(workflow, job) if s.get("name") == name]
    return step


def test_the_workflows_exist():
    assert VALIDATION.is_file()
    assert CODEQL.is_file()
    assert DEPENDABOT.is_file()


def test_the_validation_workflow_is_read_only_and_secret_free():
    assert validation_violations(_validation()) == []


def test_every_workflow_declares_permissions_and_pins_its_actions():
    for path in _workflow_files():
        assert hygiene_violations(load_workflow(path.read_text())) == [], path.name


def test_the_secret_scan_is_pinned_and_fails_on_a_finding():
    assert secret_scan_violations(_validation()) == []


def test_codeql_holds_only_the_security_events_write():
    assert codeql_violations(_codeql()) == []


def test_the_scanner_allowances_name_values():
    assert allowance_violations(GITLEAKS_CONFIG.read_text()) == []


def test_dependabot_watches_actions_and_npm():
    assert dependabot_violations(yaml.safe_load(DEPENDABOT.read_text())) == []


def test_the_allowances_match_only_the_fixtures_they_name():
    """Each allowance matches its fixture value exactly, and a near miss is not covered."""
    config = tomllib.loads(GITLEAKS_CONFIG.read_text())
    for entry in config["allowlists"]:
        for pattern in entry["regexes"]:
            literal = re.sub(r"\\(.)", r"\1", pattern[1:-1])
            if "X{24}" in literal:
                literal = literal.replace("X{24}", "X" * 24)
            assert re.fullmatch(pattern, literal), pattern
            assert not re.search(pattern, literal + "A"), pattern


def test_a_secret_reference_added_to_the_validation_job_is_found():
    mutated = _validation()
    _step(mutated, "validate-and-test", "claude plugin test")["env"] = {
        "TOKEN": "${{ secrets.DEPLOY_TOKEN }}"
    }
    found = validation_violations(mutated)
    assert any("secrets.DEPLOY_TOKEN" in item for item in found), found


def test_a_write_permission_added_to_the_validation_workflow_is_found():
    mutated = _validation()
    mutated["permissions"]["packages"] = "write"
    found = validation_violations(mutated)
    assert any("packages: write" in item for item in found), found
    job_level = _validation()
    job_level["jobs"]["validate-and-test"]["permissions"] = {"contents": "write"}
    assert any("contents: write" in item for item in validation_violations(job_level))


def test_pull_request_target_added_to_a_workflow_is_found():
    mutated = _validation()
    mutated["on"]["pull_request_target"] = None
    assert any("pull_request_target" in item for item in validation_violations(mutated))
    assert any("pull_request_target" in item for item in hygiene_violations(mutated))


def test_a_workflow_without_a_permissions_block_is_found():
    mutated = _validation()
    del mutated["permissions"]
    assert "no top-level `permissions` block" in hygiene_violations(mutated)


def test_an_action_pinned_to_a_tag_is_found():
    mutated = _validation()
    _steps(mutated, "validate-and-test")[0]["uses"] = "actions/checkout@v4"
    found = hygiene_violations(mutated)
    assert any("not pinned to a full commit SHA" in item for item in found), found


def test_a_checkout_that_keeps_its_credentials_is_found():
    mutated = _validation()
    del _steps(mutated, "validate-and-test")[0]["with"]["persist-credentials"]
    assert any("keeps its credentials" in item for item in hygiene_violations(mutated))


def test_removing_the_secret_scan_job_is_found():
    mutated = _validation()
    del mutated["jobs"]["secret-scan"]
    assert secret_scan_violations(mutated) == ["no `secret-scan` job"]


def test_an_unpinned_or_unverified_scanner_is_found():
    install = "Install gitleaks (pinned, checksum-verified)"
    unpinned = _validation()
    _step(unpinned, "secret-scan", install)["env"]["GITLEAKS_VERSION"] = "latest"
    assert any("not pinned" in item for item in secret_scan_violations(unpinned))
    unverified = _validation()
    step = _step(unverified, "secret-scan", install)
    step["run"] = step["run"].replace("sha256sum --check --strict", "true")
    assert any("not verified" in item for item in secret_scan_violations(unverified))
    narrated = _validation()
    step = _step(narrated, "secret-scan", install)
    step["run"] += "\necho 'sha256sum --check'\n"
    step["run"] = step["run"].replace("| sha256sum --check --strict", "")
    assert any("not verified" in item for item in secret_scan_violations(narrated))


def test_a_finding_that_does_not_fail_the_job_is_found():
    mutated = _validation()
    step = _step(mutated, "secret-scan", "Scan history for secrets")
    step["run"] = step["run"].replace("--exit-code 1", "--exit-code 0")
    assert any("does not fail" in item for item in secret_scan_violations(mutated))


def test_a_shallow_clone_would_scan_only_the_tip_and_is_found():
    mutated = _validation()
    _steps(mutated, "secret-scan")[0]["with"]["fetch-depth"] = 1
    assert any("fully fetched" in item for item in secret_scan_violations(mutated))
    elsewhere = _validation()
    del _steps(elsewhere, "secret-scan")[0]["with"]["fetch-depth"]
    elsewhere["jobs"]["validate-and-test"]["steps"][0]["with"]["fetch-depth"] = 0
    assert any("fully fetched" in item for item in secret_scan_violations(elsewhere))


def test_codeql_with_a_wider_token_is_found():
    widened = _codeql()
    widened["permissions"]["contents"] = "write"
    assert any("contents: write" in item for item in codeql_violations(widened))
    job_level = _codeql()
    job_level["jobs"]["analyze"]["permissions"]["packages"] = "write"
    assert any("packages: write" in item for item in codeql_violations(job_level))


def test_codeql_that_cannot_upload_or_read_is_found():
    read_only = _codeql()
    read_only["jobs"]["analyze"]["permissions"]["security-events"] = "read"
    assert any("cannot upload" in item for item in codeql_violations(read_only))
    no_contents = _codeql()
    del no_contents["jobs"]["analyze"]["permissions"]["contents"]
    assert any("`contents: read`" in item for item in codeql_violations(no_contents))


def test_codeql_that_drops_the_language_or_a_step_is_found():
    no_language = _codeql()
    no_language["jobs"]["analyze"]["strategy"]["matrix"]["language"] = ["python"]
    assert any("javascript-typescript" in item for item in codeql_violations(no_language))
    no_analyze = _codeql()
    no_analyze["jobs"]["analyze"]["steps"] = _steps(no_analyze, "analyze")[:-1]
    assert any("codeql-action/analyze" in item for item in codeql_violations(no_analyze))


def test_an_allowance_written_by_path_is_found():
    config = (
        '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "whole file"\n'
        "paths = ['''tests/redaction\\.test\\.ts''']\n"
    )
    found = allowance_violations(config)
    assert any("uses `paths`" in item for item in found), found
    assert any("names no value" in item for item in found), found
    by_commit = (
        "[extend]\nuseDefault = true\n\n[[allowlists]]\ncommits = ['abc']\nregexes = ['^x$']\n"
    )
    assert any("uses `commits`" in item for item in allowance_violations(by_commit))


def test_an_unanchored_allowance_is_found():
    config = "[extend]\nuseDefault = true\n\n[[allowlists]]\nregexes = ['''sk_live_.+''']\n"
    assert any("unanchored" in item for item in allowance_violations(config))


def test_dropping_a_watched_ecosystem_from_dependabot_is_found():
    config = copy.deepcopy(yaml.safe_load(DEPENDABOT.read_text()))
    config["updates"] = [u for u in config["updates"] if u["package-ecosystem"] != "npm"]
    assert dependabot_violations(config) == ["Dependabot does not watch `npm`"]
