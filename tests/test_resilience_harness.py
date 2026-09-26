"""Regression tests for the resilience/ harness.

These exist because of a specific escape. The harness shipped with a
`NameError` — `config_baseline.py` used `deployment` six lines before importing
it — and the pre-merge check that was supposed to catch it ran `py_compile`.
`py_compile` only proves a file *parses*; it never executes module level, so an
undefined name, a `None / "str"` TypeError, or a mandatory config read at import
time all sail straight through it.

So: every test here performs a **real import**. Three of the six modules also
resolved mandatory deployment values (`BACKUP_SSH_KEY`) while being imported,
which made them unloadable on a clean clone — you could not even ask them for
`--help`. Deployment configuration must therefore be resolved when a caller
actually needs it, not as a side effect of importing.
"""

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESILIENCE = PROJECT_ROOT / "resilience"

#: Every module in the harness. All six must import with nothing configured.
MODULES = ("_harness", "config_baseline", "failure_sim", "restore_lab",
           "soak_collector", "storage_analysis")

#: Values a real deployment would supply. A clean clone has none of them.
DEPLOYMENT_KEYS = (
    "BACKUP_SSH_KEY", "BACKUP_REMOTE_USER", "BACKUP_EXTRA_SOURCES",
    "OPENCLAW_WORKSPACE", "CAMERA_MEDIA_DIR", "RESTORE_POINT_DIR",
    "MONITORED_MOUNTS", "DNS_CREDENTIALS",
    "PCOLD_LAN_IP", "PCOLD_TAILSCALE_IP", "PI5_LAN_IP", "PI5_TAILSCALE_IP",
    "CAMERA_LAN_IP", "ROUTER_LAN_IP", "PI5_WIFI_IFACE", "ONBOARD_CONN",
)


def configless_env():
    """A genuinely unconfigured environment.

    Both halves matter. Dropping the variables is not enough on its own because
    `envfile` falls back to `/etc/metehantech-status/`; pinning
    `METEHANTECH_CONFIG_DIR` at a path that does not exist makes that search
    exclusive and empty, so the real machine's configuration cannot leak in.
    """
    env = {k: v for k, v in os.environ.items() if k not in DEPLOYMENT_KEYS}
    env["METEHANTECH_CONFIG_DIR"] = "/nonexistent/metehantech-configless-clone"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


@pytest.fixture
def resilience_path():
    """Put resilience/ on sys.path for in-process tests, then take it back off."""
    added = []
    for entry in (str(RESILIENCE), str(PROJECT_ROOT)):
        if entry not in sys.path:
            sys.path.insert(0, entry)
            added.append(entry)
    yield
    for entry in added:
        sys.path.remove(entry)


# --------------------------------------------------------------- real imports

@pytest.mark.parametrize("module", MODULES)
def test_module_imports_on_a_configless_clone(module):
    """A real import, in a subprocess, with nothing configured.

    Deliberately not `py_compile`: the bug this guards against compiled fine.
    """
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=RESILIENCE, env=configless_env(),
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (
        f"{module} cannot be imported on a clean clone:\n{result.stderr}")


@pytest.mark.parametrize("module", MODULES)
def test_module_imports_with_deployment_configured(module):
    """The configured path must keep working too."""
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=RESILIENCE, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"{module} failed to import:\n{result.stderr}"


def test_no_module_reads_mandatory_config_at_import_time():
    """`deployment.get`/`.path` at module level is what broke the clean clone.

    Calls inside a function body are fine — that is the whole point of the fix —
    so only module-level statements are inspected.
    """
    definitions = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    offenders = []
    for module in MODULES:
        tree = ast.parse((RESILIENCE / f"{module}.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, definitions):
                continue                             # a call in a body is deferred
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                func = inner.func
                if (isinstance(func, ast.Attribute)
                        and func.attr in {"get", "path"}
                        and isinstance(func.value, ast.Name)
                        and func.value.id in {"deployment", "network"}):
                    offenders.append(f"{module}.py:{inner.lineno} "
                                     f"{func.value.id}.{func.attr}()")
    assert not offenders, (
        "mandatory deployment config resolved at import time: " + ", ".join(offenders))


# ------------------------------------------------- config_baseline, unconfigured

def test_default_output_is_none_without_workspace(resilience_path, monkeypatch):
    import config_baseline

    monkeypatch.setattr(config_baseline.deployment, "_FILE_VALUES", {})
    monkeypatch.delenv("OPENCLAW_WORKSPACE", raising=False)
    assert config_baseline.default_output() is None


def test_default_output_uses_workspace_when_configured(resilience_path, monkeypatch, tmp_path):
    import config_baseline

    monkeypatch.setenv("OPENCLAW_WORKSPACE", str(tmp_path))
    assert config_baseline.default_output() == tmp_path / "config-baseline.json"


def test_main_reports_not_configured_instead_of_crashing(resilience_path, monkeypatch, capsys):
    """The documented behaviour: say so and exit, never invent a path.

    Before the fix this raised `TypeError: unsupported operand type(s) for /:
    'NoneType' and 'str'` while the module was still being imported.
    """
    import config_baseline

    monkeypatch.setattr(config_baseline.deployment, "_FILE_VALUES", {})
    monkeypatch.delenv("OPENCLAW_WORKSPACE", raising=False)

    assert config_baseline.main([]) == 3
    assert "NOT CONFIGURED" in capsys.readouterr().out


def test_explicit_output_works_without_workspace(resilience_path, monkeypatch, tmp_path):
    """`--output` is the documented escape hatch when no workspace is configured."""
    import config_baseline

    monkeypatch.setattr(config_baseline.deployment, "_FILE_VALUES", {})
    monkeypatch.delenv("OPENCLAW_WORKSPACE", raising=False)
    monkeypatch.setattr(config_baseline, "build", lambda: {"summary": {"present": 0}})

    target = tmp_path / "baseline.json"
    assert config_baseline.main(["--output", str(target)]) == 0
    assert json.loads(target.read_text())["summary"] == {"present": 0}


def test_groups_builds_without_a_backup_key(resilience_path, monkeypatch):
    """The fingerprint set must not require BACKUP_SSH_KEY to exist."""
    import config_baseline

    monkeypatch.setattr(config_baseline.deployment, "_FILE_VALUES", {})
    monkeypatch.delenv("BACKUP_SSH_KEY", raising=False)

    groups = config_baseline.groups()
    assert groups["backup_scripts"], "local groups should still be populated"
    assert all("/nonexistent" not in p for p in groups["secret_bearing_fingerprint_only"])


def test_groups_includes_backup_key_when_configured(resilience_path, monkeypatch):
    import config_baseline

    monkeypatch.setenv("BACKUP_SSH_KEY", "/lab/synthetic/id_ed25519")
    assert "/lab/synthetic/id_ed25519" in config_baseline.groups()["secret_bearing_fingerprint_only"]


# ------------------------------------------------------ deferred peer resolution

def test_pcold_ssh_raises_only_when_called(resilience_path, monkeypatch):
    import _harness
    import deployment

    monkeypatch.setattr(deployment, "_FILE_VALUES", {})
    for key in ("BACKUP_SSH_KEY", "BACKUP_REMOTE_USER"):
        monkeypatch.delenv(key, raising=False)

    with pytest.raises(deployment.DeploymentConfigError):
        _harness.pcold_ssh()


def test_soak_peer_probe_reports_not_configured(resilience_path, monkeypatch):
    """A probe that cannot be configured is recorded, not fatal."""
    import deployment
    import soak_collector

    monkeypatch.setattr(deployment, "_FILE_VALUES", {})
    for key in ("BACKUP_SSH_KEY", "BACKUP_REMOTE_USER"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(soak_collector, "_PCOLD_SSH", None)

    probe = soak_collector.pcold_sh("true")
    assert probe["configured"] is False
    assert probe["reachable"] is False


def test_storage_analysis_skips_camera_when_unconfigured(resilience_path, monkeypatch):
    import deployment
    import storage_analysis

    monkeypatch.setattr(deployment, "_FILE_VALUES", {})
    monkeypatch.delenv("CAMERA_MEDIA_DIR", raising=False)

    assert storage_analysis.camera_dir() is None
    rate = storage_analysis.frigate_rate()
    assert rate["bytes_per_day"] is None
    assert "not configured" in rate["reason"]


# ------------------------------------------------------------ restore_lab result

def test_run_lab_returns_its_results(resilience_path):
    """`run_lab` used to fall off the end, so `main` printed `null`."""
    import restore_lab

    tree = ast.parse(Path(restore_lab.__file__).read_text(encoding="utf-8"))
    run_lab = next(n for n in tree.body
                   if isinstance(n, ast.FunctionDef) and n.name == "run_lab")
    returns = [n for n in ast.walk(run_lab)
               if isinstance(n, ast.Return) and n.value is not None]
    assert returns, "run_lab must return its results object"
    assert isinstance(run_lab.body[-1], ast.Return), \
        "run_lab must end by returning results, not fall off the end"


def test_main_prints_the_result_json_not_null(resilience_path, monkeypatch, capsys, tmp_path):
    import restore_lab

    sentinel = {"nextcloud_files": {"status": "RESTORE_TESTED"}, "lab": str(tmp_path)}
    monkeypatch.setattr(restore_lab, "run_lab", lambda args: sentinel)

    rc = restore_lab.main([
        "--confirm", "--lab", str(tmp_path / "lab"),
        "--cloud-source", str(tmp_path / "src"),
        "--db-container", "lab-db", "--app-container", "lab-app",
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip() != "null"
    assert json.loads(out) == sentinel


def test_main_without_confirm_changes_nothing(resilience_path, capsys):
    """Dry run stays the default for the destructive tool."""
    import restore_lab

    assert restore_lab.main([]) == 0
    assert "DRY RUN" in capsys.readouterr().out
