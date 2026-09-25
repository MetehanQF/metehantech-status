"""Shared plumbing for the resilience harness.

Three jobs:

1. **Repo-relative imports.** These tools live inside the application they test,
   so they import `deployment`, `network`, `backup_validator` and friends as
   ordinary modules. No `sys.path` entry ever points outside this repository.

2. **Configuration.** Anything that depends on a particular deployment — the
   backup SSH key, the remote account, restore-point locations — comes from
   `deployment.py` / `network.py`. There is no fallback to a real path.

3. **Safety.** Two of these tools are destructive by nature: one deliberately
   corrupts restore points, the other starts throwaway containers and runs
   `pg_restore`. Both refuse to do anything until you opt in explicitly, and
   both refuse to touch a production location even when you do.

   The default for every tool here is a **dry run** that prints what it would do.
"""

import argparse
import os
import sys
from pathlib import Path

#: The application this harness tests. `parents[1]` because we live in resilience/.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import deployment  # noqa: E402  (after sys.path setup)


class LabGuardError(RuntimeError):
    """A destructive action was requested without the required opt-in."""


def results_dir():
    """Where tools write their JSON output.

    `RESILIENCE_RESULTS_DIR` if set, otherwise the current working directory —
    never a path baked into the source.
    """
    return Path(os.environ.get("RESILIENCE_RESULTS_DIR", ".")).resolve()


def write_results(name, payload):
    """Write `payload` as JSON into the results directory and report where."""
    import json

    target = results_dir() / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=1))
    print(f"  results -> {target}")
    return target


# --------------------------------------------------------------- safety guards

#: Locations these tools must never write to or mutate, even with --confirm.
#: A destructive run belongs in a throwaway directory, not next to live data.
def protected_paths():
    protected = [PROJECT_ROOT, deployment.DATA_DIR, Path("/etc"), Path("/srv"), Path("/var")]
    workspace = deployment.optional_path("OPENCLAW_WORKSPACE")
    if workspace:
        protected.append(workspace)
    return [p.resolve() for p in protected]


def assert_safe_lab(lab):
    """Refuse a lab directory that is inside, or a parent of, anything protected."""
    lab = Path(lab).resolve()
    for guarded in protected_paths():
        if lab == guarded or guarded in lab.parents or lab in guarded.parents:
            raise LabGuardError(
                f"refusing to use {lab} as a lab directory: it overlaps {guarded}. "
                "Point --lab at a throwaway directory (for example under /tmp)."
            )
    return lab


def add_safety_args(parser, *, needs_lab=False):
    """Add the opt-in flags every destructive tool in this package shares."""
    parser.add_argument(
        "--confirm", action="store_true",
        help="actually perform the destructive steps. Without it the tool only "
             "prints what it would do.")
    if needs_lab:
        parser.add_argument(
            "--lab", metavar="DIR", type=Path,
            help="throwaway directory for corrupted copies. Required with --confirm. "
                 "Must not overlap the project, its data directory, /etc, /srv or /var.")
        parser.add_argument(
            "--fixture", metavar="RESTORE_POINT", type=Path, action="append", default=[],
            help="restore point to copy into the lab. Repeatable. Required with "
                 "--confirm; nothing is read from a hard-coded location.")
    return parser


def require_confirmation(args, what):
    """Return True when the caller opted in; otherwise explain and return False."""
    if not getattr(args, "confirm", False):
        print(f"DRY RUN — {what}")
        print("  Nothing was changed. Re-run with --confirm to execute.")
        return False
    return True


def resolve_lab(args):
    """Validate --lab / --fixture for a confirmed destructive run."""
    if not args.lab:
        raise LabGuardError("--confirm requires --lab DIR (a throwaway directory).")
    lab = assert_safe_lab(args.lab)
    if not args.fixture:
        raise LabGuardError(
            "--confirm requires at least one --fixture RESTORE_POINT. This harness "
            "never guesses a restore point location.")
    missing = [f for f in args.fixture if not Path(f).exists()]
    if missing:
        raise LabGuardError("fixture not found: " + ", ".join(str(m) for m in missing))
    lab.mkdir(parents=True, exist_ok=True)
    return lab


def parser(description):
    return argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter)
