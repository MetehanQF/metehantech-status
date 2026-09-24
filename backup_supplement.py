"""Conservative non-secret coverage extensions; never archive raw secret configs."""
import json,os,re,subprocess,tarfile,tempfile,hashlib
from pathlib import Path
import deployment

# Values matching any sensitive reference cause exclusion, not optimistic redaction.
SENSITIVE = re.compile(r'(?i)(password|passwd|secret|token|api[_-]?key|authorization|rtsp://|https?://[^\s/]+:[^\s/@]+@|BEGIN .*PRIVATE KEY)')
PI_FILES = [Path('/etc/systemd/system')/n for n in ['metehantech-backup-pi.service','metehantech-backup-pcold.service','metehantech-backup-cloud.service']]
PI_FILES += [Path('/opt/metehantech-cloud')/n for n in ['apache-vhost.conf','apache-proxy.conf']]
PCOLD_FILES = ['/usr/local/libexec/metehantech-backup-receiver','/usr/local/libexec/metehantech-backup-pcold-export','/etc/systemd/system/metehantech-backup-export.service','/etc/systemd/system/metehantech-dashboard.service','/etc/systemd/system/metehantech-metrics.service','/etc/systemd/system/metehantech-watchdog.service','/usr/local/bin/metehantech-metrics.py']

# The OpenClaw workspace is documentation and agent memory, not a secret store; the
# Gateway's credentials live outside it in ~/.openclaw/{openclaw.json,credentials}.
# SENSITIVE above matches the bare word "secret", which every engineering report contains,
# so the workspace needs a value-bearing pattern instead: a secret-looking NAME followed by
# an actual VALUE. Anything that matches is dropped from the archive, never redacted in place.
# Opsiyonel: OpenClaw calisma alani bu deployment'a ozeldir. Tanimsizsa
# yedek takviyesi acikca devre disi kalir (sessizce yanlis dizin taranmaz).
WORKSPACE_ROOT = deployment.optional_path("OPENCLAW_WORKSPACE")
# The optional scheme word matters: `Authorization: Bearer <token>` is the single most
# common credential form in a config or a pasted log, and without it the value sits one
# word past the separator and slips through.
WORKSPACE_VALUE_BEARING = re.compile(
    r'(?i)(?:password|passwd|secret|token|api[_-]?key|authorization|bearer|private[_-]?key)'
    r'\s*[:=]\s*["\']?(?:bearer\s+|basic\s+|token\s+)?[A-Za-z0-9._\-/+=]{8,}'
    r'|BEGIN [A-Z ]*PRIVATE KEY'
    r'|rtsp://[^\s/]+:[^\s/@]+@'
    r'|https?://[^\s/]+:[^\s/@]+@'
)
# .git is skipped because its object store is compressed and therefore cannot be content
# scanned; the working tree above it carries the same content in readable form.
WORKSPACE_SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv'}
WORKSPACE_MAX_FILE_BYTES = 4 * 1024 * 1024


def collect_workspace(root=WORKSPACE_ROOT):
    """Return (files_to_copy, status) for the OpenClaw workspace, excluding secret-bearing files."""
    if root is None:
        return [], {'root': None, 'included': [], 'excluded': [],
                    'skipped_reason': 'OPENCLAW_WORKSPACE not configured'}
    root = Path(root)
    included, excluded = [], []
    if not root.is_dir():
        return [], {'root': str(root), 'included': [], 'excluded': [],
                    'skipped_reason': 'workspace directory absent'}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        if any(part in WORKSPACE_SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            excluded.append({'path': relative, 'reason': 'symlink; not followed'})
            continue
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            excluded.append({'path': relative, 'reason': 'unreadable'})
            continue
        if len(data) > WORKSPACE_MAX_FILE_BYTES:
            excluded.append({'path': relative, 'reason': 'exceeds workspace archive size limit'})
            continue
        if WORKSPACE_VALUE_BEARING.search(data.decode('utf-8', errors='replace')):
            excluded.append({'path': relative, 'reason': 'value-bearing secret pattern; operator review required'})
            continue
        included.append((relative, data))
    return included, {
        'root': str(root),
        'skipped_directories': sorted(WORKSPACE_SKIP_DIRS),
        'included_count': len(included),
        'included_bytes': sum(len(d) for _, d in included),
        'included': [{'path': r, 'sha256': hashlib.sha256(d).hexdigest(), 'bytes': len(d)} for r, d in included],
        'excluded': excluded,
    }


def add_workspace(staging, root=WORKSPACE_ROOT):
    """Write openclaw-workspace.tar.zst next to the other payloads. Caller re-manifests."""
    staging = Path(staging)
    files, status = collect_workspace(root)
    if not files:
        status['archive'] = None
        return status
    with tempfile.TemporaryDirectory(prefix='mt-workspace-') as td:
        stage = Path(td) / 'openclaw-workspace'
        for relative, data in files:
            dest = stage / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            os.chmod(dest, 0o600)
        archive = staging / 'openclaw-workspace.tar.zst'
        subprocess.run(['tar', '--zstd', '-cf', str(archive), '-C', str(stage.parent), 'openclaw-workspace'],
                       capture_output=True, timeout=120, check=True)
    os.chmod(archive, 0o600)
    status['archive'] = archive.name
    status['archive_bytes'] = archive.stat().st_size
    return status


def add_supplement(staging,node,ssh=None):
    from backups import write_manifest
    staging=Path(staging);status={'node':node,'included':[],'excluded':[],'operator_secrets':'required; never copied by this supplement'}
    with tempfile.TemporaryDirectory(prefix='mt-coverage-') as td:
        root=Path(td)
        for path in (PI_FILES if node=='pi' else PCOLD_FILES):
            p=Path(path)
            try:
                if ssh:
                    r=subprocess.run(list(ssh)+['cat',str(p)],capture_output=True,timeout=15,check=True);data=r.stdout
                else:data=p.read_bytes()
                if len(data)>1024*1024 or SENSITIVE.search(data.decode('utf-8',errors='replace')):
                    status['excluded'].append({'path':str(p),'reason':'sensitive reference/content; operator review required'});continue
                dest=root/str(p).lstrip('/');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);os.chmod(dest,0o600)
                status['included'].append({'path':str(p),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
            except (OSError,subprocess.SubprocessError):status['excluded'].append({'path':str(p),'reason':'unreadable or remote unavailable'})
        (root/'coverage.json').write_text(json.dumps(status,indent=2))
        subprocess.run(['tar','--zstd','-cf',str(staging/'coverage-supplement.tar.zst'),'-C',str(root),'.'],capture_output=True,timeout=30,check=True)
    if node=='pi':
        status['openclaw_workspace']=add_workspace(staging)
    # The incoming export manifest has already been verified; keep a provenance copy.
    manifest=staging/'SHA256SUMS'
    if manifest.exists(): (staging/'SOURCE_SHA256SUMS').write_bytes(manifest.read_bytes())
    (staging/'coverage-supplement.json').write_text(json.dumps(status,indent=2))
    write_manifest(staging)
    return status
