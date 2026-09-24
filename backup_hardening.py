"""Fail-closed backup storage and artifact checks. No restore or deletion actions."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

LOCAL_STORAGE = {'target': '/', 'source': '/dev/nvme0n1p2', 'fstype': 'ext4'}
REMOTE_STORAGE = {'target': '/', 'source': '/dev/sda1', 'fstype': 'ext4'}


def check_mount(payload, expected):
    rows = payload.get('filesystems', [])
    if len(rows) != 1:
        raise RuntimeError('Cannot identify backup filesystem')
    row = rows[0]
    if any(row.get(k) != v for k, v in expected.items()):
        raise RuntimeError('Backup filesystem identity mismatch; refusing local mount fallback')
    if 'rw' not in row.get('options', '').split(','):
        raise RuntimeError('Backup filesystem is not writable')
    return row


def storage_guard(path, expected=LOCAL_STORAGE, ssh=None):
    # Both current backup destinations are local ext4. For future NFS use an exact
    # target/source/fstype expectation; missing mounts MUST fail closed.
    prefix = list(ssh or [])
    r = subprocess.run(prefix + ['findmnt', '-J', '-T', str(path)], capture_output=True, text=True, timeout=20, check=True)
    row = check_mount(json.loads(r.stdout), expected)
    r = subprocess.run(prefix + ['df', '-Pk', str(path)], capture_output=True, text=True, timeout=20, check=True)
    free = int(r.stdout.splitlines()[-1].split()[3]) * 1024
    if free < 2 * 1024**3:
        raise RuntimeError('Backup filesystem has less than 2 GiB free')
    return {**row, 'free_bytes': free}


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def strict_verify(root, node, fresh=True):
    from backups import verify_restore_point
    root = Path(root)
    result = verify_restore_point(root, allow_staging=True)
    if any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('Symlink in backup artifact tree')
    listed = []
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        checksum, sep, relative = line.partition('  ')
        listed.append(relative)
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.name != 'SHA256SUMS'}
    # Legacy PcOld verifier opens WAL-mode snapshots and leaves regenerable caches.
    # Accept only an EMPTY WAL + its SHM alongside a manifested DB, never WAL data.
    caches = set()
    for relative in actual - set(listed):
        if relative.endswith(('-wal', '-shm')) and relative[:-4] in listed and relative[:-4].endswith('.db'):
            wal = root / (relative[:-4] + '-wal')
            if wal.is_file() and wal.stat().st_size == 0:
                caches.add(relative)
    if len(set(listed)) != len(listed) or set(listed) != actual - caches:
        raise ValueError('Checksum manifest is not complete or contains duplicates')
    result['ignored_regenerable_sqlite_caches'] = sorted(caches)

    metadata = json.loads((root / 'metadata.json').read_text())
    if metadata.get('source_node') != node:
        raise ValueError('Backup metadata source mismatch')
    created = datetime.fromisoformat(metadata['created_at'])
    age = (datetime.now(timezone.utc) - created).total_seconds()
    if age < -300 or (fresh and age > 6 * 3600):
        raise ValueError('Backup timestamp is invalid or stale')
    # Deterministic payloads only: every entry here is produced unconditionally by the job
    # code, so a missing one is a real regression. Optional sources whose absence is a
    # legitimate state (an app DB that no longer exists) are reported by the validator
    # instead of failing the backup closed.
    required = {
        'pi': ['applications.tar.zst', 'system-units.tar.zst', 'coverage-supplement.tar.zst', 'openclaw-workspace.tar.zst', 'databases/metrics.db', 'databases/alerts.db', 'databases/admin_activity.db', 'databases/backups.db'],
        'pcold': ['pcold-applications.tar.zst', 'uptime-kuma-files.tar.zst', 'coverage-supplement.tar.zst', 'databases/watchdog-events.db', 'databases/uptime-kuma.db'],
        'cloud': ['database/nextcloud.pgdump', 'nextcloud-files.tar.zst', 'deployment-metadata.tar.zst', 'nextcloud-system-config.redacted.json'],
    }[node]
    for relative in required:
        p = root / relative
        if not p.is_file() or p.stat().st_size < (512 if p.suffix in {'.db', '.pgdump'} else 32):
            raise ValueError('Required backup payload absent or implausibly small: ' + relative)
    if node == 'cloud':
        listing = subprocess.check_output(['tar', '--zstd', '-tf', str(root / 'nextcloud-files.tar.zst')], text=True, timeout=180)
        if any(Path(n).name == 'config.php' for n in listing.splitlines()):
            raise ValueError('Secret config.php unexpectedly included')
        # Parse the full custom dump, including data blocks, without connecting to any DB.
        with (root / 'database/nextcloud.pgdump').open('rb') as f:
            subprocess.run(['docker', 'exec', '-i', 'metehantech-nextcloud-db', 'pg_restore', '--file=/dev/null'], stdin=f, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180, check=True)
    return result
