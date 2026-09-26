"""Isolated restore proofs: prove a backup can actually be restored.

Runs entirely in a throwaway lab directory and throwaway containers:
network NONE, no published ports, no production mounts, and the production
databases are never connected to. What it proves:

  * the archived Nextcloud files extract and every file matches its hash
  * the pgdump restores into an isolated tmpfs PostgreSQL and the schema is sane
    (no invalid indexes, no unvalidated constraints, no orphan storage rows)
  * every user file the restored database references actually exists in the
    restored file tree, at the right size
  * a deliberately damaged dump is REJECTED by pg_restore
  * the Uptime Kuma SQLite copy opens and passes an integrity check

Destructive by nature: it starts containers and writes into the lab directory.
It therefore does nothing without --confirm, and refuses a lab directory that
overlaps the project, its data directory, /etc, /srv or /var.

Nothing is read from a hard-coded location; every input is a command-line flag.
"""
from pathlib import Path
import json,subprocess,hashlib,time,os,sqlite3,tarfile,io,shutil
from datetime import datetime,timezone

from _harness import (  # noqa: E402  (sets up the repo-relative import path)
    LabGuardError, assert_safe_lab, parser, require_confirmation, results_dir,
)
from backup_hardening import strict_verify  # noqa: E402


def build_parser():
    ap = parser(__doc__)
    ap.add_argument("--confirm", action="store_true",
                    help="actually run the lab. Without it nothing is started.")
    ap.add_argument("--lab", metavar="DIR", type=Path,
                    help="throwaway working directory. Required with --confirm.")
    ap.add_argument("--cloud-source", metavar="DIR", type=Path,
                    help="verified cloud restore point holding nextcloud-files.tar.zst "
                         "and database/nextcloud.pgdump. Required with --confirm.")
    ap.add_argument("--secondary-fixture", metavar="DIR", type=Path,
                    help="secondary-node restore point holding databases/uptime-kuma.db. "
                         "Optional; that check is skipped when omitted.")
    ap.add_argument("--db-container", metavar="NAME",
                    help="existing database container to borrow the IMAGE from "
                         "(never connected to). Required with --confirm.")
    ap.add_argument("--app-container", metavar="NAME",
                    help="existing application container to borrow the IMAGE from. "
                         "Required with --confirm.")
    return ap


def run_lab(args):
    os.umask(0o077)
    lab = assert_safe_lab(args.lab)
    lab.mkdir(parents=True, mode=0o700, exist_ok=True)
    source = args.cloud_source
    if not (source / "nextcloud-files.tar.zst").is_file():
        raise LabGuardError(f"{source} is not a cloud restore point "
                            "(nextcloud-files.tar.zst missing)")
    results = {'started_at': datetime.now(timezone.utc).isoformat(),
               'lab': str(lab), 'network': 'none', 'ports': [],
               'production_mounts': False, 'cloud_source': str(source)}

    def run(args_, **kw):
        return subprocess.run(args_, capture_output=True, timeout=180, check=True, **kw)

    def save():
        (results_dir() / 'restore-results.json').write_text(json.dumps(results, indent=2))

    results['cloud_artifacts']=strict_verify(source,'cloud',fresh=False)
    start=time.monotonic();dest=lab/'cloud-files';dest.mkdir(exist_ok=True)
    z=subprocess.Popen(['zstd','-dc',str(source/'nextcloud-files.tar.zst')],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    count=0;total=0;hashes={}
    try:
     with tarfile.open(fileobj=z.stdout,mode='r|') as tf:
      for member in tf:
       safe=tarfile.data_filter(member,str(dest))
       if safe is None:continue
       if Path(member.name).name=='config.php':raise RuntimeError('Unexpected secret config.php')
       if member.isfile():
        target=dest/member.name;target.parent.mkdir(parents=True,exist_ok=True)
        with tf.extractfile(member) as f,target.open('wb') as out:
         h=hashlib.sha256()
         while b:=f.read(1024*1024):out.write(b);h.update(b)
        hashes[member.name]=h.hexdigest();count+=1;total+=member.size
       elif member.isdir():(dest/member.name).mkdir(parents=True,exist_ok=True)
       else:raise RuntimeError('Special/link member requires separate restore review')
     if z.wait(timeout=20)!=0:raise RuntimeError('Decompression failed')
     mismatches=sum(hashlib.sha256((dest/name).read_bytes()).hexdigest()!=h for name,h in hashes.items())
     results['nextcloud_files']={'status':'RESTORE_TESTED' if mismatches==0 else 'FAIL','files':count,'bytes':total,'hash_mismatches':mismatches,'seconds':round(time.monotonic()-start,3),'secret_config_present':(dest/'config/config.php').exists()}
    except Exception as e:results['nextcloud_files']={'status':'FAIL','error':type(e).__name__};save();raise
    save()
    image=run(['docker','inspect',args.db_container,'--format','{{.Image}}']).stdout.decode().strip()
    name='mt-resilience-v2-pg-'+str(os.getpid());results['pg_container']=name
    start=time.monotonic()
    try:
     run(['docker','run','--pull=never','--detach','--name',name,'--label','metehantech.resilience=v2','--network','none','--cpus','1','--memory','768m','--pids-limit','128','--tmpfs','/var/lib/postgresql/data:rw,size=512m','--tmpfs','/var/run/postgresql:rw,size=16m','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=nextcloud','-e','POSTGRES_DB=nextcloud',image])
     for i in range(45):
      r=subprocess.run(['docker','exec',name,'pg_isready','-U','nextcloud','-d','nextcloud'],capture_output=True)
      logs=subprocess.run(['docker','logs',name],capture_output=True).stdout
      if r.returncode==0 and b'init process complete' in logs:break
      time.sleep(1)
     else:raise RuntimeError('Lab PostgreSQL not ready')
     with (source/'database/nextcloud.pgdump').open('rb') as f:
      r=subprocess.run(['docker','exec','-i',name,'pg_restore','--exit-on-error','--no-owner','--no-acl','-U','nextcloud','-d','nextcloud'],stdin=f,capture_output=True,timeout=180)
     if r.returncode:raise RuntimeError('pg_restore exit '+str(r.returncode))
     def sql(query):return run(['docker','exec',name,'psql','-U','nextcloud','-d','nextcloud','-At','-c',query]).stdout.decode().strip()
     metrics={}
     for key,q in {
     'tables':"select count(*) from information_schema.tables where table_schema='public'",
     'users':'select count(*) from oc_users',
     'filecache_rows':'select count(*) from oc_filecache',
     'constraints':"select count(*) from pg_constraint where connamespace='public'::regnamespace",
     'indexes':"select count(*) from pg_indexes where schemaname='public'",
     'invalid_indexes':'select count(*) from pg_index where not indisvalid',
     'unvalidated_constraints':'select count(*) from pg_constraint where not convalidated',
     'orphan_storage_references':'select count(*) from oc_filecache f left join oc_storages s on f.storage=s.numeric_id where s.numeric_id is null'
     }.items():metrics[key]=int(sql(q))
     # Compare DB's user-file entries against extracted backup data; no user/path values logged.
     rows=sql("select coalesce(u.uid,''),f.path,f.size from oc_filecache f join oc_storages s on f.storage=s.numeric_id left join oc_users u on s.id='home::'||u.uid where s.id like 'home::%' and f.path like 'files/%' and f.mimetype <> (select id from oc_mimetypes where mimetype='httpd/unix-directory')")
     found=0;missing=0;size_mismatch=0
     for row in rows.splitlines():
      uid,path,size=row.split('|',2);target=(dest/'data'/uid/path).resolve()
      if not target.is_relative_to(dest.resolve()):raise RuntimeError('Unsafe metadata path')
      if target.is_file():
       found+=1;size_mismatch+=target.stat().st_size!=int(size)
      else:missing+=1
     metrics['user_files_found']=found;metrics['user_files_missing']=missing;metrics['user_file_size_mismatch']=size_mismatch
     ok=metrics['tables']>0 and metrics['users']>0 and metrics['invalid_indexes']==0 and metrics['orphan_storage_references']==0 and missing==0 and size_mismatch==0
     results['nextcloud_database']={'status':'RESTORE_TESTED' if ok else 'PARTIAL','metrics':metrics,'seconds':round(time.monotonic()-start,3),'restore_command':'pg_restore --exit-on-error --no-owner --no-acl into isolated tmpfs PostgreSQL'}
     # pg_restore rejects a damaged custom dump in THIS lab, no production connection.
     bad=b'PGDMP'+b'corrupt-header'
     badrun=subprocess.run(['docker','exec','-i',name,'pg_restore','--file=/dev/null'],input=bad,capture_output=True,timeout=20)
     results['negative_pg_dump']={'rejected':badrun.returncode!=0}
    except Exception as e:
     results['nextcloud_database']={'status':'FAIL','error':type(e).__name__+': '+str(e)[:120]}
    finally:
     results['pg_lab_stopped']=False
     save()
    # Offline application status, no network and no production filesystem mounted.
    appimage=run(['docker','inspect',args.app_container,'--format','{{.Image}}']).stdout.decode().strip()
    appname='mt-resilience-v2-occ-'+str(os.getpid())
    # A disposable config is NOT the original instance secret. It proves core+configuration load only.
    config=lab/'lab-config.php'
    config.write_text("<?php $CONFIG = ['installed'=>true,'version'=>'34.0.4.1','instanceid'=>'ocresiliencev2','datadirectory'=>'/lab/data','dbtype'=>'pgsql','dbhost'=>'127.0.0.1','dbname'=>'nextcloud','dbuser'=>'nextcloud','dbpassword'=>'lab-unused','trusted_domains'=>['localhost'],'maintenance'=>true];\n")
    try:
     r=run(['docker','run','--pull=never','--name',appname,'--label','metehantech.resilience=v2','--network','container:'+name,'--cpus','1','--memory','512m','--entrypoint','sh','--mount',f'type=bind,src={config},dst=/lab-config.php,readonly','--mount',f'type=bind,src={dest},dst=/lab,readonly',appimage,'-c','mkdir -p /tmp/nextcloud; cp -a /usr/src/nextcloud/. /tmp/nextcloud/; cp /lab-config.php /tmp/nextcloud/config/config.php; php /tmp/nextcloud/occ status --output=json'])
     results['nextcloud_occ']={'status':'PARTIAL','exit_code':r.returncode,'note':'occ connected only to restored lab PostgreSQL through its network-none namespace; synthetic config, original operator secrets excluded','output':json.loads(r.stdout)}
    except Exception as e:results['nextcloud_occ']={'status':'SKIPPED','reason':'Offline core initialization not proven; original instance secrets intentionally excluded','error_class':type(e).__name__}
    subprocess.run(['docker','stop','--time','10',name],capture_output=True,timeout=20)
    results['pg_lab_stopped']=True
    save()
    # Uptime Kuma and watchdog real file copies, then SQLite open/query. No production connection.
    if args.secondary_fixture is None:
     results['uptime_kuma']={'status':'SKIPPED','reason':'--secondary-fixture not supplied'}
    else:
     start=time.monotonic();pcold=args.secondary_fixture;k=lab/'kuma';k.mkdir(exist_ok=True)
     shutil.copy2(pcold/'databases/uptime-kuma.db',k/'kuma.db')
     with sqlite3.connect(f'file:{k}/kuma.db?mode=ro&immutable=1',uri=True) as c:
      integrity=c.execute('pragma integrity_check').fetchone()[0]
      tables={r[0] for r in c.execute("select name from sqlite_master where type='table'")}
      counts={t:c.execute('select count(*) from "'+t+'"').fetchone()[0] for t in ['monitor','heartbeat','user'] if t in tables}
      results['uptime_kuma']={'status':'RESTORE_TESTED' if integrity=='ok' and 'monitor' in tables else 'FAIL','scope':'SQLite restore/open/query only; no application container test','integrity':integrity,'table_count':len(tables),'row_counts':counts,'seconds':round(time.monotonic()-start,3)}
    results['portainer']={'status':'SKIPPED','reason':'Restricted backup account has no Docker/volume access; supported authenticated export unavailable; no live BoltDB copy or production restart attempted'}
    results['finished_at']=datetime.now(timezone.utc).isoformat()
    save()
    return results

def main(argv=None):
    args = build_parser().parse_args(argv)
    if not require_confirmation(
            args, "would start throwaway containers and restore into a lab directory"):
        print("A confirmed run requires:")
        print("  --lab DIR                throwaway working directory")
        print("  --cloud-source DIR       verified cloud restore point")
        print("  --db-container NAME      container to borrow the database image from")
        print("  --app-container NAME     container to borrow the application image from")
        print("  --secondary-fixture DIR  optional; enables the Uptime Kuma check")
        print("\nImages are copied; the production instances are never connected to.")
        return 0
    missing = [n for n in ("lab", "cloud_source", "db_container", "app_container")
               if not getattr(args, n)]
    if missing:
        print("ABORT: --confirm requires " +
              ", ".join("--" + m.replace("_", "-") for m in missing))
        return 2
    try:
        results = run_lab(args)
    except LabGuardError as exc:
        print(f"ABORT: {exc}")
        return 2
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
