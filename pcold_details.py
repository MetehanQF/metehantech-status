"""Fixed read-only enrichment in the EXISTING collector cadence, no remote install."""
import json
from pathlib import Path
import subprocess
import network

# All filesystem targets and the SSH host are code-owned, never request parameters.
SCRIPT = '''import json,shutil,os,socket
u=shutil.disk_usage('/')
net={}
with open('/proc/net/dev') as f:
 for line in f:
  if ':' not in line: continue
  name,raw=line.split(':',1); name=name.strip();v=raw.split()
  if name.startswith(('wl','en','eth','tailscale')):net[name]={'rx_bytes':int(v[0]),'tx_bytes':int(v[8])}
print(json.dumps({'hostname':socket.gethostname(),'load_average':list(os.getloadavg()),'storage':{'total':u.total,'used':u.used,'free':u.free,'percent':round(u.used/u.total*100,1)},'network':net}))
'''


def read_details():
    try:
        r=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','StrictHostKeyChecking=yes',
                          '-i',str(Path.home()/'.ssh/metehantech_backup_ed25519'),
                          'metehanbackup@' + network.get('PCOLD_LAN_IP'),'python3 -'], input=SCRIPT,text=True,
                         capture_output=True,timeout=5,check=False)
        return json.loads(r.stdout) if r.returncode==0 else None
    except (OSError,subprocess.TimeoutExpired,ValueError):return None
