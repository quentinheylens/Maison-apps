import json,os,time
from pathlib import Path
from maintenance.network_lock import lock_network,assert_network_locked
lock_network()
assert_network_locked()
role=os.environ['MAISON_ROLE']
folder='diagnostic-v6' if role=='diagnostic' else 'deploy-simulation'
p=Path('/tmp')/folder/'health.json'
r=json.loads(p.read_text())
assert r['simulation'] is True and r['writes_enabled'] is False
assert r['listener_started'] is False and r['vpn_started'] is False
assert r['role']==role and time.time()-p.stat().st_mtime<30
