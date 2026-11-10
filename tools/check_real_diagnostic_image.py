#!/usr/bin/env python3
"""Exercise the real reader image without network, HA, VPN or configuration access."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def check(image):
    with tempfile.TemporaryDirectory(prefix='diagnostic-image-check-') as folder:
        options = Path(folder)/'options.json'
        options.write_text(json.dumps({'enabled':False,'read_approved':False,'acl_reviewed':False,
            'client_token':'','tailscale_auth_key':'','redact_terms':[]}))
        options.chmod(0o644)
        command = ['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
                   '--security-opt','no-new-privileges','--memory','256m','--pids-limit','64',
                   '--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--tmpfs','/run:rw,noexec,nosuid,size=4m',
                   '--mount',f'type=bind,src={options},dst=/data/options.json,readonly',
                   '-e','SUPERVISOR_TOKEN=offline-supervisor-sentinel',
                   '-e','HASSIO_TOKEN=offline-legacy-sentinel',image,'--self-test-only']
        output = subprocess.check_output(command,text=True,timeout=60)
        result = json.loads(output)
        if result != {'version':'0.8.0','offline_validation':True,'writes_enabled':False,
                      'supervisor_environment_clean':True,'listener_started':False,'vpn_started':False}:
            raise ValueError('unexpected_offline_image_result')
        version = subprocess.check_output(command[:-2] + ['--entrypoint','/usr/local/bin/tailscale',image,'version'],text=True,timeout=30)
        if '1.104.4-maison-compress-1.20.2' not in version:
            raise ValueError('unreviewed_transport_build')
        result['transport_version'] = '1.104.4-maison-compress-1.20.2'
        return result

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('image')
    print(json.dumps(check(parser.parse_args().image),sort_keys=True))
