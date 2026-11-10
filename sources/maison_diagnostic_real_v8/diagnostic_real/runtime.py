"""Separate local activation and private HTTPS node; never starts an executor."""
import json
import os
from pathlib import Path
import resource
import signal
import sys
import threading
from diagnostic_real import VERSION
from diagnostic_real.privacy import Privacy
from diagnostic_real.reader import CoreReader
from diagnostic_real.source import DiagnosticSource
from diagnostic_real.service import DiagnosticService
from gateway.audit import load_or_create_salt
from gateway.bounded_audit import BoundedAuditLogger
from gateway.network_auth import GatewayCredentials
from gateway.live_tailnet import DedicatedTailnet
from gateway.server import GatewayHTTPServer, handler_factory

KEYS = {'enabled', 'read_approved', 'acl_reviewed', 'client_token', 'tailscale_auth_key', 'redact_terms'}

def options_checked(options):
    if not isinstance(options, dict) or set(options) != KEYS:
        raise ValueError('invalid_options')
    for key in ('enabled','read_approved','acl_reviewed'):
        if type(options[key]) is not bool: raise ValueError('invalid_approval')
    for key in ('client_token','tailscale_auth_key'):
        if not isinstance(options[key],str): raise ValueError('invalid_local_credential')
    if (not isinstance(options['redact_terms'],list) or len(options['redact_terms']) > 100
            or any(not isinstance(x,str) or not 3 <= len(x) <= 100 for x in options['redact_terms'])):
        raise ValueError('invalid_redaction_terms')
    if options['enabled']:
        if not options['read_approved'] or not options['acl_reviewed']:
            raise ValueError('explicit_read_and_acl_approval_required')
        GatewayCredentials([{'identity':'codex-cloud','token':options['client_token']}])
    return options

class DiagnosticTailnet(DedicatedTailnet):
    def cli(self, *args):
        if args and args[0] == 'up':
            args = tuple('--hostname=ha-green-diagnostic-v8' if x.startswith('--hostname=') else
                         '--advertise-tags=tag:ha-diagnostic' if x.startswith('--advertise-tags=') else x for x in args)
            args += ('--advertise-exit-node=false','--advertise-routes=','--exit-node=')
            # Call Tailnet directly: DedicatedTailnet would replace the hostname with v5.
            from gateway.green_app import Tailnet
            return Tailnet.cli(self, *args)
        return super().cli(*args)

def main():
    os.umask(0o077)
    os.nice(10)
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128,128))
    path = Path('/data/options.json')
    if path.is_symlink() or path.stat().st_size > 65536: raise ValueError('invalid_options_file')
    options = options_checked(json.loads(path.read_text()))
    profile = json.loads(Path('/app/installation-profile.json').read_text())
    if profile != {'version': 1, 'real_read_capable': True, 'writes_enabled': False, 'config_read_only': True}:
        raise ValueError('invalid_profile')
    if sys.argv[1:] == ['--self-test-only']:
        # No production connection, listener, or VPN even when a Supervisor token is injected.
        clean = all(key not in os.environ and (key+'=').encode() not in Path('/proc/self/environ').read_bytes()
                    for key in ('SUPERVISOR_TOKEN','HASSIO_TOKEN'))
        if not clean: raise ValueError('privileged_environment_not_removed')
        print(json.dumps({'version':VERSION, 'offline_validation':True, 'writes_enabled':False,
                          'supervisor_environment_clean':True,'listener_started':False,'vpn_started':False}))
        return
    if sys.argv[1:]: raise ValueError('invalid_arguments')
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    data = Path('/data/diagnostic-v8')
    data.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not options['enabled']:
        print('Diagnostic real application dormant; local read approval required', flush=True)
        stopped.wait()
        return
    fd = int(os.environ.pop('HA_GATEWAY_TOKEN_FD'))
    try:
        token = os.read(fd,4097).decode()
    finally: os.close(fd)
    if not token or len(token) > 4096: raise ValueError('invalid_local_credential')
    privacy = Privacy([token, options['client_token'], options['tailscale_auth_key'], *options['redact_terms']])
    source = DiagnosticSource(CoreReader(token), '/homeassistant', privacy)
    # Validate mounted definitions and literal-secret suppression before exposing the node.
    source.definitions()
    audit = BoundedAuditLogger(data/'audit.jsonl',load_or_create_salt(data/'audit.salt'))
    service = DiagnosticService(source,audit)
    auth = GatewayCredentials([{'identity':'codex-cloud','token':options['client_token']}])
    server = GatewayHTTPServer(('127.0.0.1',8765),handler_factory(service,'unused',auth))
    network = DiagnosticTailnet(data, cancelled=stopped)
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        network.start(options['tailscale_auth_key'])
        print('Diagnostic real read ready; commands and deployment disabled',flush=True)
        while not stopped.wait(1):
            if network.daemon.poll() is not None: raise RuntimeError('private_network_lost')
            if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss > 192*1024: raise RuntimeError('memory_budget')
    finally:
        network.stop()
        server.shutdown(); server.server_close(); thread.join(timeout=5)

if __name__ == '__main__':
    try: main()
    except Exception:
        print('Diagnostic stopped: local validation or dependency unavailable',flush=True)
        raise SystemExit(1) from None
