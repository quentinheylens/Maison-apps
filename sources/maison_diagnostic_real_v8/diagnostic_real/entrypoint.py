"""Remove privileged environment from the runtime and all subprocesses via exec."""
import json
import os
from pathlib import Path
import sys
from diagnostic_real.runtime import options_checked
from gateway.simulation_entrypoint import clean_environment

def prepare(options, token, offline=False):
    options_checked(options)
    environment = clean_environment()
    fd = None
    if options['enabled'] and not offline:
        if not token or len(token.encode()) > 4096 or any(x in token for x in '\r\n'):
            raise ValueError('missing_local_supervisor_credential')
        fd, write = os.pipe()
        try:
            os.set_inheritable(fd,True)
            os.write(write,token.encode())
        except Exception:
            os.close(fd)
            raise
        finally: os.close(write)
        environment['HA_GATEWAY_TOKEN_FD'] = str(fd)
    return environment, fd

def main():
    path = Path('/data/options.json')
    if path.is_symlink() or path.stat().st_size > 65536: raise ValueError('invalid_options')
    options = json.loads(path.read_text())
    if sys.argv[1:] not in ([],['--self-test-only']): raise ValueError('invalid_arguments')
    env, fd = prepare(options,os.environ.pop('SUPERVISOR_TOKEN',''),bool(sys.argv[1:]))
    os.environ.pop('HASSIO_TOKEN',None)
    try: os.execve(sys.executable,[sys.executable,'-m','diagnostic_real.runtime',*sys.argv[1:]],env)
    finally:
        if fd is not None: os.close(fd)

if __name__ == '__main__':
    try: main()
    except Exception:
        print('Diagnostic refused startup: invalid local options',flush=True)
        raise SystemExit(1) from None
