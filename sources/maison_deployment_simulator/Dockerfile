FROM python:3.15.2-alpine3.24@sha256:a0f2e268f2ce8f3709611a90054ec6a8ae31f6251f5896b8648b9bb99835e30a
ADD --checksum=sha256:7b05bc778b8b25cd880835b40114182bd4d1581717504d0129c810c0a14291cb https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.4-r0.apk /tmp/zlib-amd64.apk
ADD --checksum=sha256:d3e30d012a3445222b0b4a28f1d4d97ce67387f8b48561921111696da174f0de https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/zlib-1.4-r0.apk /tmp/zlib-arm64.apk
RUN --network=none python3 - <<'HARDEN'
import hashlib,platform,subprocess,zlib
from pathlib import Path
arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
file=Path('/tmp/zlib-'+arch+'.apk')
checksums={'amd64': '7b05bc778b8b25cd880835b40114182bd4d1581717504d0129c810c0a14291cb', 'arm64': 'd3e30d012a3445222b0b4a28f1d4d97ce67387f8b48561921111696da174f0de'}
assert hashlib.sha256(file.read_bytes()).hexdigest()==checksums[arch]
subprocess.run(['apk','--no-network','verify',str(file)],check=True)
subprocess.run(['apk','--no-network','add',str(file)],check=True)
from pathlib import Path
import subprocess,sysconfig,shutil,importlib.util
blocks=Path('/lib/apk/db/installed').read_text().split('\n\n')
record=next(block for block in blocks if '\nP:.python-rundeps\n' in '\n'+block+'\n')
deps=next(line[2:].split() for line in record.splitlines() if line.startswith('D:'))
assert deps.count('so:libsqlite3.so.0')==1
subprocess.run(['apk','--no-network','add',*[x for x in deps if x!='so:libsqlite3.so.0']],check=True)
subprocess.run(['apk','--no-network','del','.python-rundeps'],check=True)
stdlib=Path(sysconfig.get_path('stdlib')); site=Path(sysconfig.get_path('purelib'))
for name in ('sqlite3','ensurepip'):shutil.rmtree(stdlib/name)
for file in (stdlib/'lib-dynload').glob('_sqlite3.*.so'):file.unlink()
for file in [site/'pip',*site.glob('pip-*.dist-info')]:shutil.rmtree(file)
for name in ('pip','pip3','pip3.14'):(Path('/usr/local/bin')/name).unlink(missing_ok=True)
assert all(importlib.util.find_spec(name) is None for name in ('sqlite3','_sqlite3','pip','ensurepip'))
assert not list(Path('/usr/lib').glob('libsqlite3.so*'))

# Load zlib in a fresh interpreter after replacing its shared library.
subprocess.run(['python3','-c',"import zlib; assert zlib.ZLIB_RUNTIME_VERSION=='1.4'; assert zlib.decompress(zlib.compress(b'offline-simulation'))==b'offline-simulation'"],check=True)
for file in Path('/tmp').glob('zlib-*.apk'):file.unlink()
HARDEN
WORKDIR /app
COPY gateway /app/gateway
COPY maintenance /app/maintenance
COPY yaml /app/yaml
COPY PyYAML-LICENSE /app/PyYAML-LICENSE
COPY installation-profile.json /app/installation-profile.json
COPY healthcheck.py /app/healthcheck.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 MAISON_ROLE=deployment
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["python3", "-m", "maintenance.entrypoint", "healthcheck"]
ENTRYPOINT ["python3", "-m", "maintenance.entrypoint", "deployment"]
