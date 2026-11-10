#!/usr/bin/env python3
"""Separate reviewed real-read distribution; no Home Assistant or installation client."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import catalog as base

SLUG = 'maison_diagnostic_real_v8'
VERSION = '0.8.0'
REPOSITORY = 'quentinheylens/Maison-apps'
IMAGE = 'ghcr.io/' + REPOSITORY.lower() + '/' + SLUG
WORKFLOW = '.github/workflows/publish-real.yml'
ARCHES = {'amd64':'amd64', 'arm64':'aarch64'}
ACCEPTED = {'CVE-2025-60876', 'CVE-2026-116566', 'CVE-2026-103995'}
GATEWAY = '__init__ audit bounded_audit data_source policy real_source redaction service server network_auth green_app live_tailnet simulation_entrypoint'.split()
MODULES = '__init__ privacy files reader source service runtime entrypoint'.split()
AUXILIARY = {'tools/real_catalog.py','tools/check_real_diagnostic_image.py','tools/audit_real_diagnostic.py',
             'tools/build_real_diagnostic_image.py','real-diagnostic/policy.json','real-diagnostic/README.md',
             'real-diagnostic/tests/test_read_boundary.py','real-diagnostic/tests/test_distribution.py',
             '.github/workflows/verify-real.yml','.github/workflows/publish-real.yml'}
SOURCE = {f'sources/{SLUG}/{name}' for name in ('config.yaml','Dockerfile','DOCS.md','installation-profile.json')}
SOURCE |= {f'sources/{SLUG}/gateway/{name}.py' for name in GATEWAY}
SOURCE |= {f'sources/{SLUG}/diagnostic_real/{name}.py' for name in MODULES}
SOURCE |= AUXILIARY
PROMOTED = {f'{SLUG}/{name}' for name in ('config.yaml','DOCS.md','CHANGELOG.md')} | {'real-diagnostic/release-record.json'}
DIGEST = re.compile(r'sha256:[0-9a-f]{64}')


def policy(root):
    value = base.read_json(Path(root)/'real-diagnostic/policy.json')
    if (set(value) != {'format','repository','slug','version','mode','publication_enabled'}
        or value != {'format':1,'repository':REPOSITORY,'slug':SLUG,'version':VERSION,
                     'mode':'real-read-only','publication_enabled':True}):
        raise ValueError('reviewed real-read publication policy required')
    return value


def source_config(root):
    value = base.read_json(Path(root)/'sources'/SLUG/'config.yaml')
    expected = {'name','version','slug','description','arch','startup','boot','init','timeout',
        'homeassistant_api','hassio_api','auth_api','host_network','host_pid','host_dbus','docker_api',
        'full_access','apparmor','ingress','ports','map','tmpfs','options','schema','image','breaking_versions'}
    if set(value) != expected or value['slug'] != SLUG or value['version'] != VERSION or value['image'] != IMAGE:
        raise ValueError('closed real application metadata required')
    if any(value[key] is not False for key in ('init','hassio_api','auth_api','host_network','host_pid','host_dbus','docker_api','full_access','ingress')):
        raise ValueError('write or host privilege forbidden')
    if (value['homeassistant_api'] is not True or value['apparmor'] is not True or value['tmpfs'] is not True
        or value['map'] != [{'type':'homeassistant_config','read_only':True}] or value['ports'] != {}
        or value['arch'] != ['aarch64','amd64'] or value['boot'] != 'manual' or value['startup'] != 'application'
        or value['timeout'] != 30 or value['breaking_versions'] != [VERSION]
        or value['options'] != {'enabled':False,'read_approved':False,'acl_reviewed':False,'client_token':'','tailscale_auth_key':'','redact_terms':[]}
        or value['schema'] != {'enabled':'bool','read_approved':'bool','acl_reviewed':'bool',
                               'client_token':'password','tailscale_auth_key':'password','redact_terms':['str']}):
        raise ValueError('dormant authenticated real-read profile required')
    return value


def record_checked(record):
    fields = {'format','repository','commit','simulation','read_only','workflow','run_id','run_attempt','images'}
    if (set(record) != fields or record['format'] != 1 or record['repository'] != REPOSITORY
        or record['simulation'] is not False or record['read_only'] is not True or record['workflow'] != WORKFLOW
        or not re.fullmatch('[0-9a-f]{40}',record['commit']) or set(record['images']) != {SLUG}
        or type(record['run_id']) is not int or record['run_id'] < 1
        or type(record['run_attempt']) is not int or record['run_attempt'] < 1):
        raise ValueError('invalid real release record')
    image = record['images'][SLUG]
    if (set(image) != {'image','version','digest'} or image['image'] != IMAGE or image['version'] != VERSION
        or not DIGEST.fullmatch(image['digest'])):
        raise ValueError('invalid released real digest')
    return record


def extension(root):
    root = Path(root)
    policy(root)
    inventory = base.read_json(root/'real-diagnostic/source-manifest.json')
    if set(inventory) != {'format','files'} or inventory['format'] != 1 or set(inventory['files']) != SOURCE:
        raise ValueError('closed real distribution inventory required')
    for name in SOURCE:
        raw = base.ordinary(root/name)
        if inventory['files'][name] != {'sha256':base.sha(raw),'bytes':len(raw)}:
            raise ValueError('real distribution source differs from reviewed manifest')
    config = source_config(root)
    profile = base.read_json(root/'sources'/SLUG/'installation-profile.json')
    if profile != {'version':1,'real_read_capable':True,'writes_enabled':False,'config_read_only':True}:
        raise ValueError('real read-only installation profile required')
    present = {name for name in PROMOTED if (root/name).exists()}
    if present:
        if present != PROMOTED:
            raise ValueError('incomplete real promotion')
        record_checked(base.read_json(root/'real-diagnostic/release-record.json'))
        if base.read_json(root/SLUG/'config.yaml') != config:
            raise ValueError('promotion changes approved permissions or version')
        if base.ordinary(root/SLUG/'DOCS.md') != base.ordinary(root/'sources'/SLUG/'DOCS.md'):
            raise ValueError('promotion changes approved documentation')
    return SOURCE | {'real-diagnostic/source-manifest.json'}, PROMOTED


def validate(root):
    base.validate(root)
    return policy(root)


def labels(commit, arch):
    return {'io.hass.version':VERSION,'io.hass.type':'app','io.hass.arch':ARCHES[arch],
            'org.opencontainers.image.source':'https://github.com/'+REPOSITORY,
            'org.opencontainers.image.revision':commit,'org.opencontainers.image.version':VERSION}


def tag(commit, arch):
    return IMAGE+':candidate-'+commit+'-'+arch


def metadata_checked(record, commit, arch):
    if (set(record) != {'format','repository','commit','arch','tag','image_id','archive','sha256'}
        or record['format'] != 1 or record['repository'] != REPOSITORY or record['commit'] != commit
        or record['arch'] != arch or record['tag'] != tag(commit,arch)
        or record['archive'] != 'real-'+arch+'.tar' or not DIGEST.fullmatch(record['image_id'])
        or not re.fullmatch('[0-9a-f]{64}',record['sha256'])):
        raise ValueError('invalid tested image identity')


def check_archive(path, root, record):
    """Verify image identity and every application byte before Docker loads a CI archive."""
    root, path = Path(root), Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > 512*1024*1024:
        raise ValueError('bounded ordinary image archive required')
    if base.file_sha(path) != record['sha256']:
        raise ValueError('tested archive integrity mismatch')
    expected = {f'gateway/{name}.py':base.ordinary(root/'sources'/SLUG/'gateway'/(name+'.py')) for name in GATEWAY}
    expected.update({f'diagnostic_real/{name}.py':base.ordinary(root/'sources'/SLUG/'diagnostic_real'/(name+'.py')) for name in MODULES})
    expected['installation-profile.json'] = base.ordinary(root/'sources'/SLUG/'installation-profile.json')
    original = root/'sources/maison_diagnostic_gateway_v6'
    for name in base.YAML_FILES:
        expected['yaml/'+name+'.py'] = base.ordinary(original/'yaml'/(name+'.py'))
    expected['PyYAML-LICENSE'] = base.ordinary(original/'PyYAML-LICENSE')
    actual = {}
    with tarfile.open(path,'r:*') as archive:
        manifest = json.loads(archive.extractfile('manifest.json').read(1024*1024))
        if len(manifest) != 1 or len(manifest[0]['Layers']) > 40:
            raise ValueError('one bounded tested image required')
        raw = archive.extractfile(manifest[0]['Config']).read(1024*1024)
        image = json.loads(raw)
        config = image['config']
        env = config.get('Env',[])
        if ('sha256:'+base.sha(raw) != record['image_id'] or image['architecture'] != record['arch']
            or image.get('os') != 'linux' or config.get('Labels') != labels(record['commit'],record['arch'])
            or config.get('Entrypoint') != ['python3','-m','diagnostic_real.entrypoint']
            or config.get('Healthcheck') or config.get('ExposedPorts') or config.get('Volumes')
            or len(env) != 3 or set(env) != {'PATH=/usr/local/bin:/usr/bin:/bin','PYTHONDONTWRITEBYTECODE=1','PYTHONUNBUFFERED=1'}):
            raise ValueError('unreviewed real image configuration')
        for layer in manifest[0]['Layers']:
            with tarfile.open(fileobj=archive.extractfile(layer),mode='r|*') as contents:
                for member in contents:
                    name = member.name.removeprefix('./')
                    if not name.startswith('app/') or member.isdir(): continue
                    relative = name[4:]
                    if not member.isfile() or relative not in expected or member.size > 512*1024:
                        raise ValueError('unreviewed application layer')
                    data = contents.extractfile(member).read(512*1024+1)
                    if data != expected[relative]: raise ValueError('image code differs from reviewed source')
                    actual[relative] = data
    if actual != expected: raise ValueError('incomplete reviewed application image')


def build(root, output, commit, arch):
    root, output = Path(root).resolve(), Path(output).absolute()
    validate(root); base.exact_commit(root,commit)
    native = {'x86_64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(platform.machine().lower())
    if arch not in ARCHES or native != arch: raise ValueError('native image test host required')
    if output.exists() or output.resolve() != output or root in output.parents: raise ValueError('new external output required')
    output.mkdir(mode=0o700)
    image = tag(commit,arch)
    command = ['docker','build','--secret','id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt','--platform','linux/'+arch,'--tag',image]
    for key,value in labels(commit,arch).items(): command += ['--label',key+'='+value]
    result = subprocess.run(command+[str(root/'sources'/SLUG)],capture_output=True,text=True,timeout=1200)
    print(result.stdout); print(result.stderr,file=sys.stderr)
    if result.returncode:
        tail=(result.stderr[-3300:]).replace('%','%25').replace('\r','%0D').replace('\n','%0A')
        print('::error title=Real image build::'+tail,flush=True)
        raise ValueError('real image build failed')
    subprocess.run([sys.executable,'-I','-B',str(root/'tools/check_real_diagnostic_image.py'),image],check=True)
    archive = output/('real-'+arch+'.tar')
    subprocess.run(['docker','save','--output',str(archive),image],check=True)
    record = {'format':1,'repository':REPOSITORY,'commit':commit,'arch':arch,'tag':image,
              'image_id':base.run('docker','image','inspect','--format','{{.Id}}',image),
              'archive':archive.name,'sha256':base.file_sha(archive)}
    metadata_checked(record,commit,arch);check_archive(archive,root,record)
    (output/('tested-'+arch+'.json')).write_bytes(base.canonical(record))
    return record


def load(root, artifacts, commit):
    root, artifacts = Path(root).resolve(), Path(artifacts).resolve()
    validate(root);base.exact_commit(root,commit)
    if {p.name for p in artifacts.iterdir()} != {f'{prefix}-{arch}.{suffix}' for arch in ARCHES for prefix,suffix in [('real','tar'),('tested','json')]}:
        raise ValueError('unexpected tested bundle files')
    records = []
    for arch in ARCHES:
        record = base.read_json(artifacts/('tested-'+arch+'.json'))
        metadata_checked(record,commit,arch);check_archive(artifacts/record['archive'],root,record)
        records.append(record)
    for record in records:
        subprocess.run(['docker','load','--input',str(artifacts/record['archive'])],check=True)
        if base.run('docker','image','inspect','--format','{{.Id}}',record['tag']) != record['image_id']:
            raise ValueError('loaded image identity mismatch')
    return records


def audit_checked(summary, records):
    if (summary.get('high_or_critical') != 0 or summary.get('exemptions') != []
        or summary.get('ignore_unfixed') is not False or summary.get('scanner') != 'Grype 0.121.3'
        or {x['image_id'] for x in summary['images']} != {x['image_id'] for x in records}
        or len(summary['images']) != 2):
        raise ValueError('fresh successful audit of exact tested images required')
    for item in summary['images']:
        for finding in item['findings']:
            if finding['severity'] in {'High','Critical'} or finding['id'] not in ACCEPTED:
                raise ValueError('new vulnerability requires remediation and review')


def audit(root, artifacts, output, commit):
    records = load(root,artifacts,commit)
    subprocess.run([sys.executable,'-I','-B',str(Path(root).resolve()/'tools/audit_real_diagnostic.py'),
                    '--output',str(output),*[r['tag'] for r in records]],check=True)
    summary = base.read_json(Path(output)/'summary.json')
    audit_checked(summary,records)
    summary['source_commit'] = commit
    (Path(output)/'summary.json').write_bytes(base.canonical(summary))
    return {'audited':True,'high_or_critical':0,'accepted_residual_advisories':sorted(ACCEPTED)}


def publication_allowed(root, commit, confirmation, env):
    policy(root)
    if (confirmation != 'PUBLISH-REAL-READ-'+commit or env.get('GITHUB_REPOSITORY') != REPOSITORY
        or env.get('GITHUB_SHA') != commit or env.get('GITHUB_REF') != 'refs/heads/main'
        or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
        or env.get('CATALOG_PROTECTED_ENVIRONMENT') != 'catalog-publication'):
        raise ValueError('explicit manual real-read publication approval required')
    base.exact_commit(root,commit)
    base.protected_environment({'repository':REPOSITORY})


def absent(value):
    result = subprocess.run(['docker','manifest','inspect',value],capture_output=True,text=True,timeout=60)
    if result.returncode == 0: raise ValueError('never replace a published version')
    if any(message in result.stderr.lower() for message in ('manifest unknown','no such manifest','name unknown')): return
    owner,repo = REPOSITORY.split('/')
    info = json.loads(base.run('gh','api','users/'+owner))
    prefix = 'users' if info.get('type') == 'User' else 'orgs' if info.get('type') == 'Organization' else None
    if not prefix: raise ValueError('unknown package owner')
    package = subprocess.run(['gh','api',f'{prefix}/{owner}/packages/container/{repo.lower()}%2F{SLUG}'],capture_output=True,text=True,timeout=60)
    if package.returncode != 0 and re.search(r'\bHTTP 404\b',package.stderr): return
    raise ValueError('cannot establish version tag absence')


def publish(root, artifacts, audit_file, output, commit, confirmation):
    root, output = Path(root).resolve(), Path(output).absolute()
    validate(root);publication_allowed(root,commit,confirmation,os.environ)
    records = load(root,artifacts,commit)
    summary = base.read_json(audit_file)
    if summary.get('source_commit') != commit: raise ValueError('audit source mismatch')
    audit_checked(summary,records)
    if output.exists() or output.resolve() != output or root in output.parents: raise ValueError('new external release output required')
    final = IMAGE+':'+VERSION
    children = [final+'-'+ARCHES[r['arch']] for r in records]
    for value in [final,*children]: absent(value)
    output.mkdir(mode=0o700)
    for record,child in zip(records,children):
        subprocess.run(['docker','tag',record['image_id'],child],check=True)
        subprocess.run(['docker','push',child],check=True)
    subprocess.run(['docker','buildx','imagetools','create','--tag',final,*children],check=True)
    descriptor=json.loads(base.run('docker','buildx','imagetools','inspect','--format','{{json .Manifest}}',final))
    expected={json.loads(base.run('docker','buildx','imagetools','inspect','--format','{{json .Manifest}}',child))['digest'] for child in children}
    manifests=descriptor.get('manifests',[])
    if (not DIGEST.fullmatch(descriptor.get('digest','')) or len(manifests)!=2
        or {x['digest'] for x in manifests} != expected
        or {(x['platform']['os'],x['platform']['architecture']) for x in manifests} != {('linux','amd64'),('linux','arm64')}):
        raise ValueError('registry index differs from the exact audited native images')
    record={'format':1,'repository':REPOSITORY,'commit':commit,'simulation':False,'read_only':True,'workflow':WORKFLOW,
            'run_id':int(os.environ['GITHUB_RUN_ID']),'run_attempt':int(os.environ['GITHUB_RUN_ATTEMPT']),
            'images':{SLUG:{'image':IMAGE,'version':VERSION,'digest':descriptor['digest']}}}
    record_checked(record)
    (output/'release-record.json').write_bytes(base.canonical(record))
    return record


def verify_registry(record):
    record_checked(record)
    image=record['images'][SLUG]
    with tempfile.TemporaryDirectory(prefix='real-anonymous-') as folder:
        base.run('docker','--config',folder,'manifest','inspect',IMAGE+'@'+image['digest'])
        descriptor=json.loads(base.run('docker','buildx','imagetools','inspect','--format','{{json .Manifest}}',IMAGE+':'+VERSION))
        if (descriptor.get('digest') != image['digest'] or len(descriptor.get('manifests',[])) != 2
            or {(x['platform']['os'],x['platform']['architecture']) for x in descriptor['manifests']} != {('linux','amd64'),('linux','arm64')}):
            raise ValueError('public tag/index differs from released record')
        verified=json.loads(base.run('gh','attestation','verify','oci://'+IMAGE+'@'+image['digest'],
            '--repo',REPOSITORY,'--signer-workflow',REPOSITORY+'/'+WORKFLOW,'--source-digest',record['commit'],
            '--source-ref','refs/heads/main','--deny-self-hosted-runners','--format','json'))
        expected_run=f'https://github.com/{REPOSITORY}/actions/runs/{record["run_id"]}/attempts/{record["run_attempt"]}'
        if not any(item['verificationResult']['signature']['certificate'].get('runInvocationURI') == expected_run for item in verified):
            raise ValueError('verified provenance does not belong to the official release run')


def promote(root, release, output):
    root,output=Path(root).resolve(),Path(output).absolute()
    validate(root);record=record_checked(base.read_json(release));base.exact_commit(root,record['commit'])
    if output.exists() or output.resolve()!=output or root in output.parents: raise ValueError('new external promotion output required')
    verify_registry(record)
    output.mkdir(mode=0o700);target=output/SLUG;target.mkdir()
    (target/'config.yaml').write_bytes(base.canonical(source_config(root)))
    (target/'DOCS.md').write_bytes(base.ordinary(root/'sources'/SLUG/'DOCS.md'))
    (target/'CHANGELOG.md').write_text('# '+VERSION+'\n\nReal read-only diagnostics. Manual local activation required. Source: `'+record['commit']+'`. No equipment commands or production writes.\n')
    (output/'real-diagnostic').mkdir()
    (output/'real-diagnostic/release-record.json').write_bytes(base.canonical(record))
    return {'promotion_prepared':True,'installed':False,'activated':False,'writes_enabled':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['validate','build','load','audit','publish','promote'])
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--commit');parser.add_argument('--arch',choices=list(ARCHES))
    parser.add_argument('--output',type=Path);parser.add_argument('--artifacts',type=Path);parser.add_argument('--audit',type=Path)
    parser.add_argument('--release',type=Path);parser.add_argument('--confirmation')
    args=parser.parse_args()
    if args.operation=='validate': validate(args.root);result={'valid':True,'mode':'real-read-only'}
    elif args.operation=='build': result=build(args.root,args.output,args.commit,args.arch)
    elif args.operation=='load': result=load(args.root,args.artifacts,args.commit)
    elif args.operation=='audit': result=audit(args.root,args.artifacts,args.output,args.commit)
    elif args.operation=='publish': result=publish(args.root,args.artifacts,args.audit,args.output,args.commit,args.confirmation)
    else: result=promote(args.root,args.release,args.output)
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__': main()
