#!/usr/bin/env python3
"""Fresh full-image CVE audit, no exemptions, no publication or production access."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
from urllib.request import urlopen

GRYPE_URL='https://github.com/anchore/grype/releases/download/v0.121.3/grype_0.121.3_linux_amd64.tar.gz'
GRYPE_SHA256='e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85'

def audit(images, output):
    output=Path(output).absolute()
    if output.exists(): raise ValueError('new_audit_output_required')
    output.mkdir(parents=True,mode=0o700)
    with urlopen(GRYPE_URL,timeout=60) as response: raw=response.read(100*1024*1024+1)
    if hashlib.sha256(raw).hexdigest()!=GRYPE_SHA256: raise ValueError('scanner_hash_mismatch')
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        member=archive.getmember('grype')
        if not member.isfile() or member.size>150*1024*1024: raise ValueError('invalid_scanner')
        tool=output/'grype'; tool.write_bytes(archive.extractfile(member).read());tool.chmod(0o700)
    env={**os.environ,'GRYPE_DB_CACHE_DIR':str(output/'database'),'GRYPE_CHECK_FOR_APP_UPDATE':'false'}
    subprocess.run([str(tool),'db','update'],check=True,env=env)
    status=subprocess.check_output([str(tool),'db','status','--output','json'],env=env)
    (output/'database-status.json').write_bytes(status)
    summaries=[]; high=0
    for index,image in enumerate(images):
        archive=output/f'image-{index}.tar'
        subprocess.run(['docker','save','--output',str(archive),image],check=True)
        report=output/f'image-{index}.json'
        try:
            subprocess.run([str(tool),'docker-archive:'+str(archive),'--output','json','--file',str(report)],check=True,env=env)
        finally: archive.unlink(missing_ok=True)
        findings=[]
        for match in json.loads(report.read_text()).get('matches',[]):
            vulnerability,artifact=match['vulnerability'],match['artifact']
            high+=int(vulnerability.get('severity') in {'High','Critical'})
            findings.append({'id':vulnerability['id'],'severity':vulnerability.get('severity'),
                'package':artifact['name'],'version':artifact['version'],'fix':vulnerability.get('fix',{}).get('versions',[])})
        summaries.append({'image':image,'image_id':subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',image],text=True).strip(),
                          'findings':findings,'report_sha256':hashlib.sha256(report.read_bytes()).hexdigest()})
    result={'scanner':'Grype 0.121.3','high_or_critical':high,'exemptions':[],'ignore_unfixed':False,'images':summaries}
    (output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))
    # Keep complete, bounded triage readable through the GitHub Checks API as well
    # as artifacts; artifact/log storage may require separate network domains.
    def annotation(title, data, level='notice'):
        value=json.dumps(data,sort_keys=True,separators=(',',':'))
        value=value.replace('%','%25').replace('\r','%0D').replace('\n','%0A')
        print('::'+level+' title='+title+'::'+value,flush=True)
    annotation('Real diagnostic vulnerability audit',
               {'scanner':result['scanner'],'high_or_critical':high,'exemptions':[],'images':len(summaries)},
               'warning' if high else 'notice')
    for index,item in enumerate(summaries):
        rows=[]
        for finding in item['findings']:
            if len(json.dumps(rows+[finding]))>2800 and rows:
                annotation('CVE triage image '+str(index),rows,'warning');rows=[]
            rows.append(finding)
        if rows: annotation('CVE triage image '+str(index),rows,'warning')
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:
            stream.write('```json\n'+json.dumps(result,indent=2)+'\n```\n')
    if high: raise SystemExit('High/Critical findings block publication; remediation and review required')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('images',nargs='+');args=parser.parse_args();audit(args.images,args.output)
