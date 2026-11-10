#!/usr/bin/env python3
"""Build with ephemeral CA trust and expose bounded failures in GitHub Checks."""
import argparse
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit
import re


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch',choices=['amd64','arm64'],required=True)
    parser.add_argument('--tag',required=True)
    parser.add_argument('--context',type=Path,required=True)
    args=parser.parse_args()
    result=subprocess.run(['docker','build','--secret','id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt',
        '--platform','linux/'+args.arch,'--tag',args.tag,str(args.context)],capture_output=True,text=True,timeout=1200)
    print(result.stdout)
    print(result.stderr,file=sys.stderr)
    if result.returncode:
        tail=(result.stdout+'\n'+result.stderr)[-3400:]
        tail=re.sub(r'https?://[^\s"<>]+',lambda m:urlsplit(m.group()).scheme+'://'+str(urlsplit(m.group()).hostname)+urlsplit(m.group()).path,tail)
        tail=tail.replace('%','%25').replace('\r','%0D').replace('\n','%0A')
        print('::error title=Real diagnostic image build::'+tail,flush=True)
        raise SystemExit(result.returncode)

if __name__=='__main__': main()
