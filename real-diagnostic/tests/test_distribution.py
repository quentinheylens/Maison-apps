"""Offline hostile-input coverage of the new publication trust boundaries."""
import copy
import importlib.util
import json
import subprocess
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import real_catalog as real

COMMIT='a'*40

def tested(arch):
    return {'format':1,'repository':real.REPOSITORY,'commit':COMMIT,'arch':arch,
            'tag':real.tag(COMMIT,arch),'image_id':'sha256:'+('1' if arch=='amd64' else '2')*64,
            'archive':'real-'+arch+'.tar','sha256':'3'*64}

class DistributionTests(unittest.TestCase):
    def test_release_record_rejects_wrong_repo_image_workflow_and_run(self):
        record={'format':1,'repository':real.REPOSITORY,'commit':COMMIT,'simulation':False,'read_only':True,
                'workflow':real.WORKFLOW,'run_id':123,'run_attempt':1,
                'images':{real.SLUG:{'image':real.IMAGE,'version':real.VERSION,'digest':'sha256:'+'4'*64}}}
        real.record_checked(record)
        for key,value in [('repository','other/repo'),('simulation',True),('read_only',False),('workflow','.github/workflows/publish.yml'),('run_id',0)]:
            with self.assertRaises(ValueError): real.record_checked({**record,key:value})
        bad=copy.deepcopy(record);bad['images'][real.SLUG]['image']='ghcr.io/other/image'
        with self.assertRaises(ValueError):real.record_checked(bad)
    def test_audit_requires_exact_images_no_high_and_only_accepted_residuals(self):
        records=[tested(x) for x in real.ARCHES]
        summary={'scanner':'Grype 0.121.3','high_or_critical':0,'exemptions':[],'ignore_unfixed':False,
            'images':[{'image_id':x['image_id'],'findings':[{'id':'CVE-2025-60876','severity':'Medium'}]} for x in records]}
        real.audit_checked(summary,records)
        for change in ({'high_or_critical':1},{'exemptions':['anything']},{'ignore_unfixed':True}):
            with self.assertRaises(ValueError):real.audit_checked({**summary,**change},records)
        bad=copy.deepcopy(summary);bad['images'][0]['findings']=[{'id':'NEW-ADVISORY','severity':'Low'}]
        with self.assertRaises(ValueError):real.audit_checked(bad,records)
        bad=copy.deepcopy(summary);bad['images'][0]['image_id']='sha256:'+'9'*64
        with self.assertRaises(ValueError):real.audit_checked(bad,records)
        bad=copy.deepcopy(summary);bad['images'][0]['findings'][0]['severity']='High'
        with self.assertRaises(ValueError):real.audit_checked(bad,records)
    def test_tested_metadata_cannot_change_commit_tag_archive_or_platform(self):
        item=tested('amd64');real.metadata_checked(item,COMMIT,'amd64')
        for key,value in [('commit','b'*40),('tag',real.IMAGE+':latest'),('archive','../other.tar'),('arch','arm64')]:
            with self.assertRaises(ValueError):real.metadata_checked({**item,key:value},COMMIT,'amd64')
    def test_publication_requires_manual_main_exact_sha_and_confirmation(self):
        env={'GITHUB_REPOSITORY':real.REPOSITORY,'GITHUB_SHA':COMMIT,'GITHUB_REF':'refs/heads/main',
             'GITHUB_EVENT_NAME':'workflow_dispatch','CATALOG_PROTECTED_ENVIRONMENT':'catalog-publication'}
        with patch.object(real,'policy'),patch.object(real.base,'exact_commit'),patch.object(real.base,'protected_environment'):
            real.publication_allowed(ROOT,COMMIT,'PUBLISH-REAL-READ-'+COMMIT,env)
            for key,value in [('GITHUB_REPOSITORY','fork/repo'),('GITHUB_SHA','b'*40),('GITHUB_REF','refs/heads/feature'),('GITHUB_EVENT_NAME','push'),('CATALOG_PROTECTED_ENVIRONMENT','')]:
                with self.assertRaises(ValueError):real.publication_allowed(ROOT,COMMIT,'PUBLISH-REAL-READ-'+COMMIT,{**env,key:value})
            with self.assertRaises(ValueError):real.publication_allowed(ROOT,COMMIT,'PUBLISH-SIMULATION-'+COMMIT,env)
    def test_existing_tag_and_indeterminate_authentication_do_not_allow_repush(self):
        class Result:
            returncode=0;stderr=''
        with patch.object(real.subprocess,'run',return_value=Result()):
            with self.assertRaises(ValueError):real.absent(real.IMAGE+':'+real.VERSION)
        result=Result();result.returncode=1;result.stderr='network unavailable'
        with patch.object(real.subprocess,'run',return_value=result),patch.object(real.base,'run',return_value='{"type":"User"}'):
            with self.assertRaises(ValueError):real.absent(real.IMAGE+':'+real.VERSION)
    def test_reviewed_source_and_permissions_validate(self):
        real.validate(ROOT)
        config=real.source_config(ROOT)
        self.assertEqual(config['map'],[{'type':'homeassistant_config','read_only':True}])
        self.assertFalse(config['options']['enabled'])
    def test_original_catalogue_command_remains_clean_without_bytecode_flags(self):
        result=subprocess.run([sys.executable,'-I',str(ROOT/'tools/catalog.py'),'validate','--root',str(ROOT)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse((ROOT/'tools/__pycache__').exists())
    def test_validation_never_executes_extension_code_supplied_by_target_root(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'catalogue'
            shutil.copytree(ROOT,target,ignore=shutil.ignore_patterns('.git','__pycache__'))
            marker=Path(folder)/'executed'
            (target/'tools/real_catalog.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("executed")\nraise RuntimeError("untrusted extension executed")\n')
            with self.assertRaises(ValueError):real.base.validate(target)
            self.assertFalse(marker.exists())
    def test_archive_hash_mismatch_is_refused_before_docker_load(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'real-amd64.tar';path.write_bytes(b'untrusted')
            with self.assertRaises(ValueError):real.check_archive(path,ROOT,tested('amd64'))

if __name__=='__main__':unittest.main()
