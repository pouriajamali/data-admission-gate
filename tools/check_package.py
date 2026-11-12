"""Actual local-only self-contained consumer checks; generated synthetic bundles only."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--work',type=Path,required=True);p.add_argument('--commit',required=True);p.add_argument('--local-candidate',action='store_true');a=p.parse_args()
 package=a.package.resolve();work=a.work.resolve();work.mkdir(parents=True,exist_ok=False);m=json.loads((package/'BUILD-MANIFEST.json').read_text(encoding='utf-8'))
 assert m['sourceCommit']==a.commit and m['selfContained'] and m['originalLicense']=='present' and m['rid']==('win-x64' if os.name=='nt' else 'linux-x64')
 assert (package/'LICENSE').is_file() and not (package/'ORIGINAL-LICENSE-PENDING.txt').exists()
 if not a.local_candidate:assert not m['localCandidate']
 assert {f.relative_to(package).as_posix() for f in package.rglob('*') if f.is_file()}=={f['path'] for f in m['files']}|{'BUILD-MANIFEST.json'}
 for f in m['files']:
  file=package/f['path'];assert not file.is_symlink() and file.stat().st_size==f['bytes'] and sha(file)==f['sha256']
 assert a.commit.encode() in (package/'admission.dll').read_bytes()
 pins=json.loads((package/'vendor/integrity-csv/PINS.json').read_text(encoding='utf-8'));assert pins['commit']=='eecf14a1fdeecedb55ceb6c4947ac57e70bd4a41' and len(pins['files'])==5
 for f in pins['files']:
  file=package/'vendor/integrity-csv'/f['file'];b=file.read_bytes();assert sha(file)==f['sha256'] and len(b)==f['bytes'] and hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==f['gitBlob']
 for f in ['README.md','NOTICE.md','CONTRIBUTING.md','PROVENANCE.md','docs/CONTRACT.md','docs/BOUNDS.md','docs/COMPARISON.md','vendor/PUBLIC-PATH-GUARDS-LICENSE']:assert (package/f).is_file()
 config=json.loads((package/'admission.runtimeconfig.json').read_text(encoding='utf-8'))['runtimeOptions'];assert 'includedFrameworks' in config and 'frameworks' not in config
 checks=['manifest-private-license-vendor-pins-document-links'];exe=package/('admission.exe' if os.name=='nt' else 'admission');env=dict(os.environ,DOTNET_ROOT=str(work/'no-installed-dotnet'),DOTNET_ROOT_X64=str(work/'no-installed-dotnet'),DOTNET_MULTILEVEL_LOOKUP='0',PATH='')
 def run(name,args,code):
  r=subprocess.run([str(exe),*map(str,args)],cwd=work,env=env,text=True,encoding='utf-8',capture_output=True,timeout=30)
  (work/(name+'.json')).write_text(json.dumps({'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'command':[str(exe),*map(str,args)]},indent=2)+'\n',encoding='utf-8')
  assert r.returncode==code and not r.stderr,(name,r.returncode)
  if name=='version':value=r.stdout;assert m['version'] in value
  else:
   value=json.loads(r.stdout);assert value['version']==m['version'] and a.commit in value['toolBuild'] and value['originalSoftwareLicense']=='MIT'
  checks.append(name);return value
 run('version',['--version'],0)
 demo=work/'demo with spaces';d=run('demo',['demo',demo],0);assert d['complete'] and d['outcome']=='EXPECTED_OUTCOMES_OBSERVED' and len(d['cases'])==5
 bundle=demo/'clean-acknowledged-bundle';before={f.name:sha(f) for f in bundle.iterdir()}
 hold=run('default-hold',['assess',bundle,work/'hold report'],2);assert hold['outcome']=='HOLD' and hold['coverage']['status']=='PASS' and hold['freshness']['status']=='PASS' and hold['provenance']['status']==hold['useLicense']['status']=='UNKNOWN'
 admit=run('explicit-owner-ack',['assess',bundle,work/'ack report','--ack-owner-decision'],0);assert admit['outcome']=='ADMIT' and admit['provenance']['basis']=='OWNER_DECISION_ACCEPTED' and admit['identity']==admit['authenticity']==admit['legalRights']=='NOT_PROVEN'
 again=run('ack-not-persistent',['assess',bundle,work/'again report'],2);assert again['outcome']=='HOLD'
 wrong=run('wrong-binding-without-ack',['assess',demo/'wrong-binding-bundle',work/'wrong report'],2);assert wrong['outcome']=='REJECT' and wrong['decisionBindingMatches'] is False
 denied=run('independent-license-denial',['assess',demo/'license-denied-bundle',work/'denied report','--ack-owner-decision'],2);assert denied['provenance']['status']=='PASS' and denied['useLicense']['status']=='FAIL'
 stale=run('missing-stale',['assess',demo/'missing-stale-bundle',work/'stale report'],2);assert stale['coverage']['status']==stale['freshness']['status']=='FAIL'
 q=work/'all quarantined';q.mkdir();(q/'policy.json').write_bytes((bundle/'policy.json').read_bytes());(q/'input.csv').write_text('timestamp,open,high,low,close,volume\n2026-01-01T00:02:00Z,100.00,90.00,110.00,100.00,5\n',encoding='utf-8',newline='\n')
 qr=run('all-quarantined-reject',['assess',q,work/'quarantine report'],2);assert qr['outcome']=='REJECT' and qr['rowQuality']['status']=='FAIL' and qr['freshness']['status']=='UNKNOWN' and qr['coverageDetails']['accepted']==0
 bad=work/'bad framing';bad.mkdir();(bad/'policy.json').write_bytes((bundle/'policy.json').read_bytes());(bad/'input.csv').write_text('bad header\n',encoding='utf-8');r=run('file-fatal-incomplete',['assess',bad,work/'fatal report'],1);assert not r['complete'] and not (work/'fatal report/summary.json').exists()
 malformed=work/'malformed decision';shutil.copytree(bundle,malformed);(malformed/'owner-decision.json').write_text('{}',encoding='utf-8');r=run('malformed-even-without-ack',['assess',malformed,work/'malformed report'],1);assert not r['complete'] and not (work/'malformed report/summary.json').exists()
 assert admit['dataSha256']==before['input.csv'] and admit['policySha256']==before['policy.json'] and admit['decisionSha256']==before['owner-decision.json'] and before=={f.name:sha(f) for f in bundle.iterdir()};checks.append('captured-hashes-and-input-unchanged')
 assert (work/'ack report/summary.json').stat().st_size<=128*1024 and (work/'ack report/summary.txt').stat().st_size<=32*1024 and sum(f.stat().st_size for f in (work/'ack report/csv-private').iterdir())<=2*1024*1024
 existing=work/'existing';existing.mkdir();(existing/'sentinel').write_text('untouched',encoding='utf-8');run('existing-output-preserved',['assess',bundle,existing],1);assert (existing/'sentinel').read_text(encoding='utf-8')=='untouched'
 for flag in ['--force-admit','--host']:assert run('refuse-'+flag[2:],[flag],1)['reason']=='CLI_INVALID'
 # W2 source-only draft, UNTESTED: independent literal data, not generated demo data.
 for folder,owner_line in [('hold report','provenance UNKNOWN; basis UNACKNOWLEDGED_OWNER_ASSERTION; reason EXPLICIT_ACK_REQUIRED\n'),('ack report','provenance PASS; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_ALLOW\n')]:
  explanation=(work/folder/'summary.txt').read_text(encoding='utf-8')
  assert owner_line in explanation and 'Decision meaning: offline policy only; PASS is not authenticity, legal-rights or actual-source-freshness proof.\n' in explanation
  assert 'Freshness context: asOf 2026-01-01T00:02:00Z; latestAccepted 2026-01-01T00:02:00Z; ageSeconds 0; thresholdSeconds 60\n' in explanation
 oracle=work/'literal unknown provenance';oracle.mkdir()
 oracle_csv=b'timestamp,open,high,low,close,volume\n2026-01-01T00:02:00Z,100.00,102.00,99.00,101.00,5\n'
 oracle_policy=b'{"schema":"data-admission-policy-v1","profile":"admission-ohlc-csv-v1","purpose":"offline-analysis","asOf":"2026-01-01T00:03:00Z","maxAgeSeconds":60,"expectedTimestamps":["2026-01-01T00:02:00Z"]}\n'
 (oracle/'input.csv').write_bytes(oracle_csv);(oracle/'policy.json').write_bytes(oracle_policy)
 oracle_decision={'schema':'owner-decision-v1','datasetSha256':hashlib.sha256(oracle_csv).hexdigest(),'policySha256':hashlib.sha256(oracle_policy).hexdigest(),'purpose':'offline-analysis','ownerLabel':'ORACLE_SYNTHETIC_OWNER','evidenceRefs':['LABEL_ONLY_NOT_AUTHENTICATED'],'provenance':'unknown','useLicense':'allow'}
 (oracle/'owner-decision.json').write_bytes((json.dumps(oracle_decision,separators=(',',':'))+'\n').encode('utf-8'))
 oracle_before={f.name:sha(f) for f in oracle.iterdir()};oracle_report=work/'literal unknown provenance report'
 counter=run('literal-unknown-provenance',['assess',oracle,oracle_report,'--ack-owner-decision'],2)
 assert counter['complete'] and counter['outcome']=='HOLD' and counter['exitCode']==2 and counter['decisionBindingMatches'] is True and counter['ownerDecisionAcknowledged'] is True
 assert [counter[k]['status'] for k in ['rowQuality','coverage','freshness','provenance','useLicense']]==['PASS','PASS','PASS','UNKNOWN','PASS']
 assert counter['provenance']=={'status':'UNKNOWN','basis':'OWNER_DECISION_ACCEPTED','reason':'OWNER_ASSERTION_UNKNOWN'} and counter['useLicense']=={'status':'PASS','basis':'OWNER_DECISION_ACCEPTED','reason':'OWNER_ASSERTION_ALLOW'}
 assert counter['coverageDetails']=={'expected':1,'accepted':1,'excludedQuarantined':0,'missing':0,'unexpected':0,'duplicates':0,'nonAscending':0,'diagnosticCodes':[],'scope':'DECLARED_GRID_ONLY','externalCompleteness':'NOT_PROVEN'}
 assert counter['freshnessDetails']=={'asOf':'2026-01-01T00:03:00Z','latestAccepted':'2026-01-01T00:02:00Z','ageSeconds':60,'thresholdSeconds':60,'clockAccuracy':'NOT_PROVEN','actualSourceFreshness':'NOT_PROVEN'}
 assert counter['identity']==counter['authenticity']==counter['legalRights']=='NOT_PROVEN' and counter['csvSourceProvenance']=='UNVERIFIED'
 assert counter['dataSha256']==oracle_before['input.csv'] and counter['policySha256']==oracle_before['policy.json'] and counter['decisionSha256']==oracle_before['owner-decision.json']
 assert oracle_before=={f.name:sha(f) for f in oracle.iterdir()} and len(oracle_before)==3
 counter_text=(oracle_report/'summary.txt').read_bytes()
 expected_explanation=('rowQuality PASS; basis PINNED_PUBLIC_CSV_ROW_CHECKS_ONLY; reason NO_QUARANTINED_ROWS\n'
  'coverage PASS; basis DECLARED_GRID_ONLY; reason EXACT_ACCEPTED_GRID_AGREEMENT\n'
  'freshness PASS; basis DECLARED_ASOF_ONLY; reason AGE_WITHIN_DECLARED_THRESHOLD\n'
  'provenance UNKNOWN; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_UNKNOWN\n'
  'useLicense PASS; basis OWNER_DECISION_ACCEPTED; reason OWNER_ASSERTION_ALLOW\n'
  'Freshness context: asOf 2026-01-01T00:03:00Z; latestAccepted 2026-01-01T00:02:00Z; ageSeconds 60; thresholdSeconds 60\n'
  'Decision meaning: offline policy only; PASS is not authenticity, legal-rights or actual-source-freshness proof.\n').encode('utf-8')
 assert expected_explanation in counter_text and len(counter_text)<=32*1024 and (oracle_report/'summary.json').stat().st_size<=128*1024
 assert sum(f.stat().st_size for f in (oracle_report/'csv-private').iterdir())<=2*1024*1024 and not list(oracle_report.glob('*.pending'))
 counter_main=(oracle_report/'summary.json').read_bytes()+counter_text
 assert b'ORACLE_SYNTHETIC_OWNER' not in counter_main and b'100.00' not in counter_main and str(work).encode('utf-8') not in counter_main
 assert len(checks)==17
 receipt={'status':'ACTUAL_SELF_CONTAINED_ADMISSION_PACKAGE_PASS','commit':a.commit,'rid':m['rid'],'checkCount':len(checks),'checks':checks,'manifestSha256':sha(package/'BUILD-MANIFEST.json'),'scope':'Synthetic offline companion; original MIT software; owner decision never proves identity/authenticity/legal rights; existing hosts not cleanOS proof'}
 (work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':receipt['status'],'checks':len(checks),'rid':m['rid']}))
if __name__=='__main__':main()
