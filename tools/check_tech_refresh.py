"""Four literal synthetic compatibility oracles; actual extracted apphost, no product imports."""
from pathlib import Path
import argparse,copy,hashlib,json,os,re,subprocess
VERSION='0.1.0-preview.3'
CSV=b'timestamp,open,high,low,close,volume\n2026-01-01T00:02:00Z,100.00,102.00,99.00,101.00,5\n'
POLICY=b'{"schema":"data-admission-policy-v1","profile":"admission-ohlc-csv-v1","purpose":"offline-analysis","asOf":"2026-01-01T00:03:00Z","maxAgeSeconds":60,"expectedTimestamps":["2026-01-01T00:02:00Z"]}\n'
MECHANICAL='rowQuality PASS; basis PINNED_PUBLIC_CSV_ROW_CHECKS_ONLY; reason NO_QUARANTINED_ROWS\ncoverage PASS; basis DECLARED_GRID_ONLY; reason EXACT_ACCEPTED_GRID_AGREEMENT\nfreshness PASS; basis DECLARED_ASOF_ONLY; reason AGE_WITHIN_DECLARED_THRESHOLD\n'
CONTEXT='Freshness context: asOf 2026-01-01T00:03:00Z; latestAccepted 2026-01-01T00:02:00Z; ageSeconds 60; thresholdSeconds 60\nDecision meaning: offline policy only; PASS is not authenticity, legal-rights or actual-source-freshness proof.\nCoverage DECLARED_GRID_ONLY; freshness DECLARED_ASOF_ONLY.\nOwner basis is an assertion, not verified identity/authenticity/legal rights.\nIdentity/authenticity/legal rights/external completeness NOT_PROVEN.\nCSV row artifacts may contain input values; keep them private.\nOriginal reusable software MIT; upstream notices retained.\n'
GOLDEN={'schema': 'data-admission-report-v1', 'version': '0.1.0-preview.2', 'toolBuild': '0.1.0-preview.2+9893583976da8d5042d063cabc58f65885001858', 'complete': True, 'outcome': 'HOLD', 'exitCode': 2, 'profile': 'admission-ohlc-csv-v1', 'purpose': 'offline-analysis', 'dataSha256': '156810a7487c83b2adc4908d239a5d788c36195560d0e53b1839b911ec5ac3cd', 'policySha256': '980aeaa12bd5e4b107917268cae7300dc7daa2bfcd73a4e08f6b15f587633180', 'decisionSha256': '3037729742adeafc74ffa9d99e3c75a523ecd8e446c6972fa455e54a069de71c', 'ownerDecisionAcknowledged': True, 'decisionBindingMatches': True, 'rowQuality': {'status': 'PASS', 'basis': 'PINNED_PUBLIC_CSV_ROW_CHECKS_ONLY', 'reason': 'NO_QUARANTINED_ROWS'}, 'coverage': {'status': 'PASS', 'basis': 'DECLARED_GRID_ONLY', 'reason': 'EXACT_ACCEPTED_GRID_AGREEMENT'}, 'freshness': {'status': 'PASS', 'basis': 'DECLARED_ASOF_ONLY', 'reason': 'AGE_WITHIN_DECLARED_THRESHOLD'}, 'provenance': {'status': 'UNKNOWN', 'basis': 'OWNER_DECISION_ACCEPTED', 'reason': 'OWNER_ASSERTION_UNKNOWN'}, 'useLicense': {'status': 'PASS', 'basis': 'OWNER_DECISION_ACCEPTED', 'reason': 'OWNER_ASSERTION_ALLOW'}, 'coverageDetails': {'expected': 1, 'accepted': 1, 'excludedQuarantined': 0, 'missing': 0, 'unexpected': 0, 'duplicates': 0, 'nonAscending': 0, 'diagnosticCodes': [], 'scope': 'DECLARED_GRID_ONLY', 'externalCompleteness': 'NOT_PROVEN'}, 'freshnessDetails': {'asOf': '2026-01-01T00:03:00Z', 'latestAccepted': '2026-01-01T00:02:00Z', 'ageSeconds': 60, 'thresholdSeconds': 60, 'clockAccuracy': 'NOT_PROVEN', 'actualSourceFreshness': 'NOT_PROVEN'}, 'privateArtifacts': [{'file': 'accepted.jsonl', 'bytes': 300, 'sha256': 'f18ec72afd12b42bce36ca75e8c1e879a03fd22b29b39fb2b1ffa8937deb02ca'}, {'file': 'quarantine.jsonl', 'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, {'file': 'run.lock', 'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, {'file': 'summary.json', 'bytes': 707, 'sha256': 'e8fb1fd5a66ae7882a10b62fde8765231e7bfc782a2e338c676a3c92e2061646'}], 'vendorRevision': 'eecf14a1fdeecedb55ceb6c4947ac57e70bd4a41', 'csvSourceProvenance': 'UNVERIFIED', 'identity': 'NOT_PROVEN', 'authenticity': 'NOT_PROVEN', 'legalRights': 'NOT_PROVEN', 'originalSoftwareLicense': 'MIT', 'scope': 'Offline policy decision only; owner assertions are not verified facts or legal permission proof. No trading/account/service action.'}
GOLDEN_RAW_SHA256='9aacc0619637d76cb8cb4c31c82782ecdbf9cd522a3969eb399a31932debe667'

def need(value,message):
 if not value:raise RuntimeError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def snapshot(folder):return {p.name:sha(p.read_bytes()) for p in folder.iterdir() if p.is_file()}
def parse(raw):
 def distinct(pairs):
  result={}
  for k,v in pairs:need(k not in result,'DUPLICATE_JSON_KEY');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=distinct)
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--package',type=Path,required=True);parser.add_argument('--work',type=Path,required=True);parser.add_argument('--commit',required=True);args=parser.parse_args()
 need(re.fullmatch('[a-f0-9]{40}',args.commit),'EXACT_COMMIT_REQUIRED');package=args.package.resolve();manifest=parse((package/'BUILD-MANIFEST.json').read_bytes())
 need(manifest['sourceCommit']==args.commit and manifest['version']==VERSION and manifest['rid']==('win-x64' if os.name=='nt' else 'linux-x64'),'PACKAGE_IDENTITY')
 work=args.work.resolve();work.mkdir(parents=True,exist_ok=False);exe=package/('admission.exe' if os.name=='nt' else 'admission');env=dict(os.environ,DOTNET_ROOT=str(work/'absent'),DOTNET_ROOT_X64=str(work/'absent'),DOTNET_MULTILEVEL_LOOKUP='0',PATH='');records=[];positive=None
 cases=[('ORACLE-01','unknown','allow',True,'HOLD',2,'UNKNOWN','PASS','OWNER_DECISION_ACCEPTED','OWNER_ASSERTION_UNKNOWN','OWNER_ASSERTION_ALLOW'),('ORACLE-02','allow','allow',True,'ADMIT',0,'PASS','PASS','OWNER_DECISION_ACCEPTED','OWNER_ASSERTION_ALLOW','OWNER_ASSERTION_ALLOW'),('ORACLE-03','allow','unknown',True,'HOLD',2,'PASS','UNKNOWN','OWNER_DECISION_ACCEPTED','OWNER_ASSERTION_ALLOW','OWNER_ASSERTION_UNKNOWN'),('ORACLE-04','allow','allow',False,'HOLD',2,'UNKNOWN','UNKNOWN','UNACKNOWLEDGED_OWNER_ASSERTION','EXPLICIT_ACK_REQUIRED','EXPLICIT_ACK_REQUIRED')]
 for identifier,prov,use,ack,outcome,code,ps,us,basis,pr,ur in cases:
  bundle=work/('ORACLE-02-bundle' if identifier=='ORACLE-04' else identifier+'-bundle')
  if identifier!='ORACLE-04':
   bundle.mkdir();(bundle/'input.csv').write_bytes(CSV);(bundle/'policy.json').write_bytes(POLICY)
   decision={'schema':'owner-decision-v1','datasetSha256':sha(CSV),'policySha256':sha(POLICY),'purpose':'offline-analysis','ownerLabel':'ORACLE_SYNTHETIC_OWNER','evidenceRefs':['LABEL_ONLY_NOT_AUTHENTICATED'],'provenance':prov,'useLicense':use}
   (bundle/'owner-decision.json').write_bytes((json.dumps(decision,separators=(',',':'))+'\n').encode())
  before=snapshot(bundle)
  if identifier=='ORACLE-02':positive=before
  if identifier=='ORACLE-04':need(before==positive,'ACK_CONTROL_NOT_SAME_BYTES')
  report=work/(identifier+'-report');argv=[str(exe),'assess',str(bundle),str(report)]+(['--ack-owner-decision'] if ack else [])
  result=subprocess.run(argv,cwd=work,env=env,capture_output=True,timeout=30)
  (work/(identifier+'-process.json')).write_text(json.dumps({'argv':argv,'exit':result.returncode,'stdout':result.stdout.decode('utf-8'),'stderr':result.stderr.decode('utf-8')},indent=2)+'\n',encoding='utf-8')
  need(result.returncode==code and not result.stderr,'LITERAL_EXIT_OR_STDERR');actual=parse(result.stdout)
  expected=copy.deepcopy(GOLDEN);expected.update({'version':VERSION,'toolBuild':VERSION+'+'+args.commit,'outcome':outcome,'exitCode':code,'ownerDecisionAcknowledged':ack,'decisionSha256':before['owner-decision.json'],'provenance':{'status':ps,'basis':basis,'reason':pr},'useLicense':{'status':us,'basis':basis,'reason':ur}})
  need(actual==expected,'FULL_LITERAL_JSON_CHANGED')
  raw=(report/'summary.json').read_bytes();need(parse(raw)==actual and raw.endswith(b'\n') and result.stdout.strip()==raw.strip(),'SAVED_CLI_REPORT_MISMATCH')
  wire=(json.dumps(expected,separators=(',',':'),ensure_ascii=True).replace('+','\\u002B')+'\n').encode();need(raw==wire,'WIRE_BYTES_CHANGED_BEYOND_METADATA')
  text=('Data Admission Gate: '+outcome+'\nProfile admission-ohlc-csv-v1; purpose offline-analysis\nRow quality PASS; coverage PASS; freshness PASS; provenance '+ps+'; useLicense '+us+'\n'+MECHANICAL+'provenance '+ps+'; basis '+basis+'; reason '+pr+'\nuseLicense '+us+'; basis '+basis+'; reason '+ur+'\n'+CONTEXT).encode()
  need((report/'summary.txt').read_bytes()==text,'FULL_LITERAL_TEXT_CHANGED')
  need(len(raw)<=128*1024 and len(text)<=32*1024 and not list(report.glob('*.pending')),'OUTPUT_CAP_OR_PARTIAL')
  for item in GOLDEN['privateArtifacts']:
   f=report/'csv-private'/item['file'];data=f.read_bytes();need(len(data)==item['bytes'] and sha(data)==item['sha256'],'CSV_ARTIFACT_BYTES_CHANGED')
  need(snapshot(bundle)==before and b'ORACLE_SYNTHETIC_OWNER' not in raw+text and b'100.00' not in raw+text and str(work).encode() not in raw+text,'INPUT_OR_PRIVACY_CHANGED')
  records.append({'id':identifier,'exit':code,'inputHashes':before,'summarySha256':sha(raw),'textSha256':sha(text),'metadataDifferencesOnly':['version','toolBuild']})
 value={'status':'FOUR_ACTUAL_LITERAL_COMPATIBILITY_CASES_PASS','sourceCommit':args.commit,'rid':manifest['rid'],'cases':records,'baselineSyntheticGoldenSha256':GOLDEN_RAW_SHA256,'oldRuntimeReplayed':False,'SDKExecutions':0}
 (work/'receipt.json').write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':value['status'],'cases':4,'rid':manifest['rid']}))
if __name__=='__main__':main()
