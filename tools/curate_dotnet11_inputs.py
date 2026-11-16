"""Producer04 explicit SDK0 discovery entry; product/SDK/graph phases stay closed."""
from __future__ import annotations
import time
ENTRY_START_NS=time.monotonic_ns()
import argparse,datetime,hashlib,json,os,re,secrets,sys,threading,types,urllib.request
from pathlib import Path

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
JOB_SHA='0959e7cb097bb17d774ed0824bb7b9e95e1b94112d968d343fb9fca0fb5166ce'
DATA_SHA='bbcebab03332fc2ea5ee3eb0344e82c83b5a56fc269cfb8fc9825dfb77ff0daf'
PROFILE_SHA='9f206d9ffee7ca7318bc2dfa0906d021aae98cb66bd3281abd56cd659553c4bc'
CONTRACT_SHA='1b91117ed75e248965b0e5634d61c9f2169ac796d58753729adf94e48d74b1a3'
LEASE_SHA='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b'
RANGE_CONTRACT_SHA='594ab353504cfd93a2927805d74004fad870f11243c65f4ae3e4bada0b42dac9'
RANGE_PROFILE_SHA='ca2bbea17139e65bb0a17a29ef38cf795c70c28812699456589b8e069071fde2'
RANGE_HELPER_SHA='142812e1124828bb8b8733b5fa476e297788e47a4986a5bac04cb1638fdb7c9b'

class AdmissionError(ValueError):pass
def need(value,code):
 if not value:raise AdmissionError(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def cause(exc):
 value=str(exc) if type(exc).__name__ in ('AdmissionError','DiscoveryError','CapError','RangeError') else 'DETAIL_REDACTED'
 return {'type':type(exc).__name__ if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',type(exc).__name__) else 'UNKNOWN','code':value if re.fullmatch(r'[A-Z][A-Z0-9_:.-]{0,95}',value) else 'DETAIL_REDACTED'}
def bounded(path,limit):
 p=Path(path);need(p.is_file() and not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400,'REGULAR_FILE_REQUIRED');need(p.stat().st_size<=limit,'DATA_FILE_BOUND')
 with p.open('rb') as stream:raw=stream.read(limit+1)
 need(len(raw)<=limit,'DATA_FILE_BOUND');return raw
def read(path,limit=32768):return json.loads(bounded(path,limit))
def write(path,value,limit=8388608):
 raw=canonical(value)+b'\n';need(len(raw)<=limit,'PROOF_BYTE_BOUND');p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);need(not p.is_symlink(),'OUTPUT_REPARSE_FORBIDDEN');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 return {'bytes':len(raw),'sha256':sha(raw)}
def load(name,digest):
 raw=bounded(HERE/(name+'.py'),262144);need(sha(raw)==digest,'SOURCE_HELPER_PIN');module=types.ModuleType(name);module.__file__=str(HERE/(name+'.py'));exec(compile(raw,module.__file__,'exec'),module.__dict__);return module
def profile(range_mode=False):
 name='producer04-runtime-range.profile.json' if range_mode else 'producer04-curation.profile.json';expected=RANGE_PROFILE_SHA if range_mode else PROFILE_SHA;raw=bounded(HERE/name,32768);need(sha(raw)==expected,'SOURCE_PROFILE_PIN');p=json.loads(raw)
 need(p['mode']==('RANGE_BYTE_CANDIDATE_ONLY_SDK0' if range_mode else 'DISCOVERY_ONLY_SDK0') and p['schema']==('sdk11-runtime-range-candidate-profile/v1' if range_mode else 'sdk11-curation-discovery-profile/v1'),'CURATION_PHASE_CLOSED');need(sha(bounded(HERE/'producer04-curation-contract.json',32768))==CONTRACT_SHA,'SOURCE_CONTRACT_PIN')
 if range_mode:need(sha(bounded(HERE/'producer04-runtime-range-contract.json',32768))==RANGE_CONTRACT_SHA,'SOURCE_RANGE_CONTRACT_PIN')
 return p
def remaining(spec):return (spec['workDeadlineNs']-time.monotonic_ns())/1e9
def work_time(spec):need(remaining(spec)>0,'ORIGINAL_WORK_DEADLINE')

def current_head():
 marker=bounded(ROOT/'.git',4096).decode().strip();need(marker.startswith('gitdir: '),'WORKTREE_GIT_IDENTITY');gd=Path(marker[8:]);gd=gd if gd.is_absolute() else ROOT/gd;head=bounded(gd/'HEAD',4096).decode().strip()
 if re.fullmatch('[0-9a-f]{40}',head):return head
 need(head.startswith('ref: refs/heads/codex/') and '..' not in head,'PRIVATE_SOURCE_REF');ref=head[5:];common=gd/ bounded(gd/'commondir',4096).decode().strip();path=common/ref
 if path.is_file():value=bounded(path,4096).decode().strip()
 else:
  rows=bounded(common/'packed-refs',1048576).decode().splitlines();matches=[r.split()[0] for r in rows if r and not r.startswith(('#','^')) and len(r.split())==2 and r.split()[1]==ref];need(len(matches)==1,'PRIVATE_SOURCE_REF');value=matches[0]
 need(re.fullmatch('[0-9a-f]{40}',value) is not None,'PRIVATE_SOURCE_REF');return value

def bind_source(handoff,p):
 range_mode=p.get('mode')=='RANGE_BYTE_CANDIDATE_ONLY_SDK0';expected_admission='ROOT_ONLY_EXACT_RANGE_BYTE_CANDIDATE' if range_mode else 'ROOT_ONLY_EXACT_STAGE_B_DISCOVERY';need(handoff.get('schema')=='producer04-sdk0-discovery-handoff/v1' and handoff.get('admission')==expected_admission,'CURATION_ADMISSION_REQUIRED');need(handoff['mode']==('range-candidate-sdk0' if range_mode else 'discover-sdk0') and handoff['contractSha256']==(RANGE_CONTRACT_SHA if range_mode else CONTRACT_SHA) and handoff['profileSha256']==(RANGE_PROFILE_SHA if range_mode else PROFILE_SHA),'CURATION_ADMISSION_IDENTITY')
 if range_mode:range_runtime_gate(handoff,p)
 need(current_head()==handoff['expectedHEAD'],'CURRENT_SOURCE_HEAD');need(sha(bounded(Path(sys.executable),33554432))==handoff['bootstrap']['pythonExeSha256'] and list(sys.version_info[:3])==handoff['bootstrap']['pythonVersion'],'BOOTSTRAP_IDENTITY')
 if handoff['bootstrap'].get('pythonDllSha256'):need(sha(bounded(Path(sys.executable).parent/'python312.dll',33554432))==handoff['bootstrap']['pythonDllSha256'],'BOOTSTRAP_DLL_IDENTITY')
 pinsPath=HERE/'dotnet11-consumer04-source-pins.json';raw=bounded(pinsPath,32768);need(sha(raw)==handoff['sourcePinsFileSha256'],'SOURCE_TABLE_PIN');table=json.loads(raw)['sourcePins'];need(len(table)==handoff['sourcePinRows'] and len(table)<=128,'SOURCE_TABLE_SHAPE');seen=set();total=0
 for row in table:
  rel=row['path'];need(isinstance(rel,str) and '\\' not in rel and not rel.startswith('/') and '..' not in rel.split('/') and row['mode'] in ('100644','100755') and rel not in seen,'SOURCE_TABLE_SHAPE');seen.add(rel);raw=bounded(ROOT/rel,8388608);total+=len(raw);need(total<=16777216,'SOURCE_TOTAL_BOUND');blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest();need(blob==row['gitBlob'],'CURRENT_SOURCE_BYTES')
 need('tools/dotnet11-consumer04-source-pins.json' not in seen,'SOURCE_SELF_PIN');return {'expectedHEAD':handoff['expectedHEAD'],'expectedTree':handoff['expectedTree'],'sourcePinRows':len(table),'sourcePinsFileSha256':handoff['sourcePinsFileSha256'],'workingBytesVerified':True}

def held_context(spec,j):
 need(os.name=='nt' and spec.get('purpose') in ('PRODUCER04_SDK0_DATA_DISCOVERY','PRODUCER04_SDK0_RANGE_BYTE_CANDIDATE') and spec['workerPID']==os.getpid() and spec['workerStart']==j._start_identity(os.getpid()),'CURRENT_HELD_IDENTITY');held=spec['beforeResume'];need(held['membership'] is True and held['retainedCreationHandles'] is True and held['memoryMax']==4294967296 and held['activeProcessMax']==64 and 0<held['effectiveCpuCores']<=2,'CURRENT_HELD_CAPS');actual=j.current_witness(spec['jobName']);need(actual['currentProcessMember'] is True and actual['memoryMax']==4294967296 and actual['tasksMax']==64 and 0<actual['effectiveCpuCores']<=2,'CURRENT_JOB_CAPS');return actual

def current_lease(spec,p,j):
 need(sha(bounded(p['lease']['protocolPath'],8192))==LEASE_SHA,'CANONICAL_LEASE_PROTOCOL');own=spec['leaseOwner'];current=read(p['lease']['canonicalWindows'],4096);need(own['projectId']=='04' and all(current.get(k)==own[k] for k in ['projectId','randomToken','ownerPID','ownerProcessStartIdentity']) and j._start_identity(own['ownerPID'])==own['ownerProcessStartIdentity'],'CURRENT_LEASE_IDENTITY')

def validate_row(row,p):
 need(type(row) is dict and row in p['exactGetInputs'] and row['url'].startswith('https://api.nuget.org/v3-flatcontainer/') and row['rid']=='linux-x64' and row['version']=='11.0.0','FINITE_URL_NOT_ADMITTED');need(row['maximumGets']==1 and row['redirects']==row['proxy']==row['auth']==row['retry']==0 and row['perFileSeconds']==40 and row['expectedDeclaredBytes']<=67108864,'FINITE_TRANSPORT_POLICY')

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AdmissionError('REDIRECT_FORBIDDEN')

def acquire_exact(row,dest,spec,p):
 validate_row(row,p);work_time(spec);start=time.monotonic_ns();deadline=min(spec['workDeadlineNs'],start+40000000000);need(deadline-start>0,'FILE_DEADLINE');h1=hashlib.sha256();h2=hashlib.sha512();count=0
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 req=urllib.request.Request(row['url'],headers={'Accept-Encoding':'identity','User-Agent':'producer04-exact-sdk0-discovery'},method='GET');fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as out:
  with opener.open(req,timeout=min(10,max(.001,(deadline-time.monotonic_ns())/1e9))) as response:
   headers=response.headers;lengths=headers.get_all('Content-Length');need(response.status==200 and response.geturl()==row['url'] and lengths==[str(row['expectedDeclaredBytes'])] and headers.get('Content-Encoding','identity')=='identity' and not headers.get('Content-Range') and not headers.get('Transfer-Encoding'),'HTTP_IDENTITY')
   while True:
    need(time.monotonic_ns()<deadline,'FILE_DEADLINE');raw=response.read(65536)
    if not raw:break
    count+=len(raw);need(count<=row['expectedDeclaredBytes']<=p['profile']['rawSingleMaxBytes'],'RAW_BODY_BOUND');out.write(raw);h1.update(raw);h2.update(raw)
   need(count==row['expectedDeclaredBytes'] and time.monotonic_ns()<deadline,'RAW_FINAL_SIZE_OR_TIME');out.flush();os.fsync(out.fileno())
 return {'id':row['id'],'version':row['version'],'rid':row['rid'],'observedRawBytes':count,'rawSignedSHA256':h1.hexdigest(),'rawSignedSHA512':h2.hexdigest(),'declaredPolicyHash':p['declaredPolicyHashes'][row['id']],'normalizedNuGetContentHash':'UNKNOWN','authenticity':'UNKNOWN','GETs':1,'redirects':0,'encoding':'identity','bodySeconds':(time.monotonic_ns()-start)/1e9}

def disk_bytes(root):
 total=0;count=0
 for base,dirs,files in os.walk(root,followlinks=False):
  need(not any((Path(base)/d).is_symlink() for d in dirs),'DATA_REPARSE_FORBIDDEN')
  for name in files:
   path=Path(base)/name;need(not path.is_symlink() and not getattr(path.lstat(),'st_file_attributes',0)&0x400,'DATA_REPARSE_FORBIDDEN');total+=path.stat().st_size;count+=1;need(count<=512 and total<=268435456,'DATA_DISK_BOUND')
 return total

def original_spec(root,handoff,handoff_path,handoff_sha,p,j,start_ns):
 now_tick=j.tick();elapsed=(time.monotonic_ns()-start_ns)//1000000;start_tick=now_tick-elapsed
 return {'purpose':'PRODUCER04_SDK0_RANGE_BYTE_CANDIDATE' if p.get('mode')=='RANGE_BYTE_CANDIDATE_ONLY_SDK0' else 'PRODUCER04_SDK0_DATA_DISCOVERY','root':str(root),'handoff':str(handoff_path),'handoffSha256':handoff_sha,'startNs':start_ns,'workDeadlineNs':start_ns+150000000000,'wholeDeadlineNs':start_ns+180000000000,'startTick':start_tick,'workDeadlineTick':start_tick+150000,'expectedHEAD':handoff['expectedHEAD'],'profileSha256':RANGE_PROFILE_SHA if p.get('mode')=='RANGE_BYTE_CANDIDATE_ONLY_SDK0' else PROFILE_SHA}

def child_state(path):
 try:
  rec=read(path,32768);cap=rec['actualCap'];need(type(rec['exitCode']) is int and cap['activeProcessesAtTeardown']==0,'CHILD_TERMINAL_UNKNOWN');return {'state':'ACTUAL_TERMINAL','exitCode':rec['exitCode'],'timedOut':rec['timedOut'],'activeProcessesAtTeardown':0,'actualCap':{k:cap[k] for k in ['kind','memoryMax','activeProcessMax','cpuRate','logicalHostCpu','effectiveCpuCores','childMembershipBeforeResume','inheritedAggregateBeforeResume','retainedCreationHandles','peakJobMemory','activeProcessesAtTeardown','totalProcesses']},'processReceiptSha256':sha(bounded(path,32768))}
 except Exception:return {'state':'UNKNOWN'}

def recorded_failure(root):
 # Typed leaf causes survive process exit; never parse or publish raw logs.
 for name in ['range-failure.json','fetch-failure-0.json','fetch-failure-1.json','fetch-failure-2.json','worker-failure.json']:
  try:
   path=Path(root)/name
   if not path.is_file():continue
   value=read(path,4096)
   if type(value) is dict and set(value)=={'type','code'} and type(value['type']) is str and type(value['code']) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',value['type']) and re.fullmatch(r'[A-Z][A-Z0-9_:.-]{0,95}',value['code']):return value
  except Exception:pass
 return None

def record_entry_failure(exc):
 try:
  flags=[x for x in ['--inspect-worker','--fetch-worker','--range-worker'] if x in sys.argv]
  if len(flags)!=1:return
  flag=flags[0];spec=read(sys.argv[sys.argv.index(flag)+1],32768);need(spec.get('purpose') in ('PRODUCER04_SDK0_DATA_DISCOVERY','PRODUCER04_SDK0_RANGE_BYTE_CANDIDATE'),'CURATION_PHASE_CLOSED');raw=bounded(spec['handoff'],65536);need(sha(raw)==spec['handoffSha256'],'HANDOFF_PIN');handoff=json.loads(raw);need(handoff.get('admission') in ('ROOT_ONLY_EXACT_STAGE_B_DISCOVERY','ROOT_ONLY_EXACT_RANGE_BYTE_CANDIDATE') and Path(spec['root']).resolve()==Path(handoff['outputRoot']).resolve(),'FAILURE_RECEIPT_SCOPE');root=Path(spec['root'])
  if flag=='--fetch-worker':need(type(spec.get('index')) is int and 0<=spec['index']<3,'FINITE_INPUT_INDEX');name='fetch-failure-'+str(spec['index'])+'.json'
  else:name='range-failure.json' if flag=='--range-worker' else 'worker-failure.json'
  target=root/name
  if not target.exists():write(target,cause(exc),4096)
 except Exception:pass

def fetch_worker(spec,p,j,data):
 work_time(spec);current_lease(spec,p,j);held=held_context(spec,j);row=spec['row'];validate_row(row,p);need(type(spec['index']) is int and 0<=spec['index']<3 and p['exactGetInputs'][spec['index']]==row,'FINITE_INPUT_INDEX');root=Path(spec['root']);write(root/('GET-started-'+str(spec['index'])+'.json'),{'id':row['id'],'GETs':1,'state':'INTENT_BEFORE_SOLE_REQUEST'},4096);record=acquire_exact(row,Path(spec['rawPath']),spec,p);record['currentJob']=held;write(root/('raw-receipt-'+str(spec['index'])+'.json'),record,16384);inspection=inspect_one(spec,p,data,row,spec['index'],record);write(root/('file-result-'+str(spec['index'])+'.json'),inspection,262144)

def inspect_one(spec,p,data,row,index,receipt):
 # The same 40s child Job covers acquisition, disk identity, ZIP/CMS and fsync.
 work_time(spec);root=Path(spec['root']);raw=Path(spec['rawPath']);need(receipt['observedRawBytes']==row['expectedDeclaredBytes'],'RAW_RECEIPT_BINDING');h1=hashlib.sha256();h2=hashlib.sha512();disk_count=0
 with raw.open('rb') as stream:
  while True:
   work_time(spec);block=stream.read(65536)
   if not block:break
   disk_count+=len(block);need(disk_count<=row['expectedDeclaredBytes'],'RAW_RECEIPT_BINDING');h1.update(block);h2.update(block)
 need(disk_count==receipt['observedRawBytes'] and h1.hexdigest()==receipt['rawSignedSHA256'] and h2.hexdigest()==receipt['rawSignedSHA512'],'RAW_RECEIPT_BINDING');manifest=root/'proof'/('members-'+str(index)+'.ndjson');fd=os.open(manifest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);manifest_hash=hashlib.sha256();proof_bytes=retained_bytes=0
 with os.fdopen(fd,'wb') as out:
  def emit(value):
   nonlocal proof_bytes
   work_time(spec);encoded=canonical(value)+b'\n';proof_bytes+=len(encoded);need(proof_bytes<=(p['profile']['proofMaxBytes']-3145728)//3,'PROOF_BYTE_BOUND');out.write(encoded);manifest_hash.update(encoded)
  def retain(number,kind,value):
   nonlocal retained_bytes
   work_time(spec);retained_bytes+=len(value);need(retained_bytes<=4194304,'RETAINED_TOTAL_BOUND');name=f'{index}-{number}-{kind}.data';target=root/'retained-data'/name;fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
   with os.fdopen(fd,'wb') as stream:stream.write(value);stream.flush();os.fsync(stream.fileno())
   return {'relativePath':'retained-data/'+name,'bytes':len(value),'sha256':sha(value),'state':'ORIGINAL_DATA_ONLY'}
  inspection=data.inspect_package(raw,p['profile'],lambda:work_time(spec),emit,retain,{'id':row['id'],'version':row['version']});out.flush();os.fsync(out.fileno())
 work_time(spec);return {'raw':receipt,'inspection':inspection,'memberManifest':{'relativePath':'proof/'+manifest.name,'sha256':manifest_hash.hexdigest(),'bytes':manifest.stat().st_size},'retainedOriginalDataBytes':retained_bytes}

def inspect_worker(spec,p,j,data):
 work_time(spec);current_lease(spec,p,j);held=held_context(spec,j);root=Path(spec['root']);proof=root/'proof';proof.mkdir();rawdir=root/'raw';rawdir.mkdir();retained=root/'retained-data';retained.mkdir();results=[];expanded=members=retained_bytes=0
 for index,row in enumerate(p['exactGetInputs']):
  work_time(spec);raw=rawdir/(row['id'].lower()+'.11.0.0.nupkg');private=root/('fetch-spec-'+str(index)+'.json');fetch=dict(spec);fetch.update(row=row,index=index,rawPath=str(raw),workDeadlineNs=min(spec['workDeadlineNs'],time.monotonic_ns()+40000000000));job='Local\\producer04-curation-fetch-'+secrets.token_hex(12);per_file_deadline=min(spec['workDeadlineTick'],j.tick()+40000)
  j.run_job([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--fetch-worker',str(private)],ROOT,child_env(),per_file_deadline,root/('fetch-job-'+str(index)),job_name=job,inherited_job_name=spec['jobName'],ready_spec={'path':private,'value':fetch})
  need(j.tick()<=per_file_deadline,'FILE_SUPERVISOR_DEADLINE');work_time(spec);file_result=read(root/('file-result-'+str(index)+'.json'),262144);inspection=file_result['inspection'];expanded+=inspection['expandedStreamBytes'];members+=inspection['memberCount'];retained_bytes+=file_result['retainedOriginalDataBytes'];need(expanded<=p['profile']['expandedStreamAggregateMaxBytes'] and members<=p['profile']['membersAllArchivesMax'],'INSPECTION_AGGREGATE_BOUND');file_result['fetchTerminal']=child_state(root/('fetch-job-'+str(index))/'process.json');results.append(file_result);disk_bytes(root)
 value={'schema':'producer04-sdk0-data-results/v1','state':'DISCOVERY_DATA_ONLY_NO_INPUT_ADMISSION','sourceHEAD':spec['expectedHEAD'],'currentJob':held,'rawResults':results,'observedRawTotalBytes':sum(x['raw']['observedRawBytes'] for x in results),'expandedStreamBytes':expanded,'members':members,'retainedOriginalDataBytes':retained_bytes,'SDK':0,'normalizedNuGetHash':'UNKNOWN','signatureTrust':'UNKNOWN','currentAdvisory':'UNKNOWN'};need(value['observedRawTotalBytes']==60404733,'RAW_AGGREGATE_SIZE');write(root/'worker-results.json',value,524288)

def child_env():
 # No inherited tokens, proxies, SDK/runtime hooks or package/source configuration.
 return {**{k:os.environ[k] for k in ['SystemRoot','WINDIR','COMSPEC','PATHEXT','USERPROFILE'] if k in os.environ},'PATH':'C:/Windows/System32;C:/Windows','PYTHONDONTWRITEBYTECODE':'1'}

def release_lease(path,own,terminal):
 need(terminal.get('state')=='ACTUAL_TERMINAL' and terminal.get('activeProcessesAtTeardown')==0,'LEASE_TERMINAL_UNKNOWN');current=read(path,4096);need(all(current.get(k)==own[k] for k in ['projectId','randomToken','ownerPID','ownerProcessStartIdentity']),'LEASE_OWNERSHIP_MISMATCH');path.unlink()

def discover(args,p,j,data,handoff,source):
 range_mode=p.get('mode')=='RANGE_BYTE_CANDIDATE_ONLY_SDK0'
 need(os.name=='nt','ONLY_DECLARED_WINDOWS_METADATA_HOST');need(180-(time.monotonic_ns()-ENTRY_START_NS)/1e9>30,'WHOLE180_STARTUP');root=Path(handoff['outputRoot']);need(root.is_absolute() and not root.exists() and not root.is_symlink(),'FRESH_OUTPUT_ROOT');
 if range_mode:need(not root.resolve().is_relative_to(Path(p['existingDataRoot']).resolve()),'RANGE_OUTPUT_OLD_ROOT_FORBIDDEN')
 root.mkdir(parents=False,mode=0o700);lease_path=Path(p['lease']['canonicalWindows']);protocol=Path(p['lease']['protocolPath']);need(sha(bounded(protocol,8192))==LEASE_SHA,'CANONICAL_LEASE_PROTOCOL');own={'projectId':'04','randomToken':secrets.token_hex(16),'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':j._start_identity(os.getpid()),'phase':'SDK0_EXACT_RANGE_BYTE_CANDIDATE' if range_mode else 'SDK0_THREE_EXACT_NUPKG_DATA_DISCOVERY','startedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'receiptDirectory':str(root)};claimed=False;primary=None;terminal={'state':'UNKNOWN'};result={'schema':'producer04-sdk0-final-receipt/v1','state':'HOLD','source':source,'wholeStartedMonotonicNs':ENTRY_START_NS,'contractSha256':RANGE_CONTRACT_SHA if range_mode else CONTRACT_SHA,'profileSha256':RANGE_PROFILE_SHA if range_mode else PROFILE_SHA,'SDK':0,'networkRequestsMax':1 if range_mode else 3,'curationAdmission':False,'WindowsQualification':False,'normalizedNuGetHash':'UNKNOWN'}
 try:
  try:write(lease_path,own,4096);claimed=True
  except FileExistsError:raise AdmissionError('CANONICAL_LEASE_BUSY')
  spec=original_spec(root,handoff,args.handoff,args.handoff_sha256,p,j,ENTRY_START_NS);spec['leaseOwner']={k:own[k] for k in ['projectId','randomToken','ownerPID','ownerProcessStartIdentity']};job='Local\\producer04-curation-outer-'+secrets.token_hex(12);private=root/'worker-spec.json'
  if range_mode:
   need(not root.resolve().is_relative_to(Path(p['existingDataRoot']).resolve()),'RANGE_OUTPUT_OLD_ROOT_FORBIDDEN');spec['workDeadlineNs']=min(spec['workDeadlineNs'],time.monotonic_ns()+40000000000);spec['workDeadlineTick']=min(spec['workDeadlineTick'],j.tick()+40000)
  try:j.run_job([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--range-worker' if range_mode else '--inspect-worker',str(private)],ROOT,child_env(),spec['workDeadlineTick'],root/'outer-job',job_name=job,ready_spec={'path':private,'value':spec})
  finally:terminal=child_state(root/'outer-job/process.json')
  work=read(root/'worker-results.json',1048576);need(work['state']==('BYTE_CANDIDATE_UNTRUSTED' if range_mode else 'DISCOVERY_DATA_ONLY_NO_INPUT_ADMISSION') and terminal.get('exitCode')==0 and terminal.get('activeProcessesAtTeardown')==0,'WORKER_DATA_OR_TERMINAL');result.update(state='BYTE_CANDIDATE_UNTRUSTED' if range_mode else 'DISCOVERY_DATA_ONLY_NOT_TRUST_OR_NORMALIZED_ADMISSION',workerResults=work)
 except BaseException as exc:
  primary=exc;result['outerCause']=cause(exc);result['primaryCause']=recorded_failure(root) or cause(exc)
 result['terminal']=terminal;result['lease']={'claimed':claimed,'released':False,'ownership':'UNKNOWN' if not claimed else 'OWNED','tokenSha256':sha(own['randomToken'].encode())};result['wholeElapsedSeconds']=(time.monotonic_ns()-ENTRY_START_NS)/1e9
 try:
  need(result['wholeElapsedSeconds']<180,'ORIGINAL_WHOLE180_DEADLINE');result['dataDiskBytes']=disk_bytes(root)
  if range_mode:result['combinedRetainedPlusFreshDiskBytes']=result['dataDiskBytes']+disk_bytes(Path(p['existingDataRoot']));need(result['combinedRetainedPlusFreshDiskBytes']<=268435456,'RANGE_COMBINED_DISK_BUDGET');result['HTTPRepresentationContinuity']='UNKNOWN_WITHOUT_ORIGINAL_STRONG_VALIDATOR'
  write(root/'FINAL-RECEIPT.json',result,1048576)
  if claimed:
   release_lease(lease_path,own,terminal);write(root/'LEASE-RELEASED.json',{'released':True,'ownerPID':own['ownerPID'],'ownerProcessStartIdentity':own['ownerProcessStartIdentity'],'tokenSha256':result['lease']['tokenSha256'],'terminalReceiptSha256':terminal['processReceiptSha256']},4096)
 except BaseException as exc:
  if primary is None:primary=exc
  try:write(root/'FINALIZATION-HOLD.json',{'state':'HOLD','cause':cause(exc),'primaryPreserved':result.get('primaryCause'),'leaseRelease':'UNKNOWN_OR_NOT_RELEASED'},8192)
  except Exception:pass
 # Final receipt+release marker are distinct durable observations; no guessed cleanup success.
 print(json.dumps({'state':result['state'] if primary is None else 'HOLD','cause':cause(primary) if primary else None,'SDK':0,'receiptRootDeclaredInIntent':True}))
 return 0 if primary is None else 1

class Parser(argparse.ArgumentParser):
 def error(self,message):raise AdmissionError('ARGUMENTS_NOT_ADMITTED')

def range_runtime_gate(handoff,p):
 digest=handoff.get('rangeGateSha256');path=handoff.get('rangeGatePath');need(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest) is not None and digest!='0'*64 and type(path) is str,'RANGE_RUNTIME_GATE_REQUIRED');raw=bounded(path,32768);need(sha(raw)==digest,'RANGE_RUNTIME_GATE_PIN');g=json.loads(raw);b=p['exactByteCandidate']
 expected={'schema':'producer04-runtime-range-byte-candidate-execution-gate/v1','state':'EXACT_RANGE_GET_ONCE_APPROVED','contractSha256':RANGE_CONTRACT_SHA,'sourceHEAD':handoff['expectedHEAD'],'sourceTree':handoff['expectedTree'],'rangeProfileSha256':RANGE_PROFILE_SHA,'outputRoot':handoff['outputRoot'],'Range':b['rangeRequest'],'suffixBytes':b['suffixBytes'],'prefixSha256':b['prefixSha256'],'wholePolicySHA512':b['existingWholePolicySHA512'],'GETsMax':1,'SDK':0}
 need(type(g) is dict and all(type(g.get(k)) is type(v) and g.get(k)==v for k,v in expected.items()),'RANGE_RUNTIME_GATE_SCOPE')

def range_worker(spec,p,j,data):
 work_time(spec);current_lease(spec,p,j);actual=held_context(spec,j);r=load('curation_range_candidate',RANGE_HELPER_SHA);b=p['exactByteCandidate'];oldroot=Path(p['existingDataRoot']);root=Path(spec['root']);need(not root.resolve().is_relative_to(oldroot.resolve()),'RANGE_OUTPUT_OLD_ROOT_FORBIDDEN');need(sha(bounded(p['priorDiscoveryReceipt']['path'],32768))==p['priorDiscoveryReceipt']['sha256'] and sha(bounded(p['priorLeaseRelease']['path'],4096))==p['priorLeaseRelease']['sha256'],'RANGE_PRIOR_DATA_RECEIPTS')
 oldbytes=disk_bytes(oldroot);need(oldbytes+b['wholeBytes']+p['profile']['proofMaxBytes']+4194304+2097152<=268435456,'RANGE_COMBINED_DISK_BUDGET');(root/'raw').mkdir();(root/'proof').mkdir();(root/'retained-data').mkdir();fresh=root/'raw/runtime-linux-x64-byte-candidate.nupkg';local=dict(spec,rawPath=str(fresh))
 with j.held_windows_image(Path(b['immutablePrefixPath'])) as held:
  need(held['sha256']==b['prefixSha256'],'RANGE_PREFIX_HELD_HASH');receipt=r.reconstruct(b,fresh,spec['workDeadlineNs'],held['sha256']);receipt['currentJob']=actual;write(root/'range-byte-candidate-receipt.json',receipt,32768);r.require_full_policy(receipt)
  # Full policy equality is a prerequisite, never normalization or authenticity.
  result=inspect_one(local,p,data,{'id':b['id'],'version':b['version'],'expectedDeclaredBytes':b['wholeBytes']},2,receipt)
 work_time(spec);combined=disk_bytes(oldroot)+disk_bytes(root);need(combined<=268435456,'RANGE_COMBINED_DISK_BUDGET');write(root/'worker-results.json',{'state':'BYTE_CANDIDATE_UNTRUSTED','sourceHEAD':spec['expectedHEAD'],'currentJob':actual,'result':result,'HTTPRepresentationContinuity':'UNKNOWN_WITHOUT_ORIGINAL_STRONG_VALIDATOR','combinedRetainedPlusFreshDiskBytes':combined,'SDK':0,'cryptographicAdmission':False,'normalizedNuGetContentHash':'UNKNOWN','authenticity':'UNKNOWN','advisory':'UNKNOWN'},524288)

def dispatch():
 parser=Parser();parser.add_argument('--mode',choices=['discover-sdk0','range-candidate-sdk0']);parser.add_argument('--handoff',type=Path);parser.add_argument('--handoff-sha256');parser.add_argument('--inspect-worker',type=Path);parser.add_argument('--fetch-worker',type=Path);parser.add_argument('--range-worker',type=Path);args=parser.parse_args();range_mode=bool(args.range_worker or args.mode=='range-candidate-sdk0');p=profile(range_mode);data=load('curation_data_inspector',DATA_SHA);children=[x for x in [args.inspect_worker,args.fetch_worker,args.range_worker] if x]
 if children:
  need(not args.mode and not args.handoff and len(children)==1,'CURATION_PHASE_CLOSED');spec=read(children[0],32768);raw=bounded(spec['handoff'],65536);need(sha(raw)==spec['handoffSha256'],'HANDOFF_PIN');handoff=json.loads(raw);bind_source(handoff,p);j=load('windows_qualification_job',JOB_SHA)
  if args.range_worker:range_worker(spec,p,j,data)
  elif args.fetch_worker:fetch_worker(spec,p,j,data)
  else:inspect_worker(spec,p,j,data)
  return 0
 need(args.mode in ('discover-sdk0','range-candidate-sdk0') and args.handoff and re.fullmatch('[0-9a-f]{64}',args.handoff_sha256 or '') is not None,'CURATION_ADMISSION_REQUIRED');raw=bounded(args.handoff,65536);need(sha(raw)==args.handoff_sha256,'HANDOFF_PIN');handoff=json.loads(raw);source=bind_source(handoff,p);j=load('windows_qualification_job',JOB_SHA);return discover(args,p,j,data,handoff,source)

def main():
 seconds=180-(time.monotonic_ns()-ENTRY_START_NS)/1e9;need(seconds>0,'ORIGINAL_WHOLE180_DEADLINE');watchdog=threading.Timer(seconds,lambda:os._exit(124));watchdog.daemon=True;watchdog.start()
 try:return dispatch()
 finally:watchdog.cancel()

if __name__=='__main__':
 try:raise SystemExit(main())
 except Exception as exc:
  record_entry_failure(exc);print(json.dumps({'state':'HOLD','cause':cause(exc),'SDK':0}));raise SystemExit(1)
