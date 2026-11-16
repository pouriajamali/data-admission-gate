"""Changed Stage-A offline fixtures only. HTTP/Job/source identities are mocked."""
from pathlib import Path
import binascii,contextlib,copy,hashlib,io,json,os,stat,struct,sys,time,types,zipfile,zlib

BASE=Path(__file__).resolve().parent
def source_path(name):return BASE/(name+'.py.txt') if (BASE/(name+'.py.txt')).is_file() else BASE/(name+'.py')
def module(name):
 p=source_path(name);raw=p.read_bytes();m=types.ModuleType(name);m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__);return m,raw
C,craw=module('curate_dotnet11_inputs');D,draw=module('curation_data_inspector')
profile_path=BASE/'producer04-curation.profile.json.txt';profile_path=profile_path if profile_path.is_file() else BASE/'producer04-curation.profile.json';P=json.loads(profile_path.read_bytes())
MODE=sys.argv[1];OUT=Path(sys.argv[2]);OUT.mkdir(parents=True,exist_ok=False);cases=[];started=time.monotonic();h=lambda b:hashlib.sha256(b).hexdigest()
def check(value,name):
 if not value:raise RuntimeError(name)
 cases.append(name)
def denied(call,name):
 try:call()
 except (C.AdmissionError,D.DiscoveryError,ValueError,EOFError,struct.error):cases.append(name);return
 raise RuntimeError(name)

# Fixed phase and actual-current-context deltas; no real host/kernel API.
for phase in ['graph','signature','restore','product','sdk','windows-qualify']:
 old=C.sys.argv;C.sys.argv=['fixture','--mode',phase]
 try:denied(C.dispatch,'phase_closed_'+phase)
 finally:C.sys.argv=old
denied(lambda:C.bind_source({'schema':'wrong'},P),'explicit_curation_admission')
os_save=C.os;C.os=types.SimpleNamespace(name='nt',getpid=lambda:201)
J=types.SimpleNamespace(_start_identity=lambda pid:'START',current_witness=lambda job:{'currentProcessMember':True,'memoryMax':4294967296,'tasksMax':64,'effectiveCpuCores':2})
SPEC={'purpose':'PRODUCER04_SDK0_DATA_DISCOVERY','workerPID':201,'workerStart':'START','jobName':'SYNTHETIC','beforeResume':{'membership':True,'retainedCreationHandles':True,'memoryMax':4294967296,'activeProcessMax':64,'effectiveCpuCores':2}}
check(C.held_context(SPEC,J)['currentProcessMember'],'synthetic_current_held_positive')
for label,change in [('pid',lambda s:s.update(workerPID=202)),('start',lambda s:s.update(workerStart='OLD')),('held',lambda s:s['beforeResume'].update(retainedCreationHandles=False)),('membership',lambda s:s['beforeResume'].update(membership=False)),('cpu',lambda s:s['beforeResume'].update(effectiveCpuCores=3))]:
 s=copy.deepcopy(SPEC);change(s);denied(lambda:C.held_context(s,J),'current_held_denial_'+label)
C.os=os_save

# Source validation fixture uses only an in-memory file map and a fake HEAD.
save=(C.bounded,C.current_head,C.sys,C.ROOT,C.HERE);C.ROOT=Path('/SOURCE_FIXTURE');C.HERE=C.ROOT/'tools';pins={'sourcePins':[{'path':'a.py','mode':'100644','gitBlob':hashlib.sha1(b'blob 4\0FILE').hexdigest()}]};pinbytes=C.canonical(pins);files={str(C.HERE/'dotnet11-consumer04-source-pins.json'):pinbytes,str(C.ROOT/'a.py'):b'FILE','BOOT':b'BOOT'};C.bounded=lambda path,limit:files[str(path)];C.current_head=lambda:'a'*40;C.sys=types.SimpleNamespace(executable='BOOT',version_info=(3,12,1));hand={'schema':'producer04-sdk0-discovery-handoff/v1','admission':'ROOT_ONLY_EXACT_STAGE_B_DISCOVERY','mode':'discover-sdk0','contractSha256':C.CONTRACT_SHA,'profileSha256':C.PROFILE_SHA,'expectedHEAD':'a'*40,'expectedTree':'b'*40,'sourcePinRows':1,'sourcePinsFileSha256':h(pinbytes),'bootstrap':{'pythonExeSha256':h(b'BOOT'),'pythonVersion':[3,12,1]}}
check(C.bind_source(hand,P)['workingBytesVerified'],'synthetic_source_exact_positive');files[str(C.ROOT/'a.py')]=b'WRONG';denied(lambda:C.bind_source(hand,P),'source_bytes_denial');files[str(C.ROOT/'a.py')]=b'FILE';bad=copy.deepcopy(hand);bad['expectedHEAD']='c'*40;denied(lambda:C.bind_source(bad,P),'stale_head_denial');C.bounded,C.current_head,C.sys,C.ROOT,C.HERE=save

class Headers(dict):
 def get_all(self,key):
  value=self.get(key);return value if isinstance(value,list) else [value] if value is not None else None
class Response:
 def __init__(self,row,body,status=200,headers=None,url=None):self.status=status;self.headers=Headers({'Content-Length':str(row['expectedDeclaredBytes']),**(headers or {})});self.url=url or row['url'];self.body=io.BytesIO(body)
 def geturl(self):return self.url
 def read(self,n):return self.body.read(n)
 def __enter__(self):return self
 def __exit__(self,*args):pass
class Opener:
 def __init__(self,response=None,error=None):self.response=response;self.error=error;self.calls=0
 def open(self,request,timeout):
  self.calls+=1
  if self.error:raise self.error
  return self.response
fp=copy.deepcopy(P);row=copy.deepcopy(P['exactGetInputs'][0]);row['expectedDeclaredBytes']=4;fp['exactGetInputs'][0]=row;spec={'workDeadlineNs':time.monotonic_ns()+90000000000};build=C.urllib.request.build_opener
op=Opener(Response(row,b'DATA'));C.urllib.request.build_opener=lambda *args:op;receipt=C.acquire_exact(row,OUT/'body-positive',spec,fp)
check(op.calls==1 and receipt['rawSignedSHA256']==h(b'DATA') and receipt['rawSignedSHA512']==hashlib.sha512(b'DATA').hexdigest() and receipt['normalizedNuGetContentHash']=='UNKNOWN' and receipt['authenticity']=='UNKNOWN' and receipt['declaredPolicyHash']!=receipt['rawSignedSHA512'],'one_get_raw_declared_normalized_separation')
for label,body,status,headers,url in [('status',b'DATA',302,None,None),('length_missing',b'DATA',200,{'Content-Length':None},None),('duplicate_length',b'DATA',200,{'Content-Length':['4','4']},None),('gzip',b'DATA',200,{'Content-Encoding':'gzip'},None),('range',b'DATA',200,{'Content-Range':'bytes 0-3/4'},None),('chunked',b'DATA',200,{'Transfer-Encoding':'chunked'},None),('url',b'DATA',200,None,'https://invalid.example/no'),('short',b'ABC',200,None,None),('long',b'ABCDE',200,None,None)]:
 op=Opener(Response(row,body,status,headers,url));C.urllib.request.build_opener=lambda *args:op;denied(lambda:C.acquire_exact(row,OUT/('body-'+label),spec,fp),'HTTP_body_'+label);check(op.calls==1,'HTTP_no_retry_'+label)
bad=dict(row,url='https://invalid.example/else');op=Opener();C.urllib.request.build_opener=lambda *args:op;denied(lambda:C.acquire_exact(bad,OUT/'bad-url',spec,fp),'closed_finite_url');check(op.calls==0,'closed_url_before_get')
secret=RuntimeError('SYNTHETIC_SECRET_PATH_URL_ENV_ARGS');op=Opener(error=secret);C.urllib.request.build_opener=lambda *args:op
try:C.acquire_exact(row,OUT/'primary-error',spec,fp)
except RuntimeError as exc:check(exc is secret and 'SYNTHETIC_SECRET' not in json.dumps(C.cause(exc)),'transport_primary_preserved_redacted')
else:raise RuntimeError('PRIMARY')
C.urllib.request.build_opener=build

# Synthetic nupkg bytes only, never execute or fully extract an entry.
def package(entries,compression=zipfile.ZIP_DEFLATED,unseekable=False,force64=False):
 class Sink(io.BytesIO):
  def seek(self,*args):
   if unseekable:raise io.UnsupportedOperation('synthetic nonseekable')
   return super().seek(*args)
 stream=Sink()
 with zipfile.ZipFile(stream,'w',compression=compression) as archive:
  for name,body,mode in entries:
   info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=mode<<16;info.compress_type=compression
   if force64:
    with archive.open(info,'w',force_zip64=True) as item:item.write(body)
   else:archive.writestr(info,body)
 return stream.getvalue()
NUSPEC=b'<package><metadata><id>Fixture.Package</id><version>11.0.0</version></metadata></package>'
entries=[('Fixture.Package.nuspec',NUSPEC,stat.S_IFREG|0o644),('LICENSE.txt',b'ORIGINAL LICENSE DATA',stat.S_IFREG|0o644),('runtimes/linux-x64/native/not-executed.so',b'NOT_EXECUTABLE_FIXTURE',stat.S_IFREG|0o755)]
def inspect(raw,label,prof=None):
 path=OUT/('zip-'+label);path.write_bytes(raw);manifest=[];retained=[];result=D.inspect_package(path,prof or P['profile'],lambda:None,manifest.append,lambda i,k,b:retained.append((i,k,b)) or {'sha256':h(b),'bytes':len(b)},expected={'id':'Fixture.Package','version':'11.0.0'});return result,manifest,retained
for label,compression,nonseek,force64 in [('stored',zipfile.ZIP_STORED,False,False),('deflate',zipfile.ZIP_DEFLATED,False,False),('dd32',zipfile.ZIP_DEFLATED,True,False),('zip64',zipfile.ZIP_DEFLATED,False,True),('dd64',zipfile.ZIP_DEFLATED,True,True)]:
 result,manifest,retained=inspect(package(entries,compression,nonseek,force64),label);check(len(manifest)==3 and result['normalizedContentHash']=='UNKNOWN' and result['packageTrust']=='UNKNOWN' and len(retained)==2 and result['nuspec'][0]['id']=='Fixture.Package','zip_positive_'+label)
for label,name,mode in [('traversal','../x',stat.S_IFREG),('separator','x\\y',stat.S_IFREG),('drive','C:x',stat.S_IFREG),('reserved','CON.txt',stat.S_IFREG),('symlink','x',stat.S_IFLNK|0o777),('special','x',stat.S_IFIFO|0o644)]:
 raw=package([*entries,(name,b'X',mode)])
 # ZipInfo on Windows normalizes the separator before serializing; mutate the wire fixture.
 if label=='separator':raw=raw.replace(b'x/y',b'x\\y')
 denied(lambda:inspect(raw,label),'zip_path_type_'+label)
denied(lambda:inspect(package([*entries,('license.TXT',b'X',stat.S_IFREG)]),'case'),'zip_case_collision')
denied(lambda:inspect(package([*entries,('a',b'X',stat.S_IFREG),('a/x',b'X',stat.S_IFREG)]),'parent'),'zip_file_parent_collision')
normal=package(entries,zipfile.ZIP_STORED);mut=bytearray(normal);mut[30]^=1;denied(lambda:inspect(bytes(mut),'localname'),'zip_local_central_name')
mut=bytearray(normal);mut[14]^=1;denied(lambda:inspect(bytes(mut),'localcrc'),'zip_local_central_crc')
denied(lambda:inspect(normal+b'X','trailing'),'zip_trailing_frame')
denied(lambda:inspect(b'X'+normal,'prefix'),'zip_prefix_frame')
for tag in [0x000d,0x5855,0x7075]:
 stream=io.BytesIO()
 with zipfile.ZipFile(stream,'w') as archive:
  info=zipfile.ZipInfo('Fixture.Package.nuspec');info.extra=struct.pack('<HH',tag,1)+b'X';archive.writestr(info,NUSPEC)
 denied(lambda:inspect(stream.getvalue(),'extra-'+str(tag)),'zip_extra_ambiguity_'+str(tag))
nullwire=package([*entries,('nulX',b'X',stat.S_IFREG)]).replace(b'nulX',b'nu\0X');denied(lambda:inspect(nullwire,'nul'),'zip_raw_nul_name')
prof=dict(P['profile'],membersPerArchiveMax=2);denied(lambda:inspect(normal,'members',prof),'zip_member_bound')
prof=dict(P['profile'],expandedStreamSingleMaxBytes=10);denied(lambda:inspect(normal,'expanded',prof),'zip_expansion_bound')
denied(lambda:inspect(package([('Fixture.Package.nuspec',b'<!DOCTYPE x><package/>',stat.S_IFREG)]),'DTD'),'nuspec_DTD_denied')
compress=zlib.compressobj(wbits=-15);body=compress.compress(b'DATA')+compress.flush();streamrow={'payloadOffset':0,'compressedBytes':len(body)+1,'method':8,'bytes':4,'crc32':binascii.crc32(b'DATA')};denied(lambda:D.stream_member(io.BytesIO(body+b'X'),streamrow,lambda:None),'deflate_trailing_stream_denied')

# The entire per-file data stage runs in the same strict child deadline.
one=OUT/'file-stage';one.mkdir();(one/'proof').mkdir();(one/'retained-data').mkdir();one_raw=one/'package.data';one_bytes=package(entries);one_raw.write_bytes(one_bytes);one_spec={'root':str(one),'rawPath':str(one_raw),'workDeadlineNs':time.monotonic_ns()+30000000000};one_row={'id':'Fixture.Package','version':'11.0.0','expectedDeclaredBytes':len(one_bytes)};one_receipt={'observedRawBytes':len(one_bytes),'rawSignedSHA256':h(one_bytes),'rawSignedSHA512':hashlib.sha512(one_bytes).hexdigest()};one_result=C.inspect_one(one_spec,P,D,one_row,0,one_receipt)
check(one_result['inspection']['memberCount']==3 and one_result['memberManifest']['bytes']>0 and one_result['retainedOriginalDataBytes']>0,'same_file_child_inspection_positive')
bad_receipt=dict(one_receipt,rawSignedSHA256='f'*64);denied(lambda:C.inspect_one(one_spec,P,D,one_row,1,bad_receipt),'disk_wire_identity_mismatch')
expired=dict(one_spec,workDeadlineNs=0);denied(lambda:C.inspect_one(expired,P,D,one_row,2,one_receipt),'same_original_file_deadline_no_reset')

# CMS DER and URI decoding are structural observations, never PKI operations.
def der(tag,value):
 n=len(value);length=bytes([n]) if n<128 else bytes([128+((n.bit_length()+7)//8)])+n.to_bytes((n.bit_length()+7)//8,'big');return bytes([tag])+length+value
def O(hexdata):return der(6,bytes.fromhex(hexdata))
signed_oid=O('2a864886f70d010702');data_oid=O('2a864886f70d010701');sha_oid=O('608648016503040201');algorithm=der(48,sha_oid)
uri=b'https://pki.example.invalid/bounded-data-only';extension=der(48,O('551d1f')+der(4,der(48,der(134,uri))));certificate=der(48,der(48,der(163,der(48,extension)))+der(48,b'')+der(3,b'\0X'))
signer=der(48,der(2,b'\1')+der(48,der(48,b'')+der(2,b'\1'))+algorithm+algorithm+der(4,b'SIGNATURE_DATA'))
cms=der(48,signed_oid+der(160,der(48,der(2,b'\1')+der(49,algorithm)+der(48,data_oid)+der(160,certificate)+der(49,signer))))
parsed=D.cms_data(cms);check(parsed['state']=='OBSERVED_UNVERIFIED' and parsed['certificates'][0]['sha256']==h(certificate) and parsed['observedPKIURLs'][0]['uri']==uri.decode() and parsed['cryptographicTrust']==parsed['normalizedNuGetHash']=='UNKNOWN','CMS_structural_cert_URI_only')
result,manifest,retained=inspect(package([*entries,('.signature.p7s',cms,stat.S_IFREG)]),'cms');check(result['CMS']['inspection']['state']=='OBSERVED_UNVERIFIED' and any(k=='cms' and b==cms for i,k,b in retained),'CMS_original_bytes_retained_only')
for label,raw in [('indefinite',b'\x30\x80\0\0'),('truncated',b'\x30\x08X'),('trailing',cms+b'X')]:check(D.cms_data(raw)['state']=='UNKNOWN_PARSER_OR_PROVENANCE','CMS_unknown_'+label)
deep=der(2,b'\1')
for _ in range(40):deep=der(48,deep)
denied(lambda:D.der_tree(deep),'CMS_depth_bound');denied(lambda:D.der_tree(cms,max_nodes=2),'CMS_node_bound');denied(lambda:D.der_tree(b'X'*2097153),'CMS_byte_bound')
check('SYNTHETIC_SECRET' not in json.dumps(D.safe_cause(RuntimeError('SYNTHETIC_SECRET_PATH_URL_ENV_ARGS'))),'parser_redaction')

# Inner typed causes survive a process boundary without reading raw stderr/stdout.
cause_root=OUT/'typed-cause';cause_root.mkdir();handoff_file=OUT/'cause-handoff.json';handoff_file.write_bytes(C.canonical({'admission':'ROOT_ONLY_EXACT_STAGE_B_DISCOVERY','outputRoot':str(cause_root)}));spec_file=OUT/'cause-spec.json';spec_file.write_bytes(C.canonical({'purpose':'PRODUCER04_SDK0_DATA_DISCOVERY','handoff':str(handoff_file),'handoffSha256':h(handoff_file.read_bytes()),'root':str(cause_root),'index':0}));argv=C.sys.argv;C.sys.argv=['fixture','--fetch-worker',str(spec_file)]
try:C.record_entry_failure(C.AdmissionError('HTTP_IDENTITY'))
finally:C.sys.argv=argv
check(C.recorded_failure(cause_root)=={'type':'AdmissionError','code':'HTTP_IDENTITY'},'typed_leaf_cause_durable_no_raw_log')
(cause_root/'fetch-failure-0.json').write_text(json.dumps({'raw':'SYNTHETIC_SECRET_PATH_URL_ENV_ARGS'}),encoding='utf-8');check(C.recorded_failure(cause_root) is None,'malformed_leaf_preserves_outer_cause')

# Canonical protocol semantics, exercised only on fixture-local paths.
own={'projectId':'04','randomToken':'TOKEN','ownerPID':7,'ownerProcessStartIdentity':'START'};lease=OUT/'fixture-lease.json';C.write(lease,own,4096);terminal={'state':'ACTUAL_TERMINAL','activeProcessesAtTeardown':0};denied(lambda:C.release_lease(lease,own,{'state':'UNKNOWN'}),'lease_unknown_terminal_no_release');check(lease.exists(),'lease_preserved_unknown');wrong=dict(own,randomToken='WRONG');denied(lambda:C.release_lease(lease,wrong,terminal),'lease_token_mismatch_no_release');check(lease.exists(),'lease_preserved_mismatch');C.release_lease(lease,own,terminal);check(not lease.exists(),'lease_exact_owner_terminal_release')

# Existing parent failure is preserved if finalization itself also fails.
root=OUT/'parent-fixture';protocol=OUT/'protocol-fixture.json';protocol.write_bytes(b'PROTOCOL');p=copy.deepcopy(P);p['lease']={'canonicalWindows':str(OUT/'parent-lease.json'),'protocolPath':str(protocol)};save=(C.LEASE_SHA,C.ENTRY_START_NS,C.release_lease);C.LEASE_SHA=h(b'PROTOCOL');C.ENTRY_START_NS=time.monotonic_ns();C.release_lease=lambda *a:(_ for _ in ()).throw(C.AdmissionError('LEASE_OWNERSHIP_MISMATCH'))
class CapError(RuntimeError):pass
def fake_job(*args,**kwargs):
 evidence=Path(args[4]);evidence.mkdir();cap={'kind':'actual-Windows-Job','memoryMax':4294967296,'activeProcessMax':64,'cpuRate':5000,'logicalHostCpu':4,'effectiveCpuCores':2,'childMembershipBeforeResume':True,'inheritedAggregateBeforeResume':False,'retainedCreationHandles':True,'peakJobMemory':1,'activeProcessesAtTeardown':0,'totalProcesses':1};C.write(evidence/'process.json',{'exitCode':1,'timedOut':False,'actualCap':cap});raise CapError('CHILD_NONZERO:1')
j=types.SimpleNamespace(_start_identity=lambda pid:'START',tick=lambda:int(time.monotonic()*1000),run_job=fake_job);handoff={'outputRoot':str(root),'intentCreatedAtUtc':'2026-11-16T00:00:00Z','expectedHEAD':'a'*40};args=types.SimpleNamespace(handoff=OUT/'not-read',handoff_sha256='f'*64)
with contextlib.redirect_stdout(io.StringIO()):code=C.discover(args,p,j,None,handoff,{'fixture':'SOURCE_ONLY'})
result=json.loads((root/'FINAL-RECEIPT.json').read_bytes());hold=json.loads((root/'FINALIZATION-HOLD.json').read_bytes());check(code==1 and result['primaryCause']['code']=='CHILD_NONZERO:1' and hold['primaryPreserved']['code']=='CHILD_NONZERO:1' and (OUT/'parent-lease.json').exists(),'parent_primary_preserved_on_lease_failure')
lease_now=json.loads((OUT/'parent-lease.json').read_bytes())['startedAtUtc'];check(lease_now!=handoff['intentCreatedAtUtc'] and abs(C.datetime.datetime.fromisoformat(lease_now).timestamp()-time.time())<5,'lease_actual_claim_time_not_old_intent')
def fake_job_leaf(*args,**kwargs):
 try:fake_job(*args,**kwargs)
 except CapError:
  C.write(Path(args[4]).parent/'fetch-failure-0.json',{'type':'AdmissionError','code':'HTTP_IDENTITY'},4096);raise
j.run_job=fake_job_leaf;handoff['outputRoot']=str(OUT/'parent-leaf-fixture');p['lease']['canonicalWindows']=str(OUT/'parent-leaf-lease.json')
with contextlib.redirect_stdout(io.StringIO()):code=C.discover(args,p,j,None,handoff,{'fixture':'SOURCE_ONLY'})
result=json.loads((OUT/'parent-leaf-fixture/FINAL-RECEIPT.json').read_bytes());hold=json.loads((OUT/'parent-leaf-fixture/FINALIZATION-HOLD.json').read_bytes());check(code==1 and result['primaryCause']['code']=='HTTP_IDENTITY' and result['outerCause']['code']=='CHILD_NONZERO:1' and hold['primaryPreserved']['code']=='HTTP_IDENTITY','typed_leaf_and_outer_terminal_both_preserved');C.LEASE_SHA,C.ENTRY_START_NS,C.release_lease=save

elapsed=time.monotonic()-started;result={'schema':'producer04-curation-stageA-offline-fixtures/v1','state':'DELTA_OFFLINE_PASS','mode':MODE,'optimize':sys.flags.optimize,'checks':len(cases),'caseNames':cases,'controllerSHA256':h(craw),'dataHelperSHA256':h(draw),'profileSHA256':h(profile_path.read_bytes()),'elapsedSeconds':elapsed,'HTTP':0,'SDK':0,'nativeProbeOrJob':0,'sharedOrProductControllerImport':0,'canonicalLeaseTouched':False,'normalizationOrCMSTrustClaim':False,'sourceScope':'New discovery-only entry/data helper; fakeHTTP/source/currentJob and fixture-local lease, no actualWindows API or network.'};encoded=(json.dumps(result,indent=2)+'\n').encode()
if len(encoded)>32768 or elapsed>30:raise RuntimeError('FIXTURE_BOUND')
(OUT.parent/('FIXTURE-'+MODE+'.json')).write_bytes(encoded)
print(json.dumps({k:v for k,v in result.items() if k not in ['caseNames']}))
