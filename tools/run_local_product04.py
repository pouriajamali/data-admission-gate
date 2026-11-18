"""Fixed original product04 acceptance on current local Linux/experimental Windows.
No qualification replay, acquisition, public operation or unrelated source edit.
"""
from __future__ import annotations
import argparse,base64,select,stat,datetime,hashlib,importlib.util,json,os,pathlib,platform,secrets,shlex,shutil,signal,subprocess,sys,time,uuid,zipfile,tarfile
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent

def load(name,sha):
 p=HERE/(name+'.py')
 if hashlib.sha256(p.read_bytes()).hexdigest()!=sha:raise RuntimeError('FIXED_PRODUCT_HELPER:'+name)
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);return m
Q=load('qualify_dotnet11_windows' if os.name=='nt' else 'qualify_dotnet11_linux','a8f5a9947a7bad112a2162cd59e3e464f7f599276940f4a0f36d0feb5ae60b82' if os.name=='nt' else 'cdf1773d1d672fe78d214dd9a35616aaea0b3beade1578aa9a216e88e87a43ca');R=Q.R;j=Q.j
# These producer paths are existing read-only trees, not caller-owned allocations.
SDK=pathlib.Path(r'E:/Codex WorkSpace/Git Projects/data-admission-gate/state/dotnet11-shared-20261114/trees/win-x64') if os.name=='nt' else pathlib.Path('/home/ubuntu/.frl01-sdk-qja56iv8/sdk')
H=pathlib.Path(r'E:/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave4-state/project04-shared-normal-final-20261117') if os.name=='nt' else pathlib.Path('/mnt/e/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave4-state/project04-shared-normal-final-20261117')
BASE=pathlib.Path(r'C:/Users/Office/.codex/visualizations/2026/11/10/01a1c661-2773-7f81-9ae7-c5756abd8095/metadata-framing') if os.name=='nt' else pathlib.Path('/mnt/c/Users/Office/.codex/visualizations/2026/11/10/01a1c661-2773-7f81-9ae7-c5756abd8095/metadata-framing')
RID='win-x64' if os.name=='nt' else 'linux-x64';PROFILE=HERE/('producer04-local-product-'+RID+'.profile.json');PINS=HERE/'producer04-local-source-pins.json';PURPOSE='FIXED_LOCAL_PRODUCT04_ORIGINAL_ACCEPTANCE';LEASE=pathlib.Path(r'E:/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave2-state/LOCAL-FIXTURE-LEASE.json')
# Filled with the final fixed native controller hash when this source is staged.
NATIVE_CONTROLLER_SHA='38a22d3cc48735df5b037a1d0dd481414dd6101e8132fa6f3e09aa7835e4b2da'

def need(v,why):R.f.need(v,why)

check=need
L=load('curate_dotnet11_linux_inputs','9e199eadd9d399dbb940f635a64d57e11ddd37f91e5bad15eba5bd6cd3f15216')
M=load('curation_linux_method',L.METHOD_SOURCE_PINS['curation_linux_method'])
A=load('curation_advisory_source04',L.METHOD_SOURCE_PINS['curation_advisory_source04'])
if os.name=='nt':JLOCAL=load('windows_qualification_job_local','e14e6feb51d1dfd0ea1865df36a4432ccf397dcd19849038d9b4e69cf7402d1e')
else:NET=load('local_linux_network_query','766a3711121b2188a3a0804673a3ba3ebb1818130ff1be3b703be0aa0dc49f5e')
HAND=H

def path_from_receipt(value):
 p=pathlib.Path(value)
 if os.name!='nt' and len(value)>3 and value[1:3] in (':/',':\\'):p=pathlib.Path('/mnt')/value[0].lower()/value[3:].replace('\\','/')
 return p

def context(s,root,cap,source):
 profile_sha=R.digest(PROFILE);controller_sha=R.digest(__file__);pins=R.read(PINS);start_ns=s['startMonotonicNs'];end=start_ns+900000000000
 if os.name=='nt':
  start=j._start_identity(os.getpid());w=j.current_witness(s['jobName']);worker={'pid':os.getpid(),'processStartIdentity':start,'jobName':s['jobName'],'memoryMaxBytes':w['memoryMax'],'tasksMax':w['tasksMax'],'cpuRate':w['cpuRate'],'logicalHostCpu':w['logicalHostCpu']};held=s['beforeResume'];before={**worker,'memoryMaxBytes':held['memoryMax'],'tasksMax':held['activeProcessMax'],'cpuRate':held['cpuRate'],'logicalHostCpu':held['logicalHostCpu'],'state':'SUSPENDED','membershipBeforeRelease':held['membership'],'retainedStartHandle':held['retainedCreationHandles']};key='heldBeforeExec';boot={'pythonVersion':platform.python_version(),'pythonExeSha256':R.digest(pathlib.Path(sys.executable).resolve()),'gitSha256':R.digest('C:/Program Files/Git/cmd/git.exe')};fact='LOCAL-WINDOWS04-HOST-FACT.json';fact_sha='841b508658a3a843f7d194b089b355b3e2e572873b4301349f3b545255086339'
 else:
  start='proc-start:'+Q.start_identity(os.getpid());held=R.read(root/'held-worker-before-continue.json');worker={'pid':os.getpid(),'processStartIdentity':start,'uid':os.getuid(),'gid':os.getgid(),'cgroup':cap['cgroup'],'kernelLimits':cap['kernelLimits']};before={**worker,'pid':held['pid'],'processStartIdentity':'proc-start:'+held['start'],'state':'T','membershipBeforeRelease':True,'retainedStartHandle':held['pidfdRetained']};key='beforeExec';boot={'pythonVersion':platform.python_version(),'pythonExeSha256':R.digest(pathlib.Path(sys.executable).resolve()),'gitSha256':R.digest('/usr/bin/git'),'systemctlSha256':R.digest('/usr/bin/systemctl')};fact='LOCAL-LINUX-HOST-FACT.json';fact_sha='ad63c4ad44af1844e1c937152294b07cdce9faccf2e2e7899cc221f2e485fb3c'
 proof={'schema':'sdk11-own-current-cap-evidence/v1','projectId':'04','repository':'pouriajamali/data-admission-gate','sourceCommit':source['commit'],'sourceTree':source['tree'],'profileSha256':profile_sha,'controllerSha256':controller_sha,'bootstrap':boot,'worker':worker,key:before,'supervisor':{'pid':s['supervisorPID'],'processStartIdentity':s['supervisorStartIdentity'],'deadlineMonotonicNs':end},'rowStartedMonotonicNs':start_ns,'deadlineMonotonicNs':end};cp=root/'own-current-caps.json';R.write(cp,proof);ap=root/'local-input-context.json';R.write(ap,{'schema':'sdk11-local-input-current/v1','state':'OWN_CURRENT_INPUT_CONTEXT_BOUND','projectId':'04','repository':'pouriajamali/data-admission-gate','rid':RID,'qualifiedFactPath':str(H/fact),'qualifiedFactSha256':fact_sha,'profileSha256':profile_sha,'controllerSha256':controller_sha,'ownCapsEvidenceSha256':R.digest(cp),'sourcePinTableSha256':hashlib.sha256(R.a.canonical(pins['sourcePins'])).hexdigest()})
 return {'projectId':'04','repository':'pouriajamali/data-admission-gate','checkout':str(ROOT),'controller':str(pathlib.Path(__file__).resolve()),'contract':str(ROOT/'docs/CONTRACT.md'),'profile':str(PROFILE),'sourcePins':str(PINS),'admission':str(ap),'capsEvidence':str(cp),'expectedSourceCommit':source['commit'],'expectedSourceTree':source['tree'],'rowStartedMonotonicNs':start_ns,'deadlineMonotonicNs':end,'supervisorPID':s['supervisorPID'],'supervisorStartIdentity':s['supervisorStartIdentity']}

COORDINATOR_FILES={'systemd-readiness.json','effective-root-starter.json','private-spec.json','root-starter.json','held-worker-before-continue.json','network-policy-applied.json','isolated-policy-result.json','network-transition-child-result.json','launcher-stdout.log','launcher-stderr.log','network-transition-child.stdout','network-transition-child.stderr'}
COORDINATOR_FILES|={n+'.ready' for n in tuple(COORDINATOR_FILES) if n.endswith('.json')}


def reuse_native_prerequisites(root):
 fact=pinned(HAND/'LOCAL-LINUX-HOST-FACT.json','ad63c4ad44af1844e1c937152294b07cdce9faccf2e2e7899cc221f2e485fb3c');current=[];seen={}
 check([x['name'] for x in fact['nativePrerequisites']]==['dotnet','host/fxr/11.0.0/libhostfxr.so','shared/Microsoft.NETCore.App/11.0.0/libcoreclr.so','shared/Microsoft.NETCore.App/11.0.0/libclrjit.so'],'EXACT_QUALIFIED_NATIVE_CLOSURE')
 for row in fact['nativePrerequisites']:
  binary=SDK/row['name'];check(R.a.machine(binary)==('ELF',62),'CURRENT_SDK_ELF_AMD64');prefix='ObservedExistingHostDependenciesNoInventedELFSignature:';check(row['status'].startswith(prefix),'EXACT_QUALIFIED_NATIVE_CLOSURE_FORMAT');deps=json.loads(row['status'][len(prefix):]);out=[]
  for dep in deps:
   check(pathlib.PurePosixPath(dep['import']).name==dep['import'] and pathlib.PurePosixPath(dep['resolvedName']).name==dep['resolvedName'],'FIXED_OS_SONAME_ONLY');target=binary.parent/dep['import']
   if not target.is_file():target=pathlib.Path('/lib/x86_64-linux-gnu')/dep['resolvedName']
   check(target.is_file() and R.digest(target)==dep['sha256'],'CURRENT_NATIVE_DEPENDENCY_BYTES_CHANGED');out.append({'import':dep['import'],'path':str(target),'sha256':dep['sha256']})
  current.append({'name':row['name'],'immutableQualifiedEvidenceSha256':row['evidenceSha256'],'currentPhysicalDependencyHashes':out})
 R.write(root/'current-native-prerequisite-byte-reuse.json',{'state':'QUALIFIED_ELF_CLOSURE_REUSED_CURRENT_PHYSICAL_BYTES_MATCH','qualificationFactSha256':'ad63c4ad44af1844e1c937152294b07cdce9faccf2e2e7899cc221f2e485fb3c','SDKAndSystemDependencies':current,'OSLoaderCLIReplays':0,'scope':'Historical exact DT_NEEDED/qualified dependency closure plus current binary/physical dependency hashes; no invented ELF signature or broader loaded-module claim.'})

def current_window(fixed,proof,now,reserve):
 check(type(fixed) is int and type(now) is int and type(reserve) is int and 0<=reserve<=840 and 0<=now-fixed<=86400,'CURRENT_NATIVE_PKI_TIME_WINDOW')
 rows=proof.get('inputCRLs');check(type(rows) is list and rows and all(type(r.get('thisUpdate')) is int and type(r.get('nextUpdate')) is int and r['thisUpdate']<=now<r['nextUpdate'] and now+reserve<r['nextUpdate'] for r in rows),'CURRENT_EVERY_CHAIN_CRL_WINDOW')
 check(now+reserve<=fixed+86400,'CURRENT_NATIVE_PKI_RESERVE')

def network_transition(path):
 s=R.read(path);root=path.parent;check(os.geteuid()==0 and s['purpose']==PURPOSE and s['controllerSha256']==R.digest(__file__),'FIXED_EXISTING_ROOT_NETWORK_ACTOR');check(root.parent==pathlib.Path('/home/ubuntu') and root.name.startswith('.admission04-product-') and root.stat().st_uid==1000 and root.stat().st_mode&0o777==0o700,'EXACT_PRIVATE_CURRENT_COREHOST_ROOT');request=R.read(root/'network-transition-request.json');check(request['unit']==s['unit'] and request['sourceHEAD']==s['expectedCommit'] and request['leaseAdmissionSHA256']==s['leaseAdmissionSHA256'],'EXACT_CURRENT_NETWORK_REQUEST');policy=NET.scoped_parent_transition(request);R.write(root/'isolated-policy-result.json',policy)

def isolated_transition(s,request):
 root=pathlib.Path(s['root']);deadline=min(s['startTick']+540000,R.clock()+15000);check(R.clock()<deadline,'ORIGINAL_NETWORK_POLICY_CLOCK');argv=[sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--network-transition',str(root/'private-spec.json')];result=subprocess.run(argv,env=Q.OS_ENV,capture_output=True,timeout=max(.1,(deadline-R.clock())/1000));check(len(result.stdout)+len(result.stderr)<=65536,'FINITE_NETWORK_POLICY_CHILD_REPORT');(root/'network-transition-child.stdout').write_bytes(result.stdout);(root/'network-transition-child.stderr').write_bytes(result.stderr);R.write(root/'network-transition-child-result.json',{'returnCode':result.returncode,'stdoutSha256':hashlib.sha256(result.stdout).hexdigest(),'stderrSha256':hashlib.sha256(result.stderr).hexdigest(),'localNetworkMethodSha256':R.digest(NET.__file__),'historicalMethodSha256':R.digest(M.__file__),'SDK':0});check(result.returncode==0,'ISOLATED_NETWORK_POLICY_EXIT_'+str(result.returncode));return R.read(root/'isolated-policy-result.json')

def scratch_owner(relative,uid,is_directory,mode,worker_uid):
 if relative in COORDINATOR_FILES:check(uid==0 and not is_directory and mode&0o133==0,'EXACT_ROOT_COORDINATOR_FILE_OWNER_TYPE_MODE')
 else:check(uid==worker_uid,'PRIVATE_WORKER_SCRATCH_OWNER')


def exact_test_fixture(p,root,st):
 relative=p.relative_to(root).as_posix()
 if relative not in ('tests/symlink-input','tests/fifo-input'):return False
 receipt=root/'tests/receipt.json';need(receipt.is_file(),'ONLY_COMPLETED_TEST_SPECIAL_FIXTURE')
 records=R.read(receipt)['cases'];kind='symlink-refused' if relative.endswith('symlink-input') else 'linux-fifo-refused-before-open'
 need(any(r['name']==kind and r['outcome']=='pass' for r in records),'ACTUAL_FIXTURE_REFUSAL_CASE_PASS')
 if kind=='symlink-refused':need(stat.S_ISLNK(st.st_mode) and os.readlink(p)==str(root/'tests/symlink-target') and (root/'tests/symlink-target').is_file(),'EXACT_OWN_REFUSED_SYMLINK_FIXTURE')
 else:need(os.name!='nt' and stat.S_ISFIFO(st.st_mode),'EXACT_OWN_REFUSED_FIFO_FIXTURE')
 if os.name!='nt':need(st.st_uid==os.getuid(),'EXACT_OWN_SPECIAL_FIXTURE_OWNER')
 return True

def private_scratch_bytes(root,limit,s):
 import stat
 original=R.read(root/'private-spec.json');check(all(original[k]==s[k] for k in ('purpose','root','unit','expectedCommit','controllerSha256','supervisorPID','supervisorStartIdentity','leaseAdmissionSHA256')),'CURRENT_COORDINATOR_CONTROL_IDENTITY');total=0;seen=set()
 for base,dirs,files in os.walk(root,followlinks=False):
  for name in ['.',*dirs,*files]:
   p=pathlib.Path(base)/name
   try:st=p.lstat()
   except FileNotFoundError:continue
   fixture=exact_test_fixture(p,root,st) if stat.S_ISLNK(st.st_mode) or stat.S_ISFIFO(st.st_mode) else False;check(fixture or not stat.S_ISLNK(st.st_mode),'PRIVATE_SCRATCH_LINK');check(not stat.S_ISSOCK(st.st_mode),'PRIVATE_SCRATCH_SOCKET');check(fixture or not stat.S_ISFIFO(st.st_mode),'PRIVATE_SCRATCH_FIFO');check(fixture or stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode),'PRIVATE_SCRATCH_SPECIAL_TYPE');relative=p.relative_to(root).as_posix();scratch_owner(relative,st.st_uid,stat.S_ISDIR(st.st_mode),stat.S_IMODE(st.st_mode),os.getuid())
   if (st.st_dev,st.st_ino) in seen:continue
   seen.add((st.st_dev,st.st_ino));total+=st.st_blocks*512;check(total<=limit,'ACTUAL_PRIVATE_SCRATCH_CAP')
 return total

def wait_systemd_ready(s,argv):
 root=pathlib.Path(s['root']);deadline=min(s['startTick']+60000,R.clock()+20000);check(R.clock()<deadline,'ORIGINAL_STARTUP_REMAINING');args=['/usr/bin/systemctl','is-system-running','--wait'];started=R.clock()
 try:
  result=subprocess.run(args,capture_output=True,env=Q.OS_ENV,timeout=max(.01,(deadline-R.clock())/1000));check(len(result.stdout)+len(result.stderr)<=16384,'SYSTEMD_READINESS_REPORT_BOUND');state=result.stdout.decode('ascii',errors='strict').strip();R.write(root/'systemd-readiness.json',{'argv':args,'exitCode':result.returncode,'state':state,'stdoutSHA256':hashlib.sha256(result.stdout).hexdigest(),'stderrSHA256':hashlib.sha256(result.stderr).hexdigest(),'elapsedMs':R.clock()-started,'deadlineTick':deadline,'originalStartTick':s['startTick'],'scope':'Read-only bus readiness, not host/SDK admission; no service/config changes.'});check(R.clock()<deadline and result.returncode in (0,1) and state in ('running','degraded') and not result.stderr,'SYSTEMD_NOT_READY_WITHIN_ORIGINAL_STARTUP')
 except subprocess.TimeoutExpired:
  R.write(root/'systemd-readiness.json',{'state':'TIMEOUT','originalStartTick':s['startTick'],'deadlineTick':deadline,'scope':'No unit or SDK start in readiness timeout.'});raise
 remaining=(s['startTick']+840000-R.clock())//1000;check(remaining>0,'ORIGINAL_WORK840');effective=[('--property=RuntimeMaxSec='+str(remaining)) if str(x).startswith('--property=RuntimeMaxSec=') else x for x in argv];R.write(root/'effective-root-starter.json',{'argv':effective,'originalStartTick':s['startTick'],'kernelAbsoluteWorkerEndTick':s['startTick']+840000,'readinessDeadlineTick':deadline});return effective

def run_parent(s,argv):
 root=pathlib.Path(s['root']);proc=pidfd=None;error=None;transitioned=False;held=None
 try:
  argv=wait_systemd_ready(s,argv)
  prior,_=Q.own_unit_show(s['unit'],min(s['startTick']+60000,R.clock()+2000));check(prior.get('LoadState')=='not-found','OWN_UNIT_ABSENT')
  with (root/'launcher-stdout.log').open('xb') as out,(root/'launcher-stderr.log').open('xb') as err:
   proc=subprocess.Popen(argv,stdout=out,stderr=err,env=Q.OS_ENV);deadline=min(s['startTick']+60000,R.clock()+20000)
   while not (root/'stopped-worker.json.ready').is_file():check(proc.poll() is None and R.clock()<deadline,'HELD_WORKER_STARTUP');time.sleep(.05)
   held=R.read(root/'stopped-worker.json');pid=held['pid'];pidfd=os.pidfd_open(pid);snap=M.pid_snapshot(pid,s['unit'])
   while snap['state'] not in ('T','t'):check(proc.poll() is None and R.clock()<deadline,'WORKER_MUST_STOP');time.sleep(.01);snap=M.pid_snapshot(pid,s['unit'])
   check(held['uid']==held['gid']==1000 and snap['start']==held['start'] and snap['limits']==held['cap']['kernelLimits'],'HELD_MAINPID_START_LIMITS');R.write(root/'held-worker-before-continue.json',{'pid':pid,'start':held['start'],'kernelLimits':snap['limits'],'pidfdRetained':True,'state':snap['state'],'cgroup':snap['cgroup']});signal.pidfd_send_signal(pidfd,signal.SIGCONT)
   while proc.poll() is None:
    check(R.clock()<s['startTick']+840000 and out.tell()+err.tell()<=1048576,'ORIGINAL_WORK840_LOG1M');rp=root/'network-transition-request.json'
    if not transitioned and rp.with_name(rp.name+'.ready').is_file():
     request=R.read(rp,16384);check(request['worker']['pid']==pid and request['worker']['start']==held['start'] and request['unit']==s['unit'] and request['sourceHEAD']==s['expectedCommit'] and request['originalStartMonotonicNs']==s['startTick']*1000000 and rp.stat().st_uid==1000 and root.stat().st_uid==1000 and root.stat().st_mode&0o777==0o700,'EXACT_PRIVATE_NETWORK_REQUEST')
     check(request['requestSHA256']==hashlib.sha256(json.dumps({k:v for k,v in request.items() if k!='requestSHA256'},sort_keys=True,separators=(',',':')).encode()).hexdigest(),'CANONICAL_NETWORK_REQUEST')
     while M.pid_snapshot(pid,s['unit'])['state'] not in ('T','t'):check(R.clock()<s['startTick']+540000,'ORIGINAL_NETWORK540');time.sleep(.001)
     policy=isolated_transition(s,request);R.write(root/'network-policy-applied.json',policy);transitioned=True;signal.pidfd_send_signal(pidfd,signal.SIGCONT)
    time.sleep(.02)
   check(proc.returncode==0 and transitioned,'NATIVE_WORKER_AND_TRANSITION_SUCCESS')
 except BaseException as exc:error=exc
 terminal,stop=Q.cleanup_owned_linux(s,proc,pidfd,error is not None)
 if error is not None or terminal['cleanupResult']!='OWNED_TERMINAL_OBSERVED' or stop is None or stop.get('serviceResult')!='success' or stop.get('exitCode')!='exited' or stop.get('exitStatus')!='0' or stop.get('remainingPopulationExcludingObserver')!=0:
  R.write(root/'NATIVE-HOLD.json',{'state':'HOLD','errorType':type(error).__name__ if error else None,'code':str(error)[:180] if error else 'NATIVE_TERMINAL_UNKNOWN','terminal':terminal})
  if error:raise error
  raise R.f.Denied('NATIVE_TERMINAL_UNKNOWN')
 return terminal,stop

def product_storage(root,s):
 total=private_scratch_bytes(root,2147483648,s) if os.name!='nt' else 0
 bases=[ROOT/'artifacts',ROOT/'src/Admission/bin',ROOT/'src/Admission/obj',ROOT/'tests/Admission.Tests/bin',ROOT/'tests/Admission.Tests/obj']
 if os.name=='nt':bases.insert(0,root)
 seen=set()
 for base in bases:
  if not base.exists():continue
  for current,dirs,files in os.walk(base,followlinks=False):
   for name in ['.',*dirs,*files]:
    q=pathlib.Path(current)/name
    try:st=q.lstat()
    except FileNotFoundError:continue
    fixture=exact_test_fixture(q,root,st) if os.name=='nt' and base==root and stat.S_ISLNK(st.st_mode) else False;need(fixture or (not stat.S_ISLNK(st.st_mode) and not (getattr(st,'st_file_attributes',0)&0x400)),'PRODUCT_STORAGE_REPARSE_OR_LINK')
    need(fixture or stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode),'PRODUCT_STORAGE_SPECIAL')
    if os.name!='nt':need(st.st_uid==os.getuid(),'PRODUCT_OUTPUT_OWNER')
    identity=(st.st_dev,st.st_ino)
    if identity in seen:continue
    seen.add(identity);total+=st.st_blocks*512 if os.name!='nt' else ((st.st_size+4095)//4096)*4096
    need(total<=2147483648,'ORIGINAL_PRODUCT_PRIVATE2GIB')
 return total

def retained_current_inputs(root):
 profile=R.read(PROFILE);path=H/'WINDOWS-NATIVE-CONSUMER-HANDOFF.json';need(R.digest(path)==profile['nativeHandoffSHA256'],'PINNED_NATIVE_HANDOFF')
 desc=R.read(path);need(desc['state']=='FOUR_WINDOWS_NATIVE_INPUTS_ACCEPTED_AS_DATA_NOT_RUNTIME','ACTUAL_NATIVE_FOUR_INPUTS')
 fp=path_from_receipt(desc['currentPKI']['path']);need(R.digest(fp)==desc['currentPKI']['sha256'],'CURRENT_PKI_PROOF_IDENTITY');pki=R.read(fp);now=int(time.time());current_window(pki['nativeVerifiedAtUnix'],pki['currentCRL'],now,840)
 need(0<=time.time()-desc['advisory']['observedAtUnix'] and time.time()+840<=desc['snapshotExpiresAtUnix'],'CURRENT_SNAPSHOT_COVERS_PRODUCT840')
 md=BASE/'windows-native-fresh-once-20261118-05/curation/metadata';meta=BASE/'native04-current-metadata-data-once-20261118/CURRENT-NATIVE-METADATA-DATA.json';need(R.digest(meta)==desc['metadataData']['sha256'],'CURRENT_METADATA_RECEIPT_IDENTITY');data=R.read(meta)
 objects={};bodies={}
 for row in data['responses']:
  rp=path_from_receipt(row['rawBody']['path']);b=rp.read_bytes();need(len(b)==row['rawBody']['bytes'] and hashlib.sha256(b).hexdigest()==row['rawBody']['sha256'],'CURRENT_ORIGINAL_METADATA_BYTES');bodies[row['url']]=b
  if row['mutable']:need(0<=time.time()-row['observedAtUnix']<=86400,'EVERY_MUTABLE_RESPONSE_CURRENT')
  if 'decodedBody' in row:
   dp=path_from_receipt(row['decodedBody']['path']);decoded=dp.read_bytes();need(R.digest(dp)==row['decodedBody']['sha256'] and A.decode_json(b,row['encoding'],4194304)==decoded,'CURRENT_DECODED_METADATA_BYTES');objects[row['url']]=A.strict_json(decoded)
 service=objects['https://api.nuget.org/v3/index.json'];iu=A.select_advisory_index(service['resources']);index=objects[iu];urls=A.advisory_index_urls(index,iu);pages={u:objects[u] for u in urls};contract=R.read(HERE/'producer04-linux-curation.contract.json');responses={u:bodies[u] for u in contract['finiteMetadataAcquisition']['PKIExactObservedGETs']}
 rows=desc['windowsPackages'] if os.name=='nt' else desc['linuxPackagesWithCurrentCertificateReuse']
 packages=[{'id':p['id'],'version':p['version'],**p['rawSignedArchive'],'normalizedNuGetContentHash':p['normalizedNuGetContentHash']} for p in rows]
 if os.name=='nt':locks=[path_from_receipt(x['path']) for x in desc['runtimeLocks']]
 else:
  old=R.read(BASE/'linux-input-facts-44082565011/INPUT-FACTS.json');locks=[path_from_receipt(old['durableByteLocations']['curation/locks/'+name+'.linux-x64.lock.json']['path']) for name in ['Admission','Admission.Tests']]
 expected=[x['sha256'] for x in desc['runtimeLocks']] if os.name=='nt' else [old['durableByteLocations']['curation/locks/'+name+'.linux-x64.lock.json']['sha256'] for name in ['Admission','Admission.Tests']]
 need(all(R.digest(q)==h for q,h in zip(locks,expected)),'ACTUAL_SDK_GENERATED_RUNTIME_LOCKS')
 audit=A.advisory_guard({'advisoryServiceResources':service['resources'],'advisoryIndexURI':iu,'advisoryIndex':index,'advisoryPageURLs':urls,'advisoryPages':pages},[{'id':p['id'],'version':p['version']} for p in packages],{'bodyBytes':0});audit.update(observedAtUnix=desc['advisory']['observedAtUnix'],maxAgeSeconds=86400)
 R.write(root/'current-input-data-reuse.json',{'nativeHandoffSHA256':R.digest(path),'PKIReceiptSHA256':R.digest(fp),'nativeVerifiedAtUnixPreserved':pki['nativeVerifiedAtUnix'],'currentWindowCheckedAtUnix':now,'advisory':audit,'newGETs':0,'newNativeCrypto':0,'newQualificationTargets':0})
 return packages,locks,desc,responses,index,pages,audit

def worker(path):
 s=R.read(path);root=path.parent;need(s['purpose']==PURPOSE and s['controllerSha256']==R.digest(__file__),'EXACT_PRODUCT_ROLE_AND_SOURCE');backend=Q.Backend(s)
 if os.name!='nt':
  j.bind(s);cap=j.linux_caps();R.write(root/'stopped-worker.json',{'pid':os.getpid(),'start':Q.start_identity(os.getpid()),'cap':cap,'uid':os.getuid(),'gid':os.getgid()});os.kill(os.getpid(),signal.SIGSTOP);held=R.read(root/'held-worker-before-continue.json');need(held['pid']==os.getpid() and held['start']==Q.start_identity(os.getpid()),'ACTUAL_PRODUCT_HELD_WORKER');s['parentHeldWorkerBeforeExec']=True
 else:cap=backend.caps()
 budget=R.Budget(s);env=R.job_environment(root);env.update(UseSharedCompilation='false',BuildInParallel='false',RestoreLockedMode='true',DOTNET_CLI_UI_LANGUAGE='en-US',DOTNET_NOLOGO='1',DOTNET_EnableDiagnostics='0')
 if os.name=='nt':
  for key,name in [('PROGRAMFILES(X86)','program-files-x86'),('PROGRAMFILES','program-files'),('PROGRAMDATA','program-data'),('APPDATA','app-data'),('LOCALAPPDATA','local-app-data')]:target=root/name;target.mkdir();env[key]=str(target)
  git=['C:/Program Files/Git/cmd/git.exe','-C',str(ROOT)]
 else:
  home=root/'home';home.mkdir(mode=0o700);env['HOME']=str(home);env.update(GIT_OPTIONAL_LOCKS='0',GIT_DIR='/mnt/e/Codex WorkSpace/Git Projects/data-admission-gate/repo/.git/worktrees/repo3',GIT_WORK_TREE=str(ROOT));git=['/usr/bin/git','-c','safe.directory='+str(ROOT),'-C',str(ROOT)]
 local=load('local_sdk11_input',s['localInputSha256'])
 if os.name=='nt':raw=local._windows_source_git(['rev-parse','HEAD','HEAD^{tree}'],ROOT,(s['startTick']+60000)*1000000)
 else:
  rec,raw=R.output(backend.run,[*git,'rev-parse','HEAD','HEAD^{tree}'],ROOT,env,budget.deadline(10),root/'source-git')
 v=raw.decode().splitlines();need(len(v)==2 and v[0]==s['expectedCommit'],'EXACT_PRODUCT_SOURCE');source={'commit':v[0],'tree':v[1]};ctx=context(s,root,cap,source);before=local.inspect_sdk(RID,SDK,ctx);R.write(root/'local-sdk-input-before.json',before)
 if os.name!='nt':reuse_native_prerequisites(root)
 else:
  for name in ['dotnet.exe','host/fxr/11.0.0/hostfxr.dll','shared/Microsoft.NETCore.App/11.0.0/coreclr.dll','shared/Microsoft.NETCore.App/11.0.0/clrjit.dll']:
   image=SDK/name;need(R.a.machine(image)==('PE',0x8664),'CURRENT_WINDOWS_PE_AMD64')
   for lib in R.a.pe_imports(image):
    if lib.lower().startswith(('api-ms-','ext-ms-')):continue
    need((image.parent/lib).is_file() or (pathlib.Path(os.environ['SystemRoot'])/'System32'/lib).is_file(),'CURRENT_WINDOWS_IMPORT_EXISTS')
  R.write(root/'current-native-prerequisite-byte-reuse.json',{'state':'QUALIFIED_SIGNED_WINDOWS_BYTES_REUSED_CURRENT_IMPORTS_PRESENT','factSHA256':'841b508658a3a843f7d194b089b355b3e2e572873b4301349f3b545255086339','qualificationReplays':0})
 need(R.clock()<budget.current,'ORIGINAL_STARTUP60');budget.stage(1,180)
 packages,runtime_locks,native_input_reference,responses,index,pages,audit=retained_current_inputs(root)
 phase=root/'curation';phase.mkdir();(phase/'raw').mkdir();(phase/'packages').mkdir();raws=[]
 for p in packages:
  src=path_from_receipt(p['path']);need(src.stat().st_size==p['bytes'] and R.digest(src)==p['sha256'] and R.digest(src,'sha512')==p['sha512'],'CURRENT_REQUIRED_NATIVE_RAW_BYTES');dest=phase/'raw'/(p['id'].lower()+'.'+p['version']+'.nupkg');shutil.copyfile(src,dest);raws.append({**p,'privateRaw':str(dest)})
 # Seed only exact SDK-generated runtime lock artifacts, never edit them for pass.
 lockdir=ROOT/'artifacts/runtime-locks'/RID;lockdir.mkdir(parents=True,exist_ok=True)
 for src,name in zip(runtime_locks,['Admission','Admission.Tests']):
  b=src.read_bytes();dest=lockdir/(name+'.lock.json')
  if dest.exists():need(dest.read_bytes()==b,'EXISTING_RUNTIME_LOCK_CHANGED')
  else:dest.write_bytes(b)
 server=thread=dispatcher=None
 try:
  server,thread,dispatcher,port=L._start_adapter(responses,index,pages)
  if os.name!='nt':config=L.config_bytes(str(phase),port)
  else:
   import xml.etree.ElementTree as ET
   e=ET.Element('configuration');c=ET.SubElement(e,'config');ET.SubElement(c,'add',{'key':'signatureValidationMode','value':'require'});ET.SubElement(c,'add',{'key':'globalPackagesFolder','value':str(phase/'packages')});p=ET.SubElement(e,'packageSources');ET.SubElement(p,'clear');ET.SubElement(p,'add',{'key':'own-raw-only','value':str(phase/'raw')});ET.SubElement(ET.SubElement(e,'fallbackPackageFolders'),'clear');a=ET.SubElement(e,'auditSources');ET.SubElement(a,'clear');ET.SubElement(a,'add',{'key':'own-static-audit','value':'http://127.0.0.1:'+str(port)+'/v3/index.json','allowInsecureConnections':'true'});t=ET.SubElement(e,'trustedSigners');ET.SubElement(t,'clear');repo=ET.SubElement(t,'repository',{'name':'nuget.org','serviceIndex':'https://api.nuget.org/v3/index.json'});ET.SubElement(repo,'certificate',{'fingerprint':M.REPOSITORY.upper(),'hashAlgorithm':'SHA256','allowUntrustedRoot':'false'});config=ET.tostring(e,encoding='utf-8',xml_declaration=True)
  cfg=phase/'NuGet.Config';cfg.write_bytes(config);env.update(DOTNET_ROOT=str(SDK),DOTNET_ROOT_X64=str(SDK),DOTNET_HOST_PATH=str(SDK/('dotnet.exe' if os.name=='nt' else 'dotnet')),PATH=str(SDK)+os.pathsep+env['PATH'],NUGET_PACKAGES=str(phase/'packages'),NUGET_HTTP_CACHE_PATH=str(root/'http'),NUGET_FALLBACK_PACKAGES='',DOTNET_NUGET_SIGNATURE_VERIFICATION='true',NUGET_CERT_REVOCATION_MODE='online',HTTP_PROXY='http://127.0.0.1:'+str(port),HTTPS_PROXY='http://127.0.0.1:'+str(port),NO_PROXY='127.0.0.1,localhost',RestoreConfigFile=str(cfg),NuGetAudit='true',NuGetAuditMode='all',NuGetAuditLevel='low')
  if os.name!='nt':
   M.close_external_sockets();snap=M.pid_snapshot(os.getpid(),s['unit']);request={'purpose':'PRODUCER04_LINUX_INPUT_CURATION','unit':s['unit'],'worker':snap,'uid':os.getuid(),'originalStartMonotonicNs':s['startTick']*1000000,'sourceHEAD':s['expectedCommit'],'leaseAdmissionSHA256':s['leaseAdmissionSHA256']};request['requestSHA256']=hashlib.sha256(json.dumps(request,sort_keys=True,separators=(',',':')).encode()).hexdigest();R.write(root/'network-transition-request.json',request);os.kill(os.getpid(),signal.SIGSTOP);policy=R.read(root/'network-policy-applied.json');network=M.network_witness(port,('150.171.110.119',443),snap,s['unit'],policy)
  else:network={'boundary':'Dedicated Job, exact cleared local package sources/static explicit proxy. No kernel egress-denial claim for Windows.'}
  budget.stage(3,min(660,max(1,(budget.outer-R.clock())//1000)));records=[];catalog=R.read(HERE/('dotnet11-qualification-inputs.lock.json' if os.name=='nt' else 'dotnet11-linux-qualification-inputs.lock.json'))
  def stage(name,argv,seconds):
   R.a.verify_tree(SDK,catalog['members'],RID)
   with R.contextlib.ExitStack() as stack:
    if os.name=='nt':
     for member in catalog['criticalMembers']:
      held=stack.enter_context(backend.hold(SDK/member['path']));need(held['sha256']==member['sha256'],'SDK_HELD_BEFORE_PRODUCT_TARGET')
    rec,out=R.output(backend.run,argv,ROOT,env,budget.deadline(seconds),root/('product-'+name))
   records.append({'stage':name,'exitCode':0,'seconds':rec['seconds'],'processSha256':R.digest(root/('product-'+name+'/process.json'))});product_storage(root,s);return out
  dotnet=env['DOTNET_HOST_PATH'];stage('restore',[dotnet,'restore','tests/Admission.Tests','--locked-mode','--configfile',str(cfg),'-p:NuGetAudit=true','-p:NuGetAuditMode=all','-p:NuGetAuditLevel=low'],120);out=stage('original-tests',[dotnet,'run','--project','tests/Admission.Tests','-c','Release','--no-restore','--no-launch-profile','--','--work',str(root/'tests')],180);unit_results=R.read(root/'tests/receipt.json');need(unit_results['failed']==0 and unit_results['passed']==(108 if os.name=='nt' else 109) and unit_results['skipped']==(1 if os.name=='nt' else 0),'EXPECTED_ORIGINAL_UNIT_RESULTS');stage('package',[sys.executable,'tools/package.py','--rid',RID,'--commit',source['commit'],'--work',str(root/'package-build'),'--out',str(root/'delivery'),'--dotnet',dotnet],300)
  archives=[p for p in (root/'delivery').iterdir() if p.is_file()];need(len(archives)==1,'ONE_EXACT_PRODUCT_ARCHIVE');extract=root/'extracted with spaces';extract.mkdir()
  stage('extract',['C:/Windows/System32/tar.exe' if os.name=='nt' else '/usr/bin/tar','-xf',str(archives[0]),'-C',str(extract)],30);dirs=[p for p in extract.iterdir() if p.is_dir()];need(len(dirs)==1,'ONE_EXACT_EXTRACTED_PRODUCT');package=dirs[0];stage('package-checks',[sys.executable,'tools/check_package.py','--package',str(package),'--work',str(root/'package checks with spaces'),'--commit',source['commit']],180);stage('literal-compatibility',[sys.executable,'tools/check_tech_refresh.py','--package',str(package),'--work',str(root/'literal checks with spaces'),'--commit',source['commit']],120)
  need(not dispatcher.poisoned,'NO_UNAPPROVED_STATIC_ROUTE');retained_current_inputs_after=retained_window_check(native_input_reference);after=local.inspect_sdk(RID,SDK,ctx);R.write(root/'local-sdk-input-after.json',after);R.write(root/'PRODUCT04-WORKER-FACT.json',{'schema':'product04-current-local-acceptance/v1','state':'ORIGINAL_PRODUCT04_LOCAL_ACCEPTANCE_OBSERVED','rid':RID,'source':source,'currentSDKInput':before,'packageInputHistory':native_input_reference,'applicableAdvisory':audit,'networkBoundary':network,'unitResults':unit_results,'stages':records,'controlledTopLevelSDKVectors':2,'packageScriptSDKPublishVectors':1,'qualificationSDKReplays':0,'strictScratchMaxBytes':2147483648,'archive':{'path':str(archives[0]),'bytes':archives[0].stat().st_size,'sha256':R.digest(archives[0])},'packageChecks':R.read(root/'package checks with spaces/receipt.json') if (root/'package checks with spaces/receipt.json').is_file() else {'boundary':'Recorded exact package checker stdout/process; see proof files'},'literalChecks':R.read(root/'literal checks with spaces/receipt.json'),'formalWindowsSupport':'NOT_CONFIRMED' if os.name=='nt' else None,'Actions':0,'published':False})
 finally:
  if server:server.shutdown();server.server_close()
  if thread:thread.join(timeout=2);need(not thread.is_alive(),'STATIC_ADAPTER_TERMINAL')
 if os.name!='nt':signal.setitimer(signal.ITIMER_REAL,0)

def retained_window_check(desc):
 need(0<=time.time()-desc['advisory']['observedAtUnix']<86400 and time.time()<desc['nativeVerifiedAtUnixPreserved']+86400,'CURRENT_INPUT_WINDOWS_AT_PRODUCT_END');return True

def finish(s,root,terminal,peak):
 value=R.read(root/'PRODUCT04-WORKER-FACT.json');need(R.clock()<s['startTick']+900000,'WHOLE_PRODUCT900');value['terminal']=terminal;value['peakMemoryBytes']=peak;R.write(root/'PRODUCT04-FACT.json',value);return value

def linux_parent(expected):
 need(os.geteuid()==0 and pathlib.Path('/run/systemd/private').exists(),'EXISTING_FIXED_ROOT_OS_STARTER');start=R.clock();root=pathlib.Path('/home/ubuntu')/('.admission04-product-'+uuid.uuid4().hex);root.mkdir(mode=0o700);os.chown(root,1000,1000);unit='admission04-sdk11-ci-'+uuid.uuid4().hex;current=pathlib.Path('/mnt/e/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave2-state/LOCAL-FIXTURE-LEASE.json');leasevalue=R.read(current);lease=path_from_receipt(leasevalue['receiptDirectory'])/'LEASE.json';need(current.read_bytes()==lease.read_bytes() and leasevalue['projectId']=='04' and leasevalue['phase']=='ORIGINAL_PRODUCT04_LOCAL_LINUX_ACCEPTANCE','CURRENT_OWN_PRODUCT_LEASE');s={'purpose':PURPOSE,'rid':RID,'root':str(root),'unit':unit,'uid':1000,'gid':1000,'expectedCommit':expected,'startTick':start,'startMonotonicNs':start*1000000,'controllerSha256':R.digest(__file__),'localInputSha256':R.digest(HERE/'local_sdk11_input.py'),'supervisorPID':os.getpid(),'supervisorStartIdentity':'proc-start:'+Q.start_identity(os.getpid()),'leaseAdmissionSHA256':R.digest(lease)};private=root/'private-spec.json';R.write(private,s);print(json.dumps({'state':'STARTED_PRODUCT04_LOCAL','rid':RID,'root':str(root)}),flush=True);observer=' '.join(shlex.quote(str(x)) for x in [sys.executable,'-I','-S','-B',pathlib.Path(__file__).resolve(),'--stop-post',private]);remaining=max(1,(start+840000-R.clock())//1000);argv=['/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid=1000','--gid=1000','--property=Description='+unit,'--property=MemoryMax=4294967296','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec='+str(remaining),'--property=TimeoutStopSec=5','--property=KillMode=control-group','--property=WorkingDirectory='+str(ROOT),'--property=ExecStopPost='+observer,'--setenv=PYTHONDONTWRITEBYTECODE=1',sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--worker',str(private)]
 try:
  terminal,stop=run_parent(s,argv);value=finish(s,root,terminal,stop['actualCaps']['memoryPeak']);export(root,'PRODUCT04_LOCAL_ACCEPTANCE_COMPLETE')
 except BaseException as exc:R.write(root/'PRODUCT-HOLD.json',{'state':'HOLD','errorType':type(exc).__name__,'code':str(exc)[:180]});export(root,'HOLD');raise

def windows_parent(expected):
 root=BASE/'product04-win-x64-once-20261118-01';need(not root.exists(),'FRESH_PRODUCT04_WINDOWS_ROW');need(R.digest(LEASE.with_name('LEASE-PROTOCOL.json'))=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_LEASE_PROTOCOL');boot=R.read(BASE/'local-windows04-qualification-once-20261117/bootstrap.json');need(boot['PSFSignaturesValidWithTimestamps'] is True and R.digest(sys.executable)==boot['pythonExeSha256'] and R.digest(pathlib.Path(sys.executable).parent/'python312.dll')==boot['pythonDllSha256'],'EXACT_ALREADY_PSF_VERIFIED_BOOTSTRAP');lease={'projectId':'04','randomToken':secrets.token_hex(16),'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':j._start_identity(os.getpid()),'phase':'ORIGINAL_PRODUCT04_EXPERIMENTAL_WINDOWS_ACCEPTANCE','startedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'receiptDirectory':str(root)}
 try:
  with LEASE.open('x',encoding='utf-8') as out:json.dump(lease,out);out.flush();os.fsync(out.fileno())
 except FileExistsError:print(json.dumps({'state':'LEASE_BUSY_NOT_STARTED'}));return
 root.mkdir();start=R.clock();s={'purpose':PURPOSE,'rid':RID,'root':str(root),'expectedCommit':expected,'startTick':start,'startMonotonicNs':time.monotonic_ns(),'controllerSha256':R.digest(__file__),'localInputSha256':R.digest(HERE/'local_sdk11_input.py'),'supervisorPID':os.getpid(),'supervisorStartIdentity':j._start_identity(os.getpid())};private=root/'private-spec.json';R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000});env={k:os.environ[k] for k in ('SystemRoot','WINDIR','COMSPEC','PATHEXT','USERPROFILE') if k in os.environ};env.update(PATH='C:/Windows/System32;C:/Windows',PYTHONDONTWRITEBYTECODE='1');record=error=None
 try:record=JLOCAL.run_job([sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--worker',str(private)],ROOT,env,start+840000,root/'outer-job',job_name='Local\\admission04-product-'+secrets.token_hex(12),ready_spec={'path':private,'value':s},stage_directory=root,local_console_mode='DETACHED_LOCAL_CONSOLE_FREE_V1')
 except BaseException as exc:error={'type':type(exc).__name__,'code':str(exc)[:180]}
 if record is None and (root/'outer-job/process.json').is_file():record=R.read(root/'outer-job/process.json')
 good=record and record['exitCode']==0 and not record['timedOut'] and record['actualCap']['activeProcessesAtTeardown']==0 and (root/'PRODUCT04-WORKER-FACT.json').is_file() and error is None;R.write(root/'FINAL-RECEIPT.json',{'state':'PRODUCT04_LOCAL_ACCEPTANCE_COMPLETE' if good else 'HOLD','record':record,'error':error,'elapsedSeconds':(R.clock()-start)/1000,'Actions':0,'published':False})
 if good:finish(s,root,{'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'processReceiptSha256':R.digest(root/'outer-job/process.json')},record['actualCap']['peakJobMemory'])
 if record and record['actualCap']['activeProcessesAtTeardown']==0:
  need(R.read(LEASE)==lease,'EXACT_OWN_PRODUCT_LEASE_RELEASE');LEASE.unlink();R.write(root/'LEASE-RELEASED.json',{'state':'RELEASED_AFTER_ACTUAL_TERMINAL','terminalSha256':R.digest(root/'outer-job/process.json'),'tokenSha256':hashlib.sha256(lease['randomToken'].encode()).hexdigest()})
 print(json.dumps({'state':'PRODUCT04_LOCAL_ACCEPTANCE_COMPLETE' if good else 'HOLD','rid':RID,'root':str(root),'error':error}),flush=True)
 if not good:raise SystemExit(1)


def export(root,state):
 files=[];total=0
 allowed={'receipt.json','manifest.json'}
 for q in sorted(root.rglob('*')):
  if not q.is_file() or q.is_symlink():continue
  rel=q.relative_to(root).as_posix();parts=pathlib.PurePosixPath(rel).parts
  if len(parts)>6 or any(t in parts for t in ['packages','raw','extracted with spaces','package-build','delivery','cli-home','http','home','tmp','tests']) and rel!='tests/receipt.json':continue
  if q.suffix not in ('.json','.log','.wire','.pem') and q.name not in ('stdout','stderr'):continue
  size=q.stat().st_size
  if size>1048576:continue
  total+=size;need(total<=8388608,'PRODUCT_PROOF8M');raw=q.read_bytes();files.append({'name':rel,'bytes':size,'sha256':hashlib.sha256(raw).hexdigest(),'base64':base64.b64encode(raw).decode()})
 print(json.dumps({'state':state,'root':str(root),'files':files},separators=(',',':')),flush=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('--expected-commit');p.add_argument('--worker',type=pathlib.Path);p.add_argument('--stop-post',type=pathlib.Path);p.add_argument('--network-transition',type=pathlib.Path);args=p.parse_args()
 if args.network_transition:network_transition(args.network_transition);return
 if args.stop_post:Q.stop_post(args.stop_post);return
 if args.worker:worker(args.worker);return
 need(args.expected_commit is not None,'EXACT_EXPECTED_PRODUCT_SOURCE')
 if os.name=='nt':windows_parent(args.expected_commit)
 else:linux_parent(args.expected_commit)
if __name__=='__main__':main()
