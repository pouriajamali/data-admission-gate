"""One SDK-zero validation of the existing read-only Windows input facade.
Reuses qualified byte/publisher/bootstrap histories; no SDK, package, GET or policy edit.
"""
from __future__ import annotations
import ctypes,argparse,datetime,hashlib,importlib.util,json,os,pathlib,platform,secrets,subprocess,sys,time
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent
def load(name,sha):
 p=HERE/(name+'.py')
 if hashlib.sha256(p.read_bytes()).hexdigest()!=sha:raise RuntimeError('FIXED_PRODUCT_HELPER:'+name)
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);return m
Q=load('qualify_dotnet11_windows','a8f5a9947a7bad112a2162cd59e3e464f7f599276940f4a0f36d0feb5ae60b82');R=Q.R;j=Q.j
SDK=pathlib.Path('E:/Codex WorkSpace/Git Projects/data-admission-gate/state/dotnet11-shared-20261114/trees/win-x64')
H=pathlib.Path('E:/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave4-state/project04-shared-normal-final-20261117')
BASE=pathlib.Path('C:/Users/Office/.codex/visualizations/2026/11/10/01a1c661-2773-7f81-9ae7-c5756abd8095/metadata-framing')
RID='win-x64';PROFILE=HERE/'producer04-local-job-diagnostic.profile.json';PINS=HERE/'producer04-local-source-pins.json';PURPOSE='SDK_ZERO_EXACT_JOB_IDS_AND_GIT_HANDLE_BOUNDARY';LEASE=H.parents[1]/'wave2-state/LOCAL-FIXTURE-LEASE.json'
def need(v,why):R.f.need(v,why)
def context(s,root,cap,source):
 profile_sha=R.digest(PROFILE);controller_sha=R.digest(__file__);pins=R.read(PINS);start_ns=s['startMonotonicNs'];end=start_ns+900000000000
 if os.name=='nt':
  start=j._start_identity(os.getpid());w=j.current_witness(s['jobName']);worker={'pid':os.getpid(),'processStartIdentity':start,'jobName':s['jobName'],'memoryMaxBytes':w['memoryMax'],'tasksMax':w['tasksMax'],'cpuRate':w['cpuRate'],'logicalHostCpu':w['logicalHostCpu']};held=s['beforeResume'];before={**worker,'memoryMaxBytes':held['memoryMax'],'tasksMax':held['activeProcessMax'],'cpuRate':held['cpuRate'],'logicalHostCpu':held['logicalHostCpu'],'state':'SUSPENDED','membershipBeforeRelease':held['membership'],'retainedStartHandle':held['retainedCreationHandles']};key='heldBeforeExec';boot={'pythonVersion':platform.python_version(),'pythonExeSha256':R.digest(pathlib.Path(sys.executable).resolve()),'gitSha256':R.digest('C:/Program Files/Git/cmd/git.exe')};fact='LOCAL-WINDOWS04-HOST-FACT.json';fact_sha='841b508658a3a843f7d194b089b355b3e2e572873b4301349f3b545255086339'
 else:
  start='proc-start:'+Q.start_identity(os.getpid());held=R.read(root/'held-worker-before-continue.json');worker={'pid':os.getpid(),'processStartIdentity':start,'uid':os.getuid(),'gid':os.getgid(),'cgroup':cap['cgroup'],'kernelLimits':cap['kernelLimits']};before={**worker,'pid':held['pid'],'processStartIdentity':'proc-start:'+held['start'],'state':'T','membershipBeforeRelease':True,'retainedStartHandle':held['pidfdRetained']};key='beforeExec';boot={'pythonVersion':platform.python_version(),'pythonExeSha256':R.digest(pathlib.Path(sys.executable).resolve()),'gitSha256':R.digest('/usr/bin/git'),'systemctlSha256':R.digest('/usr/bin/systemctl')};fact='LOCAL-LINUX-HOST-FACT.json';fact_sha='ad63c4ad44af1844e1c937152294b07cdce9faccf2e2e7899cc221f2e485fb3c'
 proof={'schema':'sdk11-own-current-cap-evidence/v1','projectId':'04','repository':'pouriajamali/data-admission-gate','sourceCommit':source['commit'],'sourceTree':source['tree'],'profileSha256':profile_sha,'controllerSha256':controller_sha,'bootstrap':boot,'worker':worker,key:before,'supervisor':{'pid':s['supervisorPID'],'processStartIdentity':s['supervisorStartIdentity'],'deadlineMonotonicNs':end},'rowStartedMonotonicNs':start_ns,'deadlineMonotonicNs':end};cp=root/'own-current-caps.json';R.write(cp,proof);ap=root/'local-input-context.json';R.write(ap,{'schema':'sdk11-local-input-current/v1','state':'OWN_CURRENT_INPUT_CONTEXT_BOUND','projectId':'04','repository':'pouriajamali/data-admission-gate','rid':RID,'qualifiedFactPath':str(H/fact),'qualifiedFactSha256':fact_sha,'profileSha256':profile_sha,'controllerSha256':controller_sha,'ownCapsEvidenceSha256':R.digest(cp),'sourcePinTableSha256':hashlib.sha256(R.a.canonical(pins['sourcePins'])).hexdigest()})
 return {'projectId':'04','repository':'pouriajamali/data-admission-gate','checkout':str(ROOT),'controller':str(pathlib.Path(__file__).resolve()),'contract':str(ROOT/'docs/CONTRACT.md'),'profile':str(PROFILE),'sourcePins':str(PINS),'admission':str(ap),'capsEvidence':str(cp),'expectedSourceCommit':source['commit'],'expectedSourceTree':source['tree'],'rowStartedMonotonicNs':start_ns,'deadlineMonotonicNs':end,'supervisorPID':s['supervisorPID'],'supervisorStartIdentity':s['supervisorStartIdentity']}
D=load('windows_job_close_diagnostic','7dd15e58ee4381476b53d03820df70080959e7de179faf0d6102b69ab1a2de71')
def worker(path):
 s=R.read(path);root=path.parent;need(s['purpose']==PURPOSE and s['controllerSha256']==R.digest(__file__),'EXACT_DIAGNOSTIC_CALLER');backend=Q.Backend(s);cap=backend.caps();budget=R.Budget(s);env=R.job_environment(root);events=[];errors=[]
 from ctypes import wintypes as W
 K=ctypes.WinDLL('kernel32',use_last_error=True);K.OpenJobObjectW.argtypes=[W.DWORD,W.BOOL,W.LPCWSTR];K.OpenJobObjectW.restype=W.HANDLE;K.QueryInformationJobObject.argtypes=[W.HANDLE,ctypes.c_int,ctypes.c_void_p,W.DWORD,ctypes.c_void_p];K.CloseHandle.argtypes=[W.HANDLE];K.GetCurrentProcess.restype=W.HANDLE;K.IsProcessInJob.argtypes=[W.HANDLE,W.HANDLE,ctypes.POINTER(W.BOOL)]
 class IDs(ctypes.Structure):_fields_=[('Assigned',W.DWORD),('Listed',W.DWORD),('IDs',ctypes.c_size_t*256)]
 class Accounting(ctypes.Structure):_fields_=[('User',ctypes.c_longlong),('Kernel',ctypes.c_longlong),('PeriodUser',ctypes.c_longlong),('PeriodKernel',ctypes.c_longlong),('Faults',W.DWORD),('Total',W.DWORD),('Active',W.DWORD),('Terminated',W.DWORD)]
 def observe(label,child_pid=None,child_start=None,closing_handle=None):
  h=None
  try:
   need(len(events)<16 and R.clock()<budget.current,'SINGLE_ORIGINAL_DIAGNOSTIC_BUDGET');h=K.OpenJobObjectW(4,False,s['jobName']);need(h,'EXACT_OWN_QUERY_HANDLE');ids=IDs();a=Accounting();member=W.BOOL();need(K.IsProcessInJob(K.GetCurrentProcess(),h,ctypes.byref(member)) and member.value,'ACTUAL_DIAGNOSTIC_MAIN_MEMBERSHIP');need(K.QueryInformationJobObject(h,3,ctypes.byref(ids),ctypes.sizeof(ids),None) and K.QueryInformationJobObject(h,1,ctypes.byref(a),ctypes.sizeof(a),None),'ACTUAL_JOB_LIST_AND_ACCOUNTING');need(ids.Listed<=256 and ids.Listed<=ids.Assigned,'COMPLETE_BOUNDED_PID_LIST');own=j.current_witness(s['jobName']);need(own['memoryMax']==4294967296 and own['tasksMax']==64 and own['cpuRate']==int(20000/own['logicalHostCpu']),'UNCHANGED_ACTUAL_DIAGNOSTIC_CAPS')
   events.append({'boundary':label,'observedTick':R.clock(),'mainPID':os.getpid(),'mainStart':j._start_identity(os.getpid()),'jobName':s['jobName'],'Assigned':int(ids.Assigned),'Listed':int(ids.Listed),'IDs':[int(x) for x in ids.IDs[:ids.Listed]],'accounting':{'Total':int(a.Total),'Active':int(a.Active),'TerminatedByLimit':int(a.Terminated)},'singletonExactOriginalPredicate':ids.Listed==ids.Assigned==1 and ids.IDs[0]==os.getpid(),'actualCaps':own,'childPID':child_pid,'childStartFromRetainedCreationHandle':child_start,'closingHandle':closing_handle})
  except BaseException as exc:errors.append({'boundary':label,'type':type(exc).__name__,'code':str(exc)[:120]})
  finally:
   if h:K.CloseHandle(h)
   R.write(root/'JOB-ID-OBSERVATIONS.json',{'events':events,'errors':errors,'SDK':0,'network':0})
 observe('BEFORE_GIT_CREATE');need(not errors and events[-1]['singletonExactOriginalPredicate'],'ORIGINAL_SINGLETON_REQUIRED_BEFORE_GIT')
 rec=D.run_job(['C:/Program Files/Git/cmd/git.exe','-C',str(ROOT),'rev-parse','HEAD','HEAD^{tree}'],ROOT,env,budget.deadline(10),root/'source-git',inherited_job_name=s['jobName'],observe=observe);observe('AFTER_GIT_RUN_JOB_RETURN_ALL_ITS_HANDLES_CLOSED');v=(root/'source-git/stdout.log').read_text().splitlines();need(len(v)==2 and v[0]==s['expectedCommit'],'EXACT_CURRENT_SOURCE');source={'commit':v[0],'tree':v[1]};ctx=context(s,root,cap,source);local=load('local_sdk11_input',s['localInputSha256']);C=local.C;Wmod=C._load('normal_windows_input',C.PINS['windowsNormalHelperSha256']);own=None;verdict=None
 try:own=Wmod.OwnJob(C,ctx,R.read(root/'own-current-caps.json'),ctx['deadlineMonotonicNs']);verdict={'state':'EXACT_UNCHANGED_OWNJOB_SINGLETON_GUARD_ACCEPTED','actual':own.observe()}
 except BaseException as exc:verdict={'state':'EXACT_UNCHANGED_OWNJOB_GUARD_DENIED','type':type(exc).__name__,'code':str(exc)[:120]}
 finally:
  if own:own.close()
 observe('AFTER_UNCHANGED_OWNJOB_OBSERVATION');need(not errors and len(events)==9,'ALL_NINE_BOUNDED_OBSERVATIONS_REQUIRED');R.write(root/'WINDOWS-JOB-DIAGNOSTIC-WORKER-FACT.json',{'schema':'windows-own-job-ids-and-close-boundary/v1','state':'ACTUAL_SOURCE_CHANGED_SDK_ZERO_DIAGNOSTIC_OBSERVED','source':source,'controllerSha256':R.digest(__file__),'profileSha256':R.digest(PROFILE),'derivedHelperSha256':R.digest(D.__file__),'frozenOriginalJobHelperSha256':R.digest(j.__file__),'frozenOwnJobObserverSha256':R.digest(Wmod.__file__),'worker':{'pid':os.getpid(),'start':j._start_identity(os.getpid()),'actualHeldBeforeResume':s['beforeResume']},'events':events,'ownJobGuard':verdict,'childGit':rec,'observerScope':'QueryInformationJobObject on own exact outer Job only; observer never opens/retains a child process/thread handle, changes caps, bypasses singleton or launches SDK. All original child handle closes remain in original order.','causalLimit':'Only these observed PID/count/handle boundaries. Prior failed860e IDs were not captured; do not infer their values or Linux139 cause.','SDKExecutions':0,'networkRequests':0,'Actions':0,'consumerAdmission':False,'productAdmission':False})

def finish(s,root,terminal,peak):
 value=R.read(root/'WINDOWS-JOB-DIAGNOSTIC-WORKER-FACT.json');value.update(terminal=terminal,peakMemoryBytes=peak);R.write(root/'WINDOWS-JOB-DIAGNOSTIC-FACT.json',value);return value
def windows_parent(expected):
 root=BASE/'local-windows04-job-ids-diagnostic-once-20261117';need(not root.exists(),'FRESH_PRODUCT04_WINDOWS_ROW');need(R.digest(LEASE.with_name('LEASE-PROTOCOL.json'))=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_LEASE_PROTOCOL');boot=R.read(BASE/'local-windows04-qualification-once-20261117/bootstrap.json');need(boot['PSFSignaturesValidWithTimestamps'] is True and R.digest(sys.executable)==boot['pythonExeSha256'] and R.digest(pathlib.Path(sys.executable).parent/'python312.dll')==boot['pythonDllSha256'],'EXACT_ALREADY_PSF_VERIFIED_BOOTSTRAP');lease={'projectId':'04','randomToken':secrets.token_hex(16),'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':j._start_identity(os.getpid()),'phase':'SDK_ZERO_EXACT_JOB_IDS_AND_GIT_HANDLE_BOUNDARY','startedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'receiptDirectory':str(root)}
 try:
  with LEASE.open('x',encoding='utf-8') as out:json.dump(lease,out);out.flush();os.fsync(out.fileno())
 except FileExistsError:print(json.dumps({'state':'LEASE_BUSY_NOT_STARTED'}));return
 root.mkdir();start=R.clock();s={'purpose':PURPOSE,'rid':RID,'root':str(root),'expectedCommit':expected,'startTick':start,'startMonotonicNs':time.monotonic_ns(),'controllerSha256':R.digest(__file__),'localInputSha256':R.digest(HERE/'local_sdk11_input.py'),'supervisorPID':os.getpid(),'supervisorStartIdentity':j._start_identity(os.getpid())};private=root/'private-spec.json';R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000});env={k:os.environ[k] for k in ('SystemRoot','WINDIR','COMSPEC','PATHEXT','USERPROFILE') if k in os.environ};env.update(PATH='C:/Windows/System32;C:/Windows',PYTHONDONTWRITEBYTECODE='1');record=error=None
 try:record=j.run_job([sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--worker',str(private)],ROOT,env,start+840000,root/'outer-job',job_name='Local\\admission04-input-'+secrets.token_hex(12),ready_spec={'path':private,'value':s},stage_directory=root)
 except BaseException as exc:error={'type':type(exc).__name__,'code':str(exc)[:180]}
 if record is None and (root/'outer-job/process.json').is_file():record=R.read(root/'outer-job/process.json')
 good=record and record['exitCode']==0 and not record['timedOut'] and record['actualCap']['activeProcessesAtTeardown']==0 and (root/'WINDOWS-JOB-DIAGNOSTIC-WORKER-FACT.json').is_file() and error is None;R.write(root/'FINAL-RECEIPT.json',{'state':'SDK_ZERO_JOB_BOUNDARY_DIAGNOSTIC_COMPLETE' if good else 'HOLD','record':record,'error':error,'elapsedSeconds':(R.clock()-start)/1000,'Actions':0,'published':False})
 if good:finish(s,root,{'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'processReceiptSha256':R.digest(root/'outer-job/process.json')},record['actualCap']['peakJobMemory'])
 if record and record['actualCap']['activeProcessesAtTeardown']==0:
  need(R.read(LEASE)==lease,'EXACT_OWN_PRODUCT_LEASE_RELEASE');LEASE.unlink();R.write(root/'LEASE-RELEASED.json',{'state':'RELEASED_AFTER_ACTUAL_TERMINAL','terminalSha256':R.digest(root/'outer-job/process.json'),'tokenSha256':hashlib.sha256(lease['randomToken'].encode()).hexdigest()})
 print(json.dumps({'state':'SDK_ZERO_JOB_BOUNDARY_DIAGNOSTIC_COMPLETE' if good else 'HOLD','rid':RID,'root':str(root),'error':error}),flush=True)
 if not good:raise SystemExit(1)
def main():
 p=argparse.ArgumentParser();p.add_argument('--expected-commit');p.add_argument('--worker',type=pathlib.Path);args=p.parse_args()
 if args.worker:worker(args.worker);return
 need(os.name=='nt' and args.expected_commit,'EXACT_WINDOWS_LOCAL_READONLY_DIAGNOSTIC');windows_parent(args.expected_commit)
if __name__=='__main__':main()
