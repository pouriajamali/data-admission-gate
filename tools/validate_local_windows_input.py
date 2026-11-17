"""One SDK-zero validation of the existing read-only Windows input facade.
Reuses qualified byte/publisher/bootstrap histories; no SDK, package, GET or policy edit.
"""
from __future__ import annotations
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,platform,secrets,subprocess,sys,time
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent
def load(name,sha):
 p=HERE/(name+'.py')
 if hashlib.sha256(p.read_bytes()).hexdigest()!=sha:raise RuntimeError('FIXED_PRODUCT_HELPER:'+name)
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);return m
Q=load('qualify_dotnet11_windows','a8f5a9947a7bad112a2162cd59e3e464f7f599276940f4a0f36d0feb5ae60b82');R=Q.R;j=Q.j
SDK=pathlib.Path('E:/Codex WorkSpace/Git Projects/data-admission-gate/state/dotnet11-shared-20261114/trees/win-x64')
H=pathlib.Path('E:/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave4-state/project04-shared-normal-final-20261117')
BASE=pathlib.Path('C:/Users/Office/.codex/visualizations/2026/11/10/01a1c661-2773-7f81-9ae7-c5756abd8095/metadata-framing')
RID='win-x64';PROFILE=HERE/'producer04-local-input-windows.profile.json';PINS=HERE/'producer04-local-source-pins.json';PURPOSE='READONLY_LOCAL_WINDOWS04_INPUT_INTERFACE';LEASE=H.parents[1]/'wave2-state/LOCAL-FIXTURE-LEASE.json'
def need(v,why):R.f.need(v,why)
def context(s,root,cap,source):
 profile_sha=R.digest(PROFILE);controller_sha=R.digest(__file__);pins=R.read(PINS);start_ns=s['startMonotonicNs'];end=start_ns+900000000000
 if os.name=='nt':
  start=j._start_identity(os.getpid());w=j.current_witness(s['jobName']);worker={'pid':os.getpid(),'processStartIdentity':start,'jobName':s['jobName'],'memoryMaxBytes':w['memoryMax'],'tasksMax':w['tasksMax'],'cpuRate':w['cpuRate'],'logicalHostCpu':w['logicalHostCpu']};held=s['beforeResume'];before={**worker,'memoryMaxBytes':held['memoryMax'],'tasksMax':held['activeProcessMax'],'cpuRate':held['cpuRate'],'logicalHostCpu':held['logicalHostCpu'],'state':'SUSPENDED','membershipBeforeRelease':held['membership'],'retainedStartHandle':held['retainedCreationHandles']};key='heldBeforeExec';boot={'pythonVersion':platform.python_version(),'pythonExeSha256':R.digest(pathlib.Path(sys.executable).resolve()),'gitSha256':R.digest('C:/Program Files/Git/cmd/git.exe')};fact='LOCAL-WINDOWS04-HOST-FACT.json';fact_sha='841b508658a3a843f7d194b089b355b3e2e572873b4301349f3b545255086339'
 else:
  start='proc-start:'+Q.start_identity(os.getpid());held=R.read(root/'held-worker-before-continue.json');worker={'pid':os.getpid(),'processStartIdentity':start,'uid':os.getuid(),'gid':os.getgid(),'cgroup':cap['cgroup'],'kernelLimits':cap['kernelLimits']};before={**worker,'pid':held['pid'],'processStartIdentity':'proc-start:'+held['start'],'state':'T','membershipBeforeRelease':True,'retainedStartHandle':held['pidfdRetained']};key='beforeExec';boot={'pythonVersion':platform.python_version(),'pythonExeSha256':R.digest(pathlib.Path(sys.executable).resolve()),'gitSha256':R.digest('/usr/bin/git'),'systemctlSha256':R.digest('/usr/bin/systemctl')};fact='LOCAL-LINUX-HOST-FACT.json';fact_sha='ad63c4ad44af1844e1c937152294b07cdce9faccf2e2e7899cc221f2e485fb3c'
 proof={'schema':'sdk11-own-current-cap-evidence/v1','projectId':'04','repository':'pouriajamali/data-admission-gate','sourceCommit':source['commit'],'sourceTree':source['tree'],'profileSha256':profile_sha,'controllerSha256':controller_sha,'bootstrap':boot,'worker':worker,key:before,'supervisor':{'pid':s['supervisorPID'],'processStartIdentity':s['supervisorStartIdentity'],'deadlineMonotonicNs':end},'rowStartedMonotonicNs':start_ns,'deadlineMonotonicNs':end};cp=root/'own-current-caps.json';R.write(cp,proof);ap=root/'local-input-context.json';R.write(ap,{'schema':'sdk11-local-input-current/v1','state':'OWN_CURRENT_INPUT_CONTEXT_BOUND','projectId':'04','repository':'pouriajamali/data-admission-gate','rid':RID,'qualifiedFactPath':str(H/fact),'qualifiedFactSha256':fact_sha,'profileSha256':profile_sha,'controllerSha256':controller_sha,'ownCapsEvidenceSha256':R.digest(cp),'sourcePinTableSha256':hashlib.sha256(R.a.canonical(pins['sourcePins'])).hexdigest()})
 return {'projectId':'04','repository':'pouriajamali/data-admission-gate','checkout':str(ROOT),'controller':str(pathlib.Path(__file__).resolve()),'contract':str(ROOT/'docs/CONTRACT.md'),'profile':str(PROFILE),'sourcePins':str(PINS),'admission':str(ap),'capsEvidence':str(cp),'expectedSourceCommit':source['commit'],'expectedSourceTree':source['tree'],'rowStartedMonotonicNs':start_ns,'deadlineMonotonicNs':end,'supervisorPID':s['supervisorPID'],'supervisorStartIdentity':s['supervisorStartIdentity']}
def worker(path):
 s=R.read(path);root=path.parent;need(s['purpose']==PURPOSE and s['controllerSha256']==R.digest(__file__),'EXACT_READONLY_INPUT_CALLER');backend=Q.Backend(s);cap=backend.caps();budget=R.Budget(s);env=R.job_environment(root)
 rec,raw=R.output(backend.run,['C:/Program Files/Git/cmd/git.exe','-C',str(ROOT),'rev-parse','HEAD','HEAD^{tree}'],ROOT,env,budget.deadline(10),root/'source-git');v=raw.decode().splitlines();need(len(v)==2 and v[0]==s['expectedCommit'],'EXACT_CURRENT_SOURCE');source={'commit':v[0],'tree':v[1]};ctx=context(s,root,cap,source);local=load('local_sdk11_input',s['localInputSha256']);receipt=local.inspect_sdk(RID,SDK,ctx);R.write(root/'local-sdk-input.json',receipt);need(R.clock()<budget.current,'ORIGINAL_STARTUP60');R.write(root/'PRODUCT04-WORKER-FACT.json',{'schema':'sdk11-local-input-windows-live-validation/v1','state':'CURRENT_WINDOWS_INPUT_FACADE_OBSERVED_SDK_ZERO','source':source,'input':receipt,'SDKExecutions':0,'networkRequests':0,'formalDotnet11Support':'NOT_CONFIRMED','Actions':0,'productAdmission':False})

def finish(s,root,terminal,peak):
 value=R.read(root/'PRODUCT04-WORKER-FACT.json');value.update(terminal=terminal,peakMemoryBytes=peak);R.write(root/'LOCAL-INPUT-VALIDATION-FACT.json',value);return value
def windows_parent(expected):
 root=BASE/'local-windows04-input-facade-once-20261117';need(not root.exists(),'FRESH_PRODUCT04_WINDOWS_ROW');need(R.digest(LEASE.with_name('LEASE-PROTOCOL.json'))=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_LEASE_PROTOCOL');boot=R.read(BASE/'local-windows04-qualification-once-20261117/bootstrap.json');need(boot['PSFSignaturesValidWithTimestamps'] is True and R.digest(sys.executable)==boot['pythonExeSha256'] and R.digest(pathlib.Path(sys.executable).parent/'python312.dll')==boot['pythonDllSha256'],'EXACT_ALREADY_PSF_VERIFIED_BOOTSTRAP');lease={'projectId':'04','randomToken':secrets.token_hex(16),'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':j._start_identity(os.getpid()),'phase':'SDK_ZERO_CURRENT_READONLY_WINDOWS_INPUT_VALIDATION','startedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'receiptDirectory':str(root)}
 try:
  with LEASE.open('x',encoding='utf-8') as out:json.dump(lease,out);out.flush();os.fsync(out.fileno())
 except FileExistsError:print(json.dumps({'state':'LEASE_BUSY_NOT_STARTED'}));return
 root.mkdir();start=R.clock();s={'purpose':PURPOSE,'rid':RID,'root':str(root),'expectedCommit':expected,'startTick':start,'startMonotonicNs':time.monotonic_ns(),'controllerSha256':R.digest(__file__),'localInputSha256':R.digest(HERE/'local_sdk11_input.py'),'supervisorPID':os.getpid(),'supervisorStartIdentity':j._start_identity(os.getpid())};private=root/'private-spec.json';R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000});env={k:os.environ[k] for k in ('SystemRoot','WINDIR','COMSPEC','PATHEXT','USERPROFILE') if k in os.environ};env.update(PATH='C:/Windows/System32;C:/Windows',PYTHONDONTWRITEBYTECODE='1');record=error=None
 try:record=j.run_job([sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--worker',str(private)],ROOT,env,start+840000,root/'outer-job',job_name='Local\\admission04-input-'+secrets.token_hex(12),ready_spec={'path':private,'value':s},stage_directory=root)
 except BaseException as exc:error={'type':type(exc).__name__,'code':str(exc)[:180]}
 if record is None and (root/'outer-job/process.json').is_file():record=R.read(root/'outer-job/process.json')
 good=record and record['exitCode']==0 and not record['timedOut'] and record['actualCap']['activeProcessesAtTeardown']==0 and (root/'PRODUCT04-WORKER-FACT.json').is_file() and error is None;R.write(root/'FINAL-RECEIPT.json',{'state':'LOCAL_INPUT_FACADE_VALIDATION_COMPLETE' if good else 'HOLD','record':record,'error':error,'elapsedSeconds':(R.clock()-start)/1000,'Actions':0,'published':False})
 if good:finish(s,root,{'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'processReceiptSha256':R.digest(root/'outer-job/process.json')},record['actualCap']['peakJobMemory'])
 if record and record['actualCap']['activeProcessesAtTeardown']==0:
  need(R.read(LEASE)==lease,'EXACT_OWN_PRODUCT_LEASE_RELEASE');LEASE.unlink();R.write(root/'LEASE-RELEASED.json',{'state':'RELEASED_AFTER_ACTUAL_TERMINAL','terminalSha256':R.digest(root/'outer-job/process.json'),'tokenSha256':hashlib.sha256(lease['randomToken'].encode()).hexdigest()})
 print(json.dumps({'state':'LOCAL_INPUT_FACADE_VALIDATION_COMPLETE' if good else 'HOLD','rid':RID,'root':str(root),'error':error}),flush=True)
 if not good:raise SystemExit(1)
def main():
 p=argparse.ArgumentParser();p.add_argument('--expected-commit');p.add_argument('--worker',type=pathlib.Path);args=p.parse_args()
 if args.worker:worker(args.worker);return
 need(os.name=='nt' and args.expected_commit,'EXACT_WINDOWS_LOCAL_READONLY_VALIDATION');windows_parent(args.expected_commit)
if __name__=='__main__':main()
