"""Own04 accepted-host-fact consumer; no globalREADY or qualification-input bypass."""
from __future__ import annotations
import argparse,contextlib,hashlib,importlib.util,json,os,re,select,shlex,signal,subprocess,sys,time,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent
# Controllers are source-bound siblings in the exact signed/approved CI projection.
def module(name):
 p=HERE/(name+'.py');expected={'qualify_dotnet11_windows': 'a8f5a9947a7bad112a2162cd59e3e464f7f599276940f4a0f36d0feb5ae60b82', 'qualify_dotnet11_linux': 'cdf1773d1d672fe78d214dd9a35616aaea0b3beade1578aa9a216e88e87a43ca'}[name]
 if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise RuntimeError('CONSUMER_BACKEND_SOURCE_IDENTITY')
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
Q=module('qualify_dotnet11_windows' if os.name=='nt' else 'qualify_dotnet11_linux');R=Q.R;j=Q.j
COMMON_NORMAL_SHA='d9c690d8c82825b018c04089c279036829d3baf2534c2634bba84910c415a37d'
COMMON_CATALOG_SHA='686c6c778f7841e6015fa401f3892b853df80e3341fbb5d02b27c682887c1c78'
COMMON_FACT_SHA='757abf2d3dde65d10cd895cfc97eaeccb7fc11e8685b94ad046e6a8ec8829007'
STAGES=['locked-tests','package','extract','package-checks','technology-checks']
CURATION_PURPOSE='PRODUCER04_LINUX_INPUT_CURATION'
def curation_module():
 return R.load_module('curate_dotnet11_linux_inputs','ddd6091f341b27d3dd4a978aaf263c37b61a29c6e50469522cee7ab56134db7a')
def own04_common_context(spec,source,host,route):
 root=Path(spec['root']);profilePath=HERE/'dotnet11-consumer04-normal-profile.json';pinsPath=HERE/'dotnet11-consumer04-source-pins.json';profile=R.read(profilePath);pins=R.read(pinsPath)
 R.f.need(profile.get('state')=='ADMITTED_SOURCE_PROFILE' and pins.get('state')=='EXACT_SOURCE_REVIEWED','OWN04_SOURCE_PROFILE_NOT_ADMITTED')
 R.f.need(profile.get('projectId')==pins.get('projectId')=='04' and profile.get('repository')==pins.get('repository')=='pouriajamali/data-admission-gate','OWN04_SOURCE_PROFILE_IDENTITY')
 R.f.need(R.digest(Path(__file__))==route['controllerSha256'] and R.digest(profilePath)==route['profileSha256'],'OWN04_CURRENT_SOURCE_PROFILE_HASH')
 raw=j.linux_caps();held=R.read(root/'held-worker-before-continue.json');pid=os.getpid();start=Q.start_identity(pid);R.f.need(spec.get('parentHeldWorkerBeforeExec') is True and held['pid']==pid and held['start']==start and held.get('state')=='T' and held.get('pidfdRetained') is True and held.get('cgroup')==raw['cgroup'] and held['kernelLimits']==raw['kernelLimits'],'OWN04_ACTUAL_HELD_WORKER')
 originalStart=spec['startTick']*1000000;originalEnd=(spec['startTick']+900000)*1000000
 bootstrap={'pythonVersion':R.platform.python_version(),'pythonExeSha256':R.digest(Path(sys.executable).resolve()),'gitSha256':R.digest('/usr/bin/git'),'systemctlSha256':R.digest('/usr/bin/systemctl')}
 evidence={'schema':'sdk11-own-current-cap-evidence/v1','projectId':'04','repository':'pouriajamali/data-admission-gate','sourceCommit':source['commit'],'sourceTree':source['tree'],'profileSha256':R.digest(profilePath),'controllerSha256':R.digest(Path(__file__)),'worker':{'pid':pid,'processStartIdentity':'proc-start:'+start,'uid':raw['uid'],'gid':raw['gid'],'cgroup':raw['cgroup'],'kernelLimits':raw['kernelLimits']},'beforeExec':{'pid':held['pid'],'processStartIdentity':'proc-start:'+held['start'],'cgroup':held['cgroup'],'kernelLimits':held['kernelLimits'],'state':held['state'],'membershipBeforeRelease':True,'retainedStartHandle':held['pidfdRetained']},'supervisor':{'pid':spec['supervisorPID'],'processStartIdentity':spec['supervisorStartIdentity'],'deadlineMonotonicNs':originalEnd},'rowStartedMonotonicNs':originalStart,'deadlineMonotonicNs':originalEnd,'bootstrap':bootstrap}
 evidencePath=root/'own04-current-normal-cap-evidence.json';R.write(evidencePath,evidence)
 typed={'schema':'sdk11-consumer-host-admission/v1','state':'ADMITTED_EXACT_SUPPORTED_HOST_CLASS','projectId':'04','producerFactSha256':route['producerFactsByRid']['linux-x64']['factSha256'],'admittedFor':{'hostClass':'GitHubHostedUbuntu24.04x64','rid':'linux-x64','sdk':'11.0.100','runtime':'11.0.0','memberManifestSha256':'d411111d23492b4d101dd62851d1d1fedf3a4badc057d999aedc155ae4cc103a','contractSha256':R.digest(R.ROOT/'docs/CONTRACT.md'),'sourcePinTableSha256':R.f.h(pins['sourcePins']),'controllerSha256':R.digest(Path(__file__)),'profileSha256':R.digest(profilePath)},'currentExecution':{'runId':host['runId'],'job':host['job'],'attempt':host['attempt'],'instanceId':host['instanceId'],'ownCapsEvidenceSha256':R.digest(evidencePath)},'identityRule':'QUALIFIED_ON_IS_HISTORICAL_PRODUCER_INSTANCE_CURRENT_CONSUMER_JOB_MAY_DIFFER'}
 R.f.schema_check(typed,R.read(HERE/'dotnet11-host-qualification.schema.json')['$defs']['consumerAdmission']);admissionPath=root/'consumer-host-handshake.json';R.write(admissionPath,typed)
 return {'projectId':'04','repository':'pouriajamali/data-admission-gate','checkout':str(R.ROOT.resolve()),'controller':str(Path(__file__).resolve()),'contract':str((R.ROOT/'docs/CONTRACT.md').resolve()),'profile':str(profilePath.resolve()),'sourcePins':str(pinsPath.resolve()),'admission':str(admissionPath.resolve()),'capsEvidence':str(evidencePath.resolve()),'expectedSourceCommit':source['commit'],'expectedSourceTree':source['tree'],'rowStartedMonotonicNs':originalStart,'deadlineMonotonicNs':originalEnd,'supervisorPID':spec['supervisorPID'],'supervisorStartIdentity':spec['supervisorStartIdentity']}

def consumer_work(spec,backend):
 root=Path(spec['root']);rid=spec['rid'];R.f.need(rid=='linux-x64','OWN04_WINDOWS_NORMAL_INPUT_DENIED');budget=R.Budget(spec);env=R.job_environment(root);host=R.host(rid,root);cap=backend.caps();R.f.caps(cap,rid);source=R.source_context(spec['expectedCommit'],backend.run,env,budget,root,qualification=False)
 route=R.read(HERE/'dotnet11-consumer04-admission.lock.json');R.f.need(route.get('state')=='ADMITTED_EXACT_SUPPORTED_HOST_CLASS' and route.get('projectId')=='04','CONSUMER_ADMISSION_REQUIRED');R.f.need(route.get('productInputState')=='EXACT_CLOSED_PRODUCT_INPUTS_ADMITTED','OWN04_ORIGINAL_PRODUCT_INPUTS_PENDING')
 # Preserve the original locked package/oracle/notice/advisory gates; missing
 # net11 locks cannot be promoted by the accepted producer SDK fact.
 for name in ['src/Admission/packages.lock.json','tests/Admission.Tests/packages.lock.json']:
  deps=R.read(R.ROOT/name).get('dependencies');R.f.need(type(deps) is dict and deps and all(k.startswith('net11.0') for k in deps),'OWN04_NET11_LOCKS_NOT_CLOSED')
 R.f.need(route['commonNormalModuleSha256']==COMMON_NORMAL_SHA and route['normalCatalogSha256']==COMMON_CATALOG_SHA,'OWN04_COMMON_SOURCE_IDENTITY');normal=R.load_module('check_dotnet11',COMMON_NORMAL_SHA);catalogPath=HERE/'sdk11-normal-inputs.lock.json';R.f.need(R.digest(catalogPath)==COMMON_CATALOG_SHA,'OWN04_NORMAL_CATALOG_IDENTITY');normalCatalog=R.read(catalogPath);catalog=normalCatalog['rids']['linux-x64']['input'];members=catalog['members']
 factpath=HERE/'sdk11-normal/accepted-linux-fact.json';R.f.need(R.digest(factpath)==route['producerFactsByRid']['linux-x64']['factSha256']==COMMON_FACT_SHA,'OWN04_ACCEPTED_FACT_IDENTITY');fact=R.read(factpath);binding={'factSha256':COMMON_FACT_SHA}
 cpu=R.linux_cpu(root);R.f.cpu(cpu);R.bootstrap_identity();marker,raw=R.output(backend.run,[sys.executable,'-I','-S','-B','-c','print("CONSUMER04_CAPS_MARKER")'],R.ROOT,env,budget.deadline(5),root/'own-sdk0-marker');R.f.need(raw.strip()==b'CONSUMER04_CAPS_MARKER','OWN_CONSUMER_CONTROL_REQUIRED')
 for mode,flags,opt in [('normal',[],None),('O',['-O'],None),('env2',[],'2')]:
  e=dict(env)
  if opt:e['PYTHONOPTIMIZE']=opt
  rec,raw=R.output(backend.run,[sys.executable,'-S','-B',*flags,HERE/'test_dotnet11_consumer04.py','--rid',rid,'--out',root/('own-denials-'+mode)],R.ROOT,e,budget.deadline(8),root/('own-denial-process-'+mode));v=R.read(root/('own-denials-'+mode+'/receipt.json'));R.f.need(v['count']==6 and v['optimize']==(2 if opt else 1 if flags else 0) and v['candidateSpawns']==0,'OWN_CONSUMER_DENIAL_REQUIRED')
 # The shared call gets the original900s absolute row deadline. The existing
 # own caller alarm limits this input portion to300s (120+180) within outer840;
 # neither shared transport nor materializer creates a fresh900/540 outer clock.
 budget.stage(1,300);normalContext=own04_common_context(spec,source,host,route);directory=Path(os.environ['RUNNER_TEMP']).resolve()/('sdk11-normal-04-'+host['runId']+'-'+host['attempt']+'-'+uuid.uuid4().hex)
 sdk,inputReceipt=normal.transport(rid,directory,normalContext);R.write(root/'common-normal-input-receipt.json',inputReceipt)
 budget.stage(3,max(1,int((budget.outer-R.clock())/1000)));env.update({'DOTNET_ROOT':str(sdk),'DOTNET_ROOT_X64':str(sdk),'DOTNET_HOST_PATH':str(sdk/'dotnet'),'PATH':str(sdk)+os.pathsep+env['PATH']});R.native_prerequisites(rid,sdk,root,backend.run,env,budget)
 project=R.ROOT;art=project/'artifacts';art.mkdir(exist_ok=True);R.f.need(not (art/'controlled-consumer04.json').exists(),'CONSUMER_OUTPUT_EXISTS')
 def run_stage(name,argv):
  R.a.verify_tree(sdk,members,rid)
  with contextlib.ExitStack() as stack:
   if rid=='win-x64':
    for x in catalog['criticalMembers']:R.f.need(stack.enter_context(backend.hold(sdk/x['path']))['sha256']==x['sha256'],'SDK_HELD_IMAGE_IDENTITY')
   rec,raw=R.output(backend.run,argv,project,env,budget.current,root/('product-'+name))
  return {'stage':name,'exitCode':0,'processEvidenceSha256':R.digest(root/('product-'+name+'/process.json'))}
 hostexe=env['DOTNET_HOST_PATH'];records=[];records.append(run_stage('restore',[hostexe,'restore','tests/Admission.Tests','--locked-mode']));records.append(run_stage('locked-tests',[hostexe,'run','--project','tests/Admission.Tests','-c','Release','--no-restore','--','--work','artifacts/tests']));records.append(run_stage('package',[sys.executable,'tools/package.py','--rid',rid,'--commit',spec['expectedCommit'],'--work','artifacts/build','--out','artifacts/delivery']))
 archives=[p for p in (art/'delivery').iterdir() if p.is_file()];R.f.need(len(archives)==1,'EXACT_ONE_PRODUCT_ARCHIVE');extract=art/'extracted with spaces';extract.mkdir(exist_ok=False)
 # Same established OS extraction recipe inside the owned aggregate, never root.
 ps="if ($IsWindows) { Expand-Archive -LiteralPath $env:CONSUMER04_ARCHIVE -DestinationPath $env:CONSUMER04_EXTRACT } else { tar -xzf $env:CONSUMER04_ARCHIVE -C $env:CONSUMER04_EXTRACT; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }";env['CONSUMER04_ARCHIVE']=str(archives[0]);env['CONSUMER04_EXTRACT']=str(extract);pwsh=Path('C:/Program Files/PowerShell/7/pwsh.exe' if rid=='win-x64' else '/usr/bin/pwsh');R.f.need(pwsh.is_file(),'EXISTING_PRODUCT_PWSH_REQUIRED');records.append(run_stage('extract',[pwsh,'-NoProfile','-NonInteractive','-Command',ps]));packages=[p for p in extract.iterdir() if p.is_dir()];R.f.need(len(packages)==1,'EXACT_ONE_PRODUCT_ROOT');package=packages[0]
 records.append(run_stage('package-checks',[sys.executable,'tools/check_package.py','--package',package,'--work','artifacts/package checks with spaces','--commit',spec['expectedCommit']]));records.append(run_stage('technology-checks',[sys.executable,'tools/check_tech_refresh.py','--package',package,'--work','artifacts/technology checks with spaces','--commit',spec['expectedCommit']]))
 normal.inspect_sdk(rid,sdk,normalContext);R.write(root/'consumer-worker.json',{'state':'CONTROLLED_CONSUMER04_PRODUCT_COMPLETED','rid':rid,'source':source,'producerFactSha256':binding['factSha256'],'producerQualifiedOn':fact['qualifiedOn'],'currentExecution':{k:host[k] for k in ['hostClass','rid','runId','job','attempt','imageVersion','instanceId']},'caps':backend.caps(),'stages':records,'admissionSha256':R.digest(HERE/'dotnet11-consumer04-admission.lock.json'),'commonNormalModuleSha256':COMMON_NORMAL_SHA,'normalCatalogSha256':COMMON_CATALOG_SHA,'normalInputReceiptSha256':R.digest(root/'common-normal-input-receipt.json'),'scope':'Alloriginal109/17/4acceptance remains in originaltools; not automaticallypassed by SDKqualification.'})
 if os.name!='nt':signal.setitimer(signal.ITIMER_REAL,0)
def finish_consumer(spec,terminal,peak):
 R.f.need(spec.get('purpose')!='PRODUCER04_LINUX_INPUT_CURATION','CURATION_METHOD_HOLD_NO_SUCCESS_RECEIPT')
 R.f.terminal(terminal);value=R.read(Path(spec['root'])/'consumer-worker.json');value['terminal']=terminal;value['caps']['peakMemoryBytes']=int(peak);R.f.need(R.clock()<spec['startTick']+900000,'CONSUMER900_DEADLINE');R.write(R.ROOT/'artifacts/controlled-consumer04.json',value)
def check_stage(name,expected):
 R.f.need(name in STAGES,'FIXED_STAGE_REQUIRED');v=R.read(R.ROOT/'artifacts/controlled-consumer04.json');R.f.source(v['source']['commit'],expected);R.f.terminal(v['terminal']);R.f.need(any(x['stage']==name and x['exitCode']==0 for x in v['stages']),'CONTROLLED_STAGE_NOT_COMPLETED')
def consumer_worker(path):
 s=R.read(path);R.f.need(s['purpose'] in ('CONSUMER04_PRODUCT',CURATION_PURPOSE),'FIXED_CONSUMER_ROLE')
 if s['purpose']==CURATION_PURPOSE:
  R.f.need(os.name!='nt','CURATION_LINUX_ONLY');curation_module().parent_admission(s['curationAdmissionPath'],s['curationAdmissionSHA256'],s['expectedCommit'])
 if os.name=='nt':
  boot=R.read(s['bootstrap']);R.f.need(Path(sys.executable).resolve()==Path(boot['pythonExe']).resolve() and R.digest(sys.executable)==boot['pythonExeSha256'] and boot['pythonSignature']=='ValidPythonSoftwareFoundationWithTimestamp','PYTHON_BOOTSTRAP_IDENTITY');consumer_work(s,Q.Backend(s));return
 j.bind(s);cap=j.linux_caps();R.write(Path(s['root'])/'stopped-worker.json',{'pid':os.getpid(),'start':Q.start_identity(os.getpid()),'cap':cap,'uid':os.getuid(),'gid':os.getgid()});os.kill(os.getpid(),signal.SIGSTOP);w=R.read(Path(s['root'])/'held-worker-before-continue.json');R.f.need(w['pid']==os.getpid() and w['start']==Q.start_identity(os.getpid()),'HELD_WORKER_PREEXEC_IDENTITY');s['parentHeldWorkerBeforeExec']=True
 if s['purpose']==CURATION_PURPOSE:curation_module().worker(s,Q.Backend(s),R,Q)
 else:consumer_work(s,Q.Backend(s))
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--expected-commit');parser.add_argument('--worker',type=Path);parser.add_argument('--stop-post',type=Path);parser.add_argument('--check-stage',choices=STAGES);parser.add_argument('--curation-admission',type=Path);parser.add_argument('--curation-admission-sha256');args=parser.parse_args()
 R.f.need(bool(args.curation_admission)==bool(args.curation_admission_sha256),'CURATION_GATE_ARGUMENT_PAIR')
 if args.curation_admission:
  R.f.need(not (args.worker or args.stop_post or args.check_stage) and os.name!='nt','CURATION_EXCLUSIVE_LINUX_PURPOSE')
  curation_module().parent_admission(args.curation_admission,args.curation_admission_sha256,args.expected_commit)
 if args.check_stage:check_stage(args.check_stage,args.expected_commit);return
 if args.stop_post:R.f.need(os.name!='nt','FIXED_OBSERVER_HOST');Q.stop_post(args.stop_post);return
 if args.worker:consumer_worker(args.worker);return
 if os.name=='nt':win_parent(args)
 else:linux_parent(args)

def win_parent(args):
 R.f.source(os.environ.get('GITHUB_SHA'),args.expected_commit);R.f.need(os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Windows','NAMED_WINDOWS_HOST_REQUIRED')
 start=int(os.environ['SDK11_QUALIFICATION_START_TICK']);R.f.need(0<=R.clock()-start<60000,'STARTUP60_EXPIRED');temp=Path(os.environ['RUNNER_TEMP']).resolve();root=temp/('admission04-sdk11-win-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);R.a.scoped(root,temp,absent=True);root.mkdir();bootstrap=Path(os.environ['SDK11_QUALIFICATION_BOOTSTRAP']);R.a.scoped(bootstrap,temp);boot=R.read(bootstrap);R.f.need(R.digest(sys.executable)==boot['pythonExeSha256'],'PYTHON_BOOTSTRAP_CHANGED')
 R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000});private=root/'private-spec.json';value={'root':str(root),'rid':'win-x64','purpose':'CONSUMER04_PRODUCT','expectedCommit':args.expected_commit,'startTick':start,'bootstrap':str(bootstrap)};name='Local\\admission04-sdk11-'+uuid.uuid4().hex
 env={k:v for k,v in os.environ.items() if not k.upper().endswith(('TOKEN','SECRET','PASSWORD'))};env['PYTHONDONTWRITEBYTECODE']='1'
 # The existing trusted image Python/shell before this call is a bounded bootstrap,
 # not claimed insideJob. Allworker/acquisition/extraction/tests/SDK descendants are.
 record=j.run_job([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(private)],R.ROOT,env,start+840000,root/'outer-job',job_name=name,ready_spec={'path':private,'value':value},stage_directory=root)
 R.f.need(record['actualCap']['activeProcessesAtTeardown']==0 and record['exitCode']==0,'OWNED_AGGREGATE_TERMINAL');terminal={'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'typedStopResult':'success','terminalEvidenceSha256':R.digest(root/'outer-job/process.json')};finish_consumer(value,terminal,record['actualCap']['peakJobMemory'])

def linux_parent(args):
 R.f.need(os.name!='nt' and os.getuid()>0 and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Linux' and Path('/proc/1/comm').read_text().strip()=='systemd' and not Path('/.dockerenv').exists(),'NAMED_UBUNTU_HOST_REQUIRED');R.host('linux-x64');R.f.source(os.environ.get('GITHUB_SHA'),args.expected_commit)
 start=int(os.environ['SDK11_QUALIFICATION_START_TICK']);R.f.need(0<=R.clock()-start<60000,'STARTUP60_EXPIRED');temp=Path(os.environ['RUNNER_TEMP']).resolve();root=temp/('admission04-sdk11-linux-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);R.a.scoped(root,temp,absent=True);root.mkdir(mode=0o700);R.f.need(root.stat().st_uid==os.getuid() and root.stat().st_gid==os.getgid() and (root.stat().st_mode&0o777)==0o700,'FRESH_PRIVATE_RUNNER_ROOT')
 unit='admission04-sdk11-ci-'+uuid.uuid4().hex;private=root/'private-spec.json';s={'purpose':'CONSUMER04_PRODUCT','rid':'linux-x64','root':str(root),'unit':unit,'uid':os.getuid(),'gid':os.getgid(),'expectedCommit':args.expected_commit,'startTick':start,'supervisorPID':os.getpid(),'supervisorStartIdentity':'proc-start:'+Q.start_identity(os.getpid())}
 if args.curation_admission:s.update({'purpose':CURATION_PURPOSE,'curationAdmissionPath':str(args.curation_admission),'curationAdmissionSHA256':args.curation_admission_sha256})
 R.write(private,s);R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000})
 for path in [str(HERE),str(root),sys.executable]:R.f.need(not any(c in path for c in ['\n','\r','%','$','"',"'"]),'SYSTEMD_FIXED_ARGV_PATH')
 envnames=['GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_EVENT_PATH','GITHUB_JOB','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_NAME','ImageOS','ImageVersion','RUNNER_TEMP'];sets=['--setenv='+k+'='+os.environ[k] for k in envnames if k in os.environ];remaining=max(1,(start+840000-R.clock())//1000);observer=' '.join(shlex.quote(str(x)) for x in [sys.executable,'-I','-S','-B',Path(__file__).resolve(),'--stop-post',private])
 argv=['/usr/bin/sudo','-n','/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid='+str(s['uid']),'--gid='+str(s['gid']),'--property=Description='+unit,'--property=MemoryMax=4294967296','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec='+str(remaining),'--property=TimeoutStopSec=5','--property=KillMode=control-group','--property=WorkingDirectory='+str(R.ROOT),'--property=ExecStopPost='+observer,'--setenv=PYTHONDONTWRITEBYTECODE=1',*sets,sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(private)]
 R.write(root/'root-starter.json',{'argv':argv,'boundary':'ExistingtrustedrootOSstarter only; fixednonrootUser/Group. Allworker/acquisition/extraction/targets/observer insideactualcgroup; norootSDK/arbitraryrootcommand/install/config.'})
 terminal,stop=Q.run_owned_linux(s,argv);finish_consumer(s,terminal,stop['actualCaps']['memoryPeak'])

if __name__=='__main__':
 try:main()
 except BaseException as exc:
  R.capture_entry_failure(exc);raise
