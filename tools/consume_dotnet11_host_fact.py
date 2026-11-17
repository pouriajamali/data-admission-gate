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
CURATION_ACTIVE=False
CURATION_DIAGNOSTICS=None
CURATION_SAFE_ROOT=None
def safe_cause_module():
 global CURATION_DIAGNOSTICS
 if CURATION_DIAGNOSTICS is None:
  CURATION_DIAGNOSTICS=R.load_module('curation_safe_cause04','73e49eda3fb928eb79dd0d469702d4bbbd3c315959cd9bb43e85618d46e4bde3')
  D=CURATION_DIAGNOSTICS.STATE;D.bind(CURATION_DIAGNOSTICS,R.digest(CURATION_DIAGNOSTICS.__file__),'safe-cause');D.bind(sys.modules[__name__],R.read(HERE/'dotnet11-consumer04-admission.lock.json')['controllerSha256'],'caller');D.bind_loaded(HERE)
 return CURATION_DIAGNOSTICS

def curation_module():
 m=R.load_module('curate_dotnet11_linux_inputs','49b92363136e4651eb94f4f731f73b725402e44caee0509ab84625010847513f');safe_cause_module().STATE.bind(m,'49b92363136e4651eb94f4f731f73b725402e44caee0509ab84625010847513f','curation');return m

def capture_curation_cause(exc,secondary=False):
 try:
  D=safe_cause_module().STATE;D.bind_loaded(HERE);D.capture(exc,secondary);D.emit(CURATION_SAFE_ROOT,os.environ,R.ROOT,sys.stderr.buffer);return D.nodes[0]['code'] if D.nodes else 'UNKNOWN_OR_REDACTED'
 except BaseException:
  sys.stderr.buffer.write(b'{"schema":"producer04-safe-original-cause/v1","state":"HOLD_SAFE_DIAGNOSTICS_UNAVAILABLE","code":"UNKNOWN_OR_REDACTED","SDK_READY":false}\n');return 'UNKNOWN_OR_REDACTED'

def own04_common_context(spec,source,host,route,curation=False):
 root=Path(spec['root']);profilePath=HERE/('producer04-linux-curation.profile.json' if curation else 'dotnet11-consumer04-normal-profile.json');pinsPath=HERE/'dotnet11-consumer04-source-pins.json';profile=R.read(profilePath);pins=R.read(pinsPath)
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
 if spec.get('purpose')==CURATION_PURPOSE:
  return finish_curation(spec,terminal,peak)
 R.f.terminal(terminal);value=R.read(Path(spec['root'])/'consumer-worker.json');value['terminal']=terminal;value['caps']['peakMemoryBytes']=int(peak);R.f.need(R.clock()<spec['startTick']+900000,'CONSUMER900_DEADLINE');R.write(R.ROOT/'artifacts/controlled-consumer04.json',value)
def check_stage(name,expected):
 R.f.need(name in STAGES,'FIXED_STAGE_REQUIRED');v=R.read(R.ROOT/'artifacts/controlled-consumer04.json');R.f.source(v['source']['commit'],expected);R.f.terminal(v['terminal']);R.f.need(any(x['stage']==name and x['exitCode']==0 for x in v['stages']),'CONTROLLED_STAGE_NOT_COMPLETED')
def consumer_worker(path):
 global CURATION_ACTIVE,CURATION_SAFE_ROOT
 s=R.read(path);R.f.need(s['purpose'] in ('CONSUMER04_PRODUCT',CURATION_PURPOSE),'FIXED_CONSUMER_ROLE')
 if s['purpose']==CURATION_PURPOSE:
  CURATION_ACTIVE=True;CURATION_SAFE_ROOT=Path(s['root']);safe_cause_module().require_workspace(os.environ,R.ROOT);safe_cause_module().STATE.mark('bootstrap',spec=s,now=R.clock())
  R.f.need(os.name!='nt','CURATION_LINUX_ONLY');curation_module().parent_admission(s['curationAdmissionPath'],s['curationAdmissionSHA256'],s['expectedCommit'])
 if os.name=='nt':
  boot=R.read(s['bootstrap']);R.f.need(Path(sys.executable).resolve()==Path(boot['pythonExe']).resolve() and R.digest(sys.executable)==boot['pythonExeSha256'] and boot['pythonSignature']=='ValidPythonSoftwareFoundationWithTimestamp','PYTHON_BOOTSTRAP_IDENTITY');consumer_work(s,Q.Backend(s));return
 j.bind(s);cap=j.linux_caps();R.write(Path(s['root'])/'stopped-worker.json',{'pid':os.getpid(),'start':Q.start_identity(os.getpid()),'cap':cap,'uid':os.getuid(),'gid':os.getgid()});os.kill(os.getpid(),signal.SIGSTOP);w=R.read(Path(s['root'])/'held-worker-before-continue.json');R.f.need(w['pid']==os.getpid() and w['start']==Q.start_identity(os.getpid()),'HELD_WORKER_PREEXEC_IDENTITY');s['parentHeldWorkerBeforeExec']=True
 if s['purpose']==CURATION_PURPOSE:curation_module().worker(s,Q.Backend(s),R,Q)
 else:consumer_work(s,Q.Backend(s))
def main():
 global CURATION_ACTIVE
 parser=argparse.ArgumentParser();parser.add_argument('--expected-commit');parser.add_argument('--worker',type=Path);parser.add_argument('--stop-post',type=Path);parser.add_argument('--check-stage',choices=STAGES);parser.add_argument('--curation-admission',type=Path);parser.add_argument('--curation-admission-sha256');parser.add_argument('--curation-input-manifest',type=Path);parser.add_argument('--curation-event-handoff',action='store_true');args=parser.parse_args()
 CURATION_ACTIVE=bool(args.curation_admission or args.curation_event_handoff or args.curation_input_manifest)
 if args.curation_event_handoff:
  R.f.need(not (args.worker or args.stop_post or args.check_stage or args.curation_admission) and os.name!='nt','CURATION_EVENT_EXCLUSIVE')
  args.curation_admission,args.curation_admission_sha256,args.curation_input_manifest=curation_module().prepare_event_handoff(args.expected_commit)
 R.f.need(bool(args.curation_admission)==bool(args.curation_admission_sha256)==bool(args.curation_input_manifest),'CURATION_GATE_ARGUMENT_PAIR')
 if args.curation_admission:
  R.f.need(not (args.worker or args.stop_post or args.check_stage) and os.name!='nt','CURATION_EXCLUSIVE_LINUX_PURPOSE')
  gate=curation_module().parent_admission(args.curation_admission,args.curation_admission_sha256,args.expected_commit)
  curation_module().load_json(args.curation_input_manifest,gate['inputManifestSHA256'])
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
 global CURATION_SAFE_ROOT
 if args.curation_admission:
  safe_cause_module().STATE.mark('bootstrap',now=R.clock());safe_cause_module().require_workspace(os.environ,R.ROOT)
 R.f.need(os.name!='nt' and os.getuid()>0 and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Linux' and Path('/proc/1/comm').read_text().strip()=='systemd' and not Path('/.dockerenv').exists(),'NAMED_UBUNTU_HOST_REQUIRED');R.host('linux-x64');R.f.source(os.environ.get('GITHUB_SHA'),args.expected_commit)
 start=int(os.environ['SDK11_QUALIFICATION_START_TICK']);R.f.need(0<=R.clock()-start<60000,'STARTUP60_EXPIRED');temp=Path(os.environ['RUNNER_TEMP']).resolve();root=temp/('admission04-sdk11-linux-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);R.a.scoped(root,temp,absent=True);root.mkdir(mode=0o700);R.f.need(root.stat().st_uid==os.getuid() and root.stat().st_gid==os.getgid() and (root.stat().st_mode&0o777)==0o700,'FRESH_PRIVATE_RUNNER_ROOT')
 if args.curation_admission:CURATION_SAFE_ROOT=root
 unit='admission04-sdk11-ci-'+uuid.uuid4().hex;private=root/'private-spec.json';s={'purpose':'CONSUMER04_PRODUCT','rid':'linux-x64','root':str(root),'unit':unit,'uid':os.getuid(),'gid':os.getgid(),'expectedCommit':args.expected_commit,'startTick':start,'supervisorPID':os.getpid(),'supervisorStartIdentity':'proc-start:'+Q.start_identity(os.getpid())}
 if args.curation_admission:s.update({'purpose':CURATION_PURPOSE,'curationAdmissionPath':str(args.curation_admission),'curationAdmissionSHA256':args.curation_admission_sha256,'curationInputManifestPath':str(args.curation_input_manifest)})
 if args.curation_admission:
  R.f.need(curation_module().policies()[1]['inputTransport']=='PUBLIC_ORIGINALS_V1','PUBLIC_INPUT_TRANSPORT_REQUIRED');R.f.need('CURATION_INPUT_TOKEN' not in os.environ,'PUBLIC_INPUT_TOKEN_CONFIG_FORBIDDEN')
 R.write(private,s);R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000})
 for path in [str(HERE),str(root),sys.executable]:R.f.need(not any(c in path for c in ['\n','\r','%','$','"',"'"]),'SYSTEMD_FIXED_ARGV_PATH')
 envnames=['GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_EVENT_PATH','GITHUB_JOB','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_NAME','ImageOS','ImageVersion','RUNNER_TEMP'];sets=safe_cause_module().forward_environment(os.environ,R.ROOT) if args.curation_admission else ['--setenv='+k+'='+os.environ[k] for k in envnames if k in os.environ];remaining=max(1,(start+840000-R.clock())//1000);observer=' '.join(shlex.quote(str(x)) for x in [sys.executable,'-I','-S','-B',Path(__file__).resolve(),'--stop-post',private])
 argv=['/usr/bin/sudo','-n','/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid='+str(s['uid']),'--gid='+str(s['gid']),'--property=Description='+unit,'--property=MemoryMax=4294967296','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec='+str(remaining),'--property=TimeoutStopSec=5','--property=KillMode=control-group','--property=WorkingDirectory='+str(R.ROOT),'--property=ExecStopPost='+observer,'--setenv=PYTHONDONTWRITEBYTECODE=1',*sets,sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(private)]
 R.write(root/'root-starter.json',{'argv':argv,'boundary':'ExistingtrustedrootOSstarter only; fixednonrootUser/Group. Allworker/acquisition/extraction/targets/observer insideactualcgroup; norootSDK/arbitraryrootcommand/install/config.'})
 terminal,stop=(run_curation_linux(s,argv) if s['purpose']==CURATION_PURPOSE else Q.run_owned_linux(s,argv));finish_consumer(s,terminal,stop['actualCaps']['memoryPeak'])

def run_curation_linux(s,argv):
 root=Path(s['root']);proc=None;pidfd=None;error=None;stop=None;terminal=None;transitioned=False;L=curation_module();M,_=L.method_modules()
 try:
  prior,code=Q.own_unit_show(s['unit'],min(s['startTick']+60000,R.clock()+2000));R.f.need(prior.get('LoadState')=='not-found','OWN_UNIT_MUST_BE_ABSENT')
  with (root/'launcher-stdout.log').open('xb') as out,(root/'launcher-stderr.log').open('xb') as err:
   proc=subprocess.Popen(argv,stdout=out,stderr=err,env=Q.OS_ENV);deadline=min(s['startTick']+60000,R.clock()+20000)
   while not (root/'stopped-worker.json.ready').exists():
    R.f.need(proc.poll() is None and R.clock()<deadline,'STOPPED_WORKER_STARTUP_HOLD');time.sleep(.05)
   held=R.read(root/'stopped-worker.json');pid=held['pid'];R.f.need(held['uid']==s['uid'] and held['gid']==s['gid'] and Q.start_identity(pid)==held['start'],'STOPPED_WORKER_IDENTITY');pidfd=os.pidfd_open(pid);snap=M.pid_snapshot(pid,s['unit'])
   while snap['state'] not in ('T','t'):
    R.f.need(R.clock()<deadline and proc.poll() is None,'WORKER_NOT_STOPPED');time.sleep(.01);snap=M.pid_snapshot(pid,s['unit'])
   R.f.need(snap['start']==held['start'] and snap['limits']==held['cap']['kernelLimits'],'WORKER_KERNEL_READBACK');R.write(root/'held-worker-before-continue.json',{'pid':pid,'start':held['start'],'kernelLimits':snap['limits'],'pidfdRetained':True,'state':snap['state'],'cgroup':snap['cgroup']});signal.pidfd_send_signal(pidfd,signal.SIGCONT)
   while proc.poll() is None:
    R.f.need(R.clock()<s['startTick']+840000,'OWNED_WORKER840_DEADLINE');R.f.need(out.tell()+err.tell()<=1048576,'OWNED_LAUNCHER_LOG_CAP')
    requestPath=root/'network-transition-request.json'
    if not transitioned and requestPath.with_name(requestPath.name+'.ready').is_file():
     R.f.need(R.clock()<s['startTick']+540000,'OWNED_NETWORK_STAGE540');body=requestPath.read_bytes();request=json.loads(body);R.f.need(request['worker']['pid']==pid and request['worker']['start']==held['start'] and request['unit']==s['unit'] and request['sourceHEAD']==s['expectedCommit'] and request['originalStartMonotonicNs']==s['startTick']*1000000,'NETWORK_EXACT_HELD_GENERATION')
     while M.pid_snapshot(pid,s['unit'])['state'] not in ('T','t'):
      R.f.need(R.clock()<s['startTick']+540000,'NETWORK_STOPPED_HANDSHAKE');time.sleep(.001)
     R.f.need(R.digest(M.__file__)==L.METHOD_SOURCE_PINS['curation_linux_method'],'PRIVILEGED_METHOD_SOURCE_PIN')
     call=subprocess.run(['/usr/bin/sudo','-n',sys.executable,'-I','-S','-B',M.__file__,'--deny-parent',str(requestPath),'--sha256',hashlib.sha256(body).hexdigest()],capture_output=True,env=Q.OS_ENV,timeout=max(.001,min(12,(s['startTick']+540000-R.clock())/1000)))
     R.f.need(len(call.stdout)+len(call.stderr)<=16384 and not call.stderr,'OWNED_DENY_PARENT_FAILED');policy=json.loads(call.stdout)
     if call.returncode!=0:
      code=policy.get('code','OWNED_DENY_PARENT_FAILED');R.f.need(re.fullmatch('[A-Z][A-Z0-9_]{0,95}',code),'OWNED_DENY_TYPED_FAILURE');raise R.f.Denied(code)
     R.f.need(call.returncode==0,'OWNED_DENY_PARENT_FAILED');R.f.need(policy['requestSHA256']==request['requestSHA256'] and policy['worker']['pid']==pid and policy['worker']['start']==held['start'],'OWNED_DENY_PARENT_RESULT');R.write(root/'network-policy-applied.json',policy);transitioned=True;signal.pidfd_send_signal(pidfd,signal.SIGCONT)
    time.sleep(.02)
   R.f.need(proc.returncode==0 and transitioned,'OWNED_CURATION_NONZERO_OR_NO_TRANSITION')
 except BaseException as exc:error=exc;capture_curation_cause(exc)
 finally:
  safe_cause_module().STATE.mark('terminal',spec=s,now=R.clock())
  try:terminal,stop=Q.cleanup_owned_linux(s,proc,pidfd,error is not None)
  except BaseException as cleanup:
   capture_curation_cause(cleanup,secondary=error is not None)
   if error is None:error=cleanup
  if terminal is None:terminal={'cleanupResult':'UNKNOWN','ownedPopulation':'UNKNOWN','workerExitCode':'UNKNOWN'}
 if error is not None or terminal['cleanupResult']!='OWNED_TERMINAL_OBSERVED' or stop is None or stop.get('serviceResult')!='success' or stop.get('exitCode')!='exited' or stop.get('exitStatus')!='0' or stop.get('remainingPopulationExcludingObserver')!=0:
  R.failure_summary(s,R.failure_code(error) if error is not None else {'exceptionType':'Denied','code':'TYPED_CURATION_TERMINAL_REQUIRED'},terminal,stop)
  if error is not None:raise error
  raise R.f.Denied('TYPED_CURATION_TERMINAL_REQUIRED')
 return {'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'typedStopResult':'success','terminalEvidenceSha256':terminal['evidenceSha256']},stop

def finish_curation(spec,terminal,peak):
 R.f.terminal(terminal);root=Path(spec['root']);value=R.read(root/'curation-worker.json');R.f.need(value['state']=='LINUX_CURATED_INPUT_GRAPH_CANDIDATE_NOT_PRODUCT_ADMITTED' and len(value['commands'])==7 and len(value['locks'])==4 and value['network']['state']=='OWN_CURRENT_KERNEL_DENY_AND_LOOPBACK_WITNESSED','CURATION_INPUT_GRAPH_RESULTS_REQUIRED');R.f.need(R.clock()<spec['startTick']+900000,'CURATION900_DEADLINE');value.update(terminal=terminal,peakMemoryBytes=peak)
 # Existing proof artifact only. Originals plus redacted reports stay within8MiB.
 dest=R.ROOT/'artifacts/sdk11-curation-linux-x64';R.f.need(not dest.exists(),'CURATION_PROOF_EXISTS');proofModule=curation_module();candidates,durable=proofModule.curation_proof_candidates(root,value,True);total=0;files=[];prepared=[]
 for path in candidates:
  if not path.is_file():continue
  body=proofModule.read_proof_payload(root,path,value,durable);relative=path.relative_to(root).as_posix()
  originalSHA256=hashlib.sha256(body).hexdigest()
  if path.suffix=='.log':
   R.f.need(len(body)<=32768,'CURATION_REPORT_BOUND');text=body.decode('utf-8',errors='strict').replace(str(root),'${OWN_PRIVATE_ROOT}').replace(str(R.ROOT),'${CHECKOUT}');body=text.encode()
  if relative not in durable and path.suffix in ('.json','.log') and 'metadata' not in path.parts:
   body=body.decode('utf-8',errors='strict').replace(str(root),'${OWN_PRIVATE_ROOT}').replace(str(R.ROOT),'${CHECKOUT}').replace(os.environ['RUNNER_TEMP'],'${RUNNER_TEMP}').encode()
  total+=len(body);R.f.need(total<=8388608,'CURATION_PROOF8M_OVERFLOW');prepared.append((relative,body))
  files.append({'path':relative,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'originalSHA256':originalSHA256,'exactDurableOriginal':relative in durable})
 summary={'schema':'producer04-linux-curation-terminal-candidate/v1','state':value['state'],'source':value['source'],'terminal':terminal,'proofFiles':files,'proofBytes':total,'SDK_READY':False,'productAdmission':False,'WindowsQualification':False};body=(json.dumps(summary,indent=2)+'\n').encode();R.f.need(total+len(body)<=8388608,'CURATION_PROOF8M_OVERFLOW')
 dest.mkdir(parents=True,mode=0o700)
 for relative,payload in prepared:
  target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb') as out:out.write(payload)
 with (dest/'FINAL-CANDIDATE.json').open('xb') as out:out.write(body)

def publish_curation_failure_data(code):
 root=Path(os.environ['RUNNER_TEMP'])/('admission04-sdk11-linux-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);terminalPath=root/'cleanup-terminal.json'
 if not terminalPath.is_file() or R.read(terminalPath).get('cleanupResult')!='OWNED_TERMINAL_OBSERVED':return
 dest=R.ROOT/'artifacts/sdk11-curation-linux-x64'
 if dest.exists():return
 value=R.read(root/'curation-worker.json') if (root/'curation-worker.json').is_file() else R.read(root/'curation-method-failure.json') if (root/'curation-method-failure.json').is_file() else {};evidenceHold=None;proofModule=curation_module()
 try:candidates,durable=proofModule.curation_proof_candidates(root,value,False)
 except proofModule.Hold as failure:
  evidenceHold=str(failure);candidates=[];durable=set()
 bodies=[];total=0
 for path in candidates:
  if not path.is_file():continue
  R.f.need(not path.is_symlink(),'CURATION_FAILURE_PROOF_LINK');size=path.stat().st_size;total+=size
  if total>8388608-65536:break
  try:body=proofModule.read_proof_payload(root,path,value,durable)
  except proofModule.Hold as failure:evidenceHold=str(failure);break
  original=hashlib.sha256(body).hexdigest()
  if path.relative_to(root).as_posix() not in durable and path.suffix in ('.json','.log') and 'metadata' not in path.parts:body=body.decode('utf-8',errors='strict').replace(str(root),'${OWN_PRIVATE_ROOT}').replace(str(R.ROOT),'${CHECKOUT}').replace(os.environ['RUNNER_TEMP'],'${RUNNER_TEMP}').encode()
  bodies.append((path.relative_to(root),body,original))
 dest.mkdir(parents=True,mode=0o700)
 if evidenceHold is not None:
  R.write(dest/'HOLD.json',{'state':'HOLD_DURABLE_EVIDENCE_MISSING_OR_CHANGED','primaryCode':code,'durableEvidenceCode':evidenceHold,'SDK_READY':False});return
 if total>8388608-65536:
  R.write(dest/'HOLD.json',{'state':'HOLD_ORIGINALS_AND_PROOF_OVERFLOW_NO_ORIGINALS_PUBLISHED','primaryCode':code,'observedBytesAtLeast':total,'budgetBytes':8388608,'extraArtifactPermissionInferred':False});return
 for relative,body,original in bodies:
  target=dest/relative;target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb') as out:out.write(body)
 R.write(dest/'HOLD.json',{'state':'HOLD_DATA_ONLY_OWNED_TERMINAL_OBSERVED','primaryCode':code,'originalsRetained':True,'proofBytes':sum(len(b) for _,b,_ in bodies),'originalFileHashes':{p.as_posix():h for p,_,h in bodies},'exactDurableOriginals':sorted(durable),'SDK_READY':False,'productAdmission':False})

if __name__=='__main__':
 try:main()
 except BaseException as exc:
  if CURATION_ACTIVE:
   code=capture_curation_cause(exc)
   converted=R.f.Denied(code);converted.__traceback__=exc.__traceback__
   try:R.capture_entry_failure(converted)
   except BaseException as secondary:capture_curation_cause(secondary,secondary=True)
   if '--worker' not in sys.argv and '--stop-post' not in sys.argv:
    try:publish_curation_failure_data(code)
    except BaseException as secondary:capture_curation_cause(secondary,secondary=True)
   raise SystemExit(1) from None
  R.capture_entry_failure(exc);raise
