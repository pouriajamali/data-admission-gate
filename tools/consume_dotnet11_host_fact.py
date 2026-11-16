"""Own04 accepted-host-fact consumer; no globalREADY or qualification-input bypass."""
from __future__ import annotations
import argparse,contextlib,hashlib,importlib.util,json,os,re,select,shlex,signal,subprocess,sys,time,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent
# Controllers are source-bound siblings in the exact signed/approved CI projection.
def module(name):
 p=HERE/(name+'.py');expected={'qualify_dotnet11_windows': '1d6b9a6cb7cfbac0c46be6de519b65a4f913475d87544528cc4c405632446244', 'qualify_dotnet11_linux': '2182f7989e9d7c4bf3aa4fb7d8878106fbf75de9f49f0746dea2cad8c0e35d4e'}[name]
 if hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise RuntimeError('CONSUMER_BACKEND_SOURCE_IDENTITY')
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
Q=module('qualify_dotnet11_windows' if os.name=='nt' else 'qualify_dotnet11_linux');R=Q.R;j=Q.j
STAGES=['locked-tests','package','extract','package-checks','technology-checks']
def consumer_work(spec,backend):
 root=Path(spec['root']);rid=spec['rid'];budget=R.Budget(spec);env=R.job_environment(root);host=R.host(rid);cap=backend.caps();R.f.caps(cap,rid);source=R.source_context(spec['expectedCommit'],backend.run,env,budget,root,qualification=False)
 lock=R.read(HERE/'dotnet11-consumer04-admission.lock.json');R.f.need(lock.get('state')=='ADMITTED_EXACT_SUPPORTED_HOST_CLASS' and lock.get('projectId')=='04','CONSUMER_ADMISSION_REQUIRED');binding=lock.get('producerFactsByRid',{}).get(rid);R.f.need(type(binding) is dict,'CONSUMER_RID_FACT_UNBOUND')
 base=HERE/'accepted-sdk11-ci';factpath=R.a.scoped(base/binding['factFile'],base);R.f.need(R.digest(factpath)==binding['factSha256'],'CONSUMER_FACT_IDENTITY');fact=R.read(factpath);R.f.validate_fact(fact,R.read(HERE/'dotnet11-host-qualification.schema.json'))
 current={'rid':rid,'hostClass':host['hostClass'],'sourceCommit':source['commit'],'sourceTree':source['tree'],'contractSha256':lock['contractSha256'],'runId':host['runId'],'job':host['job'],'attempt':host['attempt'],'caps':cap};admission=dict(binding['admission'])
 pins=lock.get('sourcePins');R.f.need(type(pins) is list and pins and R.f.h(pins)==lock.get('sourcePinTableSha256'),'CONSUMER_SOURCE_PIN_TABLE')
 git=Path('C:/Program Files/Git/cmd/git.exe' if os.name=='nt' else '/usr/bin/git');rec,index=R.output(backend.run,[git,'-C',R.ROOT,'ls-files','--stage','-z'],R.ROOT,env,budget.deadline(10),root/'source-index');actual={}
 for row in index.split(b'\0'):
  if not row:continue
  metadata,path=row.split(b'\t',1);mode,blob,stage=metadata.decode().split();R.f.need(stage=='0' and mode in ('100644','100755'),'CONSUMER_SOURCE_INDEX_MODE');actual[path.decode()]={'mode':mode,'gitBlob':blob}
 expected={x['path']:{'mode':x['mode'],'gitBlob':x['gitBlob']} for x in pins};exceptions={'tools/dotnet11-consumer04-admission.lock.json'}
 for entry in lock['producerFactsByRid'].values():
  if type(entry) is dict:exceptions.update('tools/accepted-sdk11-ci/'+entry[k] for k in ['factFile','catalogFile'])
 R.f.need(set(actual)-exceptions==set(expected) and all(actual.get(k)==v for k,v in expected.items()),'CONSUMER_SOURCE_CHANGED');R.output(backend.run,[git,'-C',R.ROOT,'diff','--quiet','HEAD','--'],R.ROOT,env,budget.deadline(10),root/'source-clean')
 R.f.need(lock.get('sourceBindingStrategy')=='EXACT_EVENT_COMMIT_AND_SOURCE_PINS','CONSUMER_SOURCE_STRATEGY');admission.update(sourceCommit=source['commit'],sourceTree=source['tree']);handshake=R.f.consume(fact,admission,current,R.digest(factpath));schema=R.read(HERE/'dotnet11-host-qualification.schema.json');typed={'schema':'sdk11-consumer-host-admission/v1','state':'ADMITTED_EXACT_SUPPORTED_HOST_CLASS','projectId':'04','producerFactSha256':R.digest(factpath),'admittedFor':{'hostClass':host['hostClass'],'rid':rid,'sdk':'11.0.100','runtime':'11.0.0','memberManifestSha256':fact['tree']['memberManifestSha256'],'contractSha256':lock['contractSha256'],'sourcePinTableSha256':lock['sourcePinTableSha256'],'controllerSha256':R.digest(Path(__file__)),'profileSha256':R.digest(HERE/'dotnet11-consumer04-admission.lock.json')},'currentExecution':{'runId':host['runId'],'job':host['job'],'attempt':host['attempt'],'instanceId':host['instanceId'],'ownCapsEvidenceSha256':cap['kernelReadbackSha256']},'identityRule':'QUALIFIED_ON_IS_HISTORICAL_PRODUCER_INSTANCE_CURRENT_CONSUMER_JOB_MAY_DIFFER'};R.f.schema_check(typed,schema['$defs']['consumerAdmission']);R.write(root/'consumer-host-handshake.json',typed)
 cp=R.a.scoped(base/binding['catalogFile'],base);R.f.need(R.digest(cp)==binding['catalogSha256'],'CONSUMER_CATALOG_IDENTITY');catalog=R.read(cp);R.f.need(catalog.get('state')=='ACCEPTED_HOST_TYPED_CATALOG' and catalog.get('rid')==rid and catalog.get('memberManifestSha256')==fact['tree']['memberManifestSha256'] and R.f.h(catalog['members'])==catalog['memberManifestSha256'],'CONSUMER_CATALOG_NOT_ADMITTED');R.f.need((catalog['url'],catalog['bytes'],catalog['sha512'])==R.f.RAW[rid],'CONSUMER_ARCHIVE_IDENTITY')
 cpu=R.windows_cpu(root) if rid=='win-x64' else R.linux_cpu(root);R.f.cpu(cpu);R.bootstrap_identity();marker,raw=R.output(backend.run,[sys.executable,'-I','-S','-B','-c','print("CONSUMER04_CAPS_MARKER")'],R.ROOT,env,budget.deadline(5),root/'own-sdk0-marker');R.f.need(raw.strip()==b'CONSUMER04_CAPS_MARKER','OWN_CONSUMER_CONTROL_REQUIRED')
 for mode,flags,opt in [('normal',[],None),('O',['-O'],None),('env2',[],'2')]:
  e=dict(env)
  if opt:e['PYTHONOPTIMIZE']=opt
  rec,raw=R.output(backend.run,[sys.executable,'-S','-B',*flags,HERE/'test_dotnet11_consumer04.py','--rid',rid,'--out',root/('own-denials-'+mode)],R.ROOT,e,budget.deadline(8),root/('own-denial-process-'+mode));v=R.read(root/('own-denials-'+mode+'/receipt.json'));R.f.need(v['count']==6 and v['optimize']==(2 if opt else 1 if flags else 0) and v['candidateSpawns']==0,'OWN_CONSUMER_DENIAL_REQUIRED')
 budget.stage(1,120);archive,archive_fact=R.acquire(catalog,root,budget);budget.stage(2,180);sdk=root/'sdk'
 if rid=='win-x64':members=R.a.extract_members(archive,sdk,rid);R.f.need(members==catalog['members'],'CONSUMER_MEMBER_MANIFEST');R.a.verify_tree(sdk,members,rid,full=True)
 else:lm=R.load_module('materialize_qualification_linux',R.PINS['linuxMaterializerSha256']);members=lm.materialize(catalog,archive,sdk)
 budget.stage(3,max(1,int((budget.outer-R.clock())/1000)));env.update({'DOTNET_ROOT':str(sdk),'DOTNET_ROOT_X64':str(sdk),'DOTNET_HOST_PATH':str(sdk/('dotnet.exe' if rid=='win-x64' else 'dotnet')),'PATH':str(sdk)+os.pathsep+env['PATH']});R.native_prerequisites(rid,sdk,root,backend.run,env,budget)
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
 R.a.verify_tree(sdk,members,rid,full=True);R.write(root/'consumer-worker.json',{'state':'CONTROLLED_CONSUMER04_PRODUCT_COMPLETED','rid':rid,'source':source,'producerFactSha256':binding['factSha256'],'producerQualifiedOn':fact['qualifiedOn'],'currentExecution':{k:host[k] for k in ['hostClass','rid','runId','job','attempt','imageVersion','instanceId']},'caps':backend.caps(),'stages':records,'admissionSha256':R.digest(HERE/'dotnet11-consumer04-admission.lock.json'),'scope':'Alloriginal109/17/4acceptance remains in originaltools; not automaticallypassed by SDKqualification.'})
 if os.name!='nt':signal.setitimer(signal.ITIMER_REAL,0)
def finish_consumer(spec,terminal,peak):
 R.f.terminal(terminal);value=R.read(Path(spec['root'])/'consumer-worker.json');value['terminal']=terminal;value['caps']['peakMemoryBytes']=int(peak);R.f.need(R.clock()<spec['startTick']+900000,'CONSUMER900_DEADLINE');R.write(R.ROOT/'artifacts/controlled-consumer04.json',value)
def check_stage(name,expected):
 R.f.need(name in STAGES,'FIXED_STAGE_REQUIRED');v=R.read(R.ROOT/'artifacts/controlled-consumer04.json');R.f.source(v['source']['commit'],expected);R.f.terminal(v['terminal']);R.f.need(any(x['stage']==name and x['exitCode']==0 for x in v['stages']),'CONTROLLED_STAGE_NOT_COMPLETED')
def consumer_worker(path):
 s=R.read(path);R.f.need(s['purpose']=='CONSUMER04_PRODUCT','FIXED_CONSUMER_ROLE')
 if os.name=='nt':
  boot=R.read(s['bootstrap']);R.f.need(Path(sys.executable).resolve()==Path(boot['pythonExe']).resolve() and R.digest(sys.executable)==boot['pythonExeSha256'] and boot['pythonSignature']=='ValidPythonSoftwareFoundationWithTimestamp','PYTHON_BOOTSTRAP_IDENTITY');consumer_work(s,Q.Backend(s));return
 j.bind(s);cap=j.linux_caps();R.write(Path(s['root'])/'stopped-worker.json',{'pid':os.getpid(),'start':Q.start_identity(os.getpid()),'cap':cap,'uid':os.getuid(),'gid':os.getgid()});os.kill(os.getpid(),signal.SIGSTOP);w=R.read(Path(s['root'])/'held-worker-before-continue.json');R.f.need(w['pid']==os.getpid() and w['start']==Q.start_identity(os.getpid()),'HELD_WORKER_PREEXEC_IDENTITY');s['parentHeldWorkerBeforeExec']=True;consumer_work(s,Q.Backend(s))
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--expected-commit');parser.add_argument('--worker',type=Path);parser.add_argument('--stop-post',type=Path);parser.add_argument('--check-stage',choices=STAGES);args=parser.parse_args()
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
 unit='admission04-sdk11-ci-'+uuid.uuid4().hex;private=root/'private-spec.json';s={'purpose':'CONSUMER04_PRODUCT','rid':'linux-x64','root':str(root),'unit':unit,'uid':os.getuid(),'gid':os.getgid(),'expectedCommit':args.expected_commit,'startTick':start};R.write(private,s);R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000})
 for path in [str(HERE),str(root),sys.executable]:R.f.need(not any(c in path for c in ['\n','\r','%','$','"',"'"]),'SYSTEMD_FIXED_ARGV_PATH')
 envnames=['GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_EVENT_PATH','GITHUB_JOB','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_NAME','ImageOS','ImageVersion','RUNNER_TEMP'];sets=['--setenv='+k+'='+os.environ[k] for k in envnames if k in os.environ];remaining=max(1,(start+840000-R.clock())//1000);observer=' '.join(shlex.quote(str(x)) for x in [sys.executable,'-I','-S','-B',Path(__file__).resolve(),'--stop-post',private])
 argv=['/usr/bin/sudo','-n','/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid='+str(s['uid']),'--gid='+str(s['gid']),'--property=Description='+unit,'--property=MemoryMax=4294967296','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec='+str(remaining),'--property=TimeoutStopSec=5','--property=KillMode=control-group','--property=WorkingDirectory='+str(R.ROOT),'--property=ExecStopPost='+observer,'--setenv=PYTHONDONTWRITEBYTECODE=1',*sets,sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(private)]
 R.write(root/'root-starter.json',{'argv':argv,'boundary':'ExistingtrustedrootOSstarter only; fixednonrootUser/Group. Allworker/acquisition/extraction/targets/observer insideactualcgroup; norootSDK/arbitraryrootcommand/install/config.'})
 terminal,stop=Q.run_owned_linux(s,argv);finish_consumer(s,terminal,stop['actualCaps']['memoryPeak'])

if __name__=='__main__':
 try:main()
 except BaseException as exc:
  R.capture_entry_failure(exc);raise
