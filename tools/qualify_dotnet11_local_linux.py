"""Local Ubuntu24 qualification delta. Reuses the existing fixed supervisor.
No CI environment impersonation, SDK acquisition, installation or schema mutation.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,platform,re,select,shlex,signal,subprocess,sys,time,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=HERE/'qualify_dotnet11_linux.py'
if hashlib.sha256(p.read_bytes()).hexdigest()!='cdf1773d1d672fe78d214dd9a35616aaea0b3beade1578aa9a216e88e87a43ca':raise RuntimeError('EXISTING_SUPERVISOR_IDENTITY')
spec=importlib.util.spec_from_file_location('qualify_dotnet11_linux',p);Q=importlib.util.module_from_spec(spec);sys.modules[spec.name]=Q;spec.loader.exec_module(Q)
R=Q.R;j=Q.j
PURPOSE='FIXED_LOCAL_UBUNTU24_QUALIFICATION_ONLY'
SDK=Path('/home/ubuntu/.frl01-sdk-qja56iv8/sdk')
CATALOG_SHA='307d56b0590f5adf8bfdc03ca22d151b987774c2e49934598cfd0ac0700c0571'

def local_host(release,machine,kernel,pid1,uid,gid,github):
 R.f.need(not github,'LOCAL_CI_ENVIRONMENT_FORBIDDEN')
 R.f.need(release.get('ID')=='ubuntu' and release.get('VERSION_ID','').strip('"')=='24.04' and machine=='x86_64' and pid1=='systemd' and uid>0 and gid>0,'LOCAL_UBUNTU24_HOST_REQUIRED')
 return {'hostClass':'LocalUbuntu24.04x64','rid':'linux-x64','osRelease':release,'architecture':machine,'kernelBuild':kernel,'uid':uid,'gid':gid,'pid1':pid1,'WSL2Observed':'microsoft' in kernel.lower(),'CI':False,'supportBoundary':'Ubuntu24.04 is listed by dotnet11 supported-os.json; WSL kernel is recorded separately. This is an observed local qualification, not a CI or vendor certification.'}

def host():
 release=dict(x.split('=',1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
 return local_host(release,platform.machine(),platform.release(),Path('/proc/1/comm').read_text().strip(),os.getuid(),os.getgid(),any(os.environ.get(k) for k in ['GITHUB_ACTIONS','GITHUB_RUN_ID','RUNNER_ENVIRONMENT']))

def worker(path):
 s=R.read(path);R.f.need(s['purpose']==PURPOSE and s['controllerSha256']==R.digest(__file__),'LOCAL_PURPOSE_SOURCE');j.bind(s);cap=j.linux_caps();root=Path(s['root'])
 R.write(root/'stopped-worker.json',{'pid':os.getpid(),'start':Q.start_identity(os.getpid()),'cap':cap,'uid':os.getuid(),'gid':os.getgid()});os.kill(os.getpid(),signal.SIGSTOP)
 held=R.read(root/'held-worker-before-continue.json');R.f.need(held['pid']==os.getpid() and held['start']==Q.start_identity(os.getpid()) and held['kernelLimits']==cap['kernelLimits'],'HELD_WORKER_PREEXEC_IDENTITY');s['parentHeldWorkerBeforeExec']=True
 backend=Q.Backend(s);budget=R.Budget(s);env=R.job_environment(root);actual=host();cpu=R.linux_cpu(root);R.f.cpu(cpu);current=backend.caps();R.f.caps(current,'linux-x64')
 R.f.need(R.digest(HERE/'dotnet11-linux-qualification-inputs.lock.json')==CATALOG_SHA,'CATALOG_IDENTITY');catalog=R.read(HERE/'dotnet11-linux-qualification-inputs.lock.json');R.f.catalog(catalog,'linux-x64')
 R.f.need(SDK.is_dir() and not SDK.is_symlink(),'EXISTING_EXACT_SDK_REQUIRED');lm=R.load_module('materialize_qualification_linux',R.PINS['linuxMaterializerSha256']);lm.verify_physical(SDK,catalog['members'])
 rec,raw=R.output(backend.run,['/usr/bin/git','-c','safe.directory='+str(R.ROOT),'-C',R.ROOT,'rev-parse','HEAD','HEAD^{tree}'],R.ROOT,env,budget.deadline(10),root/'source-git');source=raw.decode().splitlines();R.f.need(len(source)==2 and source[0]==s['expectedCommit'],'EXACT_SOURCE_COMMIT')
 rec,raw=R.output(backend.run,['/usr/bin/git','-c','safe.directory='+str(R.ROOT),'-C',R.ROOT,'status','--porcelain','--untracked-files=no'],R.ROOT,env,budget.deadline(10),root/'source-clean');R.f.need(not raw.strip(),'TRACKED_SOURCE_MUST_BE_CLEAN')
 bootstrap=R.bootstrap_identity();bootstrap['boundary']='EXISTING_LOCAL_OS_BOOTSTRAP_NO_INSTALL';
 for tool in bootstrap['nativeTools']:tool['provenance']='Existing local OS tool; measured binary identity, no independent publisher verification or CI attribution.'
 R.f.need(R.clock()<budget.current,'LOCAL_BOOTSTRAP60_EXPIRED');budget.stage(3,480)
 native=R.native_prerequisites('linux-x64',SDK,root,backend.run,env,budget)
 env.update(DOTNET_ROOT=str(SDK),DOTNET_ROOT_X64=str(SDK),DOTNET_HOST_PATH=str(SDK/'dotnet'))
 work=root/'qualification';work.mkdir(mode=0o700)
 (work/'global.json').write_text('{"sdk":{"version":"11.0.100","rollForward":"disable","allowPrerelease":false}}\n')
 (work/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n')
 (work/'qualification.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework><LangVersion>15.0</LangVersion><RuntimeFrameworkVersion>11.0.0</RuntimeFrameworkVersion><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile><TreatWarningsAsErrors>true</TreatWarningsAsErrors><UseSharedCompilation>false</UseSharedCompilation></PropertyGroup></Project>\n')
 (work/'packages.lock.json').write_text('{"version":1,"dependencies":{"net11.0":{}}}\n')
 (work/'Program.cs').write_text('using System; using System.Runtime.InteropServices; Console.WriteLine("SDK11_QUALIFIED_TOKEN"); Console.WriteLine(RuntimeInformation.FrameworkDescription);\n')
 commands=[('version',['--version'],30),('info',['--info'],30),('list-sdks',['--list-sdks'],30),('list-runtimes',['--list-runtimes'],30),('compiler',['exec',str(SDK/'sdk/11.0.100/Roslyn/bincore/csc.dll'),'-version'],30),('restore',['restore','qualification.csproj','--configfile',str(work/'NuGet.Config'),'--locked-mode','-p:NuGetAudit=true','-p:NuGetAuditMode=all','-p:NuGetAuditLevel=low'],180),('build',['build','qualification.csproj','-c','Release','--no-restore','--nologo','-p:UseSharedCompilation=false','-p:BuildInParallel=false','-m:1'],300),('hello',['exec',str(work/'bin/Release/net11.0/qualification.dll')],30)]
 results=[]
 for name,args,seconds in commands:
  R.a.verify_tree(SDK,catalog['members'],'linux-x64');rec,raw=R.output(backend.run,[SDK/'dotnet',*args],work,env,budget.deadline(seconds),root/('sdk-'+name));text=raw.decode('utf-8-sig').replace('\r\n','\n')
  if name=='version':R.f.need(text.strip()=='11.0.100','SDK_VERSION')
  if name=='info':R.f.need('11.0.100' in text and '11.0.0' in text,'SDK_INFO')
  if name=='list-sdks':R.f.need('11.0.100' in text,'SDK_LIST')
  if name=='list-runtimes':R.f.need('Microsoft.NETCore.App 11.0.0 ' in text,'SDK_RUNTIME')
  if name=='compiler':R.f.need(re.fullmatch(r'[0-9]+\.[0-9]+[^\r\n]*\s*',text) is not None,'SDK_COMPILER')
  if name=='hello':R.f.need(text.splitlines()==['SDK11_QUALIFIED_TOKEN','.NET 11.0.0'],'SDK_HELLO')
  R.f.need(sum(p.stat().st_size for p in root.rglob('*') if p.is_file())<=2147483648,'LOCAL_PRIVATE2GIB')
  R.f.need(sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and p.suffix in ('.json','.log'))<=8388608,'LOCAL_PROOF8MIB')
  results.append({'name':name,'exitCode':rec['exitCode'],'pid':rec['pid'],'startIdentity':rec['childBeforeExec']['processStartIdentity'],'seconds':rec['seconds'],'processReceiptSha256':R.digest(root/('sdk-'+name+'/process.json')),'stdoutSha256':hashlib.sha256(raw).hexdigest()})
 lm.verify_physical(SDK,catalog['members']);R.f.need(R.clock()<budget.current,'SDK_AGGREGATE480_EXPIRED')
 R.write(root/'local-worker-fact.json',{'schema':'sdk11-local-ubuntu24-qualification/v1','purpose':PURPOSE,'outcome':'LOCAL_NATIVE_HOST_QUALIFICATION_OBSERVED','qualifiedOn':actual,'source':{'commit':source[0],'tree':source[1],'controllerSha256':R.digest(__file__),'existingSupervisorSha256':R.digest(Q.__file__),'runtimeSha256':R.digest(R.__file__),'jobSha256':R.digest(j.__file__)},'bootstrap':bootstrap,'cpu':cpu,'caps':current,'SDKPath':str(SDK),'archiveSHA512FromReviewedCatalog':catalog['sha512'],'memberManifestSha256':catalog['memberManifestSha256'],'fullPhysicalVerificationBeforeAndAfter':True,'physicalFiles':sum(x['type']=='file' for x in catalog['members']),'commands':results,'nativePrerequisites':native,'historicalCIQualificationReusedForInputBytesOnly':True,'freshArchiveGETs':0,'denialSuiteReplays':0,'Actions':0,'SDK_READY':False,'productAdmission':False,'frozenSchemaChanged':False})
 signal.setitimer(signal.ITIMER_REAL,0)

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--worker',type=Path,required=True);args=parser.parse_args();worker(args.worker)

def direct_root_starter():
 # Existing local-frl-delivery direct cgroup method; no daemon/password change.
 parser=argparse.ArgumentParser();parser.add_argument('--local-root-starter',action='store_true');parser.add_argument('--expected-commit',required=True);args=parser.parse_args()
 R.f.need(os.getuid()==0 and Path('/proc/1/comm').read_text().strip()=='systemd','FIXED_LOCAL_OS_STARTER_REQUIRED');R.f.source(args.expected_commit,args.expected_commit)
 start=R.clock();unit='admission04-sdk11-ci-'+uuid.uuid4().hex;group=Path('/sys/fs/cgroup')/(unit+'.service');root=Path('/home/ubuntu')/('.admission04-local-'+uuid.uuid4().hex)
 R.f.need({'cpu','memory','pids'}<=set(Path('/sys/fs/cgroup/cgroup.subtree_control').read_text().split()),'EXISTING_CGROUP_CONTROLLERS_REQUIRED_NO_CONFIGURATION_CHANGE')
 group.mkdir();limits={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'}
 for name,value in limits.items():(group/name).write_text(value)
 R.f.need({name:(group/name).read_text().strip() for name in limits}==limits,'ACTUAL_OWN_GROUP_LIMITS');root.mkdir(mode=0o700);os.chown(root,1000,1000)
 s={'purpose':PURPOSE,'rid':'linux-x64','root':str(root),'unit':unit,'uid':1000,'gid':1000,'expectedCommit':args.expected_commit,'startTick':start,'controllerSha256':R.digest(__file__),'supervisorPID':os.getpid(),'supervisorStart':Q.start_identity(os.getpid()),'rootStarterMethod':'EXISTING_LOCAL_DIRECT_CGROUP_METHOD_NO_SYSTEMD_BUS_OR_SUDO'};private=root/'private-spec.json';R.write(private,s)
 print(json.dumps({'state':'STARTED_LOCAL_QUALIFICATION','root':str(root),'unit':unit}),flush=True);proc=None;pidfd=None;error=None;terminal=None
 def confined_nonroot():
  (group/'cgroup.procs').write_text(str(os.getpid()));os.setgroups([]);os.setgid(1000);os.setuid(1000)
 try:
  with (root/'launcher-stdout.log').open('xb') as out,(root/'launcher-stderr.log').open('xb') as err:
   proc=subprocess.Popen(['/usr/bin/python3','-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(private)],cwd=R.ROOT,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'},preexec_fn=confined_nonroot,stdin=subprocess.DEVNULL,stdout=out,stderr=err);pidfd=os.pidfd_open(proc.pid)
   while not (root/'stopped-worker.json.ready').exists():
    R.f.need(proc.poll() is None and R.clock()<start+60000,'LOCAL_HELD_WORKER_STARTUP60');time.sleep(.05)
   held=R.read(root/'stopped-worker.json');pid=held['pid'];R.f.need(pid==proc.pid and held['uid']==held['gid']==1000 and Q.start_identity(pid)==held['start'],'ORIGINAL_NONROOT_WORKER_START');raw=Path('/proc',str(pid),'stat').read_text()
   while raw[raw.rfind(')')+2:].split()[0] not in ('T','t'):
    R.f.need(proc.poll() is None and R.clock()<start+60000,'LOCAL_WORKER_MUST_STOP');time.sleep(.01);raw=Path('/proc',str(pid),'stat').read_text()
   R.f.need(Q.start_identity(pid)==held['start'] and held['cap']['cgroup']=='/'+group.name and ('0::/'+group.name) in Path('/proc',str(pid),'cgroup').read_text().splitlines() and held['cap']['kernelLimits']==limits and {n:(group/n).read_text().strip() for n in limits}==limits,'HELD_ORIGINAL_CGROUP_LIMITS')
   R.write(root/'held-worker-before-continue.json',{'pid':pid,'start':held['start'],'kernelLimits':limits,'pidfdRetained':True,'state':'T','cgroup':'/'+group.name});signal.pidfd_send_signal(pidfd,signal.SIGCONT)
   while proc.poll() is None:
    R.f.need(R.clock()<start+840000,'ORIGINAL_WORK840_DEADLINE');R.f.need(out.tell()+err.tell()<=1048576,'LAUNCHER_LOG1MIB');time.sleep(.05)
   R.f.need(proc.returncode==0,'LOCAL_WORKER_NONZERO')
 except BaseException as exc:error=exc
 finally:
  end=min(start+890000,R.clock()+50000)
  if 'populated 0' not in (group/'cgroup.events').read_text():(group/'cgroup.kill').write_text('1')
  if proc is not None:
   try:proc.wait(timeout=max(.01,min(10,(end-R.clock())/1000)))
   except subprocess.TimeoutExpired:pass
  while 'populated 0' not in (group/'cgroup.events').read_text() and R.clock()<end:time.sleep(.05)
  population=0 if 'populated 0' in (group/'cgroup.events').read_text() else 'UNKNOWN';pidfdTerminal=bool(pidfd is not None and select.select([pidfd],[],[],0)[0]);launcherTerminal=bool(proc is not None and proc.poll() is not None);peak=int((group/'memory.peak').read_text());terminal={'schema':'owned-local-linux-direct-cleanup/v1','launcherTerminal':launcherTerminal,'workerPidfdTerminal':pidfdTerminal,'ownedPopulation':population,'workerExitCode':proc.returncode if launcherTerminal else 'UNKNOWN','cleanupResult':'OWNED_TERMINAL_OBSERVED' if launcherTerminal and pidfdTerminal and population==0 else 'TERMINAL_UNKNOWN_HOLD','actualKernelLimits':limits,'cgroup':'/'+group.name,'peakMemoryBytes':peak,'rootSDKExecutions':0,'existingDirectMethodReused':True};R.write(root/'cleanup-terminal.json',terminal)
  if pidfd is not None:os.close(pidfd)
  if terminal['cleanupResult']=='OWNED_TERMINAL_OBSERVED':group.rmdir()
 if error is not None or terminal['cleanupResult']!='OWNED_TERMINAL_OBSERVED':
  print(json.dumps({'state':'HOLD','root':str(root),'code':str(error)[:180] if error else 'TERMINAL_UNKNOWN_HOLD'}),flush=True)
  if error is not None:raise error
  raise R.f.Denied('TERMINAL_UNKNOWN_HOLD')
 fact=R.read(root/'local-worker-fact.json');R.f.need(len(fact['commands'])==8 and all(x['exitCode']==0 for x in fact['commands']) and R.clock()<start+900000,'EIGHT_LOCAL_COMMANDS_AND_WHOLE900');fact['terminal']=terminal;fact['caps']['peakMemoryBytes']=peak;fact['rootStarterMethod']=s['rootStarterMethod'];R.write(root/'LOCAL-HOST-FACT.json',fact);print(json.dumps({'state':'LOCAL_QUALIFICATION_COMPLETE','root':str(root),'factSha256':R.digest(root/'LOCAL-HOST-FACT.json'),'terminal':terminal}),flush=True)

if __name__=='__main__':
 if '--local-root-starter' in sys.argv:direct_root_starter()
 else:main()
