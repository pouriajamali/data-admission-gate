"""One explicitly approved experimental Windows04 qualification; no CI claims."""
from __future__ import annotations
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,platform,secrets,subprocess,sys,time,winreg
HERE=pathlib.Path(__file__).resolve().parent
p=HERE/'qualify_dotnet11_windows.py'
if hashlib.sha256(p.read_bytes()).hexdigest()!='a8f5a9947a7bad112a2162cd59e3e464f7f599276940f4a0f36d0feb5ae60b82':raise RuntimeError('EXISTING_WINDOWS_SUPERVISOR_IDENTITY')
sp=importlib.util.spec_from_file_location('qualify_dotnet11_windows',p);Q=importlib.util.module_from_spec(sp);sys.modules[sp.name]=Q;sp.loader.exec_module(Q);R=Q.R;j=Q.j
L=pathlib.Path(r'C:/Users/Office/.codex/visualizations/2026/11/10/01a1c661-2773-7f81-9ae7-c5756abd8095/metadata-framing');ROOT=L/'local-windows04-qualification-once-20261117';APPROVAL=L/'WINDOWS04-EXPERIMENTAL-HUMAN-APPROVAL.json';APPROVAL_SHA='0c62aceda7199b1027f5f0b79733a1dd732bd00d23a4d4580810bb126abfed15';SDK=pathlib.Path(r'E:/Codex WorkSpace/Git Projects/data-admission-gate/state/dotnet11-shared-20261114/trees/win-x64');LEASE=pathlib.Path(r'E:/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave2-state/LOCAL-FIXTURE-LEASE.json')

ORIGINAL_ROOT=ROOT
RESUME_ROOT=L/'local-windows04-resume-three-20261117'
RESUME_APPROVAL=L/'WINDOWS04-RESUME3-HUMAN-APPROVAL.json'
PRIOR_HEALTHY=[{'name': 'version', 'exitCode': 0, 'processReceiptSha256': '244ce36379eef315cf2c202642b2d7fce2e5fc50c32692ff9a75c736f744c0f0', 'stdoutSha256': '0bfc55ed052ad680a22f2f57cb84cb32763e7b561081b696025356d41c88bd8c', 'seconds': 0.09399999999732245}, {'name': 'info', 'exitCode': 0, 'processReceiptSha256': '8b803722491b900c01b7e4e9b54899fbb7b1bb4aed96aa7da961894580e90ea1', 'stdoutSha256': 'b0f7446966650cd559de25450de84d5402e83853f495b11e39d9e05d58a0d066', 'seconds': 0.06199999999080319}, {'name': 'list-sdks', 'exitCode': 0, 'processReceiptSha256': '65793403f2795e8ba3aae9b55ced998208609eba694b800ef97273e94edf6a32', 'stdoutSha256': '0e7c909fb5760a175dd74235e740708ee487913b79baf366af4b83675855392f', 'seconds': 0.14100000000325963}, {'name': 'list-runtimes', 'exitCode': 0, 'processReceiptSha256': 'ecf67de225cf798479b4b694d40f939febee9aedff2aeadb9ea329cdd488d2ab', 'stdoutSha256': '5e625cd017e040a11626c7f91c012719a86949267a6ad404285ffcf9c1414c32', 'seconds': 0.125}, {'name': 'compiler', 'exitCode': 0, 'processReceiptSha256': 'f1171500af06f1a512de1ca99d4093c61ebe17c9fb86f87ebdcd8b436decc476', 'stdoutSha256': '5caf8682c0c27a2a02db98f9c04cc73b4eebecb9f9839c8bcb396e4bbd3d7a12', 'seconds': 0.09399999999732245}]

def continuation_authority(v):
 R.f.need(v.get('projectId')=='04' and v.get('approved') is True and v.get('maxTotalSDKAttempts')==9 and v.get('newSDKCommandsMax')==3 and v.get('wholeSecondsMax')==300 and v.get('workSecondsMax')==240 and v.get('SDKStageSecondsMax')==180,'EXPLICIT_NUMERICAL_CONTINUATION_AUTHORITY_REQUIRED')
 return v

def previous_qualification():
 R.f.need(R.digest(ORIGINAL_ROOT/'FINAL-RECEIPT.json')=='317c018f77b1a568452610283ebfa5d06199389662b92e6786ba5e37ad66b841','EXACT_ORIGINAL_TERMINAL');old=R.read(ORIGINAL_ROOT/'FINAL-RECEIPT.json');R.f.need(old['record']['actualCap']['activeProcessesAtTeardown']==0 and old['record']['exitCode']==1,'PREVIOUS_ACTUAL_TERMINAL')
 for item in PRIOR_HEALTHY:
  path=ORIGINAL_ROOT/('sdk-'+item['name']+'/process.json');rec=R.read(path);R.f.need(rec['exitCode']==0 and not rec['timedOut'] and R.digest(path)==item['processReceiptSha256'] and R.digest(path.with_name('stdout.log'))==item['stdoutSha256'],'EXACT_HEALTHY_COMMAND_REUSE')
 R.f.need(R.digest(ORIGINAL_ROOT/'sdk-restore/process.json')=='fe18edce045893aded43595a2fb51ed4476ce27ca0a4a0e1cce9ee11f6200e39' and R.read(ORIGINAL_ROOT/'sdk-restore/process.json')['exitCode']==1,'EXACT_FAILED_RESTORE')
 pub=R.read(ORIGINAL_ROOT/'publisher.json');rec=R.read(ORIGINAL_ROOT/'publisher-check/process.json');R.f.need(len(pub)==4 and all(x['status']=='Valid' and x['timestamp'] for x in pub) and rec['exitCode']==0 and not rec['timedOut'],'EXACT_PREVIOUS_NATIVE_PUBLISHER_RESULT')
 return list(PRIOR_HEALTHY),{'reuse':'Exact prior native Microsoft publisher report; SDK full byte/namespace identity rechecked in current row.','publisherSha256':R.digest(ORIGINAL_ROOT/'publisher.json'),'processSha256':R.digest(ORIGINAL_ROOT/'publisher-check/process.json')}

def experimental_host(approved,version,build,machine,product,ci):
 R.f.need(approved and version=='26H2' and build=='26300.9974' and machine.lower()=='amd64' and product==1 and not ci,'EXACT_OWNER_APPROVED_EXPERIMENTAL_WINDOWS04_ONLY')
 return {'hostClass':'ExperimentalLocalWindows26H2x64','projectId':'04','rid':'win-x64','displayVersion':version,'kernelBuild':build,'architecture':machine,'productType':product,'CI':False,'formalDotnet11Support':'NOT_CONFIRMED','approvalSha256':APPROVAL_SHA,'scope':'Only04; neither current consumer admission nor other projects follow from this producer observation.'}

def host():
 R.f.need(R.digest(APPROVAL)==APPROVAL_SHA,'DIRECT_HUMAN_APPROVAL_IDENTITY');a=R.read(APPROVAL);R.f.need(a['projectId']=='04','SCOPED04_APPROVAL')
 with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
  v=winreg.QueryValueEx(key,'DisplayVersion')[0];b=str(winreg.QueryValueEx(key,'CurrentBuildNumber')[0])+'.'+str(winreg.QueryValueEx(key,'UBR')[0])
 return experimental_host(True,v,b,platform.machine(),sys.getwindowsversion().product_type,any(os.environ.get(k) for k in ['GITHUB_ACTIONS','GITHUB_RUN_ID','RUNNER_ENVIRONMENT']))

def worker(path):
 s=R.read(path);R.f.need(s['purpose']=='FIXED_EXPERIMENTAL_WINDOWS04_QUALIFICATION' and s['controllerSha256']==R.digest(__file__) and s['approvalSha256']==APPROVAL_SHA,'EXACT_SCOPED_LOCAL_SOURCE');boot=R.read(path.parent/'bootstrap.json');R.f.need(sys.version_info[:3]==(3,12,10) and R.digest(sys.executable)==boot['pythonExeSha256'] and R.digest(pathlib.Path(sys.executable).parent/'python312.dll')==boot['pythonDllSha256'] and boot['PSFSignaturesValidWithTimestamps'] is True,'LOCAL_PSF_BOOTSTRAP_IDENTITY');backend=Q.Backend(s);budget=R.Budget(s);resume=s.get('resumeThree',False);prior=[];prior_native=None
 if resume:
  R.f.need(R.digest(RESUME_APPROVAL)==s['continuationApprovalSha256'],'CONTINUATION_APPROVAL_BYTES');continuation_authority(R.read(RESUME_APPROVAL));prior,prior_native=previous_qualification();budget.outer=budget.start+240000;budget.current=budget.start+30000
 env=R.job_environment(ROOT)
 empty=ROOT/'program-files';empty.mkdir();empty86=ROOT/'program-files-x86';empty86.mkdir();env.update({'PROGRAMFILES':str(empty),'ProgramFiles':str(empty),'PROGRAMFILES(X86)':str(empty86),'ProgramFiles(x86)':str(empty86),'ProgramW6432':str(empty)})
 for key,name in [('PROGRAMDATA','program-data'),('APPDATA','app-data'),('LOCALAPPDATA','local-app-data')]:
  target=ROOT/name;target.mkdir();env[key]=str(target)
 actual=host();cap=backend.caps();R.f.caps(cap,'win-x64');cpu=R.windows_cpu(ROOT);R.f.cpu(cpu);catalog=R.read(HERE/'dotnet11-qualification-inputs.lock.json');R.f.need(R.digest(HERE/'dotnet11-qualification-inputs.lock.json')==R.PINS['catalogSha256'],'REVIEWED_WINDOWS_CATALOG');R.f.catalog(catalog,'win-x64');R.a.verify_tree(SDK,catalog['members'],'win-x64',full=True)
 rec,raw=R.output(backend.run,['C:/Program Files/Git/cmd/git.exe','-C',R.ROOT,'rev-parse','HEAD','HEAD^{tree}'],R.ROOT,env,budget.deadline(10),ROOT/'source-git');source=raw.decode().splitlines();R.f.need(len(source)==2 and source[0]==s['expectedCommit'],'EXACT_CURRENT_SOURCE');rec,raw=R.output(backend.run,['C:/Program Files/Git/cmd/git.exe','-C',R.ROOT,'status','--porcelain','--untracked-files=no'],R.ROOT,env,budget.deadline(10),ROOT/'source-clean');R.f.need(not raw.strip(),'CLEAN_CURRENT_SOURCE')
 bootstrap=R.bootstrap_identity();bootstrap['boundary']='EXISTING_LOCAL_PSF_SIGNED_BOOTSTRAP_NO_INSTALL'
 for tool in bootstrap['nativeTools']:tool['provenance']='Existing local OS tool, measured binary identity; no hosted CI attribution.'
 R.f.need(R.clock()<budget.current,'BOOTSTRAP60_EXPIRED');budget.stage(3,180 if resume else 480);native=prior_native if resume else R.native_prerequisites('win-x64',SDK,ROOT,backend.run,env,budget);env.update(DOTNET_ROOT=str(SDK),DOTNET_ROOT_X64=str(SDK),DOTNET_HOST_PATH=str(SDK/'dotnet.exe'))
 work=ROOT/'qualification';work.mkdir();(work/'global.json').write_text('{"sdk":{"version":"11.0.100","rollForward":"disable","allowPrerelease":false}}\n');(work/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n');(work/'qualification.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework><LangVersion>15.0</LangVersion><RuntimeFrameworkVersion>11.0.0</RuntimeFrameworkVersion><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile><TreatWarningsAsErrors>true</TreatWarningsAsErrors><UseSharedCompilation>false</UseSharedCompilation></PropertyGroup></Project>\n');(work/'packages.lock.json').write_text('{"version":1,"dependencies":{"net11.0":{}}}\n');(work/'Program.cs').write_text('using System; using System.Runtime.InteropServices; Console.WriteLine("SDK11_QUALIFIED_TOKEN"); Console.WriteLine(RuntimeInformation.FrameworkDescription);\n')
 commands=[('version',['--version'],30),('info',['--info'],30),('list-sdks',['--list-sdks'],30),('list-runtimes',['--list-runtimes'],30),('compiler',['exec',str(SDK/'sdk/11.0.100/Roslyn/bincore/csc.dll'),'-version'],30),('restore',['restore','qualification.csproj','--configfile',str(work/'NuGet.Config'),'--locked-mode','-p:NuGetAudit=true','-p:NuGetAuditMode=all','-p:NuGetAuditLevel=low'],180),('build',['build','qualification.csproj','-c','Release','--no-restore','--nologo','-p:UseSharedCompilation=false','-p:BuildInParallel=false','-m:1'],300),('hello',['exec',str(work/'bin/Release/net11.0/qualification.dll')],30)];results=[]
 if resume:commands=commands[5:]
 for name,args,seconds in commands:
  R.a.verify_tree(SDK,catalog['members'],'win-x64')
  with R.contextlib.ExitStack() as stack:
   for member in catalog['criticalMembers']:
    held=stack.enter_context(backend.hold(SDK/member['path']));R.f.need(held['sha256']==member['sha256'],'SDK_CRITICAL_HELD_IDENTITY')
   rec,raw=R.output(backend.run,[SDK/'dotnet.exe',*args],work,env,budget.deadline(seconds),ROOT/('sdk-'+name))
  text=raw.decode('utf-8-sig').replace('\r\n','\n')
  if name=='version':R.f.need(text.strip()=='11.0.100','SDK_VERSION')
  if name=='info':R.f.need('11.0.100' in text and '11.0.0' in text,'SDK_INFO')
  if name=='list-sdks':R.f.need('11.0.100' in text,'SDK_LIST')
  if name=='list-runtimes':R.f.need('Microsoft.NETCore.App 11.0.0 ' in text,'SDK_RUNTIME')
  if name=='compiler':R.f.need(R.re.fullmatch(r'[0-9]+\.[0-9]+[^\r\n]*\s*',text) is not None,'SDK_COMPILER')
  if name=='hello':R.f.need(text.splitlines()==['SDK11_QUALIFIED_TOKEN','.NET 11.0.0'],'SDK_HELLO')
  R.f.need(sum(p.stat().st_size for p in ROOT.rglob('*') if p.is_file())<=2147483648,'PRIVATE2GIB');R.f.need(sum(p.stat().st_size for p in ROOT.rglob('*') if p.is_file() and p.suffix in ('.json','.log'))<=8388608,'PROOF8MIB');results.append({'name':name,'exitCode':rec['exitCode'],'seconds':rec['seconds'],'processReceiptSha256':R.digest(ROOT/('sdk-'+name+'/process.json')),'stdoutSha256':hashlib.sha256(raw).hexdigest()})
 R.a.verify_tree(SDK,catalog['members'],'win-x64',full=True);R.f.need(R.clock()<budget.current,'SDK_AGGREGATE480');R.write(ROOT/'LOCAL-WINDOWS-WORKER-FACT.json',{'schema':'sdk11-experimental-local-windows04-qualification/v1','state':'EXPERIMENTAL_LOCAL_NATIVE_QUALIFICATION_OBSERVED','qualifiedOn':actual,'source':{'commit':source[0],'tree':source[1],'controllerSha256':R.digest(__file__),'existingSupervisorSha256':R.digest(Q.__file__),'runtimeSha256':R.digest(R.__file__),'jobSha256':R.digest(j.__file__)},'bootstrap':bootstrap,'caps':cap,'cpu':cpu,'nativePublisherValidation':native,'SDKPath':str(SDK),'memberManifestSha256':catalog['memberManifestSha256'],'fullPhysicalFilesVerified':5480,'fullPhysicalBeforeAndAfter':True,'archiveSHA512FromReviewedCatalog':catalog['sha512'],'commands':prior+results,'newSDKCommands':len(results),'SDKAttemptsTotal':9 if resume else 8,'priorSourceCommit':'ec5cd5565d5bdf86899dd0dcbbd05f0ac2c3d870' if resume else None,'qualificationBoundary':'Composite qualification: five exact healthy original command receipts plus three new commands; one failed restore retained and counted.' if resume else 'Single qualification row','Actions':0,'SDKDownloads':0,'healthyCIReplays':0,'frozenSchemaChanged':False,'SDK_READY':False,'productAdmission':False,'formalDotnet11Support':'NOT_CONFIRMED'})

def main():
 global ROOT
 p=argparse.ArgumentParser();p.add_argument('--expected-commit');p.add_argument('--worker',type=pathlib.Path);p.add_argument('--resume-three',action='store_true');p.add_argument('--continuation-approval-sha');args=p.parse_args()
 if args.resume_three or (args.worker and args.worker.parent==RESUME_ROOT):ROOT=RESUME_ROOT
 if args.resume_three:
  R.f.need(args.continuation_approval_sha and R.digest(RESUME_APPROVAL)==args.continuation_approval_sha,'NEW_HUMAN_NUMERICAL_APPROVAL_REQUIRED');continuation_authority(R.read(RESUME_APPROVAL));previous_qualification()
 if args.worker:
  R.f.need(args.worker==ROOT/'private-spec.json','EXACT_WORKER_SPEC_PATH');worker(args.worker);return
 host();R.f.need(args.expected_commit is not None and not ROOT.exists(),'ONE_FRESH_WINDOWS04_QUALIFICATION');R.f.need(R.digest(LEASE.with_name('LEASE-PROTOCOL.json'))=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CANONICAL_LEASE_PROTOCOL');lease={'projectId':'04','randomToken':secrets.token_hex(16),'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':j._start_identity(os.getpid()),'phase':'EXPLICIT_EXPERIMENTAL_WINDOWS04_EIGHT_SDK_QUALIFICATION','startedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'receiptDirectory':str(ROOT)}
 start=R.clock();python=pathlib.Path(sys.executable);dll=python.parent/'python312.dll';ps="$ErrorActionPreference='Stop'; $paths=@('"+str(python).replace("'","''")+"','"+str(dll).replace("'","''")+"'); @($paths | ForEach-Object { $s=Get-AuthenticodeSignature -LiteralPath $_; [pscustomobject]@{valid=($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -match 'Python Software Foundation' -and $null -ne $s.TimeStamperCertificate)} }) | ConvertTo-Json -Compress";signatures=json.loads(subprocess.check_output(['C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-NonInteractive','-Command',ps],env={**{k:os.environ[k] for k in ('SystemRoot','WINDIR','COMSPEC','USERPROFILE','TEMP','TMP') if k in os.environ},'PATH':'C:/Windows/System32;C:/Windows','PSModulePath':'C:/Windows/System32/WindowsPowerShell/v1.0/Modules'},timeout=20));R.f.need(len(signatures)==2 and all(x['valid'] for x in signatures),'PSF_BOOTSTRAP_SIGNATURES');boot={'pythonExeSha256':R.digest(python),'pythonDllSha256':R.digest(dll),'PSFSignaturesValidWithTimestamps':True}
 try:
  with LEASE.open('x',encoding='utf-8') as out:json.dump(lease,out);out.flush();os.fsync(out.fileno())
 except FileExistsError:print(json.dumps({'state':'LEASE_BUSY_NOT_STARTED','SDK':0}));return
 ROOT.mkdir();R.write(ROOT/'bootstrap.json',boot);R.write(ROOT/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+(30000 if args.resume_three else 60000)});s={'root':str(ROOT),'rid':'win-x64','purpose':'FIXED_EXPERIMENTAL_WINDOWS04_QUALIFICATION','expectedCommit':args.expected_commit,'startTick':start,'controllerSha256':R.digest(__file__),'approvalSha256':APPROVAL_SHA,'resumeThree':args.resume_three,'continuationApprovalSha256':args.continuation_approval_sha};private=ROOT/'private-spec.json';record=None;error=None
 env={k:os.environ[k] for k in ('SystemRoot','WINDIR','COMSPEC','PATHEXT','USERPROFILE') if k in os.environ};env.update(PATH='C:/Windows/System32;C:/Windows',PYTHONDONTWRITEBYTECODE='1')
 try:record=j.run_job([sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--worker',str(private)],R.ROOT,env,start+(240000 if args.resume_three else 840000),ROOT/'outer-job',job_name='Local\\admission04-experimental-'+secrets.token_hex(12),ready_spec={'path':private,'value':s},stage_directory=ROOT)
 except BaseException as exc:error={'type':type(exc).__name__,'code':str(exc)[:180]}
 if record is None and (ROOT/'outer-job/process.json').is_file():record=R.read(ROOT/'outer-job/process.json')
 good=record and record['exitCode']==0 and not record['timedOut'] and record['actualCap']['activeProcessesAtTeardown']==0 and (ROOT/'LOCAL-WINDOWS-WORKER-FACT.json').is_file() and error is None and R.clock()<start+(300000 if args.resume_three else 900000)
 R.write(ROOT/'FINAL-RECEIPT.json',{'state':'EXPERIMENTAL_WINDOWS04_QUALIFICATION_COMPLETE' if good else 'HOLD','record':record,'error':error,'elapsedSeconds':(R.clock()-start)/1000,'formalDotnet11Support':'NOT_CONFIRMED','Actions':0,'SDK_READY':False,'productAdmission':False})
 if good:
  fact=R.read(ROOT/'LOCAL-WINDOWS-WORKER-FACT.json');fact['terminal']={'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'processReceiptSha256':R.digest(ROOT/'outer-job/process.json')};fact['caps']['peakMemoryBytes']=record['actualCap']['peakJobMemory'];R.write(ROOT/'LOCAL-WINDOWS-HOST-FACT.json',fact)
 if record and record['actualCap']['activeProcessesAtTeardown']==0:
  R.f.need(R.read(LEASE)==lease,'EXACT_OWN_LEASE_RELEASE');LEASE.unlink();R.write(ROOT/'LEASE-RELEASED.json',{'state':'RELEASED_AFTER_ACTUAL_TERMINAL','terminalSha256':R.digest(ROOT/'outer-job/process.json'),'tokenSha256':hashlib.sha256(lease['randomToken'].encode()).hexdigest()})
 print(json.dumps({'state':'EXPERIMENTAL_WINDOWS04_QUALIFICATION_COMPLETE' if good else 'HOLD','receipt':str(ROOT/'FINAL-RECEIPT.json'),'error':error}),flush=True)
 if not good:raise SystemExit(1)
if __name__=='__main__':main()
