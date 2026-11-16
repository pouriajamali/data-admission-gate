"""Fixed SDK11 CI recipes; library only. No source import performs acquisition/targets."""
from __future__ import annotations
import argparse,contextlib,ctypes,gzip,hashlib,importlib.util,json,os,platform,re,signal,ssl,stat,struct,subprocess,sys,tarfile,time,urllib.request,zipfile
from pathlib import Path,PureWindowsPath,PurePosixPath
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
PINS={'catalogSha256': 'f87ecbf9ffebd4bcb6cd435739a070042e8c20299f63882e0277803478b54c7a', 'fixtureSha256': 'd8b2b3bc9a95ba1e7ab9332f3fcef9826e7cbd9fd83059c7f2e0d475627aa13f', 'jobHelperSha256': '0959e7cb097bb17d774ed0824bb7b9e95e1b94112d968d343fb9fca0fb5166ce', 'memberManifestSha256': '7eb452d5eaa748773eb0b12d1abc8da1a9f1c192b06444dc88c6511de56b63c3', 'catalogRows': 5480, 'schemaSha256': '63e04fa5d270c87b93e6e1f4c38bfbcf336b950b39fe1854dc4e514f0661f14c', 'factHelperSha256': '6bb0fe5199377dfdb0caed76cf274bcef631205648d9dbf0d67e1f43433e9a7e', 'linuxCatalogSha256': '307d56b0590f5adf8bfdc03ca22d151b987774c2e49934598cfd0ac0700c0571', 'inputGuardSha256': '7420b08d78d3b1476be41385d179a42212a2a7e1a965a8d8ea3b67bb14da7925', 'linuxMaterializerSha256': '5f0dbb951cbe615d8c6dd9edbb63b11143cc457319bdcc9000ea9a486f660fb8', 'profileSha256': '8b5805bea186078e76afd0917bc5a2a990af3f3b990ba231965d99290e417ad9'}
def digest(p,algorithm='sha256'):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,algorithm).hexdigest()
def load_module(name,sha):
 p=HERE/(name+'.py')
 if digest(p)!=sha:raise RuntimeError('SOURCE_MODULE_IDENTITY:'+name)
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
f=load_module('sdk11_ci_facts',PINS['factHelperSha256']);a=load_module('qualification_input_guard',PINS['inputGuardSha256'])
def write(p,v):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('x',encoding='utf-8',newline='\n') as out:json.dump(v,out,indent=2);out.write('\n')
 with p.with_name(p.name+'.ready').open('x'):pass
def read(p,limit=16777216):
 p=Path(p);f.need(p.is_file() and not p.is_symlink() and p.stat().st_size<=limit,'INPUT_FILE_IDENTITY');return json.loads(p.read_bytes())
def clock():
 if os.name=='nt':
  k=ctypes.WinDLL('kernel32');k.GetTickCount64.restype=ctypes.c_ulonglong;return int(k.GetTickCount64())
 return time.monotonic_ns()//1000000
class Budget:
 def __init__(self,spec):
  self.spec=spec;self.root=Path(spec['root']);self.start=int(spec['startTick']);self.outer=self.start+840000;self.current=self.start+60000
  if os.name!='nt':signal.setitimer(signal.ITIMER_REAL,max(.001,(self.current-clock())/1000))
 def stage(self,index,seconds):
  self.current=min(self.outer,clock()+seconds*1000) if index else self.start+60000
  f.need(clock()<self.current,'OUTER_STAGE_BUDGET_EXPIRED');write(self.root/('stage-'+str(index)+'.json'),{'index':index,'deadlineTick':self.current,'startedTick':clock()})
  if os.name!='nt':signal.setitimer(signal.ITIMER_REAL,max(.001,(self.current-clock())/1000))
 def deadline(self,seconds):f.need(clock()<self.current,'OUTER_STAGE_BUDGET_EXPIRED');return min(self.current,clock()+seconds*1000)
def host(rid,diagnostic_root=None):
 base={'hostClass':f.HOSTS[rid],'rid':rid,'imageOS':os.environ.get('ImageOS',''),'imageVersion':os.environ.get('ImageVersion',''),'runId':os.environ.get('GITHUB_RUN_ID',''),'job':os.environ.get('GITHUB_JOB',''),'attempt':os.environ.get('GITHUB_RUN_ATTEMPT',''),'repository':os.environ.get('GITHUB_REPOSITORY',''),'architecture':'x64','instanceId':os.environ.get('RUNNER_NAME','')}
 machine=platform.machine();machine_ok=machine.lower() in ('amd64','x86_64')
 if rid=='win-x64':
  import winreg
  observed={'imageOS':base['imageOS'],'imageVersion':base['imageVersion'],'machine':machine,'pointerBits':ctypes.sizeof(ctypes.c_void_p)*8,'runnerEnvironment':os.environ.get('RUNNER_ENVIRONMENT','UNKNOWN'),'runnerOS':os.environ.get('RUNNER_OS','UNKNOWN'),'productType':'UNKNOWN','windowsBuild':'UNKNOWN','registryProductName':'UNKNOWN','registryCurrentBuildNumber':'UNKNOWN','registryUBR':'UNKNOWN','readStatus':'UNKNOWN','readErrorType':'NONE','readErrorCode':None}
  try:
   version=sys.getwindowsversion();observed.update(productType=version.product_type,windowsBuild=version.build)
   with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
    for source,dest in [('ProductName','registryProductName'),('CurrentBuildNumber','registryCurrentBuildNumber'),('UBR','registryUBR')]:observed[dest]=winreg.QueryValueEx(key,source)[0]
   observed['readStatus']='COMPLETE'
  except OSError as exc:observed.update(readStatus='PARTIAL_OR_UNAVAILABLE',readErrorType=type(exc).__name__,readErrorCode=getattr(exc,'winerror',getattr(exc,'errno',None)))
  base.update(osVersion=observed['registryProductName'],kernelBuild=str(observed['registryCurrentBuildNumber'])+'.'+str(observed['registryUBR']),uid=None,gid=None)
  predicates={'machineX64':machine_ok,'pointer64':observed['pointerBits']==64,'serverProduct3':observed['productType']==3,'kernelBuild26100':observed['windowsBuild']==26100,'hostedRunner':observed['runnerEnvironment']=='github-hosted','windowsRunner':observed['runnerOS']=='Windows','registryReadComplete':observed['readStatus']=='COMPLETE',**f.windows_host_predicates(base)}
  if diagnostic_root is not None:write(Path(diagnostic_root)/'windows-host-observation.json',{'schema':'sdk11-windows-host-observation/v1','state':'OBSERVED_BEFORE_WINDOWS_OS_DENIAL','observed':observed,'predicates':predicates})
  f.need(machine_ok,'Q_HOST_CLASS');f.need(all(predicates.values()),'Q_HOST_OS')
 else:
  f.need(machine_ok,'Q_HOST_CLASS');f.need('microsoft' not in platform.release().lower() and not os.environ.get('WSL_DISTRO_NAME'),'LOCAL_WSL_SDK_TARGETS_EXCLUDED')
  release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line);f.need(release.get('ID')=='ubuntu' and release.get('VERSION_ID','').strip('"')=='24.04','Q_HOST_OS');base.update(osVersion='Ubuntu 24.04',kernelBuild=platform.release(),uid=os.getuid(),gid=os.getgid())
 f.host(base,rid);return base
def source_context(expected,run,env,budget,root,qualification=True):
 f.need(os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_REPOSITORY')=='pouriajamali/data-admission-gate','Q_HOST_IMAGE')
 if qualification:
  event=read(os.environ['GITHUB_EVENT_PATH'],4194304);f.need(os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and event.get('inputs',{}).get('mode')=='sdk11-ci-qualification' and os.environ.get('GITHUB_REF')=='refs/heads/codex/sdk11-supported-ci-qualification-20261116','Q_QUALIFICATION_EVENT')
  f.source(event['inputs'].get('expected_commit'),expected)
 elif os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch':f.need(read(os.environ['GITHUB_EVENT_PATH'],4194304).get('inputs',{}).get('mode','ordinary')=='ordinary','CONSUMER_EVENT_SCOPE')
 git=Path('C:/Program Files/Git/cmd/git.exe' if os.name=='nt' else '/usr/bin/git');f.need(git.is_file(),'Q_BOOTSTRAP_GIT')
 rec=run([git,'-C',ROOT,'rev-parse','HEAD','HEAD^{tree}'],ROOT,env,budget.deadline(10),root/'source-git');out=(root/'source-git/stdout.log').read_text().splitlines();f.need(len(out)==2,'Q_SOURCE_IDENTITY');f.source(out[0],expected);f.source(os.environ.get('GITHUB_SHA'),expected)
 return {'commit':out[0],'tree':out[1],'ref':os.environ['GITHUB_REF'],'workflowSha256':digest(ROOT/'.github/workflows/verify.yml'),'controllerSha256':digest(HERE/(('qualify_dotnet11_windows.py' if os.name=='nt' else 'qualify_dotnet11_linux.py') if qualification else 'consume_dotnet11_host_fact.py')),'helperSha256':digest(HERE/('windows_qualification_job.py' if os.name=='nt' else 'linux_qualification_job.py')),'schemaSha256':PINS['schemaSha256'],'catalogSha256':'','normalGuardSha256':'d9c690d8c82825b018c04089c279036829d3baf2534c2634bba84910c415a37d'}
def job_environment(root):
 for key in ['LD_PRELOAD','LD_LIBRARY_PATH','DOTNET_STARTUP_HOOKS','DOTNET_ADDITIONAL_DEPS','CORECLR_ENABLE_PROFILING','CORECLR_PROFILER','NUGET_PLUGIN_PATHS']:
  f.need(not os.environ.get(key),'UNSAFE_RUNTIME_ENVIRONMENT')
 allowed=['SystemRoot','WINDIR','COMSPEC','PATHEXT','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE','LANG','LC_ALL','HOME','USERPROFILE','USER','LOGNAME'];env={k:os.environ[k] for k in allowed if k in os.environ};env['PATH']='C:/Windows/System32;C:/Windows;C:/Program Files/Git/cmd' if os.name=='nt' else '/usr/bin:/bin'
 for name in ['cli-home','packages','http','tmp']:(root/name).mkdir(mode=0o700)
 env.update({'DOTNET_CLI_HOME':str(root/'cli-home'),'NUGET_PACKAGES':str(root/'packages'),'NUGET_HTTP_CACHE_PATH':str(root/'http'),'TMP':str(root/'tmp'),'TEMP':str(root/'tmp'),'TMPDIR':str(root/'tmp'),'DOTNET_CLI_TELEMETRY_OPTOUT':'1','DOTNET_GENERATE_ASPNET_CERTIFICATE':'false','DOTNET_SKIP_FIRST_TIME_EXPERIENCE':'1','DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE':'true','DOTNET_MULTILEVEL_LOOKUP':'0','DOTNET_PROCESSOR_COUNT':'2','MSBUILDDISABLENODEREUSE':'1','DOTNET_CLI_USE_MSBUILD_SERVER':'0','DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER':'1','PYTHONDONTWRITEBYTECODE':'1'});return env
def bootstrap_identity():
 f.need(sys.version_info[:2]==(3,12) and (os.name!='nt' or sys.version_info[:3]==(3,12,10)),'PYTHON_VERSION_IDENTITY');rows=[];seen=set();total=0
 for m in list(sys.modules.values()):
  name=getattr(m,'__file__',None)
  if not name:continue
  p=Path(name).resolve()
  if p in seen or not p.is_file():continue
  seen.add(p);total+=p.stat().st_size;f.need(len(seen)<=512 and total<=268435456,'PYTHON_STDLIB_CLOSURE_LIMIT')
  if p.is_relative_to(ROOT):relative='REPO/'+p.relative_to(ROOT).as_posix()
  else:f.need(p.is_relative_to(Path(sys.base_prefix).resolve()),'PYTHON_STDLIB_EXTERNAL');relative='PYTHON/'+p.relative_to(Path(sys.base_prefix).resolve()).as_posix()
  rows.append({'relative':relative,'bytes':p.stat().st_size,'sha256':digest(p)})
 if os.name=='nt':
  prefix=Path(sys.base_prefix)
  for p in [*prefix.glob('*.dll'),*(prefix/'DLLs').glob('*.dll'),*(prefix/'DLLs').glob('*.pyd')]:
   p=p.resolve()
   if p not in seen:
    seen.add(p);total+=p.stat().st_size;f.need(len(seen)<=512 and total<=268435456,'PYTHON_STDLIB_CLOSURE_LIMIT');rows.append({'relative':'PYTHON/'+p.relative_to(prefix.resolve()).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)})
 rows.sort(key=lambda x:x['relative']);tools=[]
 names=[('kernel32','C:/Windows/System32/kernel32.dll'),('ntdll','C:/Windows/System32/ntdll.dll'),('git','C:/Program Files/Git/cmd/git.exe')] if os.name=='nt' else [('sudo','/usr/bin/sudo'),('systemd-run','/usr/bin/systemd-run'),('systemctl','/usr/bin/systemctl'),('python','/usr/bin/python3'),('readelf','/usr/bin/readelf'),('ldconfig','/sbin/ldconfig'),('git','/usr/bin/git')]
 for name,path in names:
  p=Path(path).resolve();f.need(p.is_file(),'TRUSTED_BOOTSTRAP_TOOL_MISSING');tools.append({'name':name,'sha256':digest(p),'version':'UNKNOWN_NOT_QUERIED_USE_MEASURED_BINARY_IDENTITY','provenance':'ExistingGitHubhostedimage; no acquisition/install; SHA is measuredidentity not independentpublisherverification.'})
 if os.name=='nt' and os.environ.get('SDK11_QUALIFICATION_BOOTSTRAP'):
  boot=read(os.environ['SDK11_QUALIFICATION_BOOTSTRAP'],16384);tools.extend([{'name':'existing-pwsh-bootstrap','sha256':boot['powershellExeSha256'],'version':boot['powershellVersion'],'provenance':'Trustedhostedimage shell beforeJob; noSDKtarget/acquisition; actualbinary hash.'},{'name':'python312.dll','sha256':boot['pythonDllSha256'],'version':'3.12.10','provenance':boot['pythonSignature']}])
 return {'boundary':'TRUSTED_HOSTED_IMAGE_SHELL_PYTHON_BEFORE_CAPS_NO_SDK_OR_ACQUISITION','pythonVersion':platform.python_version(),'pythonExeSha256':digest(sys.executable),'stdlibClosureSha256':f.h(rows),'stdlibModules':rows,'nativeTools':tools}
def windows_cpu(root):
 from ctypes import wintypes as W
 k=ctypes.WinDLL('kernel32',use_last_error=True);k.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,W.DWORD,W.DWORD];k.VirtualAlloc.restype=ctypes.c_void_p;k.VirtualProtect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,W.DWORD,ctypes.POINTER(W.DWORD)];k.VirtualFree.argtypes=[ctypes.c_void_p,ctypes.c_size_t,W.DWORD];k.GetCurrentProcess.restype=W.HANDLE;k.GetCurrentThread.restype=W.HANDLE;k.GetProcessAffinityMask.argtypes=[W.HANDLE,ctypes.POINTER(ctypes.c_size_t),ctypes.POINTER(ctypes.c_size_t)];k.SetThreadAffinityMask.argtypes=[W.HANDLE,ctypes.c_size_t];k.SetThreadAffinityMask.restype=ctypes.c_size_t;k.FlushInstructionCache.argtypes=[W.HANDLE,ctypes.c_void_p,ctypes.c_size_t]
 code=bytes.fromhex('5389c889d10fa241890041895804418948084189500c5bc3');memory=k.VirtualAlloc(None,4096,0x3000,4);f.need(memory,'CPU_CPUID_ALLOCATION');old=W.DWORD();records=[];old_affinity=0
 try:
  ctypes.memmove(memory,code,len(code));f.need(k.VirtualProtect(memory,4096,0x20,ctypes.byref(old)) and k.FlushInstructionCache(k.GetCurrentProcess(),memory,len(code)),'CPU_CPUID_RX_POLICY')
  call=ctypes.WINFUNCTYPE(None,W.DWORD,W.DWORD,ctypes.POINTER(W.DWORD))(memory);pm=ctypes.c_size_t();sm=ctypes.c_size_t();f.need(k.GetProcessAffinityMask(k.GetCurrentProcess(),ctypes.byref(pm),ctypes.byref(sm)) and pm.value,'CPU_AFFINITY')
  k.GetActiveProcessorGroupCount.restype=W.WORD;f.need(k.GetActiveProcessorGroupCount()==1,'CPU_GROUP_SCOPE_UNSUPPORTED')
  for index in range(64):
   if not(pm.value&(1<<index)):continue
   previous=k.SetThreadAffinityMask(k.GetCurrentThread(),1<<index);f.need(previous,'CPU_AFFINITY');old_affinity=previous;v=(W.DWORD*4)();call(0,0,v);f.need(v[0]>=1,'CPU_CPUID_LEAF');call(1,0,v);ecx=int(v[2]);call(0x80000000,0,v);f.need(v[0]>=0x80000001,'CPU_CPUID_LEAF');call(0x80000001,0,v);ext=int(v[2]);f.need(ecx&((1<<0)|(1<<9)|(1<<13)|(1<<19)|(1<<20)|(1<<23))==((1<<0)|(1<<9)|(1<<13)|(1<<19)|(1<<20)|(1<<23)) and ext&1,'Q_CPU_V2_BEFORE_SDK');records.append({'processor':index,'leaf1Ecx':ecx,'extendedEcx':ext});f.need(k.SetThreadAffinityMask(k.GetCurrentThread(),old_affinity),'CPU_AFFINITY_RESTORE');old_affinity=0
 finally:
  if old_affinity:k.SetThreadAffinityMask(k.GetCurrentThread(),old_affinity)
  k.VirtualFree(memory,0,0x8000)
 write(root/'cpu-evidence.json',{'method':'FixedCPUIDthunkRWtoRX, noRWX/nohostpolicychange, perallowedprocessor, no.NETbootstrap','codeHex':code.hex(),'codeSha256':hashlib.sha256(code).hexdigest(),'processors':records})
 return {'method':'FIXED_CPUID_PER_ALLOWED_LOGICAL_PROCESSOR','processorCount':len(records),'evidenceSha256':digest(root/'cpu-evidence.json'),'features':f.FEATURES}
def linux_cpu(root):
 raw=Path('/proc/cpuinfo').read_bytes();sets=[set(x.split(':',1)[1].split()) for x in raw.decode().splitlines() if x.startswith('flags')];f.need(sets and all({'cx16','popcnt','pni','ssse3','sse4_1','sse4_2','lahf_lm'}<=x for x in sets),'Q_CPU_V2_BEFORE_SDK');write(root/'cpu-evidence.json',{'method':'All/proc/cpuinfo logicalCPUflags','cpuinfoSha256':hashlib.sha256(raw).hexdigest(),'processorCount':len(sets),'features':f.FEATURES});return {'method':'ALL_LOGICAL_PROC_CPUINFO_FLAGS','processorCount':len(sets),'evidenceSha256':digest(root/'cpu-evidence.json'),'features':f.FEATURES}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise f.Denied('ARCHIVE_REDIRECT_FORBIDDEN')
def acquire(catalog,root,budget):
 dest=root/'official-archive';h=hashlib.sha512();size=0;opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());req=urllib.request.Request(catalog['url'],headers={'Accept-Encoding':'identity','User-Agent':'admission04-fixed-ci-qualification'})
 with opener.open(req,timeout=min(30,max(1,(budget.current-clock())/1000))) as response,dest.open('xb') as out:
  f.need(response.status==200 and response.url==catalog['url'] and response.headers.get('Content-Length')==str(catalog['bytes']) and not response.headers.get('Content-Range') and response.headers.get('Content-Encoding','identity')=='identity','ARCHIVE_HTTP_IDENTITY')
  while True:
   f.need(clock()<budget.current,'ARCHIVE_STAGE_TIMEOUT');block=response.read(1048576)
   if not block:break
   size+=len(block);f.need(size<=catalog['bytes']<=536870912,'ARCHIVE_BYTE_LIMIT');out.write(block);h.update(block)
 f.need(size==catalog['bytes'] and h.hexdigest()==catalog['sha512'],'ARCHIVE_HASH_IDENTITY');return dest,{'url':catalog['url'],'bytes':size,'sha512':h.hexdigest(),'httpStatus':200,'contentLength':size,'redirects':0,'contentEncoding':'identity'}

def output(run,argv,cwd,env,deadline,evidence):
 rec=run(argv,cwd,env,deadline,evidence);raw=(evidence/'stdout.log').read_bytes();f.need(len(raw)<=1048576,'CHILD_OUTPUT_CAP');return rec,raw

def native_prerequisites(rid,sdk,root,run,env,budget):
 records=[]
 if rid=='win-x64':
  names=['dotnet.exe','host/fxr/11.0.0/hostfxr.dll','shared/Microsoft.NETCore.App/11.0.0/coreclr.dll','shared/Microsoft.NETCore.App/11.0.0/clrjit.dll'];system=Path(os.environ['SystemRoot'])/'System32'
  for name in names:
   p=sdk/name;f.need(a.machine(p)==('PE',0x8664),'NATIVE_PE_AMD64_REQUIRED')
   for lib in a.pe_imports(p):
    if lib.lower().startswith(('api-ms-','ext-ms-')):continue
    target=p.parent/lib
    if not target.is_file():target=system/lib
    f.need(target.is_file(),'NATIVE_IMPORT_MISSING')
  paths=','.join("'"+str(sdk/n).replace("'","''")+"'" for n in names)
  script="$ErrorActionPreference='Stop'; $r=@("+paths+") | ForEach-Object { $s=Get-AuthenticodeSignature -LiteralPath $_; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'Microsoft Corporation' -or $null -eq $s.TimeStamperCertificate) { throw 'SDK_MICROSOFT_SIGNATURE_REQUIRED' }; [pscustomobject]@{name=[IO.Path]::GetFileName($_);status=[string]$s.Status;signer=$s.SignerCertificate.Subject;thumbprint=$s.SignerCertificate.Thumbprint;timestamp=$s.TimeStamperCertificate.Thumbprint} }; ConvertTo-Json -InputObject @($r) -Compress"
  rec,raw=output(run,[system/'WindowsPowerShell/v1.0/powershell.exe','-NoProfile','-NonInteractive','-Command',script],ROOT,env,budget.deadline(60),root/'publisher-check');rows=json.loads(raw);f.need(len(rows)==4 and all(x['status']=='Valid' and x['timestamp'] for x in rows),'NATIVE_PUBLISHER_REQUIRED');write(root/'publisher.json',rows);records=[{'name':x['name'],'kind':'WindowsAuthenticode','status':'Valid; signer='+x['signer']+'; signerThumbprint='+x['thumbprint']+'; timestampThumbprint='+x['timestamp'],'evidenceSha256':digest(root/'publisher.json')} for x in rows]
 else:
  rec,raw=output(run,['/sbin/ldconfig','-p'],ROOT,env,budget.deadline(15),root/'loader-map');mapping={}
  for line in raw.decode().splitlines():
   m=re.match(r'\s*(\S+)\s+\([^)]*x86-64[^)]*\)\s+=>\s+(\S+)',line)
   if m:mapping.setdefault(m.group(1),Path(m.group(2)))
  for index,name in enumerate([x for x in a.critical_names(rid) if x.endswith('.so') or x=='dotnet']):
   p=sdk/name;f.need(a.machine(p)==('ELF',62),'NATIVE_ELF_AMD64_REQUIRED');rec,raw=output(run,['/usr/bin/readelf','-d',p],ROOT,env,budget.deadline(15),root/('elf-'+str(index)));deps=[]
   for lib in re.findall(r'\(NEEDED\).*\[([^\]]+)\]',raw.decode()):
    target=p.parent/lib
    if not target.is_file():target=mapping.get(lib)
    f.need(target is not None and target.is_file(),'NATIVE_IMPORT_MISSING');deps.append({'import':lib,'resolvedName':target.name,'sha256':digest(target)})
   write(root/('elf-'+str(index)+'.json'),deps);records.append({'name':name,'kind':'ELFDependencyClosure','status':'ObservedExistingHostDependenciesNoInventedELFSignature:'+json.dumps(deps,sort_keys=True,separators=(',',':')),'evidenceSha256':digest(root/('elf-'+str(index)+'.json'))})
 return records

def qualification_profile(profile,rid,event_name,mode):
 f.need(profile.get('rows')==2 and profile.get('totalVerifySeconds')==1800,'CI_ORDINARY_PROFILE_IDENTITY')
 f.need(event_name=='workflow_dispatch' and mode=='sdk11-ci-qualification' and profile.get('qualificationMode')==mode,'CI_QUALIFICATION_MODE')
 f.need(profile.get('qualificationRows')==1 and profile.get('qualificationTotalSeconds')==900 and profile.get('rowSeconds')==900 and profile.get('maxParallel')==1 and profile.get('allowedQualificationRids')==['win-x64'] and rid=='win-x64','CI_WINDOWS_ONLY_PROFILE')
 f.need(profile.get('stageSeconds')=={'existingBootstrapAndCheckout':60,'singleArchive':120,'strictExtract':180,'eightSDKCommandsAggregate':480,'terminalAndProofUpload':60},'CI_QUALIFICATION_STAGE_BUDGET')

def worker(spec,backend):
 rid=spec['rid'];root=Path(spec['root']);profile=read(HERE/'sdk11-ci-execution.profile.json');f.need(digest(HERE/'sdk11-ci-execution.profile.json')==PINS['profileSha256'],'CI_PROFILE_IDENTITY');qualification_profile(profile,rid,os.environ.get('GITHUB_EVENT_NAME'),read(os.environ['GITHUB_EVENT_PATH'],4194304).get('inputs',{}).get('mode'));budget=Budget(spec);f.need(clock()<budget.current,'STARTUP60_EXPIRED');env=job_environment(root);actual_host=host(rid,root);bootstrap_identity();cap=backend.caps();f.caps(cap,rid);write(root/'pre-acquisition-kernel.json',cap)
 source=source_context(spec['expectedCommit'],backend.run,env,budget,root,qualification=True)
 if rid=='linux-x64':
  rec,raw=output(backend.run,['/usr/bin/dpkg-query','-W','-f=${binary:Package}|${Version}\n','python3.12-minimal','systemd','sudo','coreutils','binutils','libc-bin','git'],ROOT,env,budget.deadline(10),root/'bootstrap-packages');write(root/'bootstrap-packages.json',{'actualPackages':raw.decode().splitlines()})
 cpu=windows_cpu(root) if rid=='win-x64' else linux_cpu(root);f.cpu(cpu)
 name='dotnet11-qualification-inputs.lock.json' if rid=='win-x64' else 'dotnet11-linux-qualification-inputs.lock.json';cp=HERE/name;expected=PINS['catalogSha256' if rid=='win-x64' else 'linuxCatalogSha256'];f.need(digest(cp)==expected,'Q_CATALOG_SOURCE_SHA');catalog=read(cp);f.catalog(catalog,rid);source['catalogSha256']=expected
 denials=[]
 for mode,flags,optimization in [('normal',[],None),('O',['-O'],None),('env2',[],'2')]:
  testenv=dict(env);testenv.pop('PYTHONOPTIMIZE',None)
  if optimization:testenv['PYTHONOPTIMIZE']=optimization
  target=root/('denials-'+mode);rec,raw=output(backend.run,[sys.executable,'-S','-B',*flags,HERE/'test_dotnet11_windows_qualification.py','--rid',rid,'--out',target],ROOT,testenv,budget.deadline(8),root/('test-process-'+mode));value=read(target/'receipt.json');f.need(value['count']==12 and value['optimize']==(2 if optimization else 1 if flags else 0) and value['candidateSpawns']==value['networkAttempts']==0,'Q_DENIAL_MODE_PROOF');denials.append({'mode':mode,'optimize':value['optimize'],'count':12,'candidateSpawns':0,'networkAttempts':0,'receiptSha256':digest(target/'receipt.json')})
 budget.stage(1,120);archive,archive_fact=acquire(catalog,root,budget)
 budget.stage(2,180);sdk=root/'sdk'
 if rid=='win-x64':
  members=a.extract_members(archive,sdk,rid);f.need(members==catalog['members'],'Q_FULL_MEMBER_MANIFEST');a.verify_tree(sdk,members,rid,full=True)
 else:
  lm=load_module('materialize_qualification_linux',PINS['linuxMaterializerSha256']);members=lm.materialize(catalog,archive,sdk)
 budget.stage(3,480);publisher=native_prerequisites(rid,sdk,root,backend.run,env,budget);pre=backend.caps();f.caps(pre,rid);write(root/'before-first-sdk.json',{'actualHost':actual_host,'cpu':cpu,'actualCaps':pre,'denials':denials,'source':source});env.update({'DOTNET_ROOT':str(sdk),'DOTNET_ROOT_X64':str(sdk),'DOTNET_HOST_PATH':str(sdk/('dotnet.exe' if rid=='win-x64' else 'dotnet'))})
 work=root/'qualification';work.mkdir(mode=0o700);(work/'global.json').write_text('{"sdk":{"version":"11.0.100","rollForward":"disable","allowPrerelease":false}}\n');(work/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n');(work/'qualification.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework><LangVersion>15.0</LangVersion><RuntimeFrameworkVersion>11.0.0</RuntimeFrameworkVersion><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile><TreatWarningsAsErrors>true</TreatWarningsAsErrors><UseSharedCompilation>false</UseSharedCompilation></PropertyGroup></Project>\n');(work/'packages.lock.json').write_text('{"version":1,"dependencies":{"net11.0":{}}}\n');(work/'Program.cs').write_text('using System; using System.Runtime.InteropServices; Console.WriteLine("SDK11_QUALIFIED_TOKEN"); Console.WriteLine(RuntimeInformation.FrameworkDescription);\n')
 commands=[('version',['--version'],30),('info',['--info'],30),('list-sdks',['--list-sdks'],30),('list-runtimes',['--list-runtimes'],30),('compiler',['exec',str(sdk/'sdk/11.0.100/Roslyn/bincore/csc.dll'),'-version'],30),('restore',['restore','qualification.csproj','--configfile',str(work/'NuGet.Config'),'--locked-mode','-p:NuGetAudit=true','-p:NuGetAuditMode=all','-p:NuGetAuditLevel=low'],180),('build',['build','qualification.csproj','-c','Release','--no-restore','--nologo','-p:UseSharedCompilation=false','-p:BuildInParallel=false','-m:1'],300),('hello',['exec',str(work/'bin/Release/net11.0/qualification.dll')],30)];command_facts=[]
 for command_index,(name,args,seconds) in enumerate(commands):
  a.verify_tree(sdk,members,rid)
  with contextlib.ExitStack() as stack:
   if rid=='win-x64':
    for member in catalog['criticalMembers']:
     held=stack.enter_context(backend.hold(sdk/member['path']));f.need(held['sha256']==member['sha256'],'SDK_ENTRY_HELD_IDENTITY')
   diagnostic=fixed_command_context(name,command_index,command_facts);diagnostic['entryReceiptSha256']=capture_fixed_command_entry(root,diagnostic)
   try:
    rec,raw=output(backend.run,[env['DOTNET_HOST_PATH'],*args],work,env,budget.deadline(seconds),root/('sdk-'+name))
   except Exception as exc:
    try:exc._sdk11_fixed_command=fixed_sdk_failure(diagnostic,root/('sdk-'+name))
    except Exception:pass
    raise
  text=raw.decode('utf-8-sig').replace('\r\n','\n')
  if name=='version':f.need(text.strip()=='11.0.100','SDK_VERSION')
  if name=='info':f.need('11.0.100' in text and '11.0.0' in text,'SDK_INFO')
  if name=='list-sdks':f.need('11.0.100' in text,'SDK_LIST')
  if name=='list-runtimes':f.need('Microsoft.NETCore.App 11.0.0 ' in text,'SDK_RUNTIME')
  if name=='compiler':f.need(re.fullmatch(r'[0-9]+\.[0-9]+[^\r\n]*\s*',text) is not None,'SDK_COMPILER')
  if name=='hello':f.need(text.splitlines()==['SDK11_QUALIFIED_TOKEN','.NET 11.0.0'],'SDK_HELLO')
  public=text.replace(str(root),'<PRIVATE_WORK>').replace(str(Path.home()),'<USER_HOME>');command_facts.append({'name':name,'exitCode':0,'outputSha256':hashlib.sha256(public.encode()).hexdigest(),'outputPreview':public[:4096],'membershipBeforeExec':True,'pid':rec['pid'],'processStartIdentity':rec['childBeforeExec']['processStartIdentity'],'terminal':True,'evidenceSha256':digest(root/('sdk-'+name+'/process.json')),'seconds':rec['seconds']})
 if rid=='win-x64':a.verify_tree(sdk,members,rid,full=True)
 else:lm.verify_physical(sdk,members)
 f.need(clock()<budget.current,'SDK_AGGREGATE480_EXPIRED');bootstrap=bootstrap_identity()
 if rid=='linux-x64':
  packages=read(root/'bootstrap-packages.json')['actualPackages']
  for tool in bootstrap['nativeTools']:tool['version']='Actualdpkg:'+(';'.join(packages))
 schema=read(HERE/'dotnet11-host-qualification.schema.json');f.need(digest(HERE/'dotnet11-host-qualification.schema.json')==PINS['schemaSha256'],'FACT_SCHEMA_SOURCE')
 fact={'toolchain':{'sdk':'11.0.100','runtime':'11.0.0','framework':'net11.0','language':'15.0'},'schema':'sdk11-host-qualification/v1','factType':'WindowsCIServer2025RID' if rid=='win-x64' else 'LinuxCIUbuntu24RID','outcome':'NATIVE_HOST_QUALIFICATION_OBSERVED','qualifiedOn':actual_host,'source':source,'bootstrap':bootstrap,'cpu':cpu,'archive':archive_fact,'tree':{'memberManifestSha256':catalog['memberManifestSha256'],'members':len(members),'outputFiles':sum(x['type']=='file' for x in members),'outputDirectories':sum(x['type']=='directory' for x in members),'expandedFileBytes':sum(x['bytes'] for x in members if x['type']=='file'),'criticalMembers':[x for x in members if x['path'] in a.critical_names(rid)],'notices':[x for x in members if x['type']=='file' and re.match(r'(?i)(license|third.?party.?notices)',Path(x['path']).name)]},'caps':pre,'commands':command_facts,'denials':denials,'publisherAndNative':publisher,'boundaries':schema['properties']['boundaries']['const']}
 write(root/'worker-fact.json',fact)
 if os.name!='nt':signal.setitimer(signal.ITIMER_REAL,0)
 return fact

def publish_proof(spec,terminal,peak_memory):
 root=Path(spec['root']);f.need(clock()<int(spec['startTick'])+900000,'FINAL900_DEADLINE');value=read(root/'worker-fact.json');value['terminal']=terminal;value['caps']['peakMemoryBytes']=int(peak_memory);schema=read(HERE/'dotnet11-host-qualification.schema.json');f.validate_fact(value,schema)
 proof=ROOT/'artifacts'/('sdk11-qualification-'+spec['rid']);proof.mkdir(parents=True,exist_ok=False);write(proof/'host-fact.json',value);total=sum(p.stat().st_size for p in proof.iterdir());f.need(total<=8388608,'PROOF8MIB_LIMIT');return proof

TRACE_MODULES=frozenset({'tools/sdk11_ci_runtime.py','tools/windows_qualification_job.py','tools/linux_qualification_job.py','tools/qualify_dotnet11_windows.py','tools/qualify_dotnet11_linux.py','tools/consume_dotnet11_host_fact.py','tools/sdk11_ci_facts.py','tools/qualification_input_guard.py','tools/materialize_qualification_linux.py'})

def safe_failure_frames(exc):
 # Pure code metadata only: never inspect locals/args, source lines or format a traceback.
 try:
  flavor=PureWindowsPath if ROOT.drive else PurePosixPath;base=flavor(str(ROOT));frames=[];tb=exc.__traceback__;visited=0
  while tb is not None and visited<256:
   visited+=1;code=tb.tb_frame.f_code;file=flavor(code.co_filename);relative=file.relative_to(base).as_posix() if file.is_absolute() and file.is_relative_to(base) else file.as_posix() if not file.is_absolute() else ''
   if relative in TRACE_MODULES and re.fullmatch(r'[A-Za-z_<>][A-Za-z0-9_.<>-]{0,63}',code.co_name) and type(tb.tb_lineno) is int and 0<tb.tb_lineno<10000000:frames.append({'module':relative,'function':code.co_name,'line':tb.tb_lineno})
   tb=tb.tb_next
  frames=frames[-6:]
  return frames if len(json.dumps(frames,separators=(',',':')).encode())<=4096 else []
 except Exception:return []

def public_failure_trace(cause,worker):
 try:
  def selected(record,maximum):
   result=[];rows=record.get('frames',[]) if type(record) is dict else []
   if type(rows) is not list:return result
   for row in rows[-maximum:] if maximum else []:
    if type(row) is dict and set(row)=={'module','function','line'} and row.get('module') in TRACE_MODULES and type(row.get('function')) is str and re.fullmatch(r'[A-Za-z_<>][A-Za-z0-9_.<>-]{0,63}',row['function']) and type(row.get('line')) is int and 0<row['line']<10000000:result.append({k:row[k] for k in ['module','function','line']})
   return result
  origin=selected(worker,6);supervisor=selected(cause,6-len(origin));value={'worker':origin,'supervisor':supervisor}
  return value if len(json.dumps(value,separators=(',',':')).encode())<=4096 else {'worker':[],'supervisor':[],'state':'TRACE_INVALID_OR_OVERSIZE'}
 except Exception:return {'worker':[],'supervisor':[],'state':'TRACE_UNAVAILABLE_PRIMARY_FAILURE_PRESERVED'}


FIXED_SDK_COMMAND_NAMES=('version','info','list-sdks','list-runtimes','compiler','restore','build','hello')

def bounded_diagnostic_bytes(path,limit):
 p=Path(path)
 if not p.is_file() or p.is_symlink() or p.stat().st_size>limit:raise ValueError('OPTIONAL_DIAGNOSTIC_FILE')
 with p.open('rb') as stream:value=stream.read(limit+1)
 if len(value)>limit:raise ValueError('OPTIONAL_DIAGNOSTIC_SIZE')
 return value

def fixed_command_context(name,index,completed):
 return {'schema':'sdk11-fixed-command-diagnostic/v1','failedCommandName':name,'commandIndex':index,'completedCommandNames':[x['name'] for x in completed],'completedCommands':[{'name':x['name'],'exitCode':x['exitCode'],'outputSha256':x['outputSha256'],'processReceiptSha256':x['evidenceSha256']} for x in completed],'entryReceiptSha256':'UNKNOWN','failedProcess':{'state':'UNKNOWN'},'logs':{'state':'UNKNOWN'},'reasonCodes':['UNKNOWN']}

def capture_fixed_command_entry(root,context):
 try:
  target=root/('fixed-sdk-entry-'+context['failedCommandName']+'.json');write(target,context)
  return hashlib.sha256(bounded_diagnostic_bytes(target,4096)).hexdigest()
 except Exception:return 'UNKNOWN'

FIXED_LOG_EXCEPTION_TYPES=((b'System.IO.IOException', 'EXCEPTION_IO'), (b'System.IO.FileNotFoundException', 'EXCEPTION_FILE_NOT_FOUND'), (b'System.IO.DirectoryNotFoundException', 'EXCEPTION_DIRECTORY_NOT_FOUND'), (b'System.IO.PathTooLongException', 'EXCEPTION_PATH_TOO_LONG'), (b'System.UnauthorizedAccessException', 'EXCEPTION_UNAUTHORIZED_ACCESS'), (b'System.ComponentModel.Win32Exception', 'EXCEPTION_WIN32'), (b'System.ArgumentException', 'EXCEPTION_ARGUMENT'), (b'System.ArgumentNullException', 'EXCEPTION_ARGUMENT_NULL'), (b'System.InvalidOperationException', 'EXCEPTION_INVALID_OPERATION'), (b'System.TypeInitializationException', 'EXCEPTION_TYPE_INITIALIZATION'), (b'System.PlatformNotSupportedException', 'EXCEPTION_PLATFORM_NOT_SUPPORTED'), (b'System.NotSupportedException', 'EXCEPTION_NOT_SUPPORTED'), (b'System.OutOfMemoryException', 'EXCEPTION_OUT_OF_MEMORY'))
FIXED_LOG_HRESULTS=(b'80004005', b'80070002', b'80070003', b'80070005', b'80070008', b'8007000E', b'80070020', b'80070057', b'8007007E', b'800700CE')
FIXED_LOG_WIN32=(b'2', b'3', b'5', b'8', b'14', b'32', b'87', b'126', b'206')
FIXED_LOG_REASON_CATEGORIES=frozenset(('UNKNOWN', 'DOTNET_HOST_FRAMEWORK_MISSING', 'DOTNET_HOST_SDK_NOT_FOUND', 'DOTNET_HOST_COMMAND_NOT_LOADED', 'EXCEPTION_IO', 'EXCEPTION_FILE_NOT_FOUND', 'EXCEPTION_DIRECTORY_NOT_FOUND', 'EXCEPTION_PATH_TOO_LONG', 'EXCEPTION_UNAUTHORIZED_ACCESS', 'EXCEPTION_WIN32', 'EXCEPTION_ARGUMENT', 'EXCEPTION_ARGUMENT_NULL', 'EXCEPTION_INVALID_OPERATION', 'EXCEPTION_TYPE_INITIALIZATION', 'EXCEPTION_PLATFORM_NOT_SUPPORTED', 'EXCEPTION_NOT_SUPPORTED', 'EXCEPTION_OUT_OF_MEMORY', 'HRESULT_80004005', 'HRESULT_80070002', 'HRESULT_80070003', 'HRESULT_80070005', 'HRESULT_80070008', 'HRESULT_8007000E', 'HRESULT_80070020', 'HRESULT_80070057', 'HRESULT_8007007E', 'HRESULT_800700CE', 'WIN32_2', 'WIN32_3', 'WIN32_5', 'WIN32_8', 'WIN32_14', 'WIN32_32', 'WIN32_87', 'WIN32_126', 'WIN32_206'))

def classify_fixed_sdk_log(block):
 # Observability only: literal syntax categories, never message/path/URL/args/env.
 try:
  if type(block) is not bytes or len(block)>1048576:return []
  # Strip bounded SGR colour escapes in this classifier copy only; raw hashes stay raw.
  clean=re.sub(rb'\x1b\[[0-9;:]{0,64}m',b'',block);codes=set()
  for code in re.findall(rb'\b(?:error|warning)[ \t]+((?:NETSDK|MSB|CS|NU)[0-9]{4})[ \t]*:',clean,re.ASCII|re.IGNORECASE):codes.add(code.decode('ascii').upper())
  for literal,category in [(b'You must install or update .NET to run this application.', 'DOTNET_HOST_FRAMEWORK_MISSING'),(b'No .NET SDKs were found.', 'DOTNET_HOST_SDK_NOT_FOUND'),(b'The command could not be loaded, possibly because:', 'DOTNET_HOST_COMMAND_NOT_LOADED')]:
   if literal in clean:codes.add(category)
  for literal,category in FIXED_LOG_EXCEPTION_TYPES:
   if re.search(rb'(?<![A-Za-z0-9_.])'+re.escape(literal)+rb'(?=[:( \t\r\n])',clean,re.ASCII):codes.add(category)
  for token in FIXED_LOG_HRESULTS:
   if re.search(rb'(?<![A-Za-z0-9_.])HResult[ \t]*[:=][ \t]*0x'+token+rb'(?![A-Za-z0-9_])',clean,re.ASCII|re.IGNORECASE):codes.add('HRESULT_'+token.decode('ascii'))
  for token in FIXED_LOG_WIN32:
   if re.search(rb'(?<![A-Za-z0-9_.])(?:Win32|NativeErrorCode)[ \t]*[:=][ \t]*'+token+rb'(?![A-Za-z0-9_])',clean,re.ASCII|re.IGNORECASE):codes.add('WIN32_'+token.decode('ascii'))
  return sorted(codes)[:8]
 except Exception:return []

def fixed_sdk_failure(context,evidence):
 # Called only after the existing process wrapper raises; no command or retry.
 value=dict(context)
 try:
  raw=bounded_diagnostic_bytes(evidence/'process.json',32768);record=json.loads(raw)
  if type(record) is not dict or record.get('schema')!='bounded-sdk11-process/v1':raise ValueError('PROCESS_SCHEMA')
  cap=record.get('actualCap',{});numeric=['memoryMax','activeProcessMax','cpuRate','logicalHostCpu','effectiveCpuCores','peakJobMemory','activeProcessesAtTeardown','totalProcesses'];boolean=['childMembershipBeforeResume','inheritedAggregateBeforeResume','retainedCreationHandles']
  if type(record.get('exitCode')) is not int or not 0<=record['exitCode']<=4294967295 or type(record.get('timedOut')) is not bool or type(cap) is not dict:raise ValueError('PROCESS_FIELDS')
  selected={}
  for key in numeric:
   item=cap.get(key)
   if type(item) not in (int,float) or not 0<=item<=9223372036854775807:raise ValueError('CAP_FIELDS')
   selected[key]=item
  for key in boolean:
   if type(cap.get(key)) is not bool:raise ValueError('CAP_FIELDS')
   selected[key]=cap[key]
  value['failedProcess']={'state':'OBSERVED_PROCESS_RECEIPT','receiptSha256':hashlib.sha256(raw).hexdigest(),'exitCode':record['exitCode'],'timedOut':record['timedOut'],'actualCap':selected}
 except Exception:value['failedProcess']={'state':'UNKNOWN'}
 try:
  logs={};blocks=[];remaining=1048576
  for stream in ('stdout','stderr'):
   raw=bounded_diagnostic_bytes(evidence/(stream+'.log'),remaining);remaining-=len(raw);blocks.append(raw);logs[stream]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
  value['logs']={'state':'BOUNDED_HASHED_NO_RAW_OUTPUT',**logs}
  codes=set()
  for block in blocks:codes.update(classify_fixed_sdk_log(block))
  value['reasonCodes']=sorted(codes)[:8] or ['UNKNOWN']
 except Exception:
  value['logs']={'state':'UNKNOWN'};value['reasonCodes']=['UNKNOWN']
 return sanitize_fixed_sdk_diagnostic(value)

def sanitize_fixed_sdk_diagnostic(value):
 # Exact typed whitelist; never copy arbitrary fields from a process or log.
 try:
  required={'schema','failedCommandName','commandIndex','completedCommandNames','completedCommands','entryReceiptSha256','failedProcess','logs','reasonCodes'}
  if type(value) is not dict or set(value)!=required or value['schema']!='sdk11-fixed-command-diagnostic/v1':raise ValueError('SHAPE')
  index=value['commandIndex'];names=FIXED_SDK_COMMAND_NAMES
  if type(index) is not int or not 0<=index<8 or type(value['failedCommandName']) is not str or value['failedCommandName']!=names[index]:raise ValueError('COMMAND')
  if type(value['completedCommandNames']) is not list or value['completedCommandNames']!=list(names[:index]) or type(value['completedCommands']) is not list or len(value['completedCommands'])!=index:raise ValueError('PREFIX')
  ishash=lambda x:type(x) is str and re.fullmatch(r'[0-9a-f]{64}',x) is not None
  for i,row in enumerate(value['completedCommands']):
   if type(row) is not dict or set(row)!={'name','exitCode','outputSha256','processReceiptSha256'} or row['name']!=names[i] or type(row['exitCode']) is not int or row['exitCode']!=0 or not ishash(row['outputSha256']) or not ishash(row['processReceiptSha256']):raise ValueError('COMPLETED')
  if value['entryReceiptSha256']!='UNKNOWN' and not ishash(value['entryReceiptSha256']):raise ValueError('ENTRY')
  proc=value['failedProcess']
  if proc!={'state':'UNKNOWN'}:
   if type(proc) is not dict or set(proc)!={'state','receiptSha256','exitCode','timedOut','actualCap'} or proc['state']!='OBSERVED_PROCESS_RECEIPT' or not ishash(proc['receiptSha256']) or type(proc['exitCode']) is not int or not 0<=proc['exitCode']<=4294967295 or type(proc['timedOut']) is not bool:raise ValueError('PROCESS')
   numeric={'memoryMax','activeProcessMax','cpuRate','logicalHostCpu','effectiveCpuCores','peakJobMemory','activeProcessesAtTeardown','totalProcesses'};boolean={'childMembershipBeforeResume','inheritedAggregateBeforeResume','retainedCreationHandles'};cap=proc['actualCap']
   if type(cap) is not dict or set(cap)!=numeric|boolean or any(type(cap[k]) not in (int,float) or not 0<=cap[k]<=9223372036854775807 for k in numeric) or any(type(cap[k]) is not bool for k in boolean):raise ValueError('CAP')
  logs=value['logs']
  if logs!={'state':'UNKNOWN'}:
   if type(logs) is not dict or set(logs)!={'state','stdout','stderr'} or logs['state']!='BOUNDED_HASHED_NO_RAW_OUTPUT':raise ValueError('LOGS')
   total=0
   for stream in ('stdout','stderr'):
    row=logs[stream]
    if type(row) is not dict or set(row)!={'bytes','sha256'} or type(row['bytes']) is not int or not 0<=row['bytes']<=1048576 or not ishash(row['sha256']):raise ValueError('LOG_FIELDS')
    total+=row['bytes']
   if total>1048576:raise ValueError('LOG_TOTAL')
  codes=value['reasonCodes'];categories=FIXED_LOG_REASON_CATEGORIES
  if type(codes) is not list or not 1<=len(codes)<=8 or any(type(x) is not str or not (x in categories or re.fullmatch(r'(NETSDK|MSB|CS|NU)[0-9]{4}',x)) for x in codes):raise ValueError('REASONS')
  raw=json.dumps(value,separators=(',',':')).encode()
  if len(raw)>4096:raise ValueError('SIZE')
  return json.loads(raw)
 except Exception:return {'state':'UNKNOWN'}

def public_fixed_sdk_diagnostic(record):
 try:return sanitize_fixed_sdk_diagnostic(record.get('fixedSDKCommand') if type(record) is dict else getattr(record,'_sdk11_fixed_command',None))
 except Exception:return {'state':'UNKNOWN'}

def failure_code(exc):
 kind=type(exc).__name__;kind=kind if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',kind) else 'UNKNOWN'
 try:value=str(exc) if kind in ('Denied','CapError','AdmissionError') else ''
 except Exception:value=''
 number=getattr(exc,'errno',None);number=number if type(number) is int and abs(number)<2147483648 else None
 return {'exceptionType':kind,'code':value if re.fullmatch(r'[A-Z][A-Z0-9_:.-]{0,127}',value) else 'DETAIL_REDACTED_USE_PRIVATE_CAUSE','errno':number,'frames':safe_failure_frames(exc),'fixedSDKCommand':public_fixed_sdk_diagnostic(exc)}

def capture_entry_failure(exc):
 # No raw exception/output/path/env data crosses into the public failure receipt.
 cause=failure_code(exc);rid='win-x64' if os.name=='nt' else 'linux-x64';root=None;spec={}
 try:
  if '--worker' in sys.argv or '--stop-post' in sys.argv:
   key='--worker' if '--worker' in sys.argv else '--stop-post';spec=read(sys.argv[sys.argv.index(key)+1]);root=Path(spec['root']);target=root/('worker-failure.json' if key=='--worker' else 'observer-failure.json')
   if not target.exists():write(target,cause)
   return
  temp=Path(os.environ['RUNNER_TEMP']).resolve();root=temp/('admission04-sdk11-'+('win-' if os.name=='nt' else 'linux-')+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);a.scoped(root,temp)
  if (root/'private-spec.json').is_file():spec=read(root/'private-spec.json')
 except (OSError,ValueError,KeyError,f.Denied):root=None
 failure_summary({'root':str(root) if root else None,'rid':rid,**spec},cause)

def public_windows_host_observation(root):
 try:
  if root is None or not (root/'windows-host-observation.json.ready').is_file():return {'state':'UNKNOWN_NOT_CAPTURED'}
  value=read(root/'windows-host-observation.json',8192);f.need(value.get('schema')=='sdk11-windows-host-observation/v1','WINDOWS_HOST_OBSERVATION_SCHEMA')
  fields=['imageOS','imageVersion','machine','pointerBits','runnerEnvironment','runnerOS','productType','windowsBuild','registryProductName','registryCurrentBuildNumber','registryUBR','readStatus','readErrorType','readErrorCode'];names=['machineX64','pointer64','serverProduct3','kernelBuild26100','hostedRunner','windowsRunner','registryReadComplete','imageVariantDocumented','registryKernel26100','registryServer2025']
  f.need(type(value) is dict and type(value.get('observed')) is dict and type(value.get('predicates')) is dict and set(value['observed'])==set(fields) and set(value['predicates'])==set(names) and all(type(v) is bool for v in value['predicates'].values()),'WINDOWS_HOST_OBSERVATION_SHAPE')
  observed={}
  for key in fields:
   item=value.get('observed',{}).get(key,'UNKNOWN')
   if type(item) is int or item is None:observed[key]=item
   elif type(item) is str and re.fullmatch(r'[A-Za-z0-9 ._()-]{0,160}',item):observed[key]=item
   else:observed[key]='REDACTED_INVALID_OR_OVERSIZE_METADATA'
  predicates={key:value.get('predicates',{}).get(key,'UNKNOWN') if type(value.get('predicates',{}).get(key)) is bool else 'UNKNOWN' for key in names}
  return {'schema':value['schema'],'state':'ACTUAL_PRE_DENIAL_VALUES_NO_HOST_QUALIFICATION','observed':observed,'predicates':predicates,'observationSha256':digest(root/'windows-host-observation.json')}
 except Exception:return {'state':'INVALID_OR_OVERSIZE','boundary':'OPTIONAL_DIAGNOSTIC_UNAVAILABLE_PRIMARY_FAILURE_PRESERVED'}

def failure_summary(spec,cause,terminal=None,stop=None):
 rid=spec['rid'];f.need(rid in f.HOSTS,'FIXED_FAILURE_RID');root=Path(spec['root']) if spec.get('root') else None;stage='UNKNOWN';worker=None
 if root:
  for index in range(4):
   if (root/('stage-'+str(index)+'.json.ready')).is_file():stage=index
  if (root/'worker-failure.json.ready').is_file():worker=read(root/'worker-failure.json',8192)
  if terminal is None and (root/'cleanup-terminal.json.ready').is_file():terminal=read(root/'cleanup-terminal.json',16384)
  if terminal is None and (root/'outer-job/process.json').is_file():
   rec=read(root/'outer-job/process.json');cap=rec.get('actualCap',{});terminal={'launcherTerminal':'UNKNOWN','workerPidfdTerminal':'NOT_APPLICABLE_WINDOWS','ownedPopulation':cap.get('activeProcessesAtTeardown','UNKNOWN'),'workerExitCode':rec.get('exitCode','UNKNOWN'),'evidenceSha256':digest(root/'outer-job/process.json')}
  if stop is None and (root/'stop-outcome.json.ready').is_file():stop=read(root/'stop-outcome.json',16384)
 clean=lambda value: value if type(value) is int or value in (None,True,False) else (value if type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',value) else 'UNKNOWN')
 term={k:clean((terminal or {}).get(k,'UNKNOWN')) for k in ['launcherTerminal','workerPidfdTerminal','ownedPopulation','workerExitCode','cleanupResult','evidenceSha256']}
 stopValue={k:clean((stop or {}).get(k,'UNKNOWN')) for k in ['serviceResult','exitCode','exitStatus','remainingPopulationExcludingObserver']}
 receipt={'schema':'sdk11-ci-failure-summary/v1','state':'FAILURE_OBSERVED_NO_QUALIFICATION','rid':rid,'sourceCommit':clean(os.environ.get('GITHUB_SHA','UNKNOWN')),'runId':clean(os.environ.get('GITHUB_RUN_ID','UNKNOWN')),'job':clean(os.environ.get('GITHUB_JOB','UNKNOWN')),'attempt':clean(os.environ.get('GITHUB_RUN_ATTEMPT','UNKNOWN')),'controllerSha256':digest(Path(sys.argv[0])) if Path(sys.argv[0]).is_file() else 'UNKNOWN','workflowSha256':digest(ROOT/'.github/workflows/verify.yml') if (ROOT/'.github/workflows/verify.yml').is_file() else 'UNKNOWN','actualStage':stage,'cause':{k:clean(cause.get(k,'UNKNOWN')) for k in ['exceptionType','code','errno']},'workerCause':{k:clean((worker or {}).get(k,'UNKNOWN')) for k in ['exceptionType','code','errno']},'terminal':term,'stopOutcome':stopValue,'failureTrace':public_failure_trace(cause,worker),'fixedSDKCommand':public_fixed_sdk_diagnostic(worker) if public_fixed_sdk_diagnostic(worker).get('schema') else public_fixed_sdk_diagnostic(cause),'windowsHostObservation':public_windows_host_observation(root) if rid=='win-x64' else {'state':'NOT_APPLICABLE_LINUX'},'boundary':'SANITIZED_FAILURE_ONLY_NOT_HOST_FACT_NOT_PASS_NO_SDK_OR_RAW_OUTPUT'}
 raw=json.dumps(receipt,sort_keys=True,indent=2).encode();f.need(len(raw)<=32768,'FAILURE_SUMMARY32K_LIMIT');proof=ROOT/'artifacts'/('sdk11-qualification-'+rid);proof.mkdir(parents=True,exist_ok=True);target=proof/'failure-summary.json'
 if not target.exists():
  staged=proof/'failure-summary.private.tmp'
  with staged.open('xb') as stream:stream.write(raw)
  os.replace(staged,target)
 f.need(target.stat().st_size<=32768,'FAILURE_SUMMARY32K_LIMIT');return target
