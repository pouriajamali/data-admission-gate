"""Fixed SDK11 CI recipes; library only. No source import performs acquisition/targets."""
from __future__ import annotations
import argparse,contextlib,ctypes,gzip,hashlib,importlib.util,json,os,platform,re,signal,ssl,stat,struct,subprocess,sys,tarfile,time,urllib.request,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
PINS={'catalogSha256': 'f87ecbf9ffebd4bcb6cd435739a070042e8c20299f63882e0277803478b54c7a', 'fixtureSha256': 'd8b2b3bc9a95ba1e7ab9332f3fcef9826e7cbd9fd83059c7f2e0d475627aa13f', 'jobHelperSha256': '0ad85ec7c62fa46aee8be79ece3465060268b2f077595a0bad068ae751668694', 'memberManifestSha256': '7eb452d5eaa748773eb0b12d1abc8da1a9f1c192b06444dc88c6511de56b63c3', 'catalogRows': 5480, 'schemaSha256': '63e04fa5d270c87b93e6e1f4c38bfbcf336b950b39fe1854dc4e514f0661f14c', 'factHelperSha256': '6531854ac6d66827998bee7cdac97b534500b62bb6e941abcf6b9745c6b8daec', 'linuxCatalogSha256': '307d56b0590f5adf8bfdc03ca22d151b987774c2e49934598cfd0ac0700c0571', 'inputGuardSha256': '7420b08d78d3b1476be41385d179a42212a2a7e1a965a8d8ea3b67bb14da7925', 'linuxMaterializerSha256': '5f0dbb951cbe615d8c6dd9edbb63b11143cc457319bdcc9000ea9a486f660fb8', 'profileSha256': '641a1f8f3678fbde5dd143753d360c1322d210d04833cbfd73252626e8f7ae39'}
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
def host(rid):
 base={'hostClass':f.HOSTS[rid],'rid':rid,'imageOS':os.environ.get('ImageOS',''),'imageVersion':os.environ.get('ImageVersion',''),'runId':os.environ.get('GITHUB_RUN_ID',''),'job':os.environ.get('GITHUB_JOB',''),'attempt':os.environ.get('GITHUB_RUN_ATTEMPT',''),'repository':os.environ.get('GITHUB_REPOSITORY',''),'architecture':'x64','instanceId':os.environ.get('RUNNER_NAME','')}
 f.need(platform.machine().lower() in ('amd64','x86_64'),'Q_HOST_CLASS')
 if rid=='win-x64':
  import winreg
  with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
   get=lambda n:winreg.QueryValueEx(key,n)[0];v=sys.getwindowsversion();f.need(v.product_type==3 and v.build==26100 and ctypes.sizeof(ctypes.c_void_p)==8,'Q_HOST_OS');base.update(osVersion=get('ProductName'),kernelBuild=get('CurrentBuildNumber')+'.'+str(get('UBR')),uid=None,gid=None)
 else:
  f.need('microsoft' not in platform.release().lower() and not os.environ.get('WSL_DISTRO_NAME'),'LOCAL_WSL_SDK_TARGETS_EXCLUDED')
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
 return {'commit':out[0],'tree':out[1],'ref':os.environ['GITHUB_REF'],'workflowSha256':digest(ROOT/'.github/workflows/verify.yml'),'controllerSha256':digest(HERE/(('qualify_dotnet11_windows.py' if os.name=='nt' else 'qualify_dotnet11_linux.py') if qualification else 'consume_dotnet11_host_fact.py')),'helperSha256':digest(HERE/('windows_qualification_job.py' if os.name=='nt' else 'linux_qualification_job.py')),'schemaSha256':PINS['schemaSha256'],'catalogSha256':'','normalGuardSha256':'4786dae59cb9b0cef0d71d75d895dbdce63568844a547da3f80555a82bf2b1b6'}
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

def worker(spec,backend):
 rid=spec['rid'];root=Path(spec['root']);profile=read(HERE/'sdk11-ci-execution.profile.json');f.need(digest(HERE/'sdk11-ci-execution.profile.json')==PINS['profileSha256'] and profile['rowSeconds']==900 and profile['rows']==2 and profile['maxParallel']==1,'CI_PROFILE_IDENTITY');budget=Budget(spec);f.need(clock()<budget.current,'STARTUP60_EXPIRED');env=job_environment(root);actual_host=host(rid);bootstrap_identity();cap=backend.caps();f.caps(cap,rid);write(root/'pre-acquisition-kernel.json',cap)
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
 for name,args,seconds in commands:
  a.verify_tree(sdk,members,rid)
  with contextlib.ExitStack() as stack:
   if rid=='win-x64':
    for member in catalog['criticalMembers']:
     held=stack.enter_context(backend.hold(sdk/member['path']));f.need(held['sha256']==member['sha256'],'SDK_ENTRY_HELD_IDENTITY')
   rec,raw=output(backend.run,[env['DOTNET_HOST_PATH'],*args],work,env,budget.deadline(seconds),root/('sdk-'+name))
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

def failure_code(exc):
 value=str(exc)
 return {'exceptionType':type(exc).__name__[:64],'code':value if re.fullmatch(r'[A-Z][A-Z0-9_:.-]{0,127}',value) else 'DETAIL_REDACTED_USE_PRIVATE_CAUSE','errno':getattr(exc,'errno',None)}

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

def failure_summary(spec,cause,terminal=None,stop=None):
 rid=spec['rid'];f.need(rid in f.HOSTS,'FIXED_FAILURE_RID');root=Path(spec['root']) if spec.get('root') else None;stage='UNKNOWN';worker=None
 if root:
  for index in range(4):
   if (root/('stage-'+str(index)+'.json.ready')).is_file():stage=index
  if (root/'worker-failure.json.ready').is_file():worker=read(root/'worker-failure.json',4096)
  if terminal is None and (root/'cleanup-terminal.json.ready').is_file():terminal=read(root/'cleanup-terminal.json',16384)
  if terminal is None and (root/'outer-job/process.json').is_file():
   rec=read(root/'outer-job/process.json');cap=rec.get('actualCap',{});terminal={'launcherTerminal':'UNKNOWN','workerPidfdTerminal':'NOT_APPLICABLE_WINDOWS','ownedPopulation':cap.get('activeProcessesAtTeardown','UNKNOWN'),'workerExitCode':rec.get('exitCode','UNKNOWN'),'evidenceSha256':digest(root/'outer-job/process.json')}
  if stop is None and (root/'stop-outcome.json.ready').is_file():stop=read(root/'stop-outcome.json',16384)
 clean=lambda value: value if type(value) is int or value in (None,True,False) else (value if type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',value) else 'UNKNOWN')
 term={k:clean((terminal or {}).get(k,'UNKNOWN')) for k in ['launcherTerminal','workerPidfdTerminal','ownedPopulation','workerExitCode','cleanupResult','evidenceSha256']}
 stopValue={k:clean((stop or {}).get(k,'UNKNOWN')) for k in ['serviceResult','exitCode','exitStatus','remainingPopulationExcludingObserver']}
 receipt={'schema':'sdk11-ci-failure-summary/v1','state':'FAILURE_OBSERVED_NO_QUALIFICATION','rid':rid,'sourceCommit':clean(os.environ.get('GITHUB_SHA','UNKNOWN')),'runId':clean(os.environ.get('GITHUB_RUN_ID','UNKNOWN')),'job':clean(os.environ.get('GITHUB_JOB','UNKNOWN')),'attempt':clean(os.environ.get('GITHUB_RUN_ATTEMPT','UNKNOWN')),'controllerSha256':digest(Path(sys.argv[0])) if Path(sys.argv[0]).is_file() else 'UNKNOWN','workflowSha256':digest(ROOT/'.github/workflows/verify.yml') if (ROOT/'.github/workflows/verify.yml').is_file() else 'UNKNOWN','actualStage':stage,'cause':{k:clean(cause.get(k,'UNKNOWN')) for k in ['exceptionType','code','errno']},'workerCause':{k:clean((worker or {}).get(k,'UNKNOWN')) for k in ['exceptionType','code','errno']},'terminal':term,'stopOutcome':stopValue,'boundary':'SANITIZED_FAILURE_ONLY_NOT_HOST_FACT_NOT_PASS_NO_SDK_OR_RAW_OUTPUT'}
 raw=json.dumps(receipt,sort_keys=True,indent=2).encode();f.need(len(raw)<=32768,'FAILURE_SUMMARY32K_LIMIT');proof=ROOT/'artifacts'/('sdk11-qualification-'+rid);proof.mkdir(parents=True,exist_ok=True);target=proof/'failure-summary.json'
 if not target.exists():
  staged=proof/'failure-summary.private.tmp'
  with staged.open('xb') as stream:stream.write(raw)
  os.replace(staged,target)
 f.need(target.stat().st_size<=32768,'FAILURE_SUMMARY32K_LIMIT');return target
