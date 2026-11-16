"""Fixed Ubuntu24 CI system-unit qualifier; no localWSL/userdaemon/rootSDK route."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,select,shlex,signal,subprocess,sys,time,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent;p=HERE/'sdk11_ci_runtime.py'
if hashlib.sha256(p.read_bytes()).hexdigest()!='0c079e050119d80caadb085825e543b2baac24860637a1803c0b5444a5cc624b':raise RuntimeError('RUNTIME_SOURCE_IDENTITY')
spec=importlib.util.spec_from_file_location('sdk11_ci_runtime',p);R=importlib.util.module_from_spec(spec);sys.modules[spec.name]=R;spec.loader.exec_module(R)
j=R.load_module('linux_qualification_job','0d63594368cb6839145d4b1798730fe8fab05f6a94d86834f3a82d52475e7227')
OS_ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','SYSTEMD_PAGER':'cat','SYSTEMD_COLORS':'0'}

def start_identity(pid):
 text=Path('/proc',str(pid),'stat').read_text();return text[text.rfind(')')+2:].split()[19]
class Backend:
 def __init__(self,spec):self.spec=spec;self.n=0;j.bind(spec)
 def run(self,argv,cwd,env,deadline,evidence):return j.run(argv,cwd,env,deadline,evidence)
 def caps(self):
  cap=j.linux_caps();self.n+=1;p=Path(self.spec['root'])/('cgroup-witness-'+str(self.n)+'.json');R.write(p,cap)
  return {'kind':'actual-Linux-cgroup-v2','memoryMax':4294967296,'tasksMax':64,'effectiveCpuCores':2,'swapMax':0,'membershipBeforeExec':True,'heldChildIdentityBeforeExec':bool(self.spec.get('parentHeldWorkerBeforeExec')),'uid':cap['uid'],'gid':cap['gid'],'kernelReadbackSha256':R.digest(p),'peakMemoryBytes':cap['memoryPeak']}
def stop_post(path):
 s=R.read(path);j.bind(s);cap=j.linux_caps();pids=cap['pids'];remaining=len(set(pids)-{os.getpid()})
 R.write(Path(s['root'])/'stop-outcome.json',{'serviceResult':os.environ.get('SERVICE_RESULT','UNKNOWN'),'exitCode':os.environ.get('EXIT_CODE','UNKNOWN'),'exitStatus':os.environ.get('EXIT_STATUS','UNKNOWN'),'observerPID':os.getpid(),'observerStart':start_identity(os.getpid()),'actualCaps':cap,'remainingPopulationExcludingObserver':remaining,'boundary':'RecordednonrootExecStopPost beforecollect; observerterminal stillrequiresparentshow/cgroupabsence. No rootSDK.'})
def worker(path):
 s=R.read(path);R.f.need(s['purpose']=='FIXED_CI_QUALIFICATION_ONLY' and s['rid']=='linux-x64','FIXED_ROLE_REQUIRED');j.bind(s);cap=j.linux_caps();R.write(Path(s['root'])/'stopped-worker.json',{'pid':os.getpid(),'start':start_identity(os.getpid()),'cap':cap,'uid':os.getuid(),'gid':os.getgid()});os.kill(os.getpid(),signal.SIGSTOP)
 witness=R.read(Path(s['root'])/'held-worker-before-continue.json');R.f.need(witness['pid']==os.getpid() and witness['start']==start_identity(os.getpid()) and witness['kernelLimits']==cap['kernelLimits'],'HELD_WORKER_PREEXEC_IDENTITY');s['parentHeldWorkerBeforeExec']=True;R.worker(s,Backend(s))
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--expected-commit');parser.add_argument('--worker',type=Path);parser.add_argument('--stop-post',type=Path);args=parser.parse_args()
 if args.stop_post:stop_post(args.stop_post);return
 if args.worker:worker(args.worker);return
 R.f.need(os.name!='nt' and os.getuid()>0 and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Linux' and Path('/proc/1/comm').read_text().strip()=='systemd' and not Path('/.dockerenv').exists(),'NAMED_UBUNTU_HOST_REQUIRED');R.host('linux-x64');R.f.source(os.environ.get('GITHUB_SHA'),args.expected_commit)
 start=int(os.environ['SDK11_QUALIFICATION_START_TICK']);R.f.need(0<=R.clock()-start<60000,'STARTUP60_EXPIRED');temp=Path(os.environ['RUNNER_TEMP']).resolve();root=temp/('admission04-sdk11-linux-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);R.a.scoped(root,temp,absent=True);root.mkdir(mode=0o700);R.f.need(root.stat().st_uid==os.getuid() and root.stat().st_gid==os.getgid() and (root.stat().st_mode&0o777)==0o700,'FRESH_PRIVATE_RUNNER_ROOT')
 unit='admission04-sdk11-ci-'+uuid.uuid4().hex;private=root/'private-spec.json';s={'purpose':'FIXED_CI_QUALIFICATION_ONLY','rid':'linux-x64','root':str(root),'unit':unit,'uid':os.getuid(),'gid':os.getgid(),'expectedCommit':args.expected_commit,'startTick':start};R.write(private,s);R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000})
 for path in [str(HERE),str(root),sys.executable]:R.f.need(not any(c in path for c in ['\n','\r','%','$','"',"'"]),'SYSTEMD_FIXED_ARGV_PATH')
 envnames=['GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_EVENT_PATH','GITHUB_JOB','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_ENVIRONMENT','RUNNER_OS','RUNNER_NAME','ImageOS','ImageVersion','RUNNER_TEMP'];sets=['--setenv='+k+'='+os.environ[k] for k in envnames if k in os.environ];remaining=max(1,(start+840000-R.clock())//1000);observer=' '.join(shlex.quote(str(x)) for x in [sys.executable,'-I','-S','-B',Path(__file__).resolve(),'--stop-post',private])
 argv=['/usr/bin/sudo','-n','/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid='+str(s['uid']),'--gid='+str(s['gid']),'--property=Description='+unit,'--property=MemoryMax=4294967296','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec='+str(remaining),'--property=TimeoutStopSec=5','--property=KillMode=control-group','--property=WorkingDirectory='+str(R.ROOT),'--property=ExecStopPost='+observer,'--setenv=PYTHONDONTWRITEBYTECODE=1',*sets,sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(private)]
 R.write(root/'root-starter.json',{'argv':argv,'boundary':'ExistingtrustedrootOSstarter only; fixednonrootUser/Group. Allworker/acquisition/extraction/targets/observer insideactualcgroup; norootSDK/arbitraryrootcommand/install/config.'})
 terminal,stop=run_owned_linux(s,argv);R.publish_proof(s,terminal,stop['actualCaps']['memoryPeak'])

def own_unit_show(unit,deadline):
 R.f.need(R.clock()<deadline,'CLEANUP_DEADLINE');props={};result=subprocess.run(['/usr/bin/systemctl','show',unit+'.service','--property=Id,Description,LoadState,ActiveState,MainPID,ControlPID,ControlGroup,Result,ExecMainCode,ExecMainStatus'],capture_output=True,text=True,env=OS_ENV,timeout=max(.01,min(2,(deadline-R.clock())/1000)))
 R.f.need(len(result.stdout)+len(result.stderr)<=16384,'OWNED_SHOW_CAP')
 for line in result.stdout.splitlines():
  if '=' in line:
   key,value=line.split('=',1);props[key]=value
 return props,result.returncode

def cleanup_owned_linux(s,proc,pidfd,failed):
 # At most 50 seconds from failure, and never beyond the existing final60 reserve.
 root=Path(s['root']);unit=s['unit'];deadline=min(s['startTick']+890000,R.clock()+50000);terminal={'launcherTerminal':proc is None,'workerPidfdTerminal':'UNKNOWN','ownedPopulation':'UNKNOWN','workerExitCode':'UNKNOWN','cleanupResult':'UNKNOWN'};actions=[];props={};stop=None;hadUnit=False;stopRequested=False;termSent=False;killSent=False;launcherStop=None;launcherKilled=False
 try:
  R.f.need(re.fullmatch(r'admission04-sdk11-ci-[0-9a-f]{32}',unit) is not None,'OWN_UNIT_NAME')
  while R.clock()<deadline:
   try:
    props,showExit=own_unit_show(unit,deadline);identified=props.get('Id')==unit+'.service' and props.get('Description')==unit
    missing=props.get('LoadState')=='not-found';hadUnit=hadUnit or identified
    if identified:
     group=props.get('ControlGroup','');R.f.need(not group or group=='/system.slice/'+unit+'.service','OWN_UNIT_CGROUP_PATH')
     kernel=Path('/sys/fs/cgroup/system.slice')/(unit+'.service');population='UNKNOWN'
     if kernel.is_dir():population=0 if 'populated 0' in (kernel/'cgroup.events').read_text() else 'NONZERO'
     elif props.get('MainPID')==props.get('ControlPID')=='0' and props.get('ActiveState') in ('inactive','failed'):population=0
     terminal['ownedPopulation']=population
     if failed and proc is not None and not stopRequested:
      # Exactly the original generation-bound unit, never arbitrary/root SDK commands.
      call=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/systemctl','--no-block','stop',unit+'.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=OS_ENV,timeout=max(.01,min(2,(deadline-R.clock())/1000)));actions.append({'action':'STOP_ORIGINAL_OWNED_UNIT','exitCode':call.returncode});stopRequested=True
    if pidfd is not None:
     workerTerminal=bool(select.select([pidfd],[],[],0)[0]);terminal['workerPidfdTerminal']=workerTerminal
     if failed and not workerTerminal:
      sig=signal.SIGKILL if stopRequested and R.clock()>deadline-10000 else signal.SIGTERM
      if (sig==signal.SIGTERM and not termSent) or (sig==signal.SIGKILL and not killSent):
       try:signal.pidfd_send_signal(pidfd,sig);actions.append({'action':'ORIGINAL_WORKER_PIDFD_SIGNAL','signal':int(sig)});termSent=termSent or sig==signal.SIGTERM;killSent=killSent or sig==signal.SIGKILL
       except ProcessLookupError:pass
    if proc is not None:terminal['launcherTerminal']=proc.poll() is not None
    # A not-found unit is terminal only after its original launcher has exited.
    if missing and terminal['launcherTerminal']:terminal['ownedPopulation']=0
    if terminal['launcherTerminal'] and terminal['ownedPopulation']==0 and (pidfd is None or terminal['workerPidfdTerminal'] is True):break
   except (OSError,ValueError,subprocess.TimeoutExpired,R.f.Denied) as exc:
    if len(actions)<12:actions.append({'action':'OBSERVATION_OR_CLEANUP_UNAVAILABLE','cause':R.failure_code(exc)})
   if failed and proc is not None and not terminal['launcherTerminal'] and R.clock()>deadline-5000 and launcherStop is None:
    proc.terminate();launcherStop=R.clock();actions.append({'action':'ORIGINAL_POPEN_TERMINATE'})
   if failed and proc is not None and proc.poll() is None and launcherStop is not None and R.clock()>=launcherStop+1000 and not launcherKilled:
    proc.kill();launcherKilled=True;actions.append({'action':'ORIGINAL_POPEN_KILL'})
   time.sleep(.05)
  if proc is not None and proc.poll() is not None:proc.wait(timeout=.1);terminal['launcherTerminal']=True
  if (root/'stop-outcome.json.ready').is_file():
   stop=R.read(root/'stop-outcome.json',16384);terminal['workerExitCode']=int(stop['exitStatus']) if stop.get('exitCode')=='exited' and str(stop.get('exitStatus','')).isdigit() else 'UNKNOWN'
  terminal['cleanupResult']='OWNED_TERMINAL_OBSERVED' if terminal['launcherTerminal'] and terminal['ownedPopulation']==0 and (pidfd is None or terminal['workerPidfdTerminal'] is True) else 'TERMINAL_UNKNOWN_HOLD'
 except BaseException as exc:actions.append({'action':'CLEANUP_FAILURE','cause':R.failure_code(exc)})
 finally:
  if pidfd is not None:os.close(pidfd)
  R.write(root/'cleanup-terminal.json',{'schema':'owned-linux-cleanup/v1',**terminal,'trustedOsToolIdentities':{'systemctlSha256':R.digest('/usr/bin/systemctl'),'sudoSha256':R.digest('/usr/bin/sudo')},'hadGenerationBoundUnit':hadUnit,'actions':actions,'stopOutcome':stop,'properties':props,'remainingBudgetMs':max(0,s['startTick']+900000-R.clock())})
 terminal['evidenceSha256']=R.digest(root/'cleanup-terminal.json');return terminal,stop

def run_owned_linux(s,argv):
 root=Path(s['root']);proc=None;pidfd=None;error=None;stop=None;terminal=None
 try:
  # The random unit must be absent before launching; Description binds its generation.
  prior,code=own_unit_show(s['unit'],min(s['startTick']+60000,R.clock()+2000));R.f.need(prior.get('LoadState')=='not-found','OWN_UNIT_MUST_BE_ABSENT')
  with (root/'launcher-stdout.log').open('xb') as out,(root/'launcher-stderr.log').open('xb') as err:
   proc=subprocess.Popen(argv,stdout=out,stderr=err,env=OS_ENV);deadline=min(s['startTick']+60000,R.clock()+20000)
   while not (root/'stopped-worker.json.ready').exists():
    R.f.need(proc.poll() is None and R.clock()<deadline,'STOPPED_WORKER_STARTUP_HOLD');time.sleep(.05)
   held=R.read(root/'stopped-worker.json');pid=held['pid'];R.f.need(held['uid']==s['uid'] and held['gid']==s['gid'] and start_identity(pid)==held['start'],'STOPPED_WORKER_IDENTITY');pidfd=os.pidfd_open(pid);R.f.need(start_identity(pid)==held['start'],'PIDFD_START_IDENTITY');text=Path('/proc',str(pid),'stat').read_text()
   while text[text.rfind(')')+2:].split()[0] not in ('T','t'):
    R.f.need(R.clock()<deadline and proc.poll() is None,'WORKER_NOT_STOPPED');time.sleep(.01);text=Path('/proc',str(pid),'stat').read_text()
   R.f.need(text[text.rfind(')')+2:].split()[19]==held['start'],'STOPPED_START_IDENTITY');rel=held['cap']['cgroup'];R.f.need(rel=='/system.slice/'+s['unit']+'.service' and ('0::'+rel) in Path('/proc',str(pid),'cgroup').read_text().splitlines(),'WORKER_CGROUP_BEFORE_EXEC');kernel=Path('/sys/fs/cgroup')/rel.lstrip('/');limits={n:(kernel/n).read_text().strip() for n in ['memory.max','memory.swap.max','pids.max','cpu.max']};R.f.need(limits==held['cap']['kernelLimits'],'WORKER_KERNEL_READBACK');R.write(root/'held-worker-before-continue.json',{'pid':pid,'start':held['start'],'kernelLimits':limits,'pidfdRetained':True});signal.pidfd_send_signal(pidfd,signal.SIGCONT)
   while proc.poll() is None:
    R.f.need(R.clock()<s['startTick']+840000,'OWNED_WORKER840_DEADLINE');R.f.need(out.tell()+err.tell()<=1048576,'OWNED_LAUNCHER_LOG_CAP');time.sleep(.05)
   R.f.need(proc.returncode==0,'OWNED_LAUNCHER_NONZERO')
 except BaseException as exc:error=exc
 finally:
  terminal,stop=cleanup_owned_linux(s,proc,pidfd,error is not None)
 if error is not None or terminal['cleanupResult']!='OWNED_TERMINAL_OBSERVED' or stop is None or stop.get('serviceResult')!='success' or stop.get('exitCode')!='exited' or stop.get('exitStatus')!='0' or stop.get('remainingPopulationExcludingObserver')!=0:
  R.failure_summary(s,R.failure_code(error) if error is not None else {'exceptionType':'Denied','code':'TYPED_SERVICE_OR_TERMINAL_REQUIRED'},terminal,stop)
  if error is not None:raise error
  raise R.f.Denied('TYPED_SERVICE_OR_TERMINAL_REQUIRED')
 success={'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'typedStopResult':'success','terminalEvidenceSha256':terminal['evidenceSha256']};return success,stop

if __name__=='__main__':
 try:main()
 except BaseException as exc:
  R.capture_entry_failure(exc);raise
