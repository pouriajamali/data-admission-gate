"""Bounded SDK-zero fault isolation of the existing own-unit network transition.
Same pinned method/caps/pidfd controls, no native/SDK/qualification replay.
"""
import argparse,base64,faulthandler,hashlib,importlib.util,json,os,pathlib,select,shlex,signal,subprocess,sys,time,uuid
faulthandler.enable(all_threads=True)
HERE=pathlib.Path(__file__).resolve().parent
p=HERE/'curate_windows_inputs_local_linux.py'
if hashlib.sha256(p.read_bytes()).hexdigest()!='2cc7f454d9a31da5933f1dcba9d0f45a2ef104064f35b8b29736efe2ca188ca9':raise RuntimeError('FIXED_NATIVE_CONTROLLER_SOURCE')
sp=importlib.util.spec_from_file_location('existing_native_controller',p);N=importlib.util.module_from_spec(sp);sys.modules[sp.name]=N;sp.loader.exec_module(N)
Q=N.Q;R=N.R;j=N.j;M=N.M;check=N.check;PURPOSE='LINUX139_SCOPED_TRANSITION_DIAGNOSTIC_SDK0';PROFILE=HERE/'producer04-linux139-transition-diagnostic.profile.json'

def bound(s):
 check(s['purpose']==PURPOSE and s['controllerSha256']==R.digest(__file__) and s['profileSha256']==R.digest(PROFILE),'DIAGNOSTIC_SOURCE_BOUND')
 ref=pathlib.Path('/mnt/e/Codex WorkSpace/Git Projects/data-admission-gate/repo/.git/refs/heads/codex/shared-normal-windows-20261117');check(ref.read_text().strip()==s['expectedCommit'],'EXACT_CURRENT_SOURCE_COMMIT')
 pins=R.read(HERE/'producer04-local-source-pins.json');rows={x['path']:x for x in pins['sourcePins']}
 for p in [pathlib.Path(__file__),PROFILE,HERE/'curate_windows_inputs_local_linux.py']:
  rel=p.relative_to(HERE.parent).as_posix();b=p.read_bytes();check(rel in rows and hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==rows[rel]['gitBlob'],'ACTUAL_DIAGNOSTIC_CALLER_PIN_BYTES')
 return {'commit':s['expectedCommit'],'controllerSha256':R.digest(__file__),'profileSha256':R.digest(PROFILE),'sourcePinsSha256':R.digest(HERE/'producer04-local-source-pins.json'),'methodSha256':R.digest(M.__file__)}

def worker(path):
 s=R.read(path);source=bound(s);root=path.parent;j.bind(s);cap=j.linux_caps();R.write(root/'stopped-worker.json',{'pid':os.getpid(),'start':Q.start_identity(os.getpid()),'cap':cap,'uid':os.getuid(),'gid':os.getgid()});os.kill(os.getpid(),signal.SIGSTOP);held=R.read(root/'held-worker-before-continue.json');check(held['pid']==os.getpid() and held['start']==Q.start_identity(os.getpid()) and held['kernelLimits']==cap['kernelLimits'],'ACTUAL_HELD_DIAGNOSTIC_WORKER')
 snapshot=M.pid_snapshot(os.getpid(),s['unit']);request={'purpose':'PRODUCER04_LINUX_INPUT_CURATION','unit':s['unit'],'worker':snapshot,'uid':os.getuid(),'originalStartMonotonicNs':s['startTick']*1000000,'sourceHEAD':s['expectedCommit'],'leaseAdmissionSHA256':s['leaseAdmissionSHA256']};request['requestSHA256']=hashlib.sha256(json.dumps(request,sort_keys=True,separators=(',',':')).encode()).hexdigest();R.write(root/'network-transition-request.json',request);os.kill(os.getpid(),signal.SIGSTOP);policy=R.read(root/'network-policy-applied.json');check(policy['requestSHA256']==request['requestSHA256'],'EXACT_DIAGNOSTIC_POLICY_RESULT');R.write(root/'WORKER-DIAGNOSTIC-FACT.json',{'state':'EXISTING_SCOPED_KERNEL_TRANSITION_RETURNED_WITH_REAL_READBACK','source':source,'policy':policy,'caps':cap,'SDK':0,'networkRequests':0,'networkDenialWitness':'NOT_EXECUTED_NO_SDK_ADMISSION','parentHeldWorkerBeforeExec':held})

def transition(path):
 s=R.read(path);bound(s);root=path.parent;check(os.geteuid()==0,'EXISTING_TRUSTED_ROOT_POLICY_ACTOR');check(root.name.startswith('.admission04-linux139-diag-') and root.parent==pathlib.Path('/home/ubuntu') and root.stat().st_uid==1000 and root.stat().st_mode&0o777==0o700,'EXACT_PRIVATE_DIAGNOSTIC_SCOPE');request=R.read(root/'network-transition-request.json');check(request['unit']==s['unit'] and request['sourceHEAD']==s['expectedCommit'] and request['leaseAdmissionSHA256']==s['leaseAdmissionSHA256'],'EXACT_CURRENT_REQUEST_SCOPE');check(R.clock()<s['startTick']+45000,'ORIGINAL_DIAGNOSTIC_WORK_CLOCK');fd=os.open(root/'method-line-trace.ndjson',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);count=0
 def trace(frame,event,arg):
  nonlocal count
  if frame.f_code.co_filename==M.__file__ and frame.f_code.co_name in ('scoped_parent_transition','bpf_query','pid_snapshot','validate_stopped','policy_readback') and event in ('line','call','return'):
   count+=1;check(count<=256,'BOUNDED_METHOD_LINE_TRACE');os.write(fd,(json.dumps({'event':event,'function':frame.f_code.co_name,'line':frame.f_lineno,'tick':R.clock()})+'\n').encode())
  return trace
 try:
  sys.settrace(trace);policy=M.scoped_parent_transition(request)
 finally:sys.settrace(None);os.close(fd)
 R.write(root/'isolated-policy-result.json',policy)

def isolated_transition(s,request):
 root=pathlib.Path(s['root']);deadline=min(s['startTick']+45000,R.clock()+15000);check(R.clock()<deadline,'BOUNDARY_BEFORE_POLICY_CHILD');argv=[sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--transition',str(root/'private-spec.json')]
 result=subprocess.run(argv,capture_output=True,env=Q.OS_ENV,timeout=max(.1,(deadline-R.clock())/1000));check(len(result.stdout)+len(result.stderr)<=65536,'BOUNDED_ISOLATED_POLICY_REPORT');(root/'transition-child.stdout').write_bytes(result.stdout);(root/'transition-child.stderr').write_bytes(result.stderr);R.write(root/'transition-child-result.json',{'argv':argv,'returnCode':result.returncode,'stdoutSha256':hashlib.sha256(result.stdout).hexdigest(),'stderrSha256':hashlib.sha256(result.stderr).hexdigest(),'SDK':0,'samePinnedMethodSHA256':R.digest(M.__file__),'scope':'Fixed existing same owned-unit method only; no arbitrary/root SDK command.'});check(result.returncode==0,'ISOLATED_POLICY_EXIT_'+str(result.returncode));return R.read(root/'isolated-policy-result.json')

def run_parent(s,argv):
 root=pathlib.Path(s['root']);proc=pidfd=None;error=None;transitioned=False;held=None
 try:
  prior,_=Q.own_unit_show(s['unit'],min(s['startTick']+60000,R.clock()+2000));check(prior.get('LoadState')=='not-found','OWN_UNIT_ABSENT')
  with (root/'launcher-stdout.log').open('xb') as out,(root/'launcher-stderr.log').open('xb') as err:
   proc=subprocess.Popen(argv,stdout=out,stderr=err,env=Q.OS_ENV);deadline=min(s['startTick']+60000,R.clock()+20000)
   while not (root/'stopped-worker.json.ready').is_file():check(proc.poll() is None and R.clock()<deadline,'HELD_WORKER_STARTUP');time.sleep(.05)
   held=R.read(root/'stopped-worker.json');pid=held['pid'];pidfd=os.pidfd_open(pid);snap=M.pid_snapshot(pid,s['unit'])
   while snap['state'] not in ('T','t'):check(proc.poll() is None and R.clock()<deadline,'WORKER_MUST_STOP');time.sleep(.01);snap=M.pid_snapshot(pid,s['unit'])
   check(held['uid']==held['gid']==1000 and snap['start']==held['start'] and snap['limits']==held['cap']['kernelLimits'],'HELD_MAINPID_START_LIMITS');R.write(root/'held-worker-before-continue.json',{'pid':pid,'start':held['start'],'kernelLimits':snap['limits'],'pidfdRetained':True,'state':snap['state'],'cgroup':snap['cgroup']});signal.pidfd_send_signal(pidfd,signal.SIGCONT)
   while proc.poll() is None:
    check(R.clock()<s['startTick']+45000 and out.tell()+err.tell()<=1048576,'ORIGINAL_WORK840_LOG1M');rp=root/'network-transition-request.json'
    if not transitioned and rp.with_name(rp.name+'.ready').is_file():
     request=R.read(rp,16384);check(request['worker']['pid']==pid and request['worker']['start']==held['start'] and request['unit']==s['unit'] and request['sourceHEAD']==s['expectedCommit'] and request['originalStartMonotonicNs']==s['startTick']*1000000 and rp.stat().st_uid==1000 and root.stat().st_uid==1000 and root.stat().st_mode&0o777==0o700,'EXACT_PRIVATE_NETWORK_REQUEST')
     check(request['requestSHA256']==hashlib.sha256(json.dumps({k:v for k,v in request.items() if k!='requestSHA256'},sort_keys=True,separators=(',',':')).encode()).hexdigest(),'CANONICAL_NETWORK_REQUEST')
     while M.pid_snapshot(pid,s['unit'])['state'] not in ('T','t'):check(R.clock()<s['startTick']+540000,'ORIGINAL_NETWORK540');time.sleep(.001)
     policy=isolated_transition(s,request);R.write(root/'network-policy-applied.json',policy);transitioned=True;signal.pidfd_send_signal(pidfd,signal.SIGCONT)
    time.sleep(.02)
   check(proc.returncode==0 and transitioned,'NATIVE_WORKER_AND_TRANSITION_SUCCESS')
 except BaseException as exc:error=exc
 terminal,stop=Q.cleanup_owned_linux(s,proc,pidfd,error is not None)
 if error is not None or terminal['cleanupResult']!='OWNED_TERMINAL_OBSERVED' or stop is None or stop.get('serviceResult')!='success' or stop.get('exitCode')!='exited' or stop.get('exitStatus')!='0' or stop.get('remainingPopulationExcludingObserver')!=0:
  R.write(root/'NATIVE-HOLD.json',{'state':'HOLD','errorType':type(error).__name__ if error else None,'code':str(error)[:180] if error else 'NATIVE_TERMINAL_UNKNOWN','terminal':terminal})
  if error:raise error
  raise R.f.Denied('NATIVE_TERMINAL_UNKNOWN')
 return terminal,stop

def export(root,state):
 names=['DIAGNOSTIC-FACT.json','cleanup-terminal.json','NATIVE-HOLD.json','stop-outcome.json','WORKER-DIAGNOSTIC-FACT.json','source-binding.json','transition-child-result.json','transition-child.stdout','transition-child.stderr','method-line-trace.ndjson','network-transition-request.json','network-policy-applied.json','private-spec.json','held-worker-before-continue.json','launcher-stderr.log','launcher-stdout.log'];files=[]
 for name in names:
  p=root/name
  if p.is_file():
   b=p.read_bytes();check(len(b)<=262144,'FINITE_DIAGNOSTIC_PROOF_ITEM');files.append({'name':name,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'base64':base64.b64encode(b).decode()})
 check(sum(x['bytes'] for x in files)<=1048576,'FINITE_DIAGNOSTIC_PROOF');print(json.dumps({'state':state,'root':str(root),'files':files}),flush=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('--expected-commit');p.add_argument('--worker',type=pathlib.Path);p.add_argument('--stop-post',type=pathlib.Path);p.add_argument('--transition',type=pathlib.Path);a=p.parse_args()
 if a.stop_post:Q.stop_post(a.stop_post);return
 if a.worker:worker(a.worker);return
 if a.transition:transition(a.transition);return
 check(os.geteuid()==0 and pathlib.Path('/run/systemd/private').exists(),'EXISTING_ROOT_OS_STARTER_SYSTEMD');start=R.clock();root=pathlib.Path('/home/ubuntu')/('.admission04-linux139-diag-'+uuid.uuid4().hex);root.mkdir(mode=0o700);os.chown(root,1000,1000);unit='admission04-sdk11-ci-'+uuid.uuid4().hex;current=pathlib.Path('/mnt/e/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave2-state/LOCAL-FIXTURE-LEASE.json');leasebytes=current.read_bytes();lv=json.loads(leasebytes);lease=N.winpath(lv['receiptDirectory'])/'LEASE.json';check(lease.read_bytes()==leasebytes and lv['projectId']=='04' and lv['phase']==PURPOSE,'EXACT_OWN_DIAGNOSTIC_LEASE');s={'purpose':PURPOSE,'rid':'linux-x64','root':str(root),'unit':unit,'uid':1000,'gid':1000,'expectedCommit':a.expected_commit,'startTick':start,'controllerSha256':R.digest(__file__),'profileSha256':R.digest(PROFILE),'supervisorPID':os.getpid(),'supervisorStartIdentity':'proc-start:'+Q.start_identity(os.getpid()),'leaseAdmissionSHA256':hashlib.sha256(leasebytes).hexdigest()};private=root/'private-spec.json';R.write(private,s);R.write(root/'source-binding.json',bound(s));print(json.dumps({'state':'STARTED_CAUSAL_LINUX139_DIAGNOSTIC_SDK0','root':str(root),'unit':unit}),flush=True);observer=' '.join(shlex.quote(str(x)) for x in [sys.executable,'-I','-S','-B',pathlib.Path(__file__).resolve(),'--stop-post',private]);argv=['/usr/bin/systemd-run','--wait','--collect','--pipe','--unit='+unit,'--uid=1000','--gid=1000','--property=Description='+unit,'--property=MemoryMax=4294967296','--property=MemorySwapMax=0','--property=TasksMax=64','--property=CPUQuota=200%','--property=CPUQuotaPeriodSec=100ms','--property=RuntimeMaxSec=45','--property=TimeoutStopSec=5','--property=KillMode=control-group','--property=WorkingDirectory='+str(HERE.parent),'--property=ExecStopPost='+observer,'--setenv=PYTHONDONTWRITEBYTECODE=1',sys.executable,'-I','-S','-B',str(pathlib.Path(__file__).resolve()),'--worker',str(private)];state='HOLD'
 try:
  terminal,stop=run_parent(s,argv);check(R.clock()<start+120000,'WHOLE_DIAGNOSTIC120');R.write(root/'DIAGNOSTIC-FACT.json',{'state':'EXISTING_NETWORK_TRANSITION_DIAGNOSTIC_COMPLETED_SDK0','worker':R.read(root/'WORKER-DIAGNOSTIC-FACT.json'),'terminal':terminal,'stop':stop,'wholeSeconds':(R.clock()-start)/1000,'SDK':0,'old139Cause':'Not assumed by successful current metadata test. See preserved own core and isolated child trace.'});state='EXISTING_NETWORK_TRANSITION_DIAGNOSTIC_COMPLETED_SDK0'
 except BaseException as exc:R.write(root/'DIAGNOSTIC-FACT.json',{'state':'HOLD','errorType':type(exc).__name__,'code':str(exc)[:180],'SDK':0,'wholeSeconds':(R.clock()-start)/1000})
 export(root,state)
 if state=='HOLD':raise SystemExit(1)
if __name__=='__main__':main()
