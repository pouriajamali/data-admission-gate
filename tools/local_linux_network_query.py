"""Local ABI repair for the existing fixed own-cgroup BPF query.
Linux6.18 writes query.revision at56 even for a shorter input attr; allocate64.
Original crypto/guards remain in the immutable e882 module, never monkeypatched.
"""
import ctypes,hashlib,importlib.util,os,pathlib,platform,re,subprocess,sys,time
p=pathlib.Path(__file__).with_name('curation_linux_method.py')
if hashlib.sha256(p.read_bytes()).hexdigest()!='e882af75dc56a5a0f9eb9b4101f2ccaf88141fa3ced9037ea0fd7b1eb357ed74':raise RuntimeError('HISTORICAL_NETWORK_METHOD_IDENTITY')
s=importlib.util.spec_from_file_location('immutable_original_network_method',p);Original=importlib.util.module_from_spec(s);sys.modules[s.name]=Original;s.loader.exec_module(Original)
need=Original.need;pid_snapshot=Original.pid_snapshot;validate_stopped=Original.validate_stopped;policy_readback=Original.policy_readback

def bpf_query(cgroup):
 """Read-only BPF_PROG_QUERY for this exact directory, ingress+egress only."""
 need(platform.machine()=='x86_64' and re.fullmatch(r'/system.slice/admission04-sdk11-ci-[0-9a-f]{32}\.service',cgroup),'BPF_FIXED_NATIVE_CGROUP');fd=os.open('/sys/fs/cgroup'+cgroup,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 class Query(ctypes.Structure):_fields_=[('target_fd',ctypes.c_uint32),('attach_type',ctypes.c_uint32),('query_flags',ctypes.c_uint32),('attach_flags',ctypes.c_uint32),('prog_ids',ctypes.c_uint64),('prog_cnt',ctypes.c_uint32),('pad',ctypes.c_uint32),('prog_attach_flags',ctypes.c_uint64),('link_ids',ctypes.c_uint64),('link_attach_flags',ctypes.c_uint64),('revision',ctypes.c_uint64)]
 need(ctypes.sizeof(Query)==64 and Query.revision.offset==56,'FULL_KERNEL_QUERY_OUTPUT_BUFFER64')
 try:
  libc=ctypes.CDLL(None,use_errno=True);out={}
  for attach,name in [(0,'ingress'),(1,'egress')]:
   ids=(ctypes.c_uint32*64)();q=Query(fd,attach,0,0,ctypes.addressof(ids),64,0,0);rc=libc.syscall(ctypes.c_long(321),ctypes.c_int(16),ctypes.byref(q),ctypes.c_uint(ctypes.sizeof(q)));need(rc==0 and q.prog_cnt<=64,'BPF_QUERY_UNSUPPORTED_OR_FAILED');out[name]=list(ids)[:q.prog_cnt]
  return out
 finally:os.close(fd)

def scoped_parent_transition(request):
 """Trusted parent only. Never installs BPF or changes another unit/global policy."""
 need(os.geteuid()==0 and request.get('purpose')=='PRODUCER04_LINUX_INPUT_CURATION','TRUSTED_CURATION_PARENT_REQUIRED');before=request['worker'];unit=request['unit'];need(before['cgroup']=='/system.slice/'+unit+'.service' and before['uid']==request['uid']>0 and re.fullmatch('[0-9a-f]{40}',request['sourceHEAD']) and re.fullmatch('[0-9a-f]{64}',request['leaseAdmissionSHA256']),'DENY_EXACT_GENERATION');validate_stopped(before,pid_snapshot(before['pid'],unit));old=bpf_query(before['cgroup']);env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','SYSTEMD_PAGER':'cat','SYSTEMD_COLORS':'0'}
 now=time.monotonic_ns();need(0<=now-request['originalStartMonotonicNs']<540000000000,'DENY_ORIGINAL_STAGE540')
 call=subprocess.run(['/usr/bin/systemctl','set-property','--runtime',unit+'.service','IPAddressDeny=any','IPAddressAllow=localhost'],capture_output=True,env=env,timeout=min(5,(request['originalStartMonotonicNs']+540000000000-now)/1e9));need(call.returncode==0 and len(call.stdout)+len(call.stderr)<=16384,'DENY_SET_FAILED')
 keys='Id,Description,ControlGroup,MainPID,ActiveState,IPAddressDeny,IPAddressAllow,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,CPUQuotaPeriodUSec';show=subprocess.run(['/usr/bin/systemctl','show',unit+'.service','--property='+keys],capture_output=True,env=env,timeout=max(.001,min(5,(request['originalStartMonotonicNs']+540000000000-time.monotonic_ns())/1e9)));need(show.returncode==0 and len(show.stdout)+len(show.stderr)<=16384,'DENY_SHOW_FAILED');props={}
 for line in show.stdout.decode('ascii').splitlines():
  key,sep,val=line.partition('=');need(sep and key not in props,'DENY_PROPERTY_FORMAT');props[key]=val
 current=pid_snapshot(before['pid'],unit);validate_stopped(before,current);new=bpf_query(before['cgroup']);proof=policy_readback(props,unit,before['pid'],before['cgroup'],old,new);proof.update(worker=current,unit=unit,requestSHA256=request['requestSHA256'],sourceHEAD=request['sourceHEAD'],leaseAdmissionSHA256=request['leaseAdmissionSHA256']);return proof
