"""ExistingUbuntuOS nonrootcgroup worker/heldchildren, fixedprofile library only."""
from __future__ import annotations
import hashlib,json,os,signal,time
from pathlib import Path
MEMORY=4294967296;TASKS=64;CPUS=2;SPEC=None
class CapError(RuntimeError):pass
def need(v,why):
 if not v:raise CapError(why)
def write(p,v):
 with Path(p).open('x',encoding='utf-8') as f:json.dump(v,f,indent=2)
def bind(spec):
 global SPEC
 need(spec['uid']>0 and spec['gid']>0 and spec['unit'].startswith('admission04-sdk11-ci-'),'OWN_CI_SPEC');SPEC=spec

def linux_caps():
 need(SPEC is not None and os.getuid()==SPEC['uid'] and os.getgid()==SPEC['gid'],'ACTUAL_RUNNER_UID_GID');rel=next((x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::')),None);need(rel and rel.endswith('/'+SPEC['unit']+'.service'),'ACTUAL_OWNED_CGROUP')
 root=Path('/sys/fs/cgroup')/rel.lstrip('/');limits={n:(root/n).read_text().strip() for n in ['memory.max','memory.swap.max','pids.max','cpu.max']};need(limits=={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'},'ACTUAL_KERNEL_CAPS')
 return {'cgroup':rel,'kernelLimits':limits,'uid':os.getuid(),'gid':os.getgid(),'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'memoryPeak':int((root/'memory.peak').read_text()),'pids':[int(x) for x in (root/'cgroup.procs').read_text().split()]}
class LinuxChild:
    def __init__(self,pid): self.pid=pid; self.returncode=None
    def poll(self):
        if self.returncode is None:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid: self.returncode=os.waitstatus_to_exitcode(status)
        return self.returncode
    def wait(self,timeout=None):
        deadline=time.monotonic()+timeout if timeout is not None else None
        while self.poll() is None:
            if deadline is not None and time.monotonic()>deadline: raise CapError('OWNED_CHILD_REAP_TIMEOUT')
            time.sleep(.02)
        return self.returncode

def stopped_linux_child(argv,cwd,env,out,err,pass_fds,cap):
    pid=os.fork()
    if pid==0:
        try:
            os.setsid();os.chdir(cwd)
            with open('/dev/null','rb') as null: os.dup2(null.fileno(),0)
            os.dup2(out.fileno(),1);os.dup2(err.fileno(),2)
            for fd in pass_fds: os.set_inheritable(fd,True)
            os.kill(os.getpid(),signal.SIGSTOP)
            os.execvpe(str(argv[0]),list(map(str,argv)),env)
        except BaseException: os._exit(127)
    p=LinuxChild(pid)
    try:
        waited,status=os.waitpid(pid,os.WUNTRACED)
        need(waited==pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'OWNED_CHILD_STOP_BEFORE_EXEC')
        statrow=(Path('/proc')/str(pid)/'stat').read_text();tail=statrow[statrow.rfind(')')+2:].split()
        need(tail[0] in ('T','t'),'CHILD_NOT_STOPPED')
        membership=(Path('/proc')/str(pid)/'cgroup').read_text()
        need(('0::'+cap['cgroup']) in membership.splitlines(),'CHILD_CGROUP_MISMATCH')
        root=Path('/sys/fs/cgroup')/cap['cgroup'].lstrip('/')
        limits={k:(root/k).read_text().strip() for k in ('memory.max','memory.swap.max','pids.max','cpu.max')}
        need(limits==cap['kernelLimits'],'CHILD_ACTUAL_LIMIT_READBACK')
        proof={'pid':pid,'processStartIdentity':tail[19],'stateBeforeExec':tail[0],'cgroup':membership.strip(),'kernelLimitsBeforeExec':limits}
        os.killpg(pid,signal.SIGCONT)
        return p,proof
    except BaseException:
        try:os.killpg(pid,signal.SIGKILL)
        except ProcessLookupError: pass
        try:os.waitpid(pid,0)
        except ChildProcessError: pass
        raise


def run(argv,cwd,env,deadline_tick,evidence):
 evidence=Path(evidence);evidence.mkdir(parents=True,mode=0o700);cap=linux_caps();started=time.monotonic();timed=False
 with (evidence/'stdout.log').open('xb') as out,(evidence/'stderr.log').open('xb') as err:
  child,before=stopped_linux_child(argv,cwd,env,out,err,(),cap)
  try:
   while child.poll() is None:
    if time.monotonic_ns()//1000000>=deadline_tick or out.tell()+err.tell()>1048576:os.killpg(child.pid,signal.SIGKILL);timed=True;break
    time.sleep(.05)
   child.wait(timeout=5);remaining=[]
   for pid in linux_caps()['pids']:
    try:
     text=Path('/proc',str(pid),'stat').read_text();fields=text[text.rfind(')')+2:].split()
     if int(fields[2])==child.pid:remaining.append(pid)
    except FileNotFoundError:pass
   need(not remaining,'OWNED_CHILD_GROUP_NOT_TERMINAL')
  finally:
   if child.poll() is None:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
 rec={'childBeforeExec':before,'pid':child.pid,'exitCode':child.returncode,'timedOut':timed,'seconds':time.monotonic()-started,'actualCap':cap,'ownedChildGroupTerminal':True};write(evidence/'process.json',rec);need(not timed and child.returncode==0,'CHILD_NONZERO_OR_DEADLINE');return rec
