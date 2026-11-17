"""Only3 causal groups/mode. HTTP, processes and alarms are synthetic/mocked."""
import argparse,copy,datetime,email.message,email.utils,hashlib,importlib.util,json,tempfile,time,types
from pathlib import Path
from unittest.mock import patch
START=time.monotonic();HERE=Path(__file__).resolve().parent

def module(name):
 p=HERE/('tools__'+name+'.py') if (HERE/('tools__'+name+'.py')).exists() else HERE/(name+'.py');s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
L=module('curate_dotnet11_linux_inputs');A=module('curation_advisory_source04');rows=[]
def check(v):
 if not v:raise RuntimeError('CAUSAL_GROUP_EXPECTATION')
def deny(fn,code):
 try:fn()
 except (L.Hold,A.Hold) as e:check(str(e)==code);return
 raise RuntimeError('EXPECTED_CAUSAL_HOLD_MISSING')
def group(name,fn):fn();rows.append({'group':len(rows)+1,'name':name,'state':'PASS_SYNTHETIC_ONLY'})

def proof_group():
 with tempfile.TemporaryDirectory() as temp:
  root=Path(temp);ledger={};packages=[i.lower() for i in L.IDS];originals={}
  for relative in L.durable_proof_limits():
   p=root/relative;p.parent.mkdir(parents=True,exist_ok=True)
   if '/locks/' in relative:body=(json.dumps({'version':1,'dependencies':{'net11.0':{i:{'type':'Transitive','resolved':'11.0.0','contentHash':'observed-content'} for i in packages}}})+'\r\n').encode()
   elif relative.endswith('.nupkg.metadata'):body=b'{"contentHash":"observed-content","source":"/private/actual/raw"}\r\n'
   else:body=b'<actual private="/private/original" />\r\n'
   p.write_bytes(body);originals[relative]=body;L.capture_durable(root,relative,ledger)
  (root/'curation/packages/DO-NOT-COPY.nupkg').write_bytes(b'synthetic forbidden body');value={'durableInputs':ledger,'locks':[]};paths,durable=L.curation_proof_candidates(root,value,True);selected={p.relative_to(root).as_posix() for p in paths};check(set(originals)<=selected and 'curation/packages/DO-NOT-COPY.nupkg' not in selected)
  for relative in durable:check(L.read_proof_payload(root,root/relative,value,durable)==originals[relative] and ledger[relative]['sha256']==hashlib.sha256(originals[relative]).hexdigest())
  missing='curation/locks/'+L.LOCK_PROOF_NAMES[0];(root/missing).unlink();deny(lambda:L.curation_proof_candidates(root,value,True),'DURABLE_REQUIRED_FILE_MISSING');(root/missing).write_bytes(originals[missing]);ledger[missing]=L.durable_snapshot(root,missing)[0]
  meta=next(r for r in originals if r.endswith('.nupkg.metadata'));(root/meta).write_bytes(b'{"changed":true}');deny(lambda:L.curation_proof_candidates(root,value,True),'DURABLE_ORIGINAL_CHANGED');deny(lambda:L.curation_proof_candidates(root,value,False),'DURABLE_ORIGINAL_CHANGED')
  reserve=2097152+L.durable_proof_reserve();check(L.durable_proof_reserve()==671744 and L.retention_ledger([8388608-reserve],reserve)['fits']);check(not L.retention_ledger([8388608-reserve+1],reserve)['fits']);deny(lambda:L.durable_snapshot(root,'curation/packages/DO-NOT-COPY.nupkg'),'DURABLE_FIXED_PATH_REQUIRED')
group('R1 exact four locks consumed metadata/config originals missing changed overflow',proof_group)

class Clock:
 def __init__(self):self.ns=100000000000;self.sig=None
 def advance(self,seconds,fire=True):
  self.ns+=int(seconds*1000000000)
  if fire and self.sig.due is not None and self.ns>=self.sig.due:
   handler=self.sig.handler;self.sig.due=None;handler(14,None)
class Signals:
 SIGALRM=14;ITIMER_REAL=0
 def __init__(self,clock,old=420):self.clock=clock;clock.sig=self;self.original=object();self.handler=self.original;self.due=clock.ns+int(old*1000000000) if old else None;self.sets=[]
 def getsignal(self,*a):return self.handler
 def signal(self,sig,handler):old=self.handler;self.handler=handler;return old
 def getitimer(self,*a):return (max(0,(self.due-self.clock.ns)/1000000000) if self.due is not None else 0,0)
 def setitimer(self,kind,seconds,interval=0):self.sets.append(seconds);self.due=self.clock.ns+int(seconds*1000000000) if seconds>0 else None
URL='https://api.nuget.org/v3/index.json';WIRE=b'{"ok":true}'
class Response:
 status=200
 def __init__(self,clock,variant):
  self.clock=clock;self.variant=variant;self.remaining=b'' if variant=='zero' else WIRE;self.reads=0;self.headers=email.message.Message();self.headers['Content-Length']=str(len(self.remaining));self.headers['Date']=email.utils.formatdate(1800000000,usegmt=True);self.fp=types.SimpleNamespace(raw=types.SimpleNamespace(_sock=types.SimpleNamespace(getpeername=lambda:('13.107.1.1',443),settimeout=lambda _:None)))
 def __enter__(self):return self
 def __exit__(self,*a):
  if self.variant=='close':self.clock.advance(11,fire=False)
 def geturl(self):
  if self.variant in ('headers','zero'):self.clock.advance(11,fire=False)
  return URL
 def read(self,n):self.reads+=1;out=self.remaining[:n];self.remaining=self.remaining[n:];return out
class Job:
 def __init__(self,clock):self.clock=clock;self.starts=0;self.deadlines=[]
 def linux_caps(self):return {'uid':1001,'gid':1001,'cgroup':'/system.slice/admission04-sdk11-ci-'+('a'*32)+'.service'}
 def run(self,argv,cwd,env,deadline,evidence):
  self.starts+=1;self.deadlines.append(deadline);spec=json.loads(Path(argv[6]).read_bytes());A._owned_request_child(spec);evidence=Path(evidence);evidence.mkdir();(evidence/'stdout.log').write_bytes(b'');(evidence/'stderr.log').write_bytes(b'');rec={'exitCode':0,'ownedChildGroupTerminal':True,'actualCap':self.linux_caps()};(evidence/'process.json').write_text(json.dumps(rec));return rec

def scenario(variant):
 with tempfile.TemporaryDirectory() as temp:
  root=Path(temp);clock=Clock();signals=Signals(clock);job=Job(clock);response=Response(clock,variant);calls=[]
  ctx={'deadlineMonotonicNs':clock.ns+420000000000,'utcNow':1800000000,'requested':set(),'records':[],'ownedJob':job,'requestWorkRoot':str(root),'requestCwd':str(root),'requestEnvironment':{}}
  def open_fake(*a,**k):
   calls.append(1)
   if variant=='startup':clock.advance(11)
   if variant=='error':clock.advance(11,fire=False);raise A.Hold('SYNTHETIC_OPEN_ERROR')
   if variant=='earlyerror':clock.advance(1);raise A.Hold('SYNTHETIC_OPEN_ERROR')
   clock.advance(.1);return response
  originalsave=A.save;dest=root/'complete.wire'
  def save_fake(path,body):
   originalsave(path,body)
   if variant=='return' and Path(path)==dest:clock.advance(11,fire=False)
  with patch.object(A,'signal',signals),patch.object(A.time,'monotonic_ns',lambda:clock.ns),patch.object(A.urllib.request,'build_opener',return_value=types.SimpleNamespace(open=open_fake)),patch.object(A,'save',side_effect=save_fake):
   operation=lambda:A.bounded_get(ctx,URL,dest,1024,{'bodyBytes':0},(URL,),True)
   if variant=='good':record,body=operation();check(body==WIRE and record['ownedHTTP']['sameCgroup']==job.linux_caps()['cgroup'])
   elif variant=='earlyerror':deny(operation,'SYNTHETIC_OPEN_ERROR')
   else:deny(operation,'METADATA_REQUEST10_DEADLINE')
  check(job.starts==1 and len(calls)==1 and job.deadlines[0]<(100000000000+10000000000)//1000000);check(signals.handler is signals.original and signals.getitimer()[0]<=420 and ctx['deadlineMonotonicNs']==520000000000)
  if variant in ('startup','headers','zero','error'):check(response.reads==0)
def request_group():
 for variant in ('good','startup','headers','zero','error','close','return','earlyerror'):scenario(variant)
group('R2 owned helper startup headers zero body error and terminal absolute deadlines',request_group)

def clock_group():
 for remaining in (6,0):
  clock=Clock();signals=Signals(clock,remaining);original_end=signals.due;ctx={'deadlineMonotonicNs':clock.ns+420000000000}
  with patch.object(A,'signal',signals),patch.object(A.time,'monotonic_ns',lambda:clock.ns):
   with A.absolute_request(ctx) as (end,code):
    check(end==min(110000000000,original_end or 110000000000));clock.advance(2)
  check(signals.handler is signals.original)
  check(signals.due==original_end if remaining else signals.due is None)
 clock=Clock();signals=Signals(clock,3);ctx={'deadlineMonotonicNs':clock.ns+420000000000}
 def expires():
  with A.absolute_request(ctx):clock.advance(4,fire=False)
 with patch.object(A,'signal',signals),patch.object(A.time,'monotonic_ns',lambda:clock.ns):deny(expires,'ORIGINAL_METADATA_DEADLINE')
 check(signals.handler is signals.original and signals.due is None and max(signals.sets)<=3)
group('R2 original outer clock remaining restored without reset or extension',clock_group)
check(len(rows)==3 and time.monotonic()-START<30);inputbytes=sum(Path(m.__file__).stat().st_size for m in (L,A))+len(WIRE);check(inputbytes<=524288);result={'schema':'producer04-r1r2-causal-source-mocks/v1','state':'THREE_NEW_CAUSAL_GROUPS_PASS','groups':3,'optimize':__import__('sys').flags.optimize,'seconds':round(time.monotonic()-START,6),'inputBytes':inputbytes,'sourceSHA256':{n:hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for n,m in [('curate_dotnet11_linux_inputs',L),('curation_advisory_source04',A)]},'rows':rows,'old18Replay':0,'old24Replay':0,'commonHealthyReplay':0,'actualHTTPProcessesSignalsSDKOpenSSLKernel':0};body=(json.dumps(result,indent=2)+'\n').encode();check(len(body)<=32768);parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
with args.out.open('xb') as f:f.write(body)
print(json.dumps({k:result[k] for k in ['state','groups','optimize','seconds','inputBytes','actualHTTPProcessesSignalsSDKOpenSSLKernel']}))
