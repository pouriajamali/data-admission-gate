"""Three SOURCE-only public input groups; HTTP/clock/signals/held Job all fake."""
import argparse,ast,base64,hashlib,importlib.util,json,os,pathlib,sys,tempfile,time,types,urllib.error
HERE=pathlib.Path(__file__).resolve().parent
def file(name):
 p=HERE/(name+'.py');return p if p.exists() else HERE/('tools__'+name+'.py')
def load(name):
 p=file(name);s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
P=load('curation_public_input04');S=load('curation_safe_cause04');C=load('curate_dotnet11_linux_inputs')
def check(v,code):
 if not v:raise RuntimeError(code)
def denied(fn):
 try:fn()
 except (P.PublicHold,C.Hold,S.WorkspaceError):return
 raise RuntimeError('EXPECTED_SOURCE_DENIAL')
def source_path(name):return HERE/name.replace('/','__') if (HERE/'PREP.json').exists() else HERE.parent/name
def manifest(head='a'*40):return {'schema':'producer04-linux-public-input-manifest/v1','sourceHEAD':head,'inputTransport':P.MODE,'publicTransportAmendmentSHA256':P.AMENDMENT_SHA,'publicInputs':list(P.INPUTS),'ownerScratchLimitBytes':2147483648,'leaseAdmissionPath':str(pathlib.Path(tempfile.gettempdir()).resolve()/'lease.json')}
class Clock:
 def __init__(self):self.now=1000000000
 def advance(self,n):self.now+=n
class Signals:
 SIGALRM=14;ITIMER_REAL=0
 def __init__(self,clock,old=0):self.clock=clock;self.end=clock.now+int(old*1e9) if old else None;self.handler='original';self.calls=[]
 def getsignal(self,*a):return self.handler
 def signal(self,n,handler):self.handler=handler
 def getitimer(self,*a):return (max(0,(self.end-self.clock.now)/1e9) if self.end else 0,0)
 def setitimer(self,n,seconds):self.calls.append(seconds);self.end=self.clock.now+int(seconds*1e9) if seconds else None
class FakeFS:
 """Only tiny fresh files are real; POSIX uid/mode/large-file metadata is mocked."""
 def __init__(self):self.modes={};self.sizes={};self.fds={};self.os=types.SimpleNamespace(**{n:getattr(os,n) for n in dir(os) if not n.startswith('__')});self.os.environ={};self.os.getpid=lambda:1234;self.os.open=self.open;self.os.fstat=self.fstat;self.os.rename=self.rename
 def path(self,v):return FakePath(pathlib.Path(os.fspath(v)),self)
 def snapshot(self,s,p):
  result={k:getattr(s,k) for k in ('st_mode','st_nlink','st_uid','st_gid','st_dev','st_ino','st_size','st_mtime_ns')};result['st_mode']=(s.st_mode&~0o777)|self.modes.get(str(p),0o600);result['st_size']=self.sizes.get(str(p),s.st_size);return types.SimpleNamespace(**result)
 def open(self,p,flags,mode):fd=os.open(os.fspath(p),flags,mode);self.fds[fd]=pathlib.Path(os.fspath(p));self.modes[str(self.fds[fd])]=mode;return fd
 def fstat(self,fd):return self.snapshot(os.fstat(fd),self.fds[fd])
 def rename(self,a,b):os.rename(os.fspath(a),os.fspath(b));self.modes[str(pathlib.Path(os.fspath(b)))]=self.modes.pop(str(pathlib.Path(os.fspath(a))))
class FakePath:
 def __init__(self,p,fs):self.p=p;self.fs=fs
 def __fspath__(self):return str(self.p)
 def __str__(self):return self.p.as_posix()
 def __truediv__(self,n):return FakePath(self.p/n,self.fs)
 @property
 def name(self):return self.p.name
 def with_name(self,n):return FakePath(self.p.with_name(n),self.fs)
 def exists(self):return self.p.exists()
 def is_absolute(self):return self.p.is_absolute()
 def is_symlink(self):return self.p.is_symlink()
 def mkdir(self,**kw):return self.p.mkdir(**kw)
 def lstat(self):return self.fs.snapshot(self.p.lstat(),self.p)
 def stat(self):return self.lstat()
 def chmod(self,mode):self.fs.modes[str(self.p)]=mode
 def read_bytes(self):return self.p.read_bytes()
 def open(self,*a,**k):return self.p.open(*a,**k)
 def resolve(self):return self.p.resolve()
class Sandbox:
 def __init__(self,old=0):self.clock=Clock();self.signals=Signals(self.clock,old);self.fs=FakeFS()
 def __enter__(self):self.original=(P.Path,P.os,P.signal,P.time.monotonic_ns,P.urllib.request.build_opener);P.Path=self.fs.path;P.os=self.fs.os;P.signal=self.signals;P.time.monotonic_ns=lambda:self.clock.now;return self
 def __exit__(self,*a):P.Path,P.os,P.signal,P.time.monotonic_ns,P.urllib.request.build_opener=self.original
class Headers:
 def __init__(self,fields):self.fields=fields
 def get_all(self,k,default=None):return self.fields.get(k,default)
class Response:
 def __init__(self,body,row,clock,fields=None,status=200,body_delay=0,close_delay=0,close_error=False):self.body=body;self.row=row;self.clock=clock;self.headers=Headers(fields if fields is not None else {'Content-Length':[str(row['bytes'])]});self.status=status;self.fp=self;self.offset=0;self.reads=[];self.body_delay=body_delay;self.close_delay=close_delay;self.close_error=close_error
 def geturl(self):return self.row['url']
 def read(self,n):self.reads.append(n);self.clock.advance(self.body_delay);self.body_delay=0;piece=self.body[self.offset:self.offset+n];self.offset+=len(piece);return piece
 def close(self):
  self.clock.advance(self.close_delay)
  if self.close_error:raise PermissionError(13,'PRIVATE_CLEANUP_SENTINEL')
class Opener:
 def __init__(self,response,clock,delay=0,error=None):self.response=response;self.clock=clock;self.delay=delay;self.error=error;self.calls=0
 def open(self,request,timeout):
  self.calls+=1;check(request.full_url==self.response.row['url'] and request.headers.get('Accept-encoding')=='identity' and request.headers.get('Connection')=='close' and not any(k.lower() in ('authorization','cookie','range') for k in request.headers),'CLOSED_HTTP_REQUEST');self.clock.advance(self.delay)
  if self.error is not None:raise self.error
  return self.response
def smallrow(body):return {'index':0,'id':'PUBLIC_SYNTHETIC','version':'11.0.0','rid':'linux-x64','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'sha512':hashlib.sha512(body).hexdigest(),'url':P.INPUTS[0]['url']}
def group1():
 m=manifest();check(P.validate_manifest(m,'a'*40)==m,'EXACT_PUBLIC_MANIFEST')
 for key,value in [('inputTransport','CAPSULE'),('sourceHEAD','b'*40),('publicTransportAmendmentSHA256','0'*64),('capsule',{}),('ownerScratchLimitBytes',True)]:bad=dict(m);bad[key]=value;denied(lambda:P.validate_manifest(bad,'a'*40))
 for key,value in [('url',P.INPUTS[0]['url']+'?fallback=1'),('sha256','0'*64),('sha512','0'*128),('bytes',1),('index',False)]:rows=[dict(r) for r in P.INPUTS];rows[0][key]=value;denied(lambda:P.validate_manifest(dict(m,publicInputs=rows),'a'*40))
 denied(lambda:P.validate_manifest(dict(m,publicInputs=list(P.INPUTS)+[P.INPUTS[0]]),'a'*40));denied(lambda:P.validate_manifest(dict(m,publicInputs=list(P.INPUTS)[:2]),'a'*40));denied(lambda:P.strict(b'{"mode":"CAPSULE","mode":"PUBLIC_ORIGINALS_V1"}'));denied(lambda:C.strict_json(b'{"gate":{"x":1,"x":2}}'))
 gate={'schema':'producer04-linux-curation-execution-admission/v1','state':'EXACT_SOURCE_RUNTIME_BOUND','purpose':C.PURPOSE,'sourceHEAD':'a'*40,'sourceTree':'b'*40,'contractSHA256':C.CONTRACT_SHA,'amendmentSHA256':C.AMENDMENT_SHA,'profileSHA256':C.PROFILE_SHA,'inputManifestSHA256':'c'*64,'runId':'123','attempt':'1','leaseAdmissionSHA256':'d'*64,'dispatchNonce':'e'*32,'inputTransport':P.MODE,'publicTransportAmendmentSHA256':P.AMENDMENT_SHA};C.validate_admission(gate,'a'*40,C.PROFILE_SHA);old=dict(gate);old.pop('inputTransport');denied(lambda:C.validate_admission(old,'a'*40,C.PROFILE_SHA))
 tree=ast.parse(file('consume_dotnet11_host_fact').read_bytes());cur=ast.parse(file('curate_dotnet11_linux_inputs').read_bytes());run=next(n for n in cur.body if isinstance(n,ast.FunctionDef) and n.name=='run_curation_worker');check(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='_capsule' for n in ast.walk(run)),'NO_CAPSULE_FALLBACK');check(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='pop' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='CURATION_INPUT_TOKEN' for n in ast.walk(tree)),'NO_TOKEN_READ_POP')
 if (HERE/'PREP.json').exists():
  W=pathlib.Path(json.loads((HERE/'PREP.json').read_bytes())['worktree']);old=ast.parse((W/'tools/consume_dotnet11_host_fact.py').read_bytes())
  for name in ('win_parent','consumer_work'):check(ast.dump(next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name))==ast.dump(next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name==name)),'UNRELATED_ROUTE_UNCHANGED')
  oldw=(W/'.github/workflows/verify.yml').read_text(encoding='utf-8');neww=source_path('.github/workflows/verify.yml').read_text(encoding='utf-8');check(neww==oldw.replace("        env:\n          CURATION_INPUT_TOKEN: ${{ inputs.linux_curation && github.token || '' }}\n",''),'ONLY_WORKFLOW_TOKEN_INJECTION_REMOVED');check(source_path('docs/RELEASE-v0.1.0-preview.3.md').read_bytes().split(b'\n',1)[0]==(W/'docs/RELEASE-v0.1.0-preview.3.md').read_bytes().split(b'\n',1)[0] and b'\xe2\x80\x94' in source_path('docs/RELEASE-v0.1.0-preview.3.md').read_bytes().split(b'\n',1)[0],'TITLE_UTF8_PRESERVED')
 child={'sourceHEAD':'a'*40,'uid':1000,'gid':1000,'sourceSHA256':'1'*64,'dispatchNonce':'2'*32};priv={'purpose':'PRODUCER04_LINUX_INPUT_CURATION','expectedCommit':'a'*40,'uid':1000,'gid':1000,'curationAdmissionSHA256':'3'*64};bound={'state':'EXACT_SOURCE_RUNTIME_BOUND','purpose':'PRODUCER04_LINUX_INPUT_CURATION','sourceHEAD':'a'*40,'dispatchNonce':'2'*32,'inputTransport':P.MODE,'publicTransportAmendmentSHA256':P.AMENDMENT_SHA,'profileSHA256':'4'*64,'contractSHA256':C.CONTRACT_SHA,'amendmentSHA256':C.AMENDMENT_SHA};prof={'inputTransport':P.MODE,'publicInputTransportAmendmentSHA256':P.AMENDMENT_SHA,'publicInputHelperSHA256':'1'*64};argv=[b'python',b'-I',b'-S',b'-B',b'caller',b'--worker',b'private'];P.parent_binding(child,priv,bound,prof,'3'*64,'4'*64,'5'*64,'5'*64,argv,argv);denied(lambda:P.parent_binding(child,priv,dict(bound,dispatchNonce='0'*32),prof,'3'*64,'4'*64,'5'*64,'5'*64,argv,argv));denied(lambda:P.parent_binding(child,priv,bound,prof,'3'*64,'4'*64,'5'*64,'5'*64,[b'foreign'],argv))
 check(len(S.CONTEXT_KEYS)==15,'CONTEXT_UNCHANGED')
def group2():
 body=b'PUBLIC';base=smallrow(body)
 cases=[('good',None,body,200,0,0,0),('status',None,body,403,0,0,0),('missing',{},body,200,0,0,0),('duplicate',{'Content-Length':['6','6']},body,200,0,0,0),('transfer',{'Content-Length':['6'],'Transfer-Encoding':['chunked']},body,200,0,0,0),('encoding',{'Content-Length':['6'],'Content-Encoding':['gzip']},body,200,0,0,0),('short',None,b'PUBLI',200,0,0,0),('extra',None,body+b'X',200,0,0,0),('empty',None,b'',200,0,0,0),('headerLate',None,body,200,46000000000,0,0),('bodyLate',None,body,200,0,46000000000,0),('closeLate',None,body,200,0,0,46000000000)]
 for name,headers,data,status,opening,reading,closing in cases:
  with tempfile.TemporaryDirectory() as work,Sandbox() as box:
   response=Response(data,base,box.clock,headers,status,reading,closing);opener=Opener(response,box.clock,opening);P.urllib.request.build_opener=lambda *a:opener;total={'bodyBytes':0};uid=pathlib.Path(work).stat().st_uid;gid=pathlib.Path(work).stat().st_gid;result=P.request_once(base,work,total,box.clock.now+45000000000,uid,gid);check((result['state']=='COMPLETE')==(name=='good') and opener.calls==1 and max(response.reads or [0])<=65536,'FRAMING_DEADLINE_NO_RETRY');check(result['http']['status']==status,'ACTUAL_RESPONSE_NUMERIC_STATUS')
   if name=='extra':check(result['http']['bodyBytesRead']==7 and total['bodyBytes']==7,'REJECTED_BYTES_COUNTED')
 with tempfile.TemporaryDirectory() as work,Sandbox() as box:
  response=Response(body,base,box.clock);error=urllib.error.HTTPError(base['url'],404,'PRIVATE_TOKEN_URL_SENTINEL',None,None);opener=Opener(response,box.clock,error=error);P.urllib.request.build_opener=lambda *a:opener;result=P.request_once(base,work,{'bodyBytes':0},box.clock.now+45000000000,0,0);check(result['http']['status']==404 and b'PRIVATE_TOKEN_URL_SENTINEL' not in P.canonical(result),'EXACT_HTTPERROR_REDACTED')
 with tempfile.TemporaryDirectory() as work,Sandbox() as box:
  response=Response(body,base,box.clock,close_error=True);opener=Opener(response,box.clock);P.urllib.request.build_opener=lambda *a:opener;result=P.request_once(base,work,{'bodyBytes':0},box.clock.now+45000000000,0,0);check(result['state']=='HOLD' and result['secondaryCloseOrDeadline'] and b'PRIVATE_CLEANUP_SENTINEL' not in P.canonical(result),'CLOSE_FAILURE_REDACTED')
 with Sandbox(old=6) as box:
  with P.absolute_request(box.clock.now+420000000000,box.clock.now+135000000000) as (start,end):check(end-start==6000000000,'ORIGINAL_EARLIER_CLOCK');box.clock.advance(2000000000)
  check(box.signals.getitimer(0)[0]==4,'RESTORE_REMAINING_ONLY')
 with Sandbox(old=3) as box:
  d=S.Trace();check(d.bind(P,hashlib.sha256(file('curation_public_input04').read_bytes()).hexdigest(),'public-input'),'SOURCE_CLASS_BINDING')
  try:
   with P.absolute_request(box.clock.now+420000000000,box.clock.now+135000000000,d):box.clock.advance(4000000000);raise P.PublicHold('PUBLIC_STATUS')
  except P.PublicHold as e:check(e.args==('PUBLIC_STATUS',),'PRIMARY_NOT_MASKED_BY_EXPIRED_CLEANUP')
  check(d.nodes[0]['code']=='PUBLIC_STATUS' and box.signals.getitimer(0)[0]==0,'EXPIRED_CLOCK_NOT_RESET')
def group3():
 data=b'X'*131073;row=smallrow(data)
 with tempfile.TemporaryDirectory() as work,Sandbox() as box:
  response=Response(data,row,box.clock);opener=Opener(response,box.clock);P.urllib.request.build_opener=lambda *a:opener;total={'bodyBytes':211463422};u=pathlib.Path(work).stat().st_uid;g=pathlib.Path(work).stat().st_gid;result=P.request_once(row,work,total,box.clock.now+45000000000,u,g);check(result['state']=='COMPLETE' and result['file']['sha512']==row['sha512'] and max(response.reads)<=65536 and total['bodyBytes']==211463422+len(data),'STREAM_DUAL_HASH_INODE_COUNTER')
 with tempfile.TemporaryDirectory() as work,Sandbox() as box:
  bad=dict(smallrow(b'X'),sha512='0'*128);response=Response(b'X',bad,box.clock);P.urllib.request.build_opener=lambda *a:Opener(response,box.clock);result=P.request_once(bad,work,{'bodyBytes':0},box.clock.now+45000000000,0,0);check(result['state']=='HOLD' and result['code']=='PUBLIC_HASH','DUAL_HASH_REQUIRED')
 with tempfile.TemporaryDirectory() as work,Sandbox() as box:
  row=smallrow(b'XX');response=Response(b'XX',row,box.clock);P.urllib.request.build_opener=lambda *a:Opener(response,box.clock);total={'bodyBytes':536870911};result=P.request_once(row,work,total,box.clock.now+45000000000,0,0);check(result['state']=='HOLD' and total['bodyBytes']==536870913,'GLOBAL_BODY_HARD_STOP')
 d=S.Trace();d.observe_http({'inputIndex':0,'operation':'PUBLIC_ORIGINAL_GET','category':'HTTP_STATUS','status':404,'elapsedNs':1,'bodyBytesRead':0});raw=d.record();check(len(raw)<=16384 and b'httpOperations' in raw,'BOUNDED_SAFE_HTTP_PROOF');denied(lambda:d.observe_http({'inputIndex':0,'operation':'PUBLIC_ORIGINAL_GET','category':'HTTP_STATUS','status':'PRIVATE_SENTINEL','elapsedNs':1,'bodyBytesRead':0}));denied(lambda:d.observe_http({'inputIndex':0,'operation':'PUBLIC_ORIGINAL_GET','category':'HTTP_STATUS','status':200,'elapsedNs':1,'bodyBytesRead':0,'headers':'PRIVATE_SENTINEL'}));check(not C.retention_ledger([8388608-len(raw)+1],len(raw))['fits'] and C.retention_ledger([8388608-len(raw)],len(raw))['fits'],'SAME_8MIB_TYPED_RECORD_CAP')
 # The only held backend is fake. Large original sizes/hashes are metadata stubs,
 # and actual fixture placeholders are one byte; no original body is read.
 with tempfile.TemporaryDirectory() as work,Sandbox() as box:
  root=pathlib.Path(work);phase=root/'curation';phase.mkdir();trace=S.Trace();calls=[];original_policy=P.policy;original_start=P.start_identity;P.policy=lambda:{};P.start_identity=lambda pid:'FAKE_START'
  class Job:
   def linux_caps(self):return {'uid':0,'gid':0,'cgroup':'/system.slice/admission04-sdk11-ci-'+'a'*32+'.service','kernelLimits':{'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'}}
   def run(self,argv,cwd,env,end,evidence):
    check(argv[1:4]==['-I','-S','-B'] and argv[5]=='--owned-public-original' and not any('TOKEN' in k for k in env),'FIXED_HELD_ARGV_ENV');spec=json.loads(pathlib.Path(argv[6]).read_bytes());index=spec['index'];calls.append(index);check(end*1000000<=spec['deadlineNs']-200000000 and spec['deadlineNs']<=spec['rowStartedNs']+420000000000 and spec['deadlineNs']<=spec['requestStartedNs']+45000000000,'ABSOLUTE_SAME_HELD_WINDOW');box.clock.advance(1000000000);row=P.INPUTS[index];target=pathlib.Path(spec['rawDirectory'])/(row['id'].lower()+'.11.0.0.nupkg');target.write_bytes(b'X');box.fs.sizes[str(target)]=row['bytes'];box.fs.modes[str(target)]=0o400;st=target.stat();filemeta={'bytes':row['bytes'],'sha256':row['sha256'],'sha512':row['sha512'],'device':st.st_dev,'inode':st.st_ino,'mtimeNs':st.st_mtime_ns,'uid':0,'gid':0,'mode':256};result={'schema':'producer04-public-original-result/v1','state':'COMPLETE','code':None,'file':filemeta,'http':{'inputIndex':index,'operation':'PUBLIC_ORIGINAL_GET','category':'HTTP_STATUS','status':200,'elapsedNs':1000000000,'bodyBytesRead':row['bytes']},'secondaryCloseOrDeadline':False,'bodyBytesAfter':spec['bodyBytesBefore']+row['bytes'],**{k:spec[k] for k in ('index','amendmentSHA256','sourceSHA256','sourceHEAD','dispatchNonce')}};pathlib.Path(spec['resultPath']).write_bytes(P.canonical(result));evidence.mkdir();(evidence/'stdout.log').open('xb').close();(evidence/'stderr.log').open('xb').close();record={'exitCode':0,'ownedChildGroupTerminal':True};(evidence/'process.json').open('xb').write(P.canonical(record));return record
  try:
   total={'bodyBytes':211463422};rows=P.acquire({'expectedCommit':'a'*40,'root':str(root),'startTick':0},manifest(),phase,total,Job(),trace,{'sourceHEAD':'a'*40,'dispatchNonce':'a'*32});check(calls==[0,1,2] and len(rows)==3 and total['bodyBytes']==271868155 and len(trace.httpOperations)==3,'EXACT_THREE_ONCE_NO_FALLBACK');candidates,_=C.curation_proof_candidates(root,{'durableInputs':{}},False);check(root/'public-original-input-receipt.json' in candidates and not any(p.suffix in ('.nupkg','.partial') for p in candidates),'TYPED_ONLY_SAME_PROOF_NO_BODIES')
  finally:P.policy=original_policy;P.start_identity=original_start
def main():
 a=argparse.ArgumentParser();a.add_argument('--out',type=pathlib.Path,required=True);args=a.parse_args();started=time.monotonic();rows=[]
 for i,fn in enumerate((group1,group2,group3),1):fn();rows.append({'group':i,'state':'PASS_SYNTHETIC_ONLY'})
 seconds=time.monotonic()-started;names=('curation_public_input04','curation_safe_cause04','curate_dotnet11_linux_inputs','consume_dotnet11_host_fact');inputbytes=sum(file(n).stat().st_size for n in names)+pathlib.Path(__file__).stat().st_size+131073;check(seconds<=30 and inputbytes<=524288,'SOURCE_FIXTURE_BUDGET');value={'schema':'producer04-public-originals-source3-mocks/v1','state':'THREE_NEW_CAUSAL_GROUPS_PASS','groups':3,'optimize':sys.flags.optimize,'seconds':round(seconds,3),'inputBytes':inputbytes,'rows':rows,'sourceSHA256':{n:hashlib.sha256(file(n).read_bytes()).hexdigest() for n in names},'actualControllerHTTPDNSTLSJobSignalsSDKNativeCI':0,'old3_18_24_commonSDKCryptoReplay':0,'fixtureBodies':'Small synthetic only; large fixed original byte counts are fake metadata, never package data.'};raw=(json.dumps(value,indent=2)+'\n').encode();check(len(raw)<=32768,'SOURCE_OUTPUT_BOUND')
 with args.out.open('xb') as f:f.write(raw)
 print(json.dumps({'state':value['state'],'groups':3,'optimize':value['optimize'],'seconds':value['seconds'],'inputBytes':inputbytes,'actual':0}))
if __name__=='__main__':main()
