"""Three causal SOURCE groups only. All HTTP/Job/clock/kernel surfaces are fakes."""
from pathlib import Path
import argparse,ast,base64,contextlib,datetime,email.utils,hashlib,importlib.util,json,os,signal,sys,tempfile,time,types
from unittest.mock import patch

def check(v,label):
 if not v:raise RuntimeError(label)
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def funcs(raw):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def expect(code,fn):
 try:fn()
 except BaseException as e:
  check(type(e.args[0]) is str and e.args[0]==code,'wrong typed rejection '+code);return e
 raise RuntimeError('missing rejection '+code)
@contextlib.contextmanager
def no_alarm(ctx):yield min(NOW[0]+10000000000,ctx['deadlineMonotonicNs']),'METADATA_REQUEST10_DEADLINE'
class Headers:
 def __init__(self,values=None):self.values={'Date':[email.utils.formatdate(time.time(),usegmt=True)],'Content-Length':['2'],'Cache-Control':['SECRET_HEADER_VALUE'],'Last-Modified':['SECRET_HEADER_VALUE']};self.values.update(values or {})
 def get_all(self,key,default=None):return self.values.get(key,default)
 def get(self,key,default=None):return self.values.get(key,[default])[0]
class Response:
 def __init__(self,values=None,status=200,url=None,body=b'{}'):self.headers=Headers(values);self.status=status;self.url=url or URL;self.body=body;self.reads=0;self.fp=types.SimpleNamespace(raw=types.SimpleNamespace(_sock=types.SimpleNamespace(getpeername=lambda:('192.0.2.1',443),settimeout=lambda value:None)))
 def geturl(self):return self.url
 def __enter__(self):return self
 def __exit__(self,*unused):return False
 def read(self,n):self.reads+=1;out=self.body[:n];self.body=self.body[n:];return out
class Opener:
 def __init__(self,response):self.response=response
 def open(self,request,timeout):
  check(request.full_url==URL and request.get_method()=='GET' and 0<timeout<=10,'one fixed fake GET');FAKE['HTTP']+=1;return self.response
class FakeJob:
 def __init__(self,A,response):self.A=A;self.response=response
 def linux_caps(self):return CAPS
 def run(self,argv,cwd,env,deadline,evidence):
  check('--owned-metadata-request' in argv and argv[-2]=='--sha256' and argv[1:4]==['-I','-S','-B'],'only owned metadata fake child');FAKE['Job']+=1
  path=Path(argv[argv.index('--owned-metadata-request')+1]);raw=path.read_bytes();check(sha(raw)==argv[-1],'same fake spec hash');spec=json.loads(raw);check(spec['url']==URL and spec['allowedURLs']==[URL] and spec['limit']<=2097152 and spec['sourceSHA256']==sha(Path(self.A.__file__).read_bytes()),'fixed request source and shape');check(deadline*1000000<=spec['deadlineMonotonicNs']-200000000,'inside10 terminal reserve')
  with patch.object(self.A.urllib.request,'build_opener',return_value=Opener(self.response)):self.A._owned_request_child(spec)
  evidence=Path(evidence);evidence.mkdir();(evidence/'stdout.log').write_bytes(b'');(evidence/'stderr.log').write_bytes(b'');(evidence/'process.json').write_text('{"exitCode":0,"ownedChildGroupTerminal":true}\n');return {'exitCode':0,'ownedChildGroupTerminal':True}

def group1(A,B):
 cases=[({'Transfer-Encoding':['chunked']},'CHUNKED',1),({'Transfer-Encoding':['identity']},'IDENTITY',1),({'Transfer-Encoding':['gzip']},'GZIP',1),({'Transfer-Encoding':['deflate']},'DEFLATE',1),({'Transfer-Encoding':['SECRET_HEADER_VALUE']},'OTHER',1),({'Transfer-Encoding':['chunked','identity']},'MULTIPLE',2),({'Transfer-Encoding':['x']*101},'MULTIPLE','OVER_LIMIT')]
 for values,category,count in cases:
  response=Response(values);obs=A.framing_observation(response,URL,0);check(obs['transferEncodingCategory']==category and obs['transferEncodingHeaderCount']==count and obs['noTransferEncoding'] is False,'finite TE mapping');check(A.framing_shape(obs),'strict observed shape');check('SECRET' not in json.dumps(obs),'no header plaintext')
 for raw,shape,num in [([], 'ABSENT','UNKNOWN'),(['0'],'DECIMAL',0),(['2097152'],'DECIMAL',2097152),(['2097153'],'OVER_LIMIT','OVER_LIMIT'),(['1']*2,'DUPLICATE','UNKNOWN'),(['01'],'INVALID','UNKNOWN'),(['-1'],'INVALID','UNKNOWN'),(['x'*257],'OVER_LIMIT','UNKNOWN'),(['9'*256],'OVER_LIMIT','OVER_LIMIT'),(['2']*101,'OVER_LIMIT','OVER_LIMIT')]:
  obs=A.framing_observation(Response({'Content-Length':raw}),URL,0);check(obs['contentLengthShape']==shape and obs['declaredContentLength']==num,'bounded CL classification')
 for values,cat in [([], 'ABSENT'),(['identity'],'IDENTITY'),(['gzip'],'GZIP'),(['br'],'OTHER'),(['gzip']*2,'MULTIPLE'),(['x'*257],'OTHER')]:check(A.framing_observation(Response({'Content-Encoding':values}),URL,0)['contentEncodingCategory']==cat,'finite CE mapping')
 for status in (99,100,200,599,600,True,None):
  obs=A.framing_observation(Response(status=status),URL,0);check(obs['actualStatus']==(status if type(status) is int and 100<=status<=599 else 'UNKNOWN'),'bounded actual status')
 response=Response(url='https://foreign.invalid/SECRET');check(A.framing_observation(response,URL,0)['responseURLMatchesExpected'] is False,'URL mismatch flag')
 class Broken:
  @property
  def status(self):raise RuntimeError('SECRET_HEADER_VALUE')
 check(A.framing_observation(Broken(),URL,0)==A.unknown_framing(),'observer failure bounded UNKNOWN')
 for values,code in [({'Transfer-Encoding':['chunked']},'METADATA_HTTP_FRAMING'),({'Content-Length':['2','2']},'METADATA_HTTP_FRAMING'),({'Content-Encoding':['gzip','identity']},'METADATA_HTTP_FRAMING'),({'Content-Length':['01']},'METADATA_LENGTH')]:
  with tempfile.TemporaryDirectory(dir=TEMP) as d:
   response=Response(values);ctx={'deadlineMonotonicNs':NOW[0]+10**10,'utcNow':int(time.time()),'requested':set(),'records':[]};total={'bodyBytes':0}
   with patch.object(A.urllib.request,'build_opener',return_value=Opener(response)):expect(code,lambda:A._wire_request(ctx,URL,Path(d)/'wire',2097152,total,(URL,),True))
   check(ctx['records'][0]['framing']['observationState']=='OBSERVED' and response.reads==0,'observation precedes original rejection');check('SECRET' not in json.dumps(ctx['records']),'no headers retained on reject')
 old=ast.parse((B/'tools/curation_advisory_source04.py').read_bytes());new=ast.parse(Path(A.__file__).read_bytes())
 def needs(tree):
  f=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_wire_request');return [ast.dump(n,include_attributes=False) for n in ast.walk(f) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='need']
 check(needs(old)==needs(new),'every original wire guard predicate unchanged')
 for broken in ({},dict(A.unknown_framing(),actualStatus='SECRET'),dict(A.unknown_framing(),extra='SECRET'),dict(A.unknown_framing(),contentLengthHeaderCount=101),dict(A.unknown_framing(),primaryCode='PRIVATE_DYNAMIC')):check(not A.framing_shape(broken),'strict malformed framing denied')
 return {'boundedHeaderCases':len(cases)+10+6+7,'originalGuardPredicatesIdentical':True,'actualHTTP':0}

def parent_hold(A,root,response):
 root=Path(root);(root/'http').mkdir();ctx={'deadlineMonotonicNs':NOW[0]+10**10,'utcNow':int(time.time()),'requested':set(),'records':[],'ownedJob':FakeJob(A,response),'requestWorkRoot':str(root/'http'),'requestCwd':str(root),'requestEnvironment':{}};total={'bodyBytes':0}
 with patch.object(A,'absolute_request',no_alarm):exc=expect('METADATA_HTTP_FRAMING',lambda:A.bounded_get(ctx,URL,root/'wire',2097152,total,(URL,),True))
 check(json.loads((root/'http/request-0/result.json').read_bytes())['state']=='HOLD','OS0 not semantic pass');return exc,ctx

def group2(C,S,projection):
 C.HERE=projection;M,A=C.method_modules();check(sys.modules['curation_advisory_source04'] is A,'actual helper registered before execution');check(sha(Path(A.__file__).read_bytes())==C.METHOD_SOURCE_PINS['curation_advisory_source04'],'actual helper source pin')
 trace=S.Trace();trace.bind_loaded(projection)
 with tempfile.TemporaryDirectory(dir=TEMP) as d:
  exc,ctx=parent_hold(A,d,Response({'Transfer-Encoding':['chunked']}));trace.capture(exc);check(trace.nodes[0]['code']=='METADATA_HTTP_FRAMING' and trace.nodes[0]['source']=='curation_advisory_source04','actual class primary survives parent');check(ctx['records'][0]['framing']['primaryCode']=='METADATA_HTTP_FRAMING','child finite cause retained')
  foreign=type('Hold',(RuntimeError,),{'__module__':A.__name__});other=S.Trace();other.bind_loaded(projection);other.capture(foreign('METADATA_HTTP_FRAMING'));check(other.nodes[0]['code']=='UNKNOWN_OR_REDACTED' and other.nodes[0]['source']=='UNKNOWN_OR_REDACTED','same module/name foreign class rejected by identity')
  trace.capture(RuntimeError('SECRET_PRIVATE_EXCEPTION'),True);record=trace.record();check(len(record)<=16384 and b'SECRET' not in record and trace.nodes[0]['code']=='METADATA_HTTP_FRAMING','secondary privacy and first primary')
  entry={'framing':A.unknown_framing()};A.retain_framing(entry,'METADATA_HTTP_FRAMING',NOW[0]);check(entry['framing']['primaryCode']=='METADATA_HTTP_FRAMING','unknown observation preserves code')
 return A,{'actualLoadedOwnClassBound':True,'foreignSameModuleSameNameDenied':True,'childOS0SemanticHoldPreserved':True,'firstPrimaryPreserved':True}

def group3(C,A,S,caller,P,B):
 profile=json.loads((P/'tools/producer04-metadata-framing-diagnostic.profile.json').read_bytes());full=json.loads((P/'tools/producer04-linux-curation.profile.json').read_bytes());oldfull=json.loads((B/'tools/producer04-linux-curation.profile.json').read_bytes())
 causal={'executionMode','diagnosticProfileSHA256','sourceAllowanceSHA256','public10ProvenanceSHA256','safeCauseHelperSHA256','advisoryHelperSHA256'};check({k:v for k,v in full.items() if k not in causal}=={k:v for k,v in oldfull.items() if k not in causal},'full caps/defaults/allocations unchanged');check(full['executionMode']==C.FULL_EXECUTION_MODE,'default full mode')
 check(profile['rowSeconds']==130 and profile['workerEndSeconds']==70 and profile['terminalReserveSeconds']==60 and profile['rawPlusDecodedBytesMax']==2097152 and profile['GETsMax']==1 and profile['privateScratchMaxBytes']==33554432,'diagnostic finite profile')
 for k in ('SDKArchiveGETsMax','SDKInputTransportOrExtractMax','publicOriginalGETsMax','OpenSSLOrOtherNativeTargetsMax','SDKCommandsMax','otherMetadataGETsMax','fullAdvisoryPKIOrGraphAuditMax','productCommandsMax'):check(profile[k]==0,'forbidden profile target')
 head='a'*40;tree='b'*40;nonce='c'*32;gate={'schema':'producer04-metadata-framing-diagnostic-admission/v1','state':'EXACT_SOURCE_RUNTIME_BOUND','purpose':C.PURPOSE,'executionMode':C.DIAGNOSTIC_MODE,'sourceHEAD':head,'sourceTree':tree,'contractSHA256':C.CONTRACT_SHA,'amendmentSHA256':C.AMENDMENT_SHA,'publicTransportAmendmentSHA256':C.PUBLIC_TRANSPORT_SHA,'advisoryNamespaceAmendmentSHA256':C.NAMESPACE_AMENDMENT_SHA,'profileSHA256':C.DIAGNOSTIC_PROFILE_SHA,'diagnosticProfileSHA256':C.DIAGNOSTIC_PROFILE_SHA,'inputManifestSHA256':'d'*64,'leaseAdmissionSHA256':'e'*64,'runId':'123','attempt':'1','dispatchNonce':nonce};C.validate_diagnostic_admission(gate,head)
 for key,bad in [('executionMode',C.FULL_EXECUTION_MODE),('diagnosticProfileSHA256','0'*64),('profileSHA256','0'*64),('sourceHEAD','0'*40),('attempt','2'),('inputManifestSHA256','UNKNOWN')]:expect('DIAGNOSTIC_GATE_MODE' if key=='executionMode' else 'DIAGNOSTIC_GATE_PROFILE' if key in ('diagnosticProfileSHA256','profileSHA256') else 'DIAGNOSTIC_GATE_SOURCE' if key=='sourceHEAD' else 'DIAGNOSTIC_GATE_RUN',lambda key=key,bad=bad:C.validate_diagnostic_admission(dict(gate,**{key:bad}),head))
 expect('CURATION_EXECUTION_MODE_REQUIRED',lambda:C.diagnostic_selected({}));check(not C.diagnostic_selected({'executionMode':C.FULL_EXECUTION_MODE}),'explicit full selector stable');expect('DIAGNOSTIC_GATE_SCHEMA',lambda:C.validate_diagnostic_admission(dict(gate,SDK='fake'),head))
 source={'commit':head,'tree':tree};trace=S.Trace();state=types.SimpleNamespace(STATE=trace,require_workspace=lambda env,path:check(env['GITHUB_WORKSPACE']==str(path),'exact fake workspace'))
 forbidden=[]
 def deny(*a,**k):forbidden.append('called');raise RuntimeError('FORBIDDEN_TARGET')
 class F:
  def need(self,v,code):C.need(v,code)
  def caps(self,cap,rid):check(rid=='linux-x64' and cap['heldChildIdentityBeforeExec'] is True,'fake cap admission')
  def terminal(self,t):check(t['ownedPopulation']==0 and t['workerExitCode']==0,'natural terminal')
 route=json.loads((P/'tools/dotnet11-consumer04-admission.lock.json').read_bytes())
 observations=[]
 for good in (False,True):
  with tempfile.TemporaryDirectory(dir=TEMP) as d:
   trace=S.Trace();state.STATE=trace
   root=Path(d)/'worker';root.mkdir();checkout=Path(d)/'checkout';checkout.mkdir();runner=Path(d);held={'pid':os.getpid(),'start':'555','state':'T','pidfdRetained':True,'cgroup':CAPS['cgroup'],'kernelLimits':CAPS['kernelLimits']};manifest={'schema':'producer04-metadata-framing-diagnostic-manifest/v1','sourceHEAD':head,'executionMode':C.DIAGNOSTIC_MODE,'ownerScratchLimitBytes':33554432,'leaseAdmissionPath':str(root/'lease.json')};lease={'state':'OWN_CANONICAL_LEASE_BOUND_TO_THIS_RUN','sourceHEAD':head,'runId':'123','attempt':'1','dispatchNonce':nonce,'protocolSHA256':C.LEASE_PROTOCOL_SHA,'ownerPID':42,'ownerProcessStartIdentity':'proc-start:123','tokenSHA256':'f'*64}
   spec={'purpose':C.PURPOSE,'rid':'linux-x64','executionMode':C.DIAGNOSTIC_MODE,'root':str(root),'unit':UNIT,'uid':1001,'gid':1001,'startTick':100000,'expectedCommit':head,'curationAdmissionPath':str(root/'gate.json'),'curationAdmissionSHA256':'1'*64,'curationInputManifestPath':str(root/'manifest.json'),'parentHeldWorkerBeforeExec':True}
   response=Response({} if good else {'Transfer-Encoding':['chunked']});job=FakeJob(A,response);Q=types.SimpleNamespace(j=job,start_identity=lambda pid:'555')
   def write(p,v):p=Path(p);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v)+'\n',encoding='utf-8');p.with_name(p.name+'.ready').touch()
   def read(p,limit=10**9):
    p=Path(p)
    if p.name=='dotnet11-consumer04-admission.lock.json':return route
    if p.name=='held-worker-before-continue.json':return held
    if p.name=='manifest.json':return manifest
    if p.name=='lease.json':return lease
    return json.loads(p.read_bytes())
   R=types.SimpleNamespace(ROOT=checkout,f=F(),read=read,write=write,clock=lambda:NOW[0]//1000000,bootstrap_identity=lambda:{'pythonVersion':'3.12','pythonExeSha256':'1'*64,'stdlibClosureSha256':'2'*64,'nativeTools':[]},host=lambda rid:None,digest=lambda p:route['controllerSha256'] if str(p).endswith('consume_dotnet11_host_fact.py') else sha(Path(p).read_bytes()))
   write(root/'metadata-diagnostic-kernel-clock.json',{'schema':'producer04-diagnostic-kernel-clock/v1','executionMode':C.DIAGNOSTIC_MODE,'unit':UNIT,'pid':os.getpid(),'processStartIdentity':'555','sourceHEAD':head,'activationMonotonicNs':100000000000,'runtimeMaxNs':60000000000,'originalWorkerEndMonotonicNs':170000000000,'observedMonotonicNs':101000000000,'observedBeforeContinue':True})
   backend=types.SimpleNamespace(caps=lambda:{'heldChildIdentityBeforeExec':True});env={'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKSPACE':str(checkout),'RUNNER_TEMP':str(runner),'LD_PRELOAD':'','LD_LIBRARY_PATH':'','PYTHONPATH':'','PYTHONHOME':''}
   fake_main=types.SimpleNamespace(safe_cause_module=lambda:state,__file__=str(checkout/'tools/consume_dotnet11_host_fact.py'))
   @contextlib.contextmanager
   def clock_guard(s,sec):check(sec in (70,130) and type(s['startTick']) is int,'original selector clock');yield s['startTick']*1000000+sec*10**9
   with contextlib.ExitStack() as stack:
    stack.enter_context(patch.dict(os.environ,env));stack.enter_context(patch.dict(sys.modules,{'__main__':fake_main}));stack.enter_context(patch.object(os,'getuid',return_value=1001,create=True));stack.enter_context(patch.object(os,'getgid',return_value=1001,create=True));stack.enter_context(patch.object(A,'absolute_request',no_alarm));stack.enter_context(patch.object(C,'diagnostic_original_deadline',clock_guard));stack.enter_context(patch.object(C,'diagnostic_policies',return_value=profile));stack.enter_context(patch.object(C,'parent_admission',side_effect=lambda *a:C.validate_diagnostic_admission(gate,head)));stack.enter_context(patch.object(C,'load_json',side_effect=lambda p,*a:read(p)));stack.enter_context(patch.object(C,'diagnostics',return_value=trace));stack.enter_context(patch.object(C,'diagnostic_source_identity',return_value=(source,{'knownSignatureVerified':True})));stack.enter_context(patch.object(C,'_scratch_bytes',return_value=4096));stack.enter_context(patch.object(C,'method_modules',return_value=(None,A)))
    for name in ('run_curation_worker','_metadata','public_input_module','_capsule','_sdk_target','_start_adapter'):stack.enter_context(patch.object(C,name,deny))
    result=C.worker(spec,backend,R,Q);C.validate_diagnostic_result(result,A);check(result['state']==('SERVICE_REQUEST_ACCEPTED_DIAGNOSTIC_ONLY' if good else 'FRAMING_OBSERVED_GUARD_HOLD'),'diagnostic-only typed state');check(result['requestCount']==1 and result['inputAdmitted'] is False and result['semanticResult']==('SERVICE_REQUEST_ACCEPTED_ONLY' if good else 'HOLD'),'one GET and no admission');observations.append(result['state'])
    expect('DIAGNOSTIC_BOOTSTRAP60',lambda:C.worker(dict(spec,startTick=40000),backend,R,Q));expect('DIAGNOSTIC_RESULT_SCHEMA',lambda:C.validate_diagnostic_result(dict(result,extra='SECRET'),A));expect('DIAGNOSTIC_RESULT_BOUNDS',lambda:C.validate_diagnostic_result(dict(result,combinedBodyBytes=2097153),A))
    badheld=dict(held,pidfdRetained=False)
    with patch.object(R,'read',side_effect=lambda p,*a:badheld if Path(p).name=='held-worker-before-continue.json' else read(p)):expect('DIAGNOSTIC_ACTUAL_HELD_GENERATION',lambda:C.diagnostic_held_caps(spec,Q,R))
    oldlimits=CAPS['kernelLimits'];CAPS['kernelLimits']=dict(oldlimits,**{'memory.max':'UNKNOWN'})
    expect('DIAGNOSTIC_ACTUAL_HELD_GENERATION',lambda:C.diagnostic_held_caps(spec,Q,R));CAPS['kernelLimits']=oldlimits
    # The real parent runner follows its held-generation path with fake Popen,
    # pidfd, clocks/caps and cleanup. No deny/native/SDK transition is eligible.
    write(root/'stopped-worker.json',dict(held,uid=1001,gid=1001,cap={'kernelLimits':CAPS['kernelLimits']}));write(root/'network-transition-request.json',{'unexpected':'must stay uncalled'})
    class Proc:
     returncode=0
     def __init__(self):self.n=0
     def poll(self):self.n+=1;return None if self.n==1 else 0
    proc=Proc();snap={'state':'T','start':'555','limits':CAPS['kernelLimits'],'cgroup':CAPS['cgroup']};M=types.SimpleNamespace(pid_snapshot=lambda *a:snap)
    def cleanup(*a):
     write(root/'cleanup-terminal.json',{'cleanupResult':'OWNED_TERMINAL_OBSERVED','ownedPopulation':0,'workerExitCode':0});return {'cleanupResult':'OWNED_TERMINAL_OBSERVED','evidenceSha256':'3'*64},{'serviceResult':'success','exitCode':'exited','exitStatus':'0','remainingPopulationExcludingObserver':0,'actualCaps':{'memoryPeak':123}}
    Q.own_unit_show=lambda *a:({'LoadState':'not-found'},0);Q.cleanup_owned_linux=cleanup;Q.OS_ENV={};caller.R=R;caller.Q=Q
    stack.enter_context(patch.object(caller,'curation_module',return_value=C));stack.enter_context(patch.object(caller,'safe_cause_module',return_value=state));stack.enter_context(patch.object(caller,'capture_curation_cause',side_effect=lambda exc,*a,**k:trace.capture(exc)));stack.enter_context(patch.object(C,'method_modules',return_value=(M,A)));stack.enter_context(patch.object(caller.subprocess,'Popen',return_value=proc));stack.enter_context(patch.object(caller.os,'pidfd_open',return_value=99,create=True));stack.enter_context(patch.object(caller.signal,'SIGCONT',18,create=True));stack.enter_context(patch.object(caller.signal,'pidfd_send_signal',return_value=None,create=True));stack.enter_context(patch.object(caller.time,'sleep',return_value=None))
    stack.enter_context(patch.object(caller.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stderr='',stdout='ActiveEnterTimestampMonotonic=100000000\nRuntimeMaxUSec=60s\nType=exec\n')))
    terminal,stop=caller.run_curation_linux(spec,['FAKE_OWNED_STARTER']);caller.finish_metadata_diagnostic(spec,terminal,123);packet=json.loads((checkout/'artifacts/sdk11-curation-linux-x64/DIAGNOSTIC-ONLY.json').read_bytes());check(packet['state']==result['state'] and packet['originalWorkerEndTick']==170000 and packet['originalTerminalEndTick']==230000 and packet['fullProducerAcceptance'] is False,'typed terminal no full promotion');check(all(b'SECRET' not in p.read_bytes() for p in (checkout/'artifacts/sdk11-curation-linux-x64').rglob('*') if p.is_file()),'no response header plaintext artifact')
    expect('DIAGNOSTIC_TERMINAL130',lambda:caller.finish_metadata_diagnostic(dict(spec,startTick=-29000),terminal,123))
 check(not forbidden,'all forbidden target paths untouched')
 for value,ns in [('10s',10000000000),('1min 7s',67000000000),('1min 6.050s',66050000000),('70000000us',70000000000),('70s',70000000000)]:check(C.diagnostic_duration_ns(value)==ns,'bounded kernel timer duration')
 for value in ('infinity','UNKNOWN','71s','0s','1h','1s 1s','1s SECRET','1e2s','-1s'):expect('DIAGNOSTIC_KERNEL_DURATION',lambda value=value:C.diagnostic_duration_ns(value))
 # Execute the actual current-source/signature verifier with fixed fake Git outputs.
 with tempfile.TemporaryDirectory(dir=TEMP) as d:
  repo=Path(d)/'repo';repo.mkdir();private=Path(d)/'private';private.mkdir();(repo/'data.txt').write_bytes(b'bounded source fixture\n');blob=lambda b:hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest();row={'path':'data.txt','mode':'100644','gitBlob':blob((repo/'data.txt').read_bytes())};pins={'state':'EXACT_SOURCE_REVIEWED','projectId':'04','sourcePins':[row]};(repo/'tools').mkdir();pinpath=repo/'tools/dotnet11-consumer04-source-pins.json';pinpath.write_text(json.dumps(pins));listing=('100644 blob '+row['gitBlob']+'\tdata.txt\0'+'100644 blob '+blob(pinpath.read_bytes())+'\ttools/dotnet11-consumer04-source-pins.json\0').encode();commands=[];bad=[None]
  def run(argv,cwd,env,deadline,evidence):
   check(argv[:3]==['/usr/bin/git','-C',str(repo)] and deadline<=160000,'source-only fake Git bounded by original60');commands.append(argv[3:]);dest=Path(evidence);dest.mkdir();raw=listing if 'ls-tree' in argv else b' M data.txt\n' if 'status' in argv and bad[0]=='dirty' else b'';(dest/'stdout.log').write_bytes(raw);(dest/'stderr.log').write_bytes(b'');return {'exitCode':1 if bad[0]=='signature' and 'verify-commit' in argv else 0}
  runtime=types.SimpleNamespace(ROOT=repo,source_context=lambda *a,**k:source,read=lambda p:pins);backend=types.SimpleNamespace(run=run);spec={'root':str(private),'startTick':100000,'expectedCommit':head}
  _,identity=C.diagnostic_source_identity(spec,backend,runtime,{},profile);check(identity['knownSignatureVerified'] is True and any('verify-commit' in a and any('allowedSignersFile=' in t for t in a) for a in commands),'actual known-signature route and current blobs')
  private2=Path(d)/'dirty';private2.mkdir();bad[0]='dirty';expect('DIAGNOSTIC_SOURCE_DIRTY',lambda:C.diagnostic_source_identity(dict(spec,root=str(private2)),backend,runtime,{},profile));private3=Path(d)/'sig';private3.mkdir();bad[0]='signature';expect('DIAGNOSTIC_SOURCE_COMMAND',lambda:C.diagnostic_source_identity(dict(spec,root=str(private3)),backend,runtime,{},profile))
 # Missing framing and forced-child uncertainty cannot become an observation pass.
 for forced in (False,True):
  with tempfile.TemporaryDirectory(dir=TEMP) as d:
   root=Path(d);trace=S.Trace();runtime=types.SimpleNamespace(ROOT=root,clock=lambda:101000,write=lambda p,v:Path(p).write_text(json.dumps(v)));spec={'startTick':100000};Q=types.SimpleNamespace(j=None)
   def unknown(ctx,*a,**k):
    ctx['requested'].add(URL)
    if not forced:ctx['records'].append({'framing':A.unknown_framing()})
    raise A.Hold('METADATA_OWN_CHILD_FAILED' if forced else 'METADATA_HTTP_FRAMING')
   with patch.object(A,'bounded_json_get',side_effect=unknown),patch.object(C,'diagnostics',return_value=trace):expect('DIAGNOSTIC_OBSERVATION_INCOMPLETE',lambda:C.diagnostic_request(spec,A,Q,runtime,root,{}, {'bodyBytes':0}))
   value=json.loads((root/'metadata-diagnostic-result.json').read_bytes());check(value['state']=='HOLD_DIAGNOSTIC_INCOMPLETE' and value['semanticResult']=='HOLD' and value['primaryCode']==('METADATA_OWN_CHILD_FAILED' if forced else 'METADATA_HTTP_FRAMING'),'unknown/forced first primary preserved')
 # Exercise the actual absolute alarm context using fake signal APIs only.
 calls=[];oldnow=NOW[0]
 with patch.object(signal,'SIGALRM',14,create=True),patch.object(signal,'ITIMER_REAL',0,create=True),patch.object(signal,'getitimer',return_value=(0,0),create=True),patch.object(signal,'getsignal',return_value=signal.SIG_DFL),patch.object(signal,'signal',side_effect=lambda *a:calls.append(('handler',a[0]))),patch.object(signal,'setitimer',side_effect=lambda *a:calls.append(('timer',a[1])),create=True):
  with C.diagnostic_original_deadline({'startTick':100000},70):pass
  check(any(k=='timer' and 0<v<=69 for k,v in calls),'original70 timer no reset')
  expect('DIAGNOSTIC_ORIGINAL_DEADLINE',lambda:C.diagnostic_original_deadline({'startTick':0},70).__enter__())
  try:
   with C.diagnostic_original_deadline({'startTick':100000},130):NOW[0]=231000000000
  except C.Hold as e:check(e.args==('DIAGNOSTIC_ORIGINAL_DEADLINE',),'original130 expiry')
  else:raise RuntimeError('missing late terminal Hold')
 NOW[0]=oldnow
 before=(B/'.github/workflows/verify.yml').read_text().replace('\r\n','\n');after=(P/'.github/workflows/verify.yml').read_text();addition='      curation_execution_mode:\n        type: choice\n        options: [FULL_PRODUCER_CURATION, METADATA_SERVICE_FRAMING_DIAGNOSTIC_ONLY]\n        default: FULL_PRODUCER_CURATION\n        required: false\n';check(after.replace(addition,'')==before,'workflow only bounded explicit mode input')
 return {'typedStates':observations,'forbiddenTargetsInvoked':0,'actualSignalsJobHTTPNativeSDK':0,'originalClockExpiryAndGuardHolds':True,'fullCapsDefaultsStable':True}

def main():
 global TEMP,NOW,URL,UNIT,CAPS,FAKE
 parser=argparse.ArgumentParser();parser.add_argument('--fixture-root',type=Path,required=True);parser.add_argument('--frozen-method',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();started=time.perf_counter();base=args.fixture_root;P=base/'post';B=base/'baseline';TEMP=base;NOW=[101000000000];URL='https://api.nuget.org/v3/index.json';UNIT='admission04-sdk11-ci-'+'a'*32;CAPS={'uid':1001,'gid':1001,'cgroup':'/system.slice/'+UNIT+'.service','kernelLimits':{'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'}};FAKE={'HTTP':0,'Job':0}
 sourcepaths=[P/'tools'/n for n in ['curation_advisory_source04.py','curate_dotnet11_linux_inputs.py','curation_safe_cause04.py','consume_dotnet11_host_fact.py','producer04-metadata-framing-diagnostic.profile.json','producer04-linux-curation.profile.json','dotnet11-consumer04-admission.lock.json']]+[B/'tools'/n for n in ['curation_advisory_source04.py','producer04-linux-curation.profile.json']]+[B/'.github/workflows/verify.yml',P/'.github/workflows/verify.yml',args.frozen_method,Path(__file__)]
 inputbytes=sum(p.stat().st_size for p in sourcepaths);check(inputbytes<=524288,'input512KiB');A=load('curation_advisory_source04',P/'tools/curation_advisory_source04.py');C=load('curate_dotnet11_linux_inputs',P/'tools/curate_dotnet11_linux_inputs.py');S=load('curation_safe_cause04',P/'tools/curation_safe_cause04.py')
 path=P/'tools/consume_dotnet11_host_fact.py';caller=types.ModuleType('caller_source_mock');caller.__file__=str(path);sys.modules[caller.__name__]=caller;tree=ast.parse(path.read_bytes());tree.body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef)) or isinstance(n,ast.Assign) and not any(isinstance(t,ast.Name) and t.id in ('Q','R','j') for t in n.targets)];exec(compile(tree,str(path),'exec',dont_inherit=True,optimize=sys.flags.optimize),caller.__dict__)
 with patch.object(A.time,'monotonic_ns',side_effect=lambda:NOW[0]):one=group1(A,B)
 with tempfile.TemporaryDirectory(dir=TEMP) as d:
  projection=Path(d);(projection/'curation_advisory_source04.py').write_bytes(Path(A.__file__).read_bytes());(projection/'curation_linux_method.py').write_bytes(args.frozen_method.read_bytes())
  with patch.object(A.time,'monotonic_ns',side_effect=lambda:NOW[0]):A,two=group2(C,S,projection)
  with patch.object(A.time,'monotonic_ns',side_effect=lambda:NOW[0]):three=group3(C,A,S,caller,P,B)
 seconds=time.perf_counter()-started;check(seconds<=30,'source30s');result={'schema':'producer04-metadata-framing-source-fixtures/v1','state':'THREE_NEW_CAUSAL_GROUPS_PASS','groups':3,'optimize':sys.flags.optimize,'seconds':seconds,'inputBytes':inputbytes,'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0,'oldHealthyFullMethodPublicTransportReplay':0,'sourceSHA256':{p.name:sha(p.read_bytes()) for p in sourcepaths[:7]},'groupsEvidence':[one,two,three],'fakeCalls':FAKE};raw=(json.dumps(result,indent=2)+'\n').encode();check(len(raw)<=32768,'output32KiB');args.out.write_bytes(raw);print(json.dumps({'state':result['state'],'groups':3,'optimize':sys.flags.optimize,'seconds':round(seconds,3),'inputBytes':inputbytes,'outputBytes':len(raw),'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0}))
if __name__=='__main__':main()
