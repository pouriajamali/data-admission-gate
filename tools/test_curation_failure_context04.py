"""Exactly three causal synthetic groups; no controller/transport/SDK/OS target."""
import argparse,ast,hashlib,importlib.util,io,json,pathlib,sys,tempfile,time,types
HERE=pathlib.Path(__file__).resolve().parent
def source(name):
 p=HERE/(name+'.py');return p if p.exists() else HERE/('tools__'+name+'.py')
def check(v,code):
 if not v:raise RuntimeError(code)
def load(name):
 p=source(name);s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
H=load('curation_safe_cause04');C=load('curate_dotnet11_linux_inputs')
W=pathlib.Path(json.loads((HERE/'PREP.json').read_bytes())['worktree']) if (HERE/'PREP.json').exists() else HERE.parent
common=W/'tools/check_dotnet11.py';raw=common.read_bytes();check(hashlib.sha256(raw).hexdigest()==H.FROZEN['check_dotnet11'],'FROZEN_COMMON_IDENTITY')
# Execute only the exact source class/need definitions, never the common module,
# controller, preflight, HTTP, Job, SDK, native or main entry points.
t=ast.parse(raw);selected=[n for n in t.body if isinstance(n,ast.ImportFrom) and n.module=='__future__' or isinstance(n,ast.ClassDef) and n.name=='AdmissionError' or isinstance(n,ast.FunctionDef) and n.name=='need'];N=types.ModuleType('causal_common_source_definition');N.__file__=str(common);exec(compile(ast.Module(body=selected,type_ignores=[]),str(common),'exec'),N.__dict__)
def trace():
 d=H.Trace();check(d.bind(N,H.FROZEN['check_dotnet11'],'check_dotnet11'),'COMMON_DEFINITION_BINDING');return d
def error(code):
 try:N.need(False,code)
 except BaseException as e:return e
def group1():
 d=trace();primary=error('NORMAL_CURRENT_CHECKOUT');d.capture(primary);v=json.loads(d.record());check(v['nodes'][0]['exceptionType']=='AdmissionError' and v['nodes'][0]['code']=='NORMAL_CURRENT_CHECKOUT','ORIGINAL_COMMON_CODE');check(any(f['module']=='check_dotnet11' and f['function']=='need' for f in v['frames']),'INNER_COMMON_FRAME')
 sentinels=['UNKNOWN_LITERAL_TOKEN_SENTINEL','/private/path/sensitive','https://secret.invalid/?token=x','GITHUB_TOKEN=secret','SRC_LINE_SENTINEL','X'*65536]
 for text in sentinels:
  x=trace();x.capture(error(text));encoded=x.record();check(text.encode() not in encoded and b'UNKNOWN_OR_REDACTED' in encoded,'MESSAGE_REDACTION')
 Foreign=type('AdmissionError',(RuntimeError,),{});x=trace();x.capture(Foreign('NORMAL_CURRENT_CHECKOUT'));check(json.loads(x.record())['nodes'][0]['exceptionType']=='UNKNOWN_OR_REDACTED','FOREIGN_CLASS')
 chain=error('NORMAL_CURRENT_CHECKOUT')
 for i in range(6):
  outer=error('NORMAL_CONTEXT_SHAPE');outer.__cause__=chain;chain=outer
 x=trace();x.capture(chain);v=json.loads(x.record());check(len(v['nodes'])==3 and len(v['frames'])<=10 and v['chainOmittedOrCycle'] and v['framesOmittedOrForeign'],'CHAIN_AND_FOREIGN_BOUNDS')
 d.capture(OSError(13,'CLEANUP_SECRET_SENTINEL'),secondary=True);v=json.loads(d.record());check(v['nodes'][0]['code']=='NORMAL_CURRENT_CHECKOUT' and v['nodes'][-1]['role']=='secondary' and v['nodes'][-1]['errno']==13 and b'CLEANUP_SECRET_SENTINEL' not in d.record(),'PRIMARY_SURVIVES_CLEANUP')
 d.capture(error('NORMAL_CONTEXT_SHAPE'));check(json.loads(d.record())['nodes'][0]['code']=='NORMAL_CURRENT_CHECKOUT','CONVERSION_NO_OVERWRITE')
 x=trace();x.capture(OSError(987654321,'ERRNO_SENTINEL'));check(json.loads(x.record())['nodes'][0]['errno'] is None,'FINITE_ERRNO')
def group2():
 with tempfile.TemporaryDirectory() as work:
  exact=str(pathlib.Path(work).resolve());env={'GITHUB_WORKSPACE':exact,'GITHUB_SHA':'a'*40,'GITHUB_TOKEN':'SECRET','CURATION_INPUT_TOKEN':'SECRET','UNRELATED_SECRET':'SECRET','RUNNER_TEMP':work}
  check(H.require_workspace(env,work)==exact,'ACTUAL_EXACT_VALUE');sets=H.forward_environment(env,work);check('--setenv=GITHUB_WORKSPACE='+exact in sets and not any('SECRET' in v or 'TOKEN' in v for v in sets),'EXACT_FORWARD_NO_SECRET')
  for bad in ({},dict(env,GITHUB_WORKSPACE=exact+'/wrong'),dict(env,GITHUB_WORKSPACE=''),dict(env,GITHUB_WORKSPACE=work+'/../'+pathlib.Path(work).name)):
   try:H.forward_environment(bad,work)
   except H.WorkspaceError as e:check(e.args[0] in H.CODE_LITERALS['safe-cause'],'FINITE_WORKSPACE_CODE')
   else:raise RuntimeError('WORKSPACE_GAP_NOT_DENIED')
 caller=ast.parse(source('consume_dotnet11_host_fact').read_bytes());parent=next(n for n in caller.body if isinstance(n,ast.FunctionDef) and n.name=='linux_parent');check(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='forward_environment' for n in ast.walk(parent)),'CALLER_ACTUAL_FORWARD_WIRING');check(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='require_workspace' for n in ast.walk(parent)),'PARENT_PRE_WORKER_GUARD')
 keys=next(ast.literal_eval(n.value) for n in t.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=='CTX_KEYS' for v in n.targets));check(set(H.CONTEXT_KEYS)==keys and len(keys)==15,'FROZEN_ACTUAL_KEYS_UNCHANGED')
def group3():
 d=trace();ctx={k:'PRIVATE_CONTEXT_VALUE_SENTINEL' for k in H.CONTEXT_KEYS};ctx.update(rowStartedMonotonicNs=100,deadlineMonotonicNs=900,supervisorPID=12);d.mark('caller-context',context=ctx,spec={'startTick':100,'supervisorPID':12},identities={'sourceHEAD':'a'*40,'profileSHA256':'b'*64,'runId':'44021304386','attempt':'1'},now=101);d.mark('commontransport-enter');d.capture(error('NORMAL_CURRENT_CHECKOUT'));data=d.record();v=json.loads(data);check(len(data)<=16384 and b'PRIVATE_CONTEXT_VALUE_SENTINEL' not in data and v['context']['keySetExact'] and v['transport']=={'entered':True,'returned':False,'inputReceiptWritten':False,'HTTPStarted':'UNKNOWN','success':'UNKNOWN','bytes':'UNKNOWN'},'EARLY_TRANSPORT_UNKNOWN')
 for i in range(25):d.mark(H.STAGES[i%len(H.STAGES)])
 v=json.loads(d.record());check(len(v['stageHistory'])<=16 and v['stageOverflow'],'STAGE_BOUND')
 stream=io.BytesIO();check(not d.emit(None,{},W,stream) and stream.getvalue()==d.record(),'EARLY_TYPED_STDERR_ONLY')
 with tempfile.TemporaryDirectory() as work:
  root=pathlib.Path(work);(root/'curation-original-cause.json').write_bytes(data);paths,durable=C.curation_proof_candidates(root,{'durableInputs':{}},False);check(root/'curation-original-cause.json' in paths and C.read_proof_payload(root,root/'curation-original-cause.json',{},durable)==data,'EXISTING_ROOT_JSON_RETENTION');check(not C.retention_ledger([8388608],len(data))['fits'],'EXISTING_8MIB_CAP')
  stream=io.BytesIO();check(not d.emit(root,{'RUNNER_TEMP':str(root.parent),'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1'},W,stream) and stream.getvalue()==d.record(),'UNSAFE_ROOT_NO_WRITE')
 newhead='f'*40;desc=dict(C.RETAINED_CAPSULE);manifest={'schema':'producer04-linux-curation-input-manifest/v1','sourceHEAD':newhead,'capsule':desc,'ownerScratchLimitBytes':2147483648,'leaseAdmissionPath':str(pathlib.Path(tempfile.gettempdir()).resolve()/'lease.json')};check(C.validate_input_manifest(manifest,newhead)['capsule']['producedSourceHEAD']!=newhead,'SEPARATE_PRODUCER_CONSUMER')
 for key,bad in [('assetID',1),('releaseID',1),('sha256','0'*64),('draft',False),('producedSourceHEAD','e'*40),('name','renamed.tar'),('threeRawProvenanceSHA256','0'*64),('capsuleReceiptSHA256','0'*64),('uploadReceiptSHA256','0'*64),('bytes',1)]:
  changed=dict(desc);changed[key]=bad
  try:C.validate_capsule_descriptor(changed,newhead)
  except C.Hold:pass
  else:raise RuntimeError('RETAINED_LINEAGE_NOT_FIXED')
 legacy={k:desc[k] for k in ('assetID','releaseID','name','bytes','sha256','draft')}
 try:C.validate_capsule_descriptor(legacy,newhead)
 except C.Hold:pass
 else:raise RuntimeError('GENERIC_RETAINED_FALLBACK')
 legacy['name']='producer04-linux-native11-inputs-'+newhead+'.tar';check(C.validate_capsule_descriptor(legacy,newhead)==legacy,'DEFAULT_STRICT_POLICY_PRESERVED')
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=pathlib.Path,required=True);a=p.parse_args();started=time.monotonic();rows=[]
 for i,fn in enumerate((group1,group2,group3),1):fn();rows.append({'group':i,'state':'PASS_SYNTHETIC_ONLY'})
 seconds=time.monotonic()-started;inputbytes=len(raw)+sum(source(n).stat().st_size for n in ('curation_safe_cause04','curate_dotnet11_linux_inputs','consume_dotnet11_host_fact'));check(seconds<30 and inputbytes<=524288,'FINITE_FIXTURE_BUDGET');v={'schema':'producer04-safe-cause-workspace-causal-mocks/v1','state':'THREE_NEW_CAUSAL_GROUPS_PASS','groups':3,'optimize':sys.flags.optimize,'seconds':round(seconds,3),'inputBytes':inputbytes,'rows':rows,'sourceSHA256':{n:hashlib.sha256(source(n).read_bytes()).hexdigest() for n in ('curation_safe_cause04','curate_dotnet11_linux_inputs','consume_dotnet11_host_fact')},'frozenCommonSHA256':hashlib.sha256(raw).hexdigest(),'actualFrozenContextKeyCount':15,'actualControllerTransportHTTPJobSDKNativeProbe':0,'oldHealthyReplay':0};body=(json.dumps(v,indent=2)+'\n').encode();check(len(body)<=32768,'FIXTURE_OUTPUT_BOUND')
 with a.out.open('xb') as f:f.write(body)
 print(json.dumps({'state':v['state'],'optimize':v['optimize'],'groups':3,'seconds':v['seconds'],'inputBytes':inputbytes,'actual':0}))
if __name__=='__main__':main()
