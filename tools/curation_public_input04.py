"""Closed public-original streaming transport; no top-level IO or implicit acquisition."""
from __future__ import annotations
import contextlib,hashlib,json,os,re,signal,stat,sys,threading,time,urllib.error,urllib.request
from pathlib import Path
AMENDMENT_SHA='002a672c7df822b89a33fee8bb8e0dee867aefc719177fbc4e4c1f880326c484'
MODE='PUBLIC_ORIGINALS_V1'
INPUTS=({'index': 0, 'id': 'Microsoft.AspNetCore.App.Runtime.linux-x64', 'version': '11.0.0', 'rid': 'linux-x64', 'bytes': 13048557, 'sha256': '3f4bdd1255f9ccf02a3ad22656e165bd86e9f0179f18d88cf0fc7de02b230593', 'sha512': 'ec6ed1b5be30b1acf04abe10f173b0c1f8df48f470da277685c2821aee7cb6e6ad21748c56a15b6c9a857e6758e0aba066048a644ccaeaad09ff82e3ee463814', 'url': 'https://api.nuget.org/v3-flatcontainer/microsoft.aspnetcore.app.runtime.linux-x64/11.0.0/microsoft.aspnetcore.app.runtime.linux-x64.11.0.0.nupkg'}, {'index': 1, 'id': 'Microsoft.NETCore.App.Host.linux-x64', 'version': '11.0.0', 'rid': 'linux-x64', 'bytes': 5085644, 'sha256': 'a152b2d7ebb7fb9431ab96490e4c35c86af564419c20d81745e71760a4465469', 'sha512': 'a7d54c6d254dd2f5807f5a23f8d4e6d98ba48b9954fbb7af26994f7a26760bcf41d762fa63626b4c0773bc44c5285cc73f19ffe1c466cb9b48e2d27f11de616c', 'url': 'https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.host.linux-x64/11.0.0/microsoft.netcore.app.host.linux-x64.11.0.0.nupkg'}, {'index': 2, 'id': 'Microsoft.NETCore.App.Runtime.linux-x64', 'version': '11.0.0', 'rid': 'linux-x64', 'bytes': 42270532, 'sha256': '458f0a7e0de107e4c08b3f375b920cd9427bbb5463870187b5f8afff0eb8664f', 'sha512': 'f76bc258a41b896f53d90802453c221d51e9c69bfc7c300e8824549e53bd4242e1776a1618a26df7384737899b77b025fd6981c03fad17426df14c7939fa31ee', 'url': 'https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.runtime.linux-x64/11.0.0/microsoft.netcore.app.runtime.linux-x64.11.0.0.nupkg'})
KINDS=('HTTP_STATUS','TIMEOUT','URL_ERROR','OS_ERROR','SOURCE_FRAME_OR_HASH_HOLD','UNKNOWN_OR_REDACTED')
CODES=('PUBLIC_MODE','PUBLIC_MANIFEST','PUBLIC_POLICY','PUBLIC_SOURCE','PUBLIC_PATH','PUBLIC_FRAME','PUBLIC_STATUS','PUBLIC_SIZE','PUBLIC_HASH','PUBLIC_BODY_BUDGET','PUBLIC_DEADLINE','PUBLIC_PERIODIC_ALARM','PUBLIC_MAIN_ALARM','PUBLIC_CHILD','PUBLIC_CHILD_IDENTITY','PUBLIC_RESULT','PUBLIC_FILE_CHANGED','PUBLIC_IO','PUBLIC_TOKEN_CONFIG')
class PublicHold(RuntimeError):pass
def need(v,code):
 if not v:raise PublicHold(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def strict(raw,limit=16384):
 need(type(raw) is bytes and len(raw)<=limit,'PUBLIC_RESULT')
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'PUBLIC_RESULT');d[k]=v
  return d
 try:return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(PublicHold('PUBLIC_RESULT')))
 except (UnicodeError,ValueError):raise PublicHold('PUBLIC_RESULT') from None
def exact(v,keys):need(type(v) is dict and set(v)==set(keys),'PUBLIC_MANIFEST')
def validate_manifest(m,head):
 exact(m,('schema','sourceHEAD','inputTransport','publicTransportAmendmentSHA256','publicInputs','ownerScratchLimitBytes','leaseAdmissionPath'))
 need(m['schema']=='producer04-linux-public-input-manifest/v1' and type(head) is str and re.fullmatch('[0-9a-f]{40}',head) is not None and m['sourceHEAD']==head and m['inputTransport']==MODE and m['publicTransportAmendmentSHA256']==AMENDMENT_SHA,'PUBLIC_MODE');need(canonical(m['publicInputs'])==canonical(list(INPUTS)),'PUBLIC_MANIFEST');need(type(m['ownerScratchLimitBytes']) is int and 0<m['ownerScratchLimitBytes']<=2147483648 and type(m['leaseAdmissionPath']) is str and Path(m['leaseAdmissionPath']).is_absolute(),'PUBLIC_MANIFEST');return m
def policy():
 p=Path(__file__).resolve().parent/'producer04-linux-curation-public-input-transport.json';raw=p.read_bytes();need(len(raw)<=65536 and sha(raw)==AMENDMENT_SHA,'PUBLIC_POLICY');value=strict(raw,65536);need(value['mode']==MODE and canonical(value['fixedPublicInputs'])==canonical(list(INPUTS)),'PUBLIC_POLICY');return value
def budget(end):need(time.monotonic_ns()<end,'PUBLIC_DEADLINE')
def numeric_status(value):return value if type(value) is int and 100<=value<=599 else 'UNKNOWN'
def diagnostic(index,category,status,started,count):
 need(type(index) is int and 0<=index<=2 and category in KINDS and type(count) is int and 0<=count<=536936448,'PUBLIC_RESULT');return {'inputIndex':index,'operation':'PUBLIC_ORIGINAL_GET','category':category,'status':numeric_status(status),'elapsedNs':max(0,time.monotonic_ns()-started),'bodyBytesRead':count}
def error_kind(exc):
 if type(exc) is urllib.error.HTTPError:return 'HTTP_STATUS',numeric_status(exc.code)
 if type(exc) in (TimeoutError,):return 'TIMEOUT','UNKNOWN'
 if type(exc) is urllib.error.URLError:return 'URL_ERROR','UNKNOWN'
 if type(exc) in (OSError,FileNotFoundError,PermissionError):return 'OS_ERROR','UNKNOWN'
 if type(exc) is PublicHold:return ('TIMEOUT' if exc.args==('PUBLIC_DEADLINE',) else 'SOURCE_FRAME_OR_HASH_HOLD'),'UNKNOWN'
 return 'UNKNOWN_OR_REDACTED','UNKNOWN'
@contextlib.contextmanager
def absolute_request(stage_end,aggregate_end,trace=None,maximum_ns=45000000000):
 need(type(maximum_ns) is int and maximum_ns in (45000000000,135000000000),'PUBLIC_DEADLINE');need(hasattr(signal,'SIGALRM') and threading.current_thread() is threading.main_thread(),'PUBLIC_MAIN_ALARM');started=time.monotonic_ns();handler=signal.getsignal(signal.SIGALRM);previous=signal.getitimer(signal.ITIMER_REAL);need(previous[1]==0,'PUBLIC_PERIODIC_ALARM');old_end=started+int(previous[0]*1000000000) if previous[0]>0 else None;end=min(started+maximum_ns,stage_end,aggregate_end,old_end if old_end is not None else stage_end);budget(end)
 def expired(*unused):raise PublicHold('PUBLIC_DEADLINE')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,max(0,(end-time.monotonic_ns())/1e9))
 primary=None
 try:yield started,end
 except BaseException as exc:primary=exc;raise
 finally:
  try:
   signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,handler);signal.setitimer(signal.ITIMER_REAL,max(0,(old_end-time.monotonic_ns())/1e9) if old_end is not None else 0);budget(end)
  except BaseException as cleanup:
   if primary is None:raise
   if trace is not None:trace.capture(primary);trace.capture(cleanup,secondary=True)
def identity(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
def eligible(s,uid,gid):return stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==uid and s.st_gid==gid and not getattr(s,'st_file_attributes',0)&0x400
def final_path(rawdir,row):return Path(rawdir)/(row['id'].lower()+'.11.0.0.nupkg')
def stream_response(row,response,rawdir,total,end,uid,gid):
 budget(end);need(response.status==200 and response.geturl()==row['url'],'PUBLIC_STATUS');h=response.headers;lengths=h.get_all('Content-Length',[]);enc=h.get_all('Content-Encoding',[]);need(len(lengths)==1 and re.fullmatch('0|[1-9][0-9]*',lengths[0]) is not None and int(lengths[0])==row['bytes'] and not h.get_all('Transfer-Encoding',[]) and len(enc)<=1 and (not enc or enc[0].lower()=='identity'),'PUBLIC_FRAME')
 target=final_path(rawdir,row);partial=target.with_name(target.name+'.partial');need(not target.exists() and not partial.exists() and not Path(rawdir).is_symlink(),'PUBLIC_PATH');flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0);h256=hashlib.sha256();h512=hashlib.sha512();count=0
 with os.fdopen(os.open(partial,flags,0o600),'wb') as out:
  first=os.fstat(out.fileno());need(eligible(first,uid,gid) and first.st_size==0 and stat.S_IMODE(first.st_mode)==0o600,'PUBLIC_PATH')
  while True:
   budget(end);piece=response.fp.read(min(65536,row['bytes']-count+1,536870912-total['bodyBytes']+1));need(type(piece) is bytes,'PUBLIC_FRAME');count+=len(piece);total['bodyBytes']+=len(piece);total['requestBytes']=count;need(total['bodyBytes']<=536870912,'PUBLIC_BODY_BUDGET');need(count<=row['bytes'],'PUBLIC_SIZE');budget(end)
   if not piece:break
   out.write(piece);h256.update(piece);h512.update(piece)
  need(count==row['bytes'],'PUBLIC_SIZE');need(h256.hexdigest()==row['sha256'] and h512.hexdigest()==row['sha512'],'PUBLIC_HASH');out.flush();os.fsync(out.fileno());budget(end);last=os.fstat(out.fileno());need(eligible(last,uid,gid) and (first.st_dev,first.st_ino)==(last.st_dev,last.st_ino) and last.st_size==count and identity(partial.lstat())==identity(last),'PUBLIC_FILE_CHANGED')
 need(not target.exists() and identity(partial.lstat())==identity(last),'PUBLIC_FILE_CHANGED');partial.chmod(0o400);budget(end);os.rename(partial,target);budget(end);s=target.lstat();need(eligible(s,uid,gid) and identity(s)==identity(last) and stat.S_IMODE(s.st_mode)==0o400,'PUBLIC_FILE_CHANGED');return {'bytes':count,'sha256':h256.hexdigest(),'sha512':h512.hexdigest(),'device':s.st_dev,'inode':s.st_ino,'mtimeNs':s.st_mtime_ns,'uid':uid,'gid':gid,'mode':256}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
def request_once(row,rawdir,total,end,uid,gid):
 started=time.monotonic_ns();response=None;result=None;status='UNKNOWN';secondary=False;total['requestBytes']=0
 try:
  budget(end);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());response=opener.open(urllib.request.Request(row['url'],headers={'Accept-Encoding':'identity','User-Agent':'producer04-public-originals/1','Connection':'close'}),timeout=max(.001,(end-time.monotonic_ns())/1e9));status=numeric_status(response.status);budget(end);file=stream_response(row,response,rawdir,total,end,uid,gid);result={'state':'COMPLETE','code':None,'file':file,'http':diagnostic(row['index'],'HTTP_STATUS',status,started,total['requestBytes'])}
 except BaseException as exc:
  kind,observed=error_kind(exc)
  if observed!='UNKNOWN':status=observed
  if type(exc) is urllib.error.HTTPError:response=exc
  code=exc.args[0] if type(exc) is PublicHold and len(exc.args)==1 and exc.args[0] in CODES else 'PUBLIC_STATUS' if type(exc) is urllib.error.HTTPError else 'PUBLIC_IO';result={'state':'HOLD','code':code,'file':None,'http':diagnostic(row['index'],kind,status,started,total['requestBytes'])}
 finally:
  if response is not None:
   try:response.close()
   except BaseException:secondary=True
 if time.monotonic_ns()>=end or secondary:
  if result['state']=='COMPLETE':result['state']='HOLD';result['code']='PUBLIC_DEADLINE' if time.monotonic_ns()>=end else 'PUBLIC_IO'
  result['secondaryCloseOrDeadline']=True
 else:result['secondaryCloseOrDeadline']=False
 result['http']['elapsedNs']=max(0,time.monotonic_ns()-started);result['bodyBytesAfter']=total['bodyBytes'];return result
def start_identity(pid):
 text=Path('/proc',str(pid),'stat').read_text();return text[text.rfind(')')+2:].split()[19]
def parent_binding(spec,private,gate,profile,gate_sha,profile_sha,controller_sha,actual_controller_sha,argv,expected_argv):
 need(type(private) is dict and type(gate) is dict and type(profile) is dict and private.get('purpose')=='PRODUCER04_LINUX_INPUT_CURATION' and private.get('expectedCommit')==spec['sourceHEAD'] and private.get('uid')==spec['uid'] and private.get('gid')==spec['gid'] and private.get('curationAdmissionSHA256')==gate_sha and argv==expected_argv,'PUBLIC_SOURCE')
 need(gate.get('state')=='EXACT_SOURCE_RUNTIME_BOUND' and gate.get('purpose')=='PRODUCER04_LINUX_INPUT_CURATION' and gate.get('sourceHEAD')==spec['sourceHEAD'] and gate.get('dispatchNonce')==spec['dispatchNonce'] and gate.get('inputTransport')==MODE and gate.get('publicTransportAmendmentSHA256')==AMENDMENT_SHA and gate.get('profileSHA256')==profile_sha and gate.get('contractSHA256')=='f19c85da149c694974f6bdd1517026228a2d4a5b22b60d20f0fa229e7d934241' and gate.get('amendmentSHA256')=='0ced5ea8dfe74fed6125c0fba8f0398f592f1d395cca4aee061f3f10346e0770','PUBLIC_SOURCE')
 need(profile.get('inputTransport')==MODE and profile.get('publicInputTransportAmendmentSHA256')==AMENDMENT_SHA and profile.get('publicInputHelperSHA256')==spec['sourceSHA256'] and controller_sha==actual_controller_sha,'PUBLIC_SOURCE')
def verify_parent_source(spec):
 root=Path(spec['root']);private_path=root/'private-spec.json';need(private_path.is_file() and not private_path.is_symlink() and private_path.stat().st_size<=16384,'PUBLIC_SOURCE');private=strict(private_path.read_bytes());gate_path=Path(private.get('curationAdmissionPath',''));need(gate_path.is_absolute() and gate_path.name=='execution-admission.json' and re.fullmatch('admission04-sdk11-linux-[1-9][0-9]*-1',root.name) is not None and gate_path.parent==root.parent/('admission04-curation-intent-'+root.name[len('admission04-sdk11-linux-'):]) and not gate_path.is_symlink() and gate_path.stat().st_size<=16384,'PUBLIC_SOURCE');gate_raw=gate_path.read_bytes();gate=strict(gate_raw);need(root.name=='admission04-sdk11-linux-'+gate['runId']+'-'+gate['attempt'] and gate['attempt']=='1' and private.get('startTick')*1000000==spec['rowStartedNs'],'PUBLIC_SOURCE');tools=Path(__file__).resolve().parent;pr=(tools/'producer04-linux-curation.profile.json').read_bytes();route=strict((tools/'dotnet11-consumer04-admission.lock.json').read_bytes());caller=tools/'consume_dotnet11_host_fact.py';argv=Path('/proc',str(spec['parentPID']),'cmdline').read_bytes().rstrip(b'\0').split(b'\0');expected=[os.fsencode(sys.executable),b'-I',b'-S',b'-B',os.fsencode(str(caller)),b'--worker',os.fsencode(str(private_path))];parent_binding(spec,private,gate,strict(pr,65536),sha(gate_raw),sha(pr),route['controllerSha256'],sha(caller.read_bytes()),argv,expected)
def validate_child(spec):
 exact(spec,('schema','mode','sourceHEAD','sourceSHA256','amendmentSHA256','dispatchNonce','parentPID','parentStart','cgroup','kernelLimits','uid','gid','index','root','rawDirectory','resultPath','deadlineNs','bodyBytesBefore','rowStartedNs','aggregateStartedNs','aggregateEndNs','requestStartedNs'))
 need(spec['schema']=='producer04-public-original-child/v1' and spec['mode']==MODE and spec['amendmentSHA256']==AMENDMENT_SHA and spec['sourceSHA256']==sha(Path(__file__).read_bytes()) and re.fullmatch('[0-9a-f]{40}',spec['sourceHEAD']) is not None and re.fullmatch('[0-9a-f]{32}',spec['dispatchNonce']) is not None,'PUBLIC_SOURCE');need(type(spec['index']) is int and 0<=spec['index']<3 and type(spec['deadlineNs']) is int and type(spec['bodyBytesBefore']) is int and 0<=spec['bodyBytesBefore']<=536870912,'PUBLIC_RESULT')
 need(all(type(spec[k]) is int and spec[k]>=0 for k in ('rowStartedNs','aggregateStartedNs','aggregateEndNs','requestStartedNs')) and spec['rowStartedNs']<=spec['aggregateStartedNs']<=spec['requestStartedNs']<=time.monotonic_ns() and spec['aggregateEndNs']<=min(spec['rowStartedNs']+420000000000,spec['aggregateStartedNs']+135000000000) and spec['deadlineNs']<=min(spec['aggregateEndNs'],spec['rowStartedNs']+420000000000,spec['requestStartedNs']+45000000000),'PUBLIC_DEADLINE')
 need(os.name=='posix' and os.getuid()==spec['uid']>0 and os.getgid()==spec['gid']>0 and os.getppid()==spec['parentPID'] and start_identity(spec['parentPID'])==spec['parentStart'],'PUBLIC_CHILD_IDENTITY');need(re.fullmatch(r'/system.slice/admission04-sdk11-ci-[0-9a-f]{32}\.service',spec['cgroup']) is not None and '0::'+spec['cgroup'] in Path('/proc/self/cgroup').read_text().splitlines() and '0::'+spec['cgroup'] in Path('/proc',str(spec['parentPID']),'cgroup').read_text().splitlines(),'PUBLIC_CHILD_IDENTITY');expected={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'};base=Path('/sys/fs/cgroup')/spec['cgroup'].lstrip('/');need(spec['kernelLimits']==expected and {k:(base/k).read_text().strip() for k in expected}==expected,'PUBLIC_CHILD_IDENTITY')
 root=Path(spec['root']);need(root.is_absolute() and Path(spec['rawDirectory'])==root/'curation/raw' and Path(spec['resultPath'])==root/'curation/public-input'/str(spec['index'])/'result.json' and root.resolve()==root and not Path(spec['rawDirectory']).is_symlink() and not root.is_symlink(),'PUBLIC_PATH');verify_parent_source(spec);budget(spec['deadlineNs']);return spec
def owned_child(spec):
 validate_child(spec);policy();total={'bodyBytes':spec['bodyBytesBefore']};result=request_once(INPUTS[spec['index']],spec['rawDirectory'],total,spec['deadlineNs'],spec['uid'],spec['gid']);result.update(schema='producer04-public-original-result/v1',index=spec['index'],amendmentSHA256=AMENDMENT_SHA,sourceSHA256=spec['sourceSHA256'],sourceHEAD=spec['sourceHEAD'],dispatchNonce=spec['dispatchNonce']);raw=canonical(result)+b'\n';need(len(raw)<=16384,'PUBLIC_RESULT')
 with Path(spec['resultPath']).open('xb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
 budget(spec['deadlineNs'])
def validate_result(result,spec,total):
 exact(result,('schema','state','code','file','http','secondaryCloseOrDeadline','bodyBytesAfter','index','amendmentSHA256','sourceSHA256','sourceHEAD','dispatchNonce'));need(result['schema']=='producer04-public-original-result/v1' and all(result[k]==spec[k] for k in ('index','amendmentSHA256','sourceSHA256','sourceHEAD','dispatchNonce')) and result['state'] in ('COMPLETE','HOLD') and (result['code'] is None or result['code'] in CODES) and type(result['secondaryCloseOrDeadline']) is bool,'PUBLIC_RESULT');h=result['http'];exact(h,('inputIndex','operation','category','status','elapsedNs','bodyBytesRead'));need(type(h['inputIndex']) is int and h['inputIndex']==spec['index'] and h['operation']=='PUBLIC_ORIGINAL_GET' and h['category'] in KINDS and (h['status']=='UNKNOWN' or type(h['status']) is int and 100<=h['status']<=599) and type(h['elapsedNs']) is int and 0<=h['elapsedNs']<=10**15 and type(h['bodyBytesRead']) is int and 0<=h['bodyBytesRead']<=536936448 and type(result['bodyBytesAfter']) is int and result['bodyBytesAfter']==total['bodyBytes']+h['bodyBytesRead'],'PUBLIC_RESULT');total['bodyBytes']=result['bodyBytesAfter'];return h
def acquire(spec,manifest,phase,total,job,trace,gate):
 stage_end=spec['startTick']*1000000+420000000000
 with absolute_request(stage_end,stage_end,trace,135000000000) as (started,aggregate_end):return _acquire_in_window(spec,manifest,phase,total,job,trace,gate,started,aggregate_end)

def _acquire_in_window(spec,manifest,phase,total,job,trace,gate,started,aggregate_end):
 validate_manifest(manifest,spec['expectedCommit']);policy();need(not any(k in spec for k in ('curationTokenPath','curationTokenIdentity')) and 'CURATION_INPUT_TOKEN' not in os.environ,'PUBLIC_TOKEN_CONFIG');phase=Path(phase);rawdir=phase/'raw';rawdir.mkdir(mode=0o700);control=phase/'public-input';control.mkdir(mode=0o700);stage_end=spec['startTick']*1000000+420000000000;rows=[];receipts=[]
 for row in INPUTS:
  with absolute_request(stage_end,aggregate_end,trace) as (request_started,end):
   cap=job.linux_caps();work=control/str(row['index']);work.mkdir(mode=0o700);resultpath=work/'result.json';child={'schema':'producer04-public-original-child/v1','mode':MODE,'sourceHEAD':gate['sourceHEAD'],'sourceSHA256':sha(Path(__file__).read_bytes()),'amendmentSHA256':AMENDMENT_SHA,'dispatchNonce':gate['dispatchNonce'],'parentPID':os.getpid(),'parentStart':start_identity(os.getpid()),'cgroup':cap['cgroup'],'kernelLimits':cap['kernelLimits'],'uid':cap['uid'],'gid':cap['gid'],'index':row['index'],'root':str(Path(spec['root'])),'rawDirectory':str(rawdir),'resultPath':str(resultpath),'deadlineNs':end,'bodyBytesBefore':total['bodyBytes'],'rowStartedNs':spec['startTick']*1000000,'aggregateStartedNs':started,'aggregateEndNs':aggregate_end,'requestStartedNs':request_started};body=canonical(child)+b'\n';path=work/'request.json'
   with path.open('xb') as out:out.write(body)
   work_end=end-200000000;budget(work_end);env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(Path(spec['root'])/'home'),'TMPDIR':str(Path(spec['root'])/'tmp'),'PYTHONDONTWRITEBYTECODE':'1'}
   try:process=job.run([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--owned-public-original',str(path),'--sha256',sha(body)],phase,env,work_end//1000000,work/'process')
   except BaseException:
    trace.observe_http({'inputIndex':row['index'],'operation':'PUBLIC_ORIGINAL_GET','category':'TIMEOUT' if time.monotonic_ns()>=work_end else 'UNKNOWN_OR_REDACTED','status':'UNKNOWN','elapsedNs':max(0,time.monotonic_ns()-started),'bodyBytesRead':'UNKNOWN'});raise
   budget(end);need(process.get('exitCode')==0 and process.get('ownedChildGroupTerminal') is True and (work/'process/stdout.log').stat().st_size==(work/'process/stderr.log').stat().st_size==0,'PUBLIC_CHILD');need(resultpath.stat().st_size<=16384 and not resultpath.is_symlink(),'PUBLIC_RESULT');result=strict(resultpath.read_bytes());h=validate_result(result,child,total);trace.observe_http(h);need(total['bodyBytes']<=536870912,'PUBLIC_BODY_BUDGET')
   receipt={'inputIndex':row['index'],'urlSHA256':sha(row['url'].encode()),'publicTransportAmendmentSHA256':AMENDMENT_SHA,'http':h,'resultSHA256':sha(resultpath.read_bytes()),'processReceiptSHA256':sha((work/'process/process.json').read_bytes()),'requestAbsoluteEndNs':end,'workEndNs':work_end,'aggregateEndNs':aggregate_end};receipts.append(receipt)
   if result['state']!='COMPLETE':raise PublicHold(result['code'] if result['code'] in CODES else 'PUBLIC_CHILD')
   need(result['code'] is None and not result['secondaryCloseOrDeadline'],'PUBLIC_CHILD');file=result['file'];exact(file,('bytes','sha256','sha512','device','inode','mtimeNs','uid','gid','mode'));need(type(file) is dict and file.get('bytes')==row['bytes'] and file.get('sha256')==row['sha256'] and file.get('sha512')==row['sha512'] and file.get('uid')==cap['uid'] and file.get('gid')==cap['gid'] and file.get('mode')==256,'PUBLIC_RESULT');target=final_path(rawdir,row);s=target.lstat();need(not target.is_symlink() and eligible(s,cap['uid'],cap['gid']) and s.st_dev==file['device'] and s.st_ino==file['inode'] and s.st_size==row['bytes'] and s.st_mtime_ns==file['mtimeNs'] and stat.S_IMODE(s.st_mode)==0o400,'PUBLIC_FILE_CHANGED');budget(end);rows.append(dict(row,path=str(target)));receipt['file']=file
 budget(aggregate_end);raw=canonical({'schema':'producer04-public-original-input-receipt/v1','mode':MODE,'amendmentSHA256':AMENDMENT_SHA,'sourceHEAD':gate['sourceHEAD'],'bodyBytesRead':sum(r['bytes'] for r in rows),'rows':receipts,'inputAcceptance':'BYTE_IDENTITIES_ONLY_SIGNATURE_ADVISORY_GRAPH_UNEXECUTED'})+b'\n';need(len(raw)<=16384,'PUBLIC_RESULT')
 with (Path(spec['root'])/'public-original-input-receipt.json').open('xb') as out:out.write(raw);out.flush();os.fsync(out.fileno())
 budget(aggregate_end);return rows
def main():
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--owned-public-original',type=Path,required=True);p.add_argument('--sha256',required=True);a=p.parse_args();need(a.owned_public_original.is_absolute() and not a.owned_public_original.is_symlink() and a.owned_public_original.stat().st_size<=16384,'PUBLIC_SOURCE');raw=a.owned_public_original.read_bytes();need(sha(raw)==a.sha256,'PUBLIC_SOURCE');spec=strict(raw);need(a.owned_public_original==Path(spec['root'])/'curation/public-input'/str(spec['index'])/'request.json','PUBLIC_PATH');owned_child(spec)
if __name__=='__main__':
 try:main()
 except BaseException:raise SystemExit(1) from None
