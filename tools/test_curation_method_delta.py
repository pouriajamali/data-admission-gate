"""18 new synthetic delta mocks per mode; old24 and all real targets untouched."""
import argparse,copy,datetime,hashlib,importlib.util,json,sys,time,types
from pathlib import Path
from unittest.mock import patch
START=time.monotonic();HERE=Path(__file__).resolve().parent
def module(name):
 s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
M=module('curation_linux_method');A=module('curation_advisory_source04');L=module('curate_dotnet11_linux_inputs');rows=[]
def check(v):
 if not v:raise RuntimeError('DELTA_MOCK_EXPECTATION')
def deny(fn,code):
 try:fn()
 except (M.Hold,A.Hold,L.Hold) as e:check(str(e)==code);return
 raise RuntimeError('EXPECTED_DELTA_DENIAL_MISSING')
def case(name,fn):fn();rows.append({'case':len(rows)+1,'name':name,'state':'PASS_SYNTHETIC_MOCK'})
def tl(tag,body):
 n=len(body);size=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+n.to_bytes((n.bit_length()+7)//8,'big');return bytes([tag])+size+body
def seq(*items):return tl(48,b''.join(items))
def oid(*parts):return tl(6,bytes([40*parts[0]+parts[1],*parts[2:]]))
now=1800000000
def timestamp(n):return tl(23,datetime.datetime.fromtimestamp(n,datetime.timezone.utc).strftime('%y%m%d%H%M%SZ').encode())
name=seq(tl(49,seq(oid(2,5,4,3),tl(19,b'ROOT'))));key=b'issuer-key';aki=seq(tl(128,key));ext=seq(oid(2,5,29,35),tl(4,aki))
def crl(start=now-20,end=now+20,extra=b''):
 return seq(seq(tl(2,b'\x01'),seq(oid(1,2,3)),name,timestamp(start),timestamp(end),tl(160,seq(ext,*([extra] if extra else [])))),seq(oid(1,2,3)),tl(3,b'\x00fake-signature-not-crypto'))
case('CRL metadata remains unverified until native crypto',lambda:check(M.crl_data(crl(),now)['signatureStatus']=='UNVERIFIED_UNTIL_NATIVE_VERIFY'))
case('expired future missing nextUpdate CRLs fail',lambda:(deny(lambda:M.crl_data(crl(end=now),now),'CRL_NOT_CURRENT'),deny(lambda:M.crl_data(crl(start=now+301,end=now+400),now),'CRL_NOT_CURRENT')))
case('indirect delta CRL scopes rejected',lambda:deny(lambda:M.crl_data(crl(extra=seq(oid(2,5,29,27),tl(4,tl(2,b'\x01')))),now),'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED'))
leaf={'sha256':'leaf','issuerDER':b'root-name','subjectDER':b'leaf-name','AKI':'key','SKI':'leaf-key','notBefore':now-100,'notAfter':now+100};root={'sha256':'root','issuerDER':b'root-name','subjectDER':b'root-name','AKI':'key','SKI':'key','notBefore':now-100,'notAfter':now+100};current={'issuerDER':b'root-name','AKI':'key','sha256':'crlA'}
case('exact current structural coverage does not assert signature',lambda:check(M.coverage({'leaf':leaf},{'root':root},[current],['leaf'],now)['state']=='STRUCTURAL_CURRENT_COVERAGE_NATIVE_SIGNATURES_REQUIRED'))
case('missing CRL and duplicate issuer disagreement',lambda:(deny(lambda:M.coverage({'leaf':leaf},{'root':root},[],['leaf'],now),'CRL_CHAIN_COVERAGE_MISSING'),deny(lambda:M.coverage({'leaf':leaf},{'root':root},[current,dict(current,sha256='crlB')],['leaf'],now),'CRL_DUPLICATE_ISSUER_DISAGREES')))
case('ambiguous issuer and expired leaf fail closed',lambda:(deny(lambda:M.coverage({'leaf':leaf},{'root':root,'other':dict(root,sha256='other')},[current],['leaf'],now),'CHAIN_ISSUER_AMBIGUOUS_OR_MISSING'),deny(lambda:M.coverage({'leaf':dict(leaf,notAfter=now-1)},{'root':root},[current],['leaf'],now),'CURRENT_CERTIFICATE_VALIDITY')))
tsa='f'*64;paths={'intermediates':'/private/inter.pem','crls':'/private/crl.pem','codeRoots':'/private/code.pem','timestampRoots':'/private/tsa.pem','author':'/private/'+M.AUTHOR+'.pem','repository':'/private/'+M.REPOSITORY+'.pem','tsaLeaves':['/private/'+tsa+'.pem']}
def vectors_and_image():
 check(len(M.openssl_vectors(paths,now))==2 and M.openssl_vectors(paths,now)[0][-3:]==['any',paths['author'],paths['repository']] and '-crl_download' not in M.openssl_vectors(paths,now)[0] and '-no-CAstore' in M.openssl_vectors(paths,now)[1])
 initial=types.SimpleNamespace(st_mode=0o100755,st_uid=0,st_nlink=1,st_dev=1,st_ino=2,st_size=11,st_mtime_ns=1,st_ctime_ns=1)
 def held(changed=False):
  after=copy.copy(initial)
  if changed:after.st_mtime_ns=2
  readings=iter([b'\x7fELF',b'\x7fELFfixture',b'']);stats=iter([initial,after])
  class P:
   def __str__(self):return '/usr/bin/openssl'
   def resolve(self):return self
   def stat(self):return after
  fake=types.SimpleNamespace(O_RDONLY=0,O_NOFOLLOW=1,O_CLOEXEC=2,open=lambda *a:7,fstat=lambda _:next(stats),read=lambda *a:next(readings),lseek=lambda *a:None,close=lambda _:None)
  with patch.object(M,'Path',return_value=P()),patch.object(M,'os',fake):
   with M.held_os_image('/usr/bin/openssl') as r:check(r['sha256']==hashlib.sha256(b'\x7fELFfixture').hexdigest())
  check(r['stableAfter'] is True)
 held();deny(lambda:held(True),'OS_IMAGE_CHANGED')
case('finite OS vectors root-owned held ELF hash and stat guards',vectors_and_image)
parts=[('CN','Leaf, Inc.')];certs={'leaf':{'subjectParts':parts},'root':{'subjectParts':[('CN','Root')]}};chains={'leaf':['leaf','root']};success=b'/private/leaf.pem: OK\nChain:\ndepth=0: CN = "Leaf, Inc." (untrusted)\ndepth=1: CN = Root\n'
case('native report binds leaf chain semantic DN exactly',lambda:check(M.verify_report(success,b'',0,[('/private/leaf.pem','leaf')],chains,certs)['leafSHA256']==['leaf']))
def unknown_results():
 deny(lambda:M.verify_report(success,b'revoked',1,[('/private/leaf.pem','leaf')],chains,certs),'OPENSSL_VERIFY_EXIT_OR_REPORT');deny(lambda:M.verify_report(success+b'unexpected\n',b'',0,[('/private/leaf.pem','leaf')],chains,certs),'OPENSSL_EXTRA_OR_UNKNOWN_OUTPUT');deny(lambda:M.version_report(b'OpenSSL 1.1.1\n',b'',0),'OPENSSL3_VERSION_UNRECOGNIZED')
 import base64
 identity=L.IDS[0]+'.11.0.0';out=('Verifying '+identity+'\nContent hash: '+base64.b64encode(bytes(64)).decode()+"\nSuccessfully verified package '"+identity+"'.\nRevocation status unknown\n").encode();deny(lambda:L.content_hash(out,L.IDS[0],'11.0.0',0,{'id':L.IDS[0],'version':'11.0.0','sha256':'a'*64}),'VERIFY_ISSUE_REQUIRES_HOLD')
case('revoked nonzero warnings or unknown native and SDK output no PASS',unknown_results)
unit='admission04-sdk11-ci-'+'a'*32;cg='/system.slice/'+unit+'.service';snap={'pid':123,'start':'456','state':'T','uid':1001,'gid':1001,'cgroup':cg,'limits':M.CAPS,'bootID':'boot'}
case('wrong stopped PID start cgroup generation rejected',lambda:(deny(lambda:M.validate_stopped(snap,dict(snap,pid=124)),'EXACT_STOPPED_GENERATION'),deny(lambda:M.validate_stopped(snap,dict(snap,state='R')),'EXACT_STOPPED_GENERATION')))
props={'Id':unit+'.service','Description':unit,'ControlGroup':cg,'MainPID':'123','ActiveState':'active','IPAddressDeny':'0.0.0.0/0 ::/0','IPAddressAllow':'127.0.0.0/8 ::1/128','MemoryMax':'4294967296','MemorySwapMax':'0','TasksMax':'64','CPUQuotaPerSecUSec':'2s','CPUQuotaPeriodUSec':'100ms'};old={'ingress':[],'egress':[]};new={'ingress':[11],'egress':[12]}
case('canonical systemd properties plus new kernel attachments required',lambda:check(M.policy_readback(props,unit,123,cg,old,new)['kernelAttachment']==new))
case('property-only unsupported BPF wrong unit deny rejected',lambda:(deny(lambda:M.policy_readback(props,unit,123,cg,old,old),'DENY_KERNEL_FILTER_NOT_NEW_OR_UNSUPPORTED'),deny(lambda:M.policy_readback(dict(props,MainPID='999'),unit,123,cg,old,new),'DENY_EXACT_UNIT_READBACK')))
policy={'exactGeneration':True,'kernelAttachment':new}
case('same-generation loopback positive and permission-denied negative',lambda:check(M.witness_result(b'producer04-static-ready',M.errno.EPERM,snap,dict(snap,state='R'),('13.107.1.1',443),policy)['state']=='OWN_CURRENT_KERNEL_DENY_AND_LOOPBACK_WITNESSED'))
case('timeout unreachable nonpositive loopback never denial proof',lambda:(deny(lambda:M.witness_result(b'producer04-static-ready',M.errno.ETIMEDOUT,snap,snap,('13.107.1.1',443),policy),'DENY_TIMEOUT_OR_UNREACHABLE_NOT_PROOF'),deny(lambda:M.witness_result(b'wrong',M.errno.EPERM,snap,snap,('13.107.1.1',443),policy),'DENY_LOOPBACK_POSITIVE')))
def native_count():
 c=M.NativeCalls.__new__(M.NativeCalls);c.calls=1;c.reports=[{'reportBytes':20,'libcryptoMappingObserved':False}];allcert={f:{'subjectParts':[('CN',f)]} for f in [M.AUTHOR,M.REPOSITORY,tsa]};chain={f:[f] for f in allcert};count=[]
 def fake_run(argv,seconds,stage):
  count.append((seconds,stage));c.calls+=1;c.reports.append({'reportBytes':20,'libcryptoMappingObserved':True});leaves=argv[argv.index('-purpose')+2:];out=''
  for p in leaves:out+=p+': OK\nChain:\ndepth=0: CN = '+Path(p).stem+'\n'
  return out.encode(),b'',0
 c._run=fake_run;result=c.verify(paths,now,chain,allcert,{'state':'OWN_CURRENT_KERNEL_DENY_AND_LOOPBACK_WITNESSED'});check(len(result['results'])==2 and count==[(10,630),(10,630)] and c.calls==3)
 deny(lambda:c.verify(paths,now,chain,allcert,{'state':'OWN_CURRENT_KERNEL_DENY_AND_LOOPBACK_WITNESSED'}),'OPENSSL_VERIFY_REQUIRES_CURRENT_DENY')
case('native commands mocked finite count clock and role paths',native_count)
def advisory():
 pages=[{'@id':'https://api.nuget.org/v3-vulnerabilities/base.json','@name':'base','@updated':'2026-11-16T00:00:00Z'}];urls=A.advisory_index_urls(pages);ctx={'advisoryIndex':pages,'advisoryPages':{urls[0]:{'test.package':[{'versions':'[10.0.0,11.0.0)','severity':0,'url':'https://example.invalid/advisory'}]}}};check(A.advisory_guard(ctx,[{'id':'test.package','version':'11.0.0'}],{})['state']=='NO_SELECTED_NUGET_ADVISORY_MATCH');ctx['advisoryPages'][urls[0]]['test.package'][0]['versions']='[11.0.0]';deny(lambda:A.advisory_guard(ctx,[{'id':'test.package','version':'11.0.0'}],{}),'CURRENT_ADVISORY_MATCH');deny(lambda:A.in_range('11.0.0-preview','[11.0.0,)'),'SELECTED_VERSION_NOT_STABLE');deny(lambda:A.admit_metadata_url('https://api.nuget.org/v3-vulnerabilities/other.json',urls),'METADATA_URL_NOT_IN_INDEX')
case('adapted10 complete snapshot ranges own closed origin context',advisory)
def metadata():
 wire=b'{"a":1}';check(A.decode_json(wire,'identity',len(wire))==wire);deny(lambda:A.decode_json(wire,'identity',len(wire)-1),'METADATA_COMBINED_BYTES_CAP');deny(lambda:A.strict_json(b'{"a":1,"a":2}'),'METADATA_DUPLICATE_KEY');s=L.StaticResponses({'/ready':b'producer04-static-ready'});check(s.reply('POST','http://ocsp.digicert.com',{'Content-Length':'12'})==(503,b''));check(not s.poisoned);check(s.reply('CONNECT','example.invalid:443')[0]==403 and s.poisoned)
 import tempfile,email.message,email.utils
 url='https://api.nuget.org/v3/index.json'
 class Response:
  status=200
  def __init__(self):
   self.headers=email.message.Message();self.headers['Content-Length']=str(len(wire));self.headers['Date']=email.utils.formatdate(now,usegmt=True);self.fp=types.SimpleNamespace(raw=types.SimpleNamespace(_sock=types.SimpleNamespace(getpeername=lambda:('13.107.1.1',443),settimeout=lambda _:None)));self.remaining=wire;self.reads=0
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def geturl(self):return url
  def read(self,n):self.reads+=1;out=self.remaining[:n];self.remaining=self.remaining[n:];return out
 with tempfile.TemporaryDirectory() as tmp:
  response=Response();ctx={'deadlineMonotonicNs':time.monotonic_ns()+5000000000,'utcNow':now,'requested':set(),'records':[],'allowedURLs':{url}};total={'bodyBytes':0}
  with patch.object(A.urllib.request,'build_opener',return_value=types.SimpleNamespace(open=lambda *a,**k:response)):
   record,data=A.bounded_json_get(ctx,url,Path(tmp)/'metadata.json',1024,total,'service-index');check(data=={'a':1} and response.reads==1 and total['bodyBytes']==2*len(wire))
  response=Response();response.status=416;ctx.update(requested=set(),records=[])
  with patch.object(A.urllib.request,'build_opener',return_value=types.SimpleNamespace(open=lambda *a,**k:response)):
   deny(lambda:A.bounded_json_get(ctx,url,Path(tmp)/'bad.json',1024,{'bodyBytes':0},'service-index'),'METADATA_HTTP_STATUS_OR_URL');check(response.reads==0)
case('bounded JSON and static unavailable OCSP never forwarded',metadata)
def role_and_primary():
 deny(lambda:M.cms_roles([b'bad'],set()),'DER_FRAME');primary=M.Hold('PRIMARY');seen=False
 try:L.preserve_primary(primary,lambda:(_ for _ in ()).throw(RuntimeError('CLEANUP')))
 except M.Hold as e:seen=e is primary
 check(seen);check(M.printed_name('CN = "Leaf, Inc."')==M.printed_name(r'CN = Leaf\, Inc.'));check(M.version_report(b'OpenSSL 3.0.13 30 Jan 2024\n',b'',0)['family']=='OpenSSL3');L.require_method()
 with patch.dict(L.METHOD_SOURCE_PINS,{'curation_linux_method':'0'*64}):deny(L.require_method,'METHOD_HELPER_SOURCE_IDENTITY')
 def oo(text):
  p=list(map(int,text.split('.')));out=[]
  for n in [p[0]*40+p[1],*p[2:]]:
   b=[n&127];n>>=7
   while n:b.insert(0,(n&127)|128);n>>=7
   out.extend(b)
  return tl(6,bytes(out))
 fingerprints=[M.AUTHOR,M.REPOSITORY,tsa,*[str(i)*64 for i in range(5)]];pool={seq(tl(2,bytes([i]))):{'sha256':f,'issuerDER':name,'serialDER':tl(2,bytes([i])),'SKI':('key'+str(i)).encode().hex()} for i,f in enumerate(fingerprints)}
 def signer(i,attrs=b'',ski=False):return seq(tl(2,b'\x01'),tl(128,('key'+str(i)).encode()) if ski else seq(name,tl(2,bytes([i]))),seq(oo('1.2.3')),seq(oo('1.2.3')),tl(4,b'signature'),*([tl(161,attrs)] if attrs else []))
 def sd(content,si,certpool=False):return seq(oo('1.2.840.113549.1.7.2'),tl(160,seq(tl(2,b'\x01'),tl(49,seq(oo('1.2.3'))),seq(oo(content)),*([tl(160,b''.join(pool))] if certpool else []),tl(49,si))))
 token=sd('1.2.840.113549.1.9.16.1.4',signer(2,ski=True));attrs=seq(oo('1.2.840.113549.1.9.6'),tl(49,signer(1)))+seq(oo('1.2.840.113549.1.9.16.2.14'),tl(49,token));blob=sd('1.2.840.113549.1.7.1',signer(0,attrs),True)
 with patch.object(M,'certificate',side_effect=lambda b:pool[b]):
  cs,rs=M.cms_roles([blob],set(fingerprints));check(rs[0]['timestamp']==[tsa] and rs[0]['author']==[M.AUTHOR] and rs[0]['repository']==[M.REPOSITORY]);deny(lambda:M.cms_roles([blob.replace(b'key2',b'bad2')],set(fingerprints)),'CMS_SID_AMBIGUOUS_OR_MISSING')
 head='a'*40;gate={'schema':'producer04-linux-curation-execution-admission/v1','state':'EXACT_SOURCE_RUNTIME_BOUND','purpose':L.PURPOSE,'sourceHEAD':head,'sourceTree':'b'*40,'contractSHA256':L.CONTRACT_SHA,'amendmentSHA256':L.AMENDMENT_SHA,'profileSHA256':L.PROFILE_SHA,'inputManifestSHA256':'DERIVED_FROM_SAME_HANDOFF','leaseAdmissionSHA256':'DERIVED_FROM_SAME_HANDOFF','runId':'CURRENT_SINGLE_DISPATCH','attempt':'1','dispatchNonce':'c'*32};manifest={'schema':'producer04-linux-curation-input-manifest/v1','sourceHEAD':head,'capsule':{'assetID':1,'releaseID':2,'name':'producer04-linux-native11-inputs-'+head+'.tar','bytes':60416000,'sha256':'d'*64,'draft':True},'ownerScratchLimitBytes':2147483648,'leaseAdmission':{'sourceHEAD':head,'runId':'CURRENT_SINGLE_DISPATCH','attempt':'1','dispatchNonce':'c'*32,'protocolSHA256':'9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b'}};rendered,mb,lb=L.render_event_handoff({'gate':gate,'inputManifest':manifest},head,'123','1',HERE);check(rendered['runId']=='123' and rendered['inputManifestSHA256']==hashlib.sha256(mb).hexdigest());deny(lambda:L.render_event_handoff({'gate':gate,'inputManifest':manifest},head,'123','2',HERE),'CURATION_SINGLE_EVENT_INTENT')
case('missing roles typed primary preserved and native shape unobserved',role_and_primary)
check(len(rows)==18);input_bytes=sum((HERE/(n+'.py')).stat().st_size for n in ['curation_linux_method','curation_advisory_source04','curate_dotnet11_linux_inputs'])+sum((HERE/n).stat().st_size for n in ['producer04-linux-curation.contract.json','producer04-linux-curation.profile.json','producer04-linux-curation-method-amendment.json'])+sum(len(x) for x in [crl(),success]);check(input_bytes<=524288 and time.monotonic()-START<30)
result={'schema':'producer04-method-delta-mocks/v1','state':'EXACT18_NEW_METHOD_MOCKS_PASS','count':18,'optimize':sys.flags.optimize,'seconds':round(time.monotonic()-START,6),'inputBytes':input_bytes,'sourceSHA256':{n:hashlib.sha256((HERE/(n+'.py')).read_bytes()).hexdigest() for n in ['curation_linux_method','curation_advisory_source04','curate_dotnet11_linux_inputs']},'rows':rows,'actualOpenSSLSDKKernelNetwork':0,'old24Replay':0,'originalRawReads':0,'source10ModuleImportedExecuted':False};body=(json.dumps(result,indent=2)+'\n').encode();check(len(body)<=32768);p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);args=p.parse_args()
with args.out.open('xb') as f:f.write(body)
print(json.dumps({k:result[k] for k in ['state','count','optimize','seconds','inputBytes','actualOpenSSLSDKKernelNetwork','old24Replay']}))
