"""Exactly24 changed-only synthetic cases; no SDK/HTTP/server/kernel/old inputs."""
import argparse,base64,copy,hashlib,importlib.util,json,sys,time
from pathlib import Path
START=time.monotonic();HERE=Path(__file__).resolve().parent
sp=importlib.util.spec_from_file_location('curation_delta',HERE/'curate_dotnet11_linux_inputs.py');M=importlib.util.module_from_spec(sp);sp.loader.exec_module(M)
C,P=M.policies();rows=[];input_bytes=(HERE/'curate_dotnet11_linux_inputs.py').stat().st_size+(HERE/'producer04-linux-curation.contract.json').stat().st_size+(HERE/'producer04-linux-curation.profile.json').stat().st_size
def check(v):
 if not v:raise RuntimeError('FIXTURE_EXPECTATION')
def deny(fn,code):
 try:fn()
 except M.Hold as e:check(str(e)==code);return
 raise RuntimeError('EXPECTED_DENIAL_MISSING')
def case(name,fn):
 fn();rows.append({'case':len(rows)+1,'name':name,'state':'PASS'})
ID=M.IDS[2];H=base64.b64encode(bytes(range(64))).decode();raw={'id':ID,'version':'11.0.0','sha256':'a'*64}
def log(value=H,identity=ID+'.11.0.0'):return ('Verifying '+identity+'\nContent hash: '+value+"\nSuccessfully verified package '"+identity+"'.\n").encode()
def parse(b=None,exit=0):
 global input_bytes
 b=log() if b is None else b;input_bytes+=len(b);return M.content_hash(b,ID,'11.0.0',exit,raw)
case('same-command canonical hash distinct from raw and crypto admission',lambda:check(parse()['normalizedNuGetContentHash']==H and parse()['cryptographicAdmission'] is False))
case('nonzero verifier cannot admit output',lambda:deny(lambda:parse(exit=1),'VERIFY_EXIT_NOT_ZERO'))
case('identity mismatch and exact block order',lambda:deny(lambda:parse(log(identity='Other.11.0.0')),'VERIFY_IDENTITY_ORDER'))
case('duplicate verifying package block',lambda:deny(lambda:parse(log()+log()),'VERIFY_SINGLE_IDENTITY_HASH_BLOCK'))
case('duplicate hash line',lambda:deny(lambda:parse(log().replace(b'Content hash:',('Content hash: '+H+'\nContent hash:').encode())),'VERIFY_SINGLE_IDENTITY_HASH_BLOCK'))
case('noncanonical base64 pad bits rejected',lambda:deny(lambda:parse(log(H[:-3]+'x==')),'VERIFY_HASH_CANONICAL'))
case('missing content hash has no raw fallback',lambda:deny(lambda:parse(log().replace(('Content hash: '+H+'\n').encode(),b'')),'VERIFY_SINGLE_IDENTITY_HASH_BLOCK'))
case('bounded invalid log and warnings',lambda:(deny(lambda:parse(b'x'*32769),'VERIFY_LOG_BOUND'),deny(lambda:parse(log()+b'warning NU3028 secret\n'),'VERIFY_ISSUE_REQUIRES_HOLD')))
def config():
 b=M.config_bytes('/private/phase',19042);r=M.ET.fromstring(b);check(r.find('trustedSigners/repository/certificate').get('allowUntrustedRoot')=='false');check(r.find('config/add').get('value')=='require');check(r.find('fallbackPackageFolders/clear') is not None);check(b'http://127.0.0.1:19042/' in b and b'http://api.nuget.org' not in b)
case('closed XML serialization parseback trust and private source',config)
case('loopback endpoint and private path validation',lambda:(deny(lambda:M.config_bytes('/phase',80),'OWN_LOOPBACK_PORT'),deny(lambda:M.config_bytes('/phase/../escape',19042),'OWN_PRIVATE_CONFIG_PATH')))
repo='https://api.nuget.org/v3-index/repository-signatures/5.0.0/index.json';vuln='https://api.nuget.org/v3-vulnerabilities/index.json';pages=['https://api.nuget.org/v3-vulnerabilities/base.json']
case('finite future manifest has no native GET or external OCSP',lambda:check(len(M.finite_manifest(C,repo,vuln,pages)['GETs'])==14))
case('official URI rejects aliases credentials and query',lambda:(deny(lambda:M.official_uri('https://api.nuget.org.evil/a'),'FINITE_OFFICIAL_ORIGIN'),deny(lambda:M.official_uri('https://api.nuget.org/a?token=x'),'FINITE_OFFICIAL_ORIGIN')))
case('advisory namespace traversal encoded separator rejection',lambda:(deny(lambda:M.official_uri('https://api.nuget.org/v3/vulnerabilities/base.json',True),'FINITE_VULNERABILITY_NAMESPACE'),deny(lambda:M.official_uri('https://api.nuget.org/v3-vulnerabilities/%2f.json',True),'FINITE_OFFICIAL_ORIGIN')))
case('duplicate and excessive advisory page tuple',lambda:(deny(lambda:M.finite_manifest(C,repo,vuln,pages*2),'FINITE_DUPLICATE_OR_COUNT'),deny(lambda:M.finite_manifest(C,repo,vuln,pages*9),'FINITE_COMPLETE_PAGES')))
def static():
 d={'/v3/index.json':b'{"snapshot":"frozen"}'};s=M.StaticResponses(d);d['/v3/index.json']=b'changed';check(s.reply('GET','/v3/index.json',{'Host':'127.0.0.1:19042'})==(200,b'{"snapshot":"frozen"}'));check(not s.poisoned)
 deny(lambda:M.StaticResponses({'http://unlisted.example/a':b'bad'}),'STATIC_CLOSED_ROUTE')
case('static adapter serves frozen original bytes no forwarding',static)
def connect():
 s=M.StaticResponses({});check(s.reply('CONNECT','hidden.secret:443')[0]==403 and s.poisoned);check('hidden' not in json.dumps(s.events))
case('CONNECT and unknown route poison without target exposure',connect)
case('OCSP deterministic unavailable no external request',lambda:check(M.StaticResponses({}).reply('GET','http://ocsp.digicert.com')==(503,b'')))
def denied_headers():
 url=C['finiteMetadataAcquisition']['PKIExactObservedGETs'][0];s=M.StaticResponses({url:b'certificate'});check(s.reply('GET',url,{'Authorization':'secret'})[0]==403);check(s.reply('GET',url+'?secret=1')[0]==403)
case('adapter authorization query and body route denials',denied_headers)
case('original-data retention exact ceiling and preSDK HOLD',lambda:check(M.retention_ledger([8388608],0)['fits'] and not M.retention_ledger([8388608],1)['fits']))
case('scratch ledger subordinate owner cap and actual free',lambda:check(not M.disk_ledger({'sdk':900},1000,800)['fits'] and not M.disk_ledger({'sdk':900},800,1000)['fits'] and M.disk_ledger({'sdk':900},1000,1000)['fits']))
gate={'schema':'producer04-linux-curation-execution-admission/v1','state':'EXACT_SOURCE_RUNTIME_BOUND','purpose':M.PURPOSE,'sourceHEAD':'a'*40,'sourceTree':'b'*40,'contractSHA256':M.CONTRACT_SHA,'profileSHA256':M.PROFILE_SHA,'inputManifestSHA256':'c'*64,'runId':'123','attempt':'1','leaseAdmissionSHA256':'d'*64}
def admission():
 check(M.validate_admission(gate,'a'*40,M.PROFILE_SHA)==gate);bad=dict(gate,state='PENDING');deny(lambda:M.validate_admission(bad,'a'*40,M.PROFILE_SHA),'CURATION_GATE_STATE_PURPOSE');deny(lambda:M.validate_admission(gate,'b'*40,M.PROFILE_SHA),'CURATION_GATE_HEAD')
case('ownpurpose exact source run policy admission',admission)
case('method unconditionally closes before target and network',lambda:deny(M.require_method,'METHOD_FEASIBILITY_HOLD_BEFORE_TARGET_OR_NETWORK'))
def vectors():
 v=M.command_plan(C);check(len(v)==7 and '--verbosity' in v[0]['argv'] and '--configfile' in v[0]['argv']);check(all(any(x.startswith('-p:DirectoryBuildPropsPath=') for x in c['argv']) for c in v[3:]));p=M.ET.fromstring(M.private_graph_props('/checkout','/private/phase','linux-x64'));check(p.find('PropertyGroup/BaseIntermediateOutputPath').text=='/private/phase/obj/linux-x64/$(MSBuildProjectName)/')
case('same seven operations explicit private per-project obj delta',vectors)
def locks_clock_primary():
 admitted={ID.lower():H};lock={'version':1,'dependencies':{'net11.0/linux-x64':{ID:{'type':'Transitive','resolved':'11.0.0','contentHash':H},'Admission':{'type':'Project'}}}};meta={ID.lower():{'contentHash':H,'source':'/private/raw'}}
 check(M.validate_lock(lock,admitted,'/private/raw',meta)['productAdmission'] is False);bad=copy.deepcopy(lock);bad['dependencies']['net11.0/linux-x64'][ID]['contentHash']='rawSHA512';deny(lambda:M.validate_lock(bad,admitted,'/private/raw',meta),'GRAPH_NORMALIZED_CONTENT_HASH');check(M.deadline_tick(1000,2000,630,20)==22000);deny(lambda:M.deadline_tick(1000,632000,630,20),'ORIGINAL_CLOCK_OR_STAGE_EXPIRED')
 primary=M.Hold('PRIMARY');seen=False
 def cleanup():raise ValueError('SECONDARY')
 try:M.preserve_primary(primary,cleanup)
 except M.Hold as e:seen=e is primary
 check(seen)
case('real lock metadata binding original clock primary preservation',locks_clock_primary)
check(len(rows)==24 and input_bytes<=524288 and time.monotonic()-START<30)
result={'schema':'producer04-linux-curation-delta-mocks/v1','state':'EXACT24_NEW_CASES_PASS','count':24,'optimize':sys.flags.optimize,'seconds':round(time.monotonic()-START,6),'inputBytes':input_bytes,'sourceSHA256':hashlib.sha256((HERE/'curate_dotnet11_linux_inputs.py').read_bytes()).hexdigest(),'profileSHA256':M.PROFILE_SHA,'contractSHA256':M.CONTRACT_SHA,'rows':rows,'actualSDKHTTPNativeKernelOperations':0,'oldFixturesReplayed':0,'oldRawInputsRead':0}
out=(json.dumps(result,indent=2)+'\n').encode();check(len(out)<=32768);parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
with args.out.open('xb') as f:f.write(out)
print(json.dumps({'state':result['state'],'count':24,'optimize':sys.flags.optimize,'inputBytes':input_bytes,'outputBytes':len(out),'seconds':result['seconds']}))
