"""Own04 finite Linux input curation; exact runtime guards precede targets.

No import performs HTTP, kernel operations, SDK execution, or package inspection.
The pure format/config/allowlist/static-response components do not establish trust.
"""
from __future__ import annotations
import base64, binascii, hashlib, json, re, time
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

HERE=Path(__file__).resolve().parent
CONTRACT_SHA='f19c85da149c694974f6bdd1517026228a2d4a5b22b60d20f0fa229e7d934241'
PROFILE_SHA='d05c6d89e45c1b5c63f74664e2e60b008f90210a0ef4e3a5a4cb079933d2a9a4'
PURPOSE='PRODUCER04_LINUX_INPUT_CURATION'
AUTHOR='9A1B131BEE0605433056A4EA3815478A8E177961A968C6C0027C1093D1FEB630'
REPOSITORY='1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D'
PACKAGING_SHA='d7523d3ce9764ca3f27595d66ee0d0e3f40174f688c775a2c327a0bb27ffc75b'
IDS=('Microsoft.AspNetCore.App.Runtime.linux-x64','Microsoft.NETCore.App.Host.linux-x64','Microsoft.NETCore.App.Runtime.linux-x64')
METHOD_SOURCE_PINS={'curation_linux_method':'a2ed7e4bb9d643f02819907e27af0a1145e966f383f487d306b79372720f9451','curation_advisory_source04':'8c6313a4ae0dbb43db71b1de92624180c5fc79678a2ae50bea6cb3556c485e51'}
AMENDMENT_SHA='0ced5ea8dfe74fed6125c0fba8f0398f592f1d395cca4aee061f3f10346e0770'
class Hold(RuntimeError): pass
def need(value,code):
 if not value: raise Hold(code)
def digest(raw): return hashlib.sha256(raw).hexdigest()
def load_json(path,expected,limit=524288):
 p=Path(path);need(not p.is_symlink() and p.is_file() and p.stat().st_size<=limit,'BOUNDED_POLICY_FILE')
 raw=p.read_bytes();need(digest(raw)==expected,'POLICY_BYTES_IDENTITY');return json.loads(raw)
def policies():
 return load_json(HERE/'producer04-linux-curation.contract.json',CONTRACT_SHA),load_json(HERE/'producer04-linux-curation.profile.json',PROFILE_SHA)

def content_hash(stdout,package_id,version,exit_code,raw_receipt):
 """Strict English CLI shape hypothesis; released SDK output remains unobserved."""
 need(type(stdout) is bytes and len(stdout)<=32768,'VERIFY_LOG_BOUND')
 need(exit_code==0,'VERIFY_EXIT_NOT_ZERO')
 try: text=stdout.decode('utf-8',errors='strict')
 except UnicodeError: raise Hold('VERIFY_LOG_ENCODING') from None
 need(not any(ord(c)<32 and c not in '\r\n\t' for c in text),'VERIFY_LOG_CONTROL')
 lines=[x.strip() for x in text.splitlines()];identity=package_id+'.'+version
 blocks=[i for i,x in enumerate(lines) if x.startswith('Verifying ')]
 hashes=[i for i,x in enumerate(lines) if x.startswith('Content hash')]
 successes=[i for i,x in enumerate(lines) if x.startswith('Successfully verified package')]
 need(len(blocks)==len(hashes)==len(successes)==1,'VERIFY_SINGLE_IDENTITY_HASH_BLOCK')
 b,h,s=blocks[0],hashes[0],successes[0]
 need(lines[b]=='Verifying '+identity and lines[s]=="Successfully verified package '"+identity+"'." and b<h<s,'VERIFY_IDENTITY_ORDER')
 match=re.fullmatch(r'Content hash: ([A-Za-z0-9+/]{86}==)',lines[h]);need(match is not None,'VERIFY_HASH_SCHEMA')
 value=match.group(1)
 try: decoded=base64.b64decode(value,validate=True)
 except binascii.Error: raise Hold('VERIFY_HASH_BASE64') from None
 need(len(decoded)==64 and base64.b64encode(decoded).decode('ascii')==value,'VERIFY_HASH_CANONICAL')
 need(not any(re.search(r'\b(?:error|warning)\b|\bNU\d{4}\b|validation failed|(?:revocation|chain|timestamp).*?(?:unknown|invalid|unavailable)|(?:unknown|invalid).*?(?:revocation|chain|timestamp)',x,re.I) for x in lines),'VERIFY_ISSUE_REQUIRES_HOLD')
 need(raw_receipt.get('id')==package_id and raw_receipt.get('version')==version and re.fullmatch('[0-9a-f]{64}',raw_receipt.get('sha256','')) is not None,'VERIFY_RAW_BINDING')
 return {'id':package_id,'version':version,'rawSHA256':raw_receipt['sha256'],'normalizedNuGetContentHash':value,'algorithm':'NuGet SDK GetContentHash via same verify command; no local formula','logSHA256':digest(stdout),'cryptographicAdmission':False,'revocationCoverage':'UNKNOWN_REQUIRES_SEPARATE_METHOD'}

def official_uri(url,pages=False):
 need(type(url) is str and len(url)<=2048 and not any(ord(c)<33 for c in url),'FINITE_URI_TEXT')
 u=urlsplit(url)
 need(u.scheme=='https' and u.netloc=='api.nuget.org' and not u.query and not u.fragment and '%' not in url and '\\' not in url,'FINITE_OFFICIAL_ORIGIN')
 need(u.path.startswith('/') and '//' not in u.path and all(p not in ('.','..') for p in u.path.split('/')),'FINITE_URI_PATH')
 if pages: need(u.path.startswith('/v3-vulnerabilities/') and u.path.endswith('.json'),'FINITE_VULNERABILITY_NAMESPACE')
 return url
def finite_manifest(contract,repo_url,vuln_url,page_urls,certificate_url=None):
 need(type(page_urls) is list and 1<=len(page_urls)<=8,'FINITE_COMPLETE_PAGES')
 dynamic=[official_uri(repo_url),official_uri(vuln_url,pages=True),*[official_uri(x,pages=True) for x in page_urls]]
 if certificate_url is not None: dynamic.append(official_uri(certificate_url))
 fixed=[x['url'] for x in contract['finiteMetadataAcquisition']['sdkMetadataOnly']]
 pki=contract['finiteMetadataAcquisition']['PKIExactObservedGETs'];urls=fixed+dynamic+pki
 need(len(urls)==len(set(urls)) and len(urls)<=23,'FINITE_DUPLICATE_OR_COUNT')
 return {'state':'CLOSED_REQUEST_MANIFEST_NOT_EXECUTED','GETs':[{'url':u,'requestsMax':1,'redirects':0,'auth':False,'retry':False} for u in urls],'maxInflight':2,'perRequestSeconds':10,'absoluteEndFromRowStartSeconds':420,'OCSPExternalRequests':0,'rawBodyReGETs':0,'dynamicDiscoveryBoundary':'Exact resource and complete page IDs must be selected from retained canonical service/index bytes; this function only closes their origin/count, not discovery provenance or cryptographic authenticity.'}

def config_bytes(phase_root,port):
 need(type(port) is int and 1024<=port<=65535,'OWN_LOOPBACK_PORT')
 root=PurePosixPath(phase_root);need(root.is_absolute() and '..' not in root.parts and not any(ord(x)<32 for x in str(root)),'OWN_PRIVATE_CONFIG_PATH')
 e=ET.Element('configuration');c=ET.SubElement(e,'config')
 for k,v in [('signatureValidationMode','require'),('globalPackagesFolder',str(root/'packages'))]: ET.SubElement(c,'add',{'key':k,'value':v})
 p=ET.SubElement(e,'packageSources');ET.SubElement(p,'clear');ET.SubElement(p,'add',{'key':'own-raw-only','value':str(root/'raw')})
 ET.SubElement(ET.SubElement(e,'fallbackPackageFolders'),'clear')
 a=ET.SubElement(e,'auditSources');ET.SubElement(a,'clear');ET.SubElement(a,'add',{'key':'own-static-audit','value':f'http://127.0.0.1:{port}/v3/index.json','allowInsecureConnections':'true'})
 t=ET.SubElement(e,'trustedSigners');ET.SubElement(t,'clear');r=ET.SubElement(t,'repository',{'name':'nuget.org','serviceIndex':'https://api.nuget.org/v3/index.json'})
 ET.SubElement(r,'certificate',{'fingerprint':REPOSITORY,'hashAlgorithm':'SHA256','allowUntrustedRoot':'false'})
 raw=ET.tostring(e,encoding='utf-8',xml_declaration=True);parsed=ET.fromstring(raw)
 need(parsed.find('trustedSigners/repository/certificate').get('fingerprint')==REPOSITORY,'CONFIG_ROUNDTRIP')
 return raw

class StaticResponses:
 """Frozen data dispatcher only: no URL opener, DNS, CONNECT or forwarding."""
 def __init__(self,responses,own_port=None):
  need(type(responses) is dict and len(responses)<=32,'STATIC_ROUTE_COUNT')
  need(all(type(k) is str and type(v) is bytes for k,v in responses.items()),'STATIC_ROUTE_TYPES')
  pki=policies()[0]['finiteMetadataAcquisition']['PKIExactObservedGETs']
  need(all(k in pki or re.fullmatch(r'/(?:ready|v3/index\.json|vuln/index\.json|vuln/page/[0-7]\.json)',k) is not None for k in responses),'STATIC_CLOSED_ROUTE')
  need(sum(map(len,responses.values()))<=8388608,'STATIC_RETENTION_BOUND')
  self.responses=dict(responses);self.calls=0;self.poisoned=False;self.events=[];self.own_port=own_port
 def reply(self,method,target,headers=None):
  self.calls+=1;headers={k.lower():v for k,v in (headers or {}).items()}
  ocsp=target=='http://ocsp.digicert.com' and method in ('GET','POST')
  length=headers.get('content-length','0');ok=(method=='GET' or ocsp) and self.calls<=512 and not any(k in headers for k in ['authorization','proxy-authorization','cookie','transfer-encoding']) and re.fullmatch(r'0|[1-9][0-9]*',length) is not None and (length=='0' or ocsp and int(length)<=4096)
  ok=ok and type(target) is str and len(target)<=2048 and not any(ord(c)<33 for c in target) and not any(x in target for x in ['?','#','%','\\'])
  if not isinstance(target,str): ok=False;target='INVALID_NON_STRING_TARGET'
  if target.startswith('http://'):
   u=urlsplit(target);ok=ok and u.netloc==headers.get('host',u.netloc) and u.username is None
  elif target.startswith('/'):
   ok=ok and re.fullmatch(r'127\.0\.0\.1:[0-9]{4,5}',headers.get('host','')) is not None
   if self.own_port is not None:ok=ok and headers.get('host')=='127.0.0.1:'+str(self.own_port)
  else: ok=False
  if ok and target=='http://ocsp.digicert.com': status,body=503,b''
  elif ok and target in self.responses: status,body=200,self.responses[target]
  else: self.poisoned=True;status,body=403,b''
  self.events.append({'method':method if method in ('GET','POST') else 'DENIED','routeSHA256':digest(str(target).encode()),'status':status,'bytes':len(body),'bodySHA256':digest(body)})
  if len(self.events)>512:self.events=self.events[:512]
  return status,body

def retention_ledger(original_sizes,proof_other_bytes):
 need(type(proof_other_bytes) is int and proof_other_bytes>=0 and all(type(n) is int and n>=0 for n in original_sizes),'RETENTION_INPUT')
 total=sum(original_sizes)+proof_other_bytes
 return {'originalBytes':sum(original_sizes),'otherProofBytes':proof_other_bytes,'requiredProofBytes':total,'maxProofBytes':8388608,'fits':total<=8388608,'beforeSDK':'HOLD' if total>8388608 else 'RETENTION_FITS_ONLY_NOT_METHOD_ACCEPTANCE'}
LOCK_PROOF_MAX=131072
METADATA_PROOF_MAX=16384
CONFIG_PROOF_MAX=65536
PROPS_PROOF_MAX=16384
LOCK_PROOF_NAMES=('Admission.net11.lock.json','Admission.Tests.net11.lock.json','Admission.linux-x64.lock.json','Admission.Tests.linux-x64.lock.json')
def durable_proof_limits():
 out={'curation/locks/'+n:LOCK_PROOF_MAX for n in LOCK_PROOF_NAMES}
 out['curation/nuget.audit.sources.config']=CONFIG_PROOF_MAX
 out.update({'curation/config/curation.'+f+'.props':PROPS_PROOF_MAX for f in ('net11','linux-x64')})
 out.update({'curation/packages/'+i.lower()+'/11.0.0/.nupkg.metadata':METADATA_PROOF_MAX for i in IDS})
 return out
def durable_proof_reserve():return sum(durable_proof_limits().values())
def durable_snapshot(root,relative):
 import os,stat
 limits=durable_proof_limits();need(type(relative) is str and relative in limits,'DURABLE_FIXED_PATH_REQUIRED');root=Path(root).resolve();path=root/relative
 try:
  for p in [path,*path.parents]:
   if p==root:break
   need(not p.is_symlink() and not getattr(p.lstat(),'st_file_attributes',0)&0x400,'DURABLE_PATH_LINK')
 except FileNotFoundError:raise Hold('DURABLE_REQUIRED_FILE_MISSING') from None
 flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_BINARY',0)
 try:fd=os.open(path,flags)
 except FileNotFoundError:raise Hold('DURABLE_REQUIRED_FILE_MISSING') from None
 with os.fdopen(fd,'rb') as stream:
  before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limits[relative],'DURABLE_FILE_BOUND_OR_TYPE');body=stream.read(limits[relative]+1);after=os.fstat(stream.fileno());current=path.lstat()
  need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)==(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns) and len(body)==before.st_size,'DURABLE_FILE_CHANGED_DURING_READ')
 return {'path':relative,'bytes':len(body),'sha256':digest(body),'device':before.st_dev,'inode':before.st_ino,'mtimeNs':before.st_mtime_ns},body
def capture_durable(root,relative,ledger,json_data=False):
 record,body=durable_snapshot(root,relative)
 if relative in ledger:need(ledger[relative]==record,'DURABLE_CONSUMED_FILE_CHANGED')
 ledger[relative]=record
 return json.loads(body.decode('utf-8')) if json_data else record
def durable_proof_selection(root,value,success):
 ledger=value.get('durableInputs',{});need(type(ledger) is dict,'DURABLE_LEDGER_REQUIRED');limits=durable_proof_limits();need(set(ledger)<=set(limits),'DURABLE_UNEXPECTED_PATH')
 mandatory={p for p in limits if '/packages/' not in p}
 if success:
  need(mandatory<=set(ledger),'DURABLE_FOUR_LOCKS_AND_CONFIG_REQUIRED')
  consumed=set()
  for name in LOCK_PROOF_NAMES:
   record,body=durable_snapshot(root,'curation/locks/'+name);lock=json.loads(body.decode('utf-8'));need(type(lock.get('dependencies')) is dict,'DURABLE_LOCK_SCHEMA')
   for deps in lock['dependencies'].values():
    for identity,item in deps.items():
     if item.get('type')!='Project':consumed.add('curation/packages/'+identity.lower()+'/11.0.0/.nupkg.metadata')
  need(consumed<=set(ledger),'DURABLE_CONSUMED_METADATA_REQUIRED')
 for relative,expected in ledger.items():
  actual,body=durable_snapshot(root,relative);need(actual==expected,'DURABLE_ORIGINAL_CHANGED')
 return {relative:Path(root)/relative for relative in sorted(ledger)}
def read_proof_payload(root,path,value,durable):
 relative=Path(path).relative_to(root).as_posix()
 if relative in durable:
  actual,body=durable_snapshot(root,relative);need(actual==value['durableInputs'][relative],'DURABLE_ORIGINAL_CHANGED');return body
 return Path(path).read_bytes()
def curation_proof_candidates(root,value,success):
 root=Path(root);durable=durable_proof_selection(root,value,success);paths=[*root.glob('*.json'),*(root/'curation/metadata').rglob('*'),*(root/'curation/original-data').glob('*'),*(root/'curation').glob('*/process.json'),*(root/'curation').glob('*/stdout.log'),*(root/'curation').glob('*/stderr.log'),*durable.values()]
 unique={p.relative_to(root).as_posix():p for p in paths if p.is_file()};need(all(not p.is_symlink() for p in unique.values()),'CURATION_PROOF_LINK')
 return [unique[k] for k in sorted(unique)],set(durable)

def disk_ledger(allocations,free_bytes,owner_limit=2147483648):
 need(type(allocations) is dict and all(type(x) is int and x>=0 for x in allocations.values()) and type(free_bytes) is int and free_bytes>=0 and type(owner_limit) is int and owner_limit>0,'DISK_LEDGER_INPUT')
 required=sum(allocations.values());cap=min(owner_limit,2147483648)
 return {'allocations':allocations,'requiredBytes':required,'freeBytes':free_bytes,'applicableCapBytes':cap,'fits':required<=min(cap,free_bytes),'noCapIncrease':True}
def deadline_tick(start_tick,now_tick,stage_end_seconds,per_command_seconds):
 need(type(start_tick) is int and type(now_tick) is int and 0<=now_tick-start_tick<stage_end_seconds*1000<=840000,'ORIGINAL_CLOCK_OR_STAGE_EXPIRED')
 return min(start_tick+stage_end_seconds*1000,now_tick+per_command_seconds*1000)
def command_plan(contract):
 """Same seven SDK operations; private graph imports are an explicit argv delta."""
 commands=json.loads(json.dumps(contract['sevenSDKVectors']))
 need(len(commands)==7 and all(c['argv'][1:4]==['nuget','verify','--all'] for c in commands[:3]),'EXACT_SEVEN_OPERATIONS')
 for c in commands[3:]:
  need(c['argv'][1]=='restore' and '-p:NuGetAudit=true' in c['argv'],'GRAPH_AUDIT_REQUIRED')
  flavor='linux-x64' if '--runtime' in c['argv'] else 'net11'
  c['argv'].append('-p:DirectoryBuildPropsPath=${PHASE_ROOT}/config/curation.'+flavor+'.props')
  c['causalArgvDelta']='Private per-project/per-flavor obj and project extensions via generated props; same restore operation, no eighth SDK invocation. Root exact-source binding must accept this argv delta.'
 return commands
def private_graph_props(checkout,phase_root,flavor):
 need(flavor in ('net11','linux-x64'),'GRAPH_FLAVOR')
 need(all(PurePosixPath(x).is_absolute() and '..' not in PurePosixPath(x).parts and not any(ord(c)<32 for c in x) for x in (checkout,phase_root)),'GRAPH_PRIVATE_ROOT')
 e=ET.Element('Project');ET.SubElement(e,'Import',{'Project':str(PurePosixPath(checkout)/'Directory.Build.props')});g=ET.SubElement(e,'PropertyGroup')
 base=str(PurePosixPath(phase_root)/'obj'/flavor)+'/'+'$(MSBuildProjectName)/'
 for key,value in [('BaseIntermediateOutputPath',base),('MSBuildProjectExtensionsPath',base),('NuGetAudit','true'),('NuGetAuditMode','all'),('NuGetAuditLevel','low')]:ET.SubElement(g,key).text=value
 return ET.tostring(e,encoding='utf-8',xml_declaration=True)
def validate_lock(lock,admitted,local_source,metadata):
 """Compare applicable real package identities; no rawSHA512 substitution."""
 need(type(lock) is dict and lock.get('version')==1 and type(lock.get('dependencies')) is dict and lock['dependencies'],'GRAPH_LOCK_SCHEMA')
 seen=[]
 for tfm,deps in lock['dependencies'].items():
  need(tfm in ('net11.0','net11.0/linux-x64') and type(deps) is dict,'GRAPH_TFM')
  for name,item in deps.items():
   need(type(item) is dict,'GRAPH_DEPENDENCY_SCHEMA')
   if item.get('type')=='Project':
    need(name.lower()=='admission','GRAPH_PROJECT_EDGE');continue
   need(name.lower() in admitted and item.get('resolved')=='11.0.0','GRAPH_NEW_DEPENDENCY')
   value=admitted[name.lower()];need(item.get('contentHash')==value,'GRAPH_NORMALIZED_CONTENT_HASH')
   m=metadata.get(name.lower());need(type(m) is dict and m.get('contentHash')==value and m.get('source')==local_source,'GRAPH_ACTUAL_NUPKG_METADATA')
   seen.append(name.lower())
 return {'state':'APPLICABLE_CONTENT_IDENTITIES_MATCH','packages':sorted(set(seen)),'auditConsumption':'NOT_ESTABLISHED_BY_LOCK','productAdmission':False}
def method_modules():
 import importlib.util
 out=[]
 for name,expected in METHOD_SOURCE_PINS.items():
  p=HERE/(name+'.py');need(digest(p.read_bytes())==expected,'METHOD_HELPER_SOURCE_IDENTITY');s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);out.append(m)
 return tuple(out)
def method_feasibility():
 return {'state':'SOURCE_IMPLEMENTED_RUNTIME_GUARDS_REQUIRED','normalization':'SAME_THREE_SDK_VERIFY_CONTENT_HASH_OUTPUT_UNOBSERVED','blockers':[],'actualCurrentCRLNativeResults':'UNEXECUTED','actualOwnedKernelDenyAndWitness':'UNEXECUTED','advisoryHandoffSHA256':'c49f46dde2e3e0b36e0cf8c50c882f60a8434d9f6ed8a0cb378dd7c6df2701ca','nativeMethods':'One OpenSSL3 version <=2s plus two current-CRL verify operations <=10s each, exact SDK anchors and original CMS SID role mapping; NuGet remains CMS/RFC3161/Content hash authority.','networkMethod':'Same generation-stopped own worker; exact-unit runtime deny/allow, direct kernel BPF ingress/egress readback and same-unit loopback plus explicit permission-denial socket witness; timeout/unreachable alone HOLD.','SDKReady':False}
def require_method():
 method_modules();load_json(HERE/'producer04-linux-curation-method-amendment.json',AMENDMENT_SHA)
def validate_admission(gate,expected_head,profile_sha):
 required={'schema','state','purpose','sourceHEAD','sourceTree','contractSHA256','amendmentSHA256','profileSHA256','inputManifestSHA256','runId','attempt','leaseAdmissionSHA256','dispatchNonce'}
 need(type(gate) is dict and set(gate)==required,'CURATION_GATE_SCHEMA')
 need(all(type(v) is str for v in gate.values()),'CURATION_GATE_VALUE_TYPES')
 need(gate['schema']=='producer04-linux-curation-execution-admission/v1' and gate['state']=='EXACT_SOURCE_RUNTIME_BOUND' and gate['purpose']==PURPOSE,'CURATION_GATE_STATE_PURPOSE')
 need(gate['sourceHEAD']==expected_head and re.fullmatch('[0-9a-f]{40}',expected_head or '') is not None,'CURATION_GATE_HEAD')
 need(gate['contractSHA256']==CONTRACT_SHA and gate['amendmentSHA256']==AMENDMENT_SHA and gate['profileSHA256']==profile_sha,'CURATION_GATE_POLICY')
 need(re.fullmatch('[0-9a-f]{40}',gate['sourceTree']) is not None and all(re.fullmatch('[0-9a-f]{64}',gate[k]) is not None for k in ['inputManifestSHA256','leaseAdmissionSHA256']),'CURATION_GATE_IDENTITIES')
 need(all(re.fullmatch('[1-9][0-9]*',gate[k]) is not None for k in ['runId','attempt']),'CURATION_GATE_RUN')
 need(re.fullmatch('[0-9a-f]{32}',gate['dispatchNonce']) is not None,'CURATION_DISPATCH_NONCE')
 return gate
def parent_admission(path,sha,expected_head):
 contract,profile=policies();gate=validate_admission(load_json(path,sha),expected_head,PROFILE_SHA)
 # A runtime JSON cannot override this source-bound feasibility decision.
 require_method()
 return gate
def worker(spec,backend,runtime,qualifier):
 need(spec.get('purpose')==PURPOSE and spec.get('rid')=='linux-x64','CURATION_FIXED_PURPOSE')
 cap=backend.caps();runtime.f.caps(cap,'linux-x64')
 need(spec.get('parentHeldWorkerBeforeExec') is True,'CURATION_ACTUAL_HELD_WORKER')
 deadline_tick(spec['startTick'],runtime.clock(),60,1);require_method()
 return run_curation_worker(spec,backend,runtime,qualifier)
def preserve_primary(primary,cleanup):
 try: cleanup()
 except BaseException:
  if primary is None: raise
 if primary is not None: raise primary

def _private_write(path,body):
 import os
 p=Path(path)
 with p.open('xb') as f:f.write(body);f.flush();os.fsync(f.fileno())
 p.chmod(0o400)
def render_event_handoff(payload,expected_head,run_id,attempt,private_root):
 """Only declared server-assigned run/path substitutions; no policy weakening."""
 need(type(payload) is dict and set(payload)=={'gate','inputManifest'},'CURATION_EVENT_HANDOFF_SCHEMA');gate=dict(payload['gate']);manifest=dict(payload['inputManifest']);need(gate['runId']=='CURRENT_SINGLE_DISPATCH' and gate['attempt']==attempt=='1' and gate['inputManifestSHA256']==gate['leaseAdmissionSHA256']=='DERIVED_FROM_SAME_HANDOFF','CURATION_SINGLE_EVENT_INTENT');need(gate['sourceHEAD']==manifest['sourceHEAD']==expected_head,'CURATION_INTENT_SOURCE');lease=dict(manifest.pop('leaseAdmission'));need(lease.get('dispatchNonce')==gate['dispatchNonce'] and lease.get('sourceHEAD')==expected_head and lease.get('runId')=='CURRENT_SINGLE_DISPATCH' and lease.get('attempt')=='1' and lease.get('protocolSHA256')=='9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b','CURATION_EVENT_LEASE_INTENT');lease['runId']=run_id;leasebody=(json.dumps(lease,sort_keys=True,separators=(',',':'))+'\n').encode();manifest['leaseAdmissionPath']=str(Path(private_root)/'lease-admission.json');validate_input_manifest(manifest,expected_head);manifestbody=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode();gate.update(runId=run_id,inputManifestSHA256=digest(manifestbody),leaseAdmissionSHA256=digest(leasebody));validate_admission(gate,expected_head,PROFILE_SHA);return gate,manifestbody,leasebody
def validate_input_manifest(manifest,expected_head):
 need(type(manifest) is dict and set(manifest)=={'schema','sourceHEAD','capsule','ownerScratchLimitBytes','leaseAdmissionPath'} and manifest['schema']=='producer04-linux-curation-input-manifest/v1' and manifest['sourceHEAD']==expected_head,'CURATION_INPUT_MANIFEST')
 desc=manifest['capsule'];need(type(desc) is dict and set(desc)=={'assetID','releaseID','name','bytes','sha256','draft'} and desc['draft'] is True and all(type(desc[k]) is int and desc[k]>0 for k in ['assetID','releaseID']) and desc['bytes']==60416000 and re.fullmatch('[0-9a-f]{64}',desc.get('sha256','')) and desc['name']=='producer04-linux-native11-inputs-'+expected_head+'.tar','CAPSULE_IDENTITY')
 need(type(manifest['ownerScratchLimitBytes']) is int and 0<manifest['ownerScratchLimitBytes']<=2147483648 and Path(manifest['leaseAdmissionPath']).is_absolute(),'CURATION_OWNER_OR_LEASE_INPUT');return manifest
def prepare_event_handoff(expected_head):
 import os
 need(os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==expected_head,'CURATION_MANUAL_EXACT_SOURCE');event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes());inputs=event.get('inputs',{});need(inputs.get('linux_curation') in (True,'true') and inputs.get('mode')=='ordinary' and inputs.get('expected_commit')==expected_head,'CURATION_EVENT_SELECTOR');text=inputs.get('curation_handoff','');expected=inputs.get('curation_handoff_sha256','');need(type(text) is str and len(text.encode())<=16384 and digest(text.encode())==expected,'CURATION_ROOT_INTENT_HASH');payload=json.loads(text);private=Path(os.environ['RUNNER_TEMP'])/('admission04-curation-intent-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);private.mkdir(mode=0o700);gate,mb,lb=render_event_handoff(payload,expected_head,os.environ['GITHUB_RUN_ID'],os.environ['GITHUB_RUN_ATTEMPT'],private);gb=(json.dumps(gate,sort_keys=True,separators=(',',':'))+'\n').encode();_private_write(private/'root-intent.json',text.encode());_private_write(private/'input-manifest.json',mb);_private_write(private/'lease-admission.json',lb);_private_write(private/'execution-admission.json',gb);return private/'execution-admission.json',digest(gb),private/'input-manifest.json'
def _capsule(spec,manifest,contract,total,phase):
 """One exact private draft asset transfer; never NuGet body re-acquisition."""
 import os,tarfile,urllib.request,urllib.error
 desc=manifest['capsule'];need(desc['draft'] is True and type(desc['assetID']) is int and desc['assetID']>0 and type(desc['releaseID']) is int and desc['releaseID']>0 and desc['bytes']==60416000 and re.fullmatch('[0-9a-f]{64}',desc['sha256']),'CAPSULE_IDENTITY')
 url='https://api.github.com/repos/pouriajamali/data-admission-gate/releases/assets/'+str(desc['assetID']);tokenpath=Path(spec['curationTokenPath']);need(tokenpath.parent==Path(spec['root']) and tokenpath.name=='curation-input-token','CAPSULE_OWN_TOKEN_SCOPE');need(not tokenpath.is_symlink() and tokenpath.stat().st_uid==os.getuid() and tokenpath.stat().st_mode&0o777==0o600,'CAPSULE_TOKEN_FILE');tokenstat=tokenpath.stat();token_identity=(tokenstat.st_dev,tokenstat.st_ino);need(list(token_identity)==spec['curationTokenIdentity'],'CAPSULE_TOKEN_INODE_BINDING');token=tokenpath.read_text().strip();need(token and '\n' not in token and '\r' not in token,'CAPSULE_TOKEN_FORMAT')
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*a,**k):return None
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token,'Accept':'application/octet-stream','X-GitHub-Api-Version':'2022-11-28'});end=spec['startTick']*1000000+420000000000
 token_failure=None
 try:
  try:response=opener.open(request,timeout=min(10,(end-time.monotonic_ns())/1e9))
  except urllib.error.HTTPError as e:
   need(e.code==302,'CAPSULE_API_STATUS');location=e.headers.get('Location','');u=urlsplit(location);e.close();need(u.scheme=='https' and u.netloc=='release-assets.githubusercontent.com' and not u.username and not u.fragment and len(location)<=8192,'CAPSULE_EXACT_STORAGE_HOP');response=opener.open(urllib.request.Request(location,headers={'Accept':'application/octet-stream'}),timeout=min(10,(end-time.monotonic_ns())/1e9))
  capsule=phase/'input-capsule.tar';h=__import__('hashlib').sha256();count=0
  with response,capsule.open('xb') as out:
   need(response.status==200 and response.headers.get('Content-Length')==str(desc['bytes']) and not response.headers.get('Transfer-Encoding') and response.headers.get('Content-Encoding','identity')=='identity','CAPSULE_RESPONSE_FRAME')
   while True:
    need(time.monotonic_ns()<end,'CAPSULE_ORIGINAL420');b=response.read(min(65536,desc['bytes']-count+1))
    if not b:break
    count+=len(b);total['bodyBytes']+=len(b);need(count<=desc['bytes'] and total['bodyBytes']<=536870912,'CAPSULE_BODY_BOUND');h.update(b);out.write(b)
   out.flush();os.fsync(out.fileno())
  need(count==desc['bytes'] and h.hexdigest()==desc['sha256'],'CAPSULE_WHOLE_HASH_OR_SIZE')
 except BaseException as exc:
  token_failure=exc;raise
 finally:
  token=''
  try:
   st=tokenpath.lstat();need(not tokenpath.is_symlink() and (st.st_dev,st.st_ino)==token_identity,'CAPSULE_TOKEN_INODE_CHANGED');tokenpath.unlink() # only this fresh purpose token
  except BaseException:
   if token_failure is None:raise
 rawdir=phase/'raw';rawdir.mkdir(mode=0o700);expected={x['id'].lower()+'.11.0.0.nupkg':x for x in contract['baseline']['rawInputs']};observed=[]
 with tarfile.open(capsule,'r:') as tf:
  entries=tf.getmembers();need(len(entries)==3 and {x.name for x in entries}==set(expected),'CAPSULE_EXACT_THREE_ENTRIES')
  for entry in entries:
   row=expected[entry.name];need(entry.isfile() and not entry.pax_headers and entry.size==row['bytes'] and entry.uid==entry.gid==entry.mtime==0 and entry.mode==0o444,'CAPSULE_ENTRY_FRAME');source=tf.extractfile(entry);p=rawdir/entry.name;h256=__import__('hashlib').sha256();h512=__import__('hashlib').sha512();size=0
   with source,p.open('xb') as out:
    while True:
     need(time.monotonic_ns()<end,'CAPSULE_ORIGINAL420');b=source.read(65536)
     if not b:break
     size+=len(b);need(size<=row['bytes'],'CAPSULE_ENTRY_SIZE');out.write(b);h256.update(b);h512.update(b)
    out.flush();os.fsync(out.fileno())
   p.chmod(0o400);need(size==row['bytes'] and h256.hexdigest()==row['sha256'] and h512.hexdigest()==row['sha512'],'CAPSULE_ENTRY_HASH');observed.append(dict(row,path=str(p)))
 return observed

def _metadata(spec,phase,contract,A,total,job):
 import email.utils
 root=phase/'metadata';root.mkdir(mode=0o700);fixed=contract['finiteMetadataAcquisition']['sdkMetadataOnly'];pki=contract['finiteMetadataAcquisition']['PKIExactObservedGETs'];requestroot=root/'owned-http';requestroot.mkdir(mode=0o700);ctx={'ownedJob':job,'requestWorkRoot':str(requestroot),'requestCwd':str(phase),'requestEnvironment':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(Path(spec['root'])/'home'),'TMPDIR':str(Path(spec['root'])/'tmp'),'PYTHONDONTWRITEBYTECODE':'1'},'deadlineMonotonicNs':spec['startTick']*1000000+420000000000,'utcNow':time.time(),'utcAnchorMonotonicNs':time.monotonic_ns(),'requested':set(),'records':[],'allowedURLs':{x['url'] for x in fixed}|set(pki)}
 _,service=A.bounded_json_get(ctx,fixed[0]['url'],root/'service.json',2097152,total,'service-index');resources=service.get('resources');need(type(resources) is list,'SERVICE_RESOURCES')
 def resource(prefix):
  rows=[r for r in resources if type(r) is dict and type(r.get('@type')) is str and r['@type'].startswith(prefix)];need(rows,'OFFICIAL_RESOURCE_MISSING');versions={}
  for r in rows:
   v=r['@type'][len(prefix):]
   if r['@type'] not in ('RepositorySignatures/5.0.0','VulnerabilityInfo/6.7.0'):continue
   need(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',v),'OFFICIAL_RESOURCE_VERSION');u=r.get('@id');official_uri(u);versions.setdefault(tuple(map(int,v.split('.'))),set()).add(u)
  need(versions,'SUPPORTED_OFFICIAL_RESOURCE_MISSING');urls=versions[max(versions)];need(len(urls)==1,'OFFICIAL_RESOURCE_AMBIGUOUS');return next(iter(urls))
 repo=resource('RepositorySignatures/');vuln=resource('VulnerabilityInfo/');official_uri(vuln,True);ctx['allowedURLs'].update((repo,vuln));_,repository=A.bounded_json_get(ctx,repo,root/'repository.json',2097152,total,'repository-index');indexrec,index=A.bounded_json_get(ctx,vuln,root/'vulnerability-index.json',2097152,total,'vulnerability-index');urls=A.advisory_index_urls(index)
 for item in index:
  try:updated=A.datetime.datetime.fromisoformat(item['@updated'].replace('Z','+00:00'))
  except ValueError:raise Hold('VULNERABILITY_UPDATED_TIME') from None
  need(updated.tzinfo is not None and updated.timestamp()<=ctx['utcNow']+300,'VULNERABILITY_FUTURE_TIME')
 ctx['allowedURLs'].update(urls);pages={};used=indexrec['rawBytes']+indexrec['decodedBytes']
 for i,u in enumerate(urls):
  rec,data=A.bounded_json_get(ctx,u,root/('vulnerability-page-'+str(i)+'.json'),33554432-used,total,'vulnerability-page-'+str(i),urls);used+=rec['rawBytes']+rec['decodedBytes'];pages[u]=data
 _,servicing=A.bounded_json_get(ctx,fixed[1]['url'],root/'servicing.json',4194304,total,'servicing')
 certificates=repository.get('signingCertificates');need(type(certificates) is list and any(str(c.get('fingerprints',{}).get('2.16.840.1.101.3.4.2.1','')).lower()==REPOSITORY.lower() for c in certificates if type(c) is dict),'CURRENT_REPOSITORY_SIGNER_MISSING')
 need(servicing.get('channel-version')=='11.0' and servicing.get('support-phase') in ('active','maintenance'),'SERVICING_CHANNEL_NOT_SUPPORTED');releases=servicing.get('releases');need(type(releases) is list and releases,'SERVICING_RELEASES')
 current=[r for r in releases if r.get('runtime',{}).get('version')=='11.0.0' and any(s.get('version')=='11.0.100' for s in r.get('sdks',[]))];need(current,'EXACT_SDK_RUNTIME_SERVICING_MISSING');need(servicing.get('latest-runtime')=='11.0.0' and servicing.get('latest-sdk')=='11.0.100' and not any(r.get('security') is True and r.get('runtime',{}).get('version')!='11.0.0' for r in releases),'LATER_SERVICING_REQUIRES_POLICY_HOLD')
 aia=[];crls=[];responses={}
 for i,u in enumerate(pki):
  rec,wire=A.bounded_get(ctx,u,root/('pki-'+str(i)+'.der'),16777216 if u.endswith('.crl') else 2097152,total,(u,));need(sum(r['rawBytes'] for r in ctx['records'] if r['url'] in pki)<=67108864,'PKI_AGGREGATE_BOUND');responses[u]=wire;(crls if u.endswith('.crl') else aia).append(wire)
 ctx['advisoryIndex']=index;ctx['advisoryPages']=pages;need('boundOfficialPeer' in ctx,'OFFICIAL_PEER_SOCKET_UNOBSERVED');return ctx,aia,crls,responses

def _start_adapter(responses,index,pages):
 import http.server,threading
 server=http.server.HTTPServer(('127.0.0.1',0),http.server.BaseHTTPRequestHandler);port=server.server_address[1];base=f'http://127.0.0.1:{port}';routes=dict(responses);routes['/ready']=b'producer04-static-ready';routes['/v3/index.json']=json.dumps({'version':'3.0.0','resources':[{'@id':base+'/vuln/index.json','@type':'VulnerabilityInfo/6.7.0'}]}).encode();localindex=[]
 for i,page in enumerate(index):
  localindex.append(dict(page,**{'@id':base+'/vuln/page/'+str(i)+'.json'}));routes['/vuln/page/'+str(i)+'.json']=json.dumps(pages[page['@id']],separators=(',',':')).encode()
 routes['/vuln/index.json']=json.dumps(localindex,separators=(',',':')).encode();dispatcher=StaticResponses(routes,port)
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*a):pass
  def do_GET(self):self.respond()
  def do_POST(self):self.respond()
  def do_CONNECT(self):self.respond()
  def respond(self):
   if len(self.headers.get_all('Host',[]))!=1 or len(self.headers.get_all('Content-Length',[]))>1:dispatcher.poisoned=True;status,body=403,b''
   else:status,body=dispatcher.reply(self.command,self.path,dict(self.headers))
   self.close_connection=True;self.send_response(status);self.send_header('Content-Length',str(len(body)));self.send_header('Content-Type','application/json' if self.path.startswith('/') else 'application/octet-stream');self.end_headers();self.wfile.write(body)
 server.RequestHandlerClass=Handler;thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return server,thread,dispatcher,port

def _scratch_bytes(roots,limit):
 import os,stat
 total=0;seen=set()
 for root in roots:
  for base,dirs,files in os.walk(root,followlinks=False):
   for name in ['.',*dirs,*files]:
    p=Path(base)/name
    try:st=p.lstat()
    except FileNotFoundError:continue
    need(not stat.S_ISLNK(st.st_mode) and (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)) and st.st_uid==os.getuid(),'PRIVATE_SCRATCH_TYPE_OWNER')
    if (st.st_dev,st.st_ino) in seen:continue
    seen.add((st.st_dev,st.st_ino));total+=st.st_blocks*512;need(total<=limit,'ACTUAL_PRIVATE_SCRATCH_CAP')
 return total
def _sdk_target(spec,Q,argv,cwd,env,deadline,evidence,scratch_roots,limit):
 import os,signal
 evidence=Path(evidence);evidence.mkdir(mode=0o700);cap=Q.j.linux_caps();child=None;primary=None;peak=0;started=time.monotonic();last=0
 with (evidence/'stdout.log').open('xb') as out,(evidence/'stderr.log').open('xb') as err:
  try:
   child,before=Q.j.stopped_linux_child(argv,cwd,env,out,err,(),cap)
   while child.poll() is None:
    need(time.monotonic_ns()//1000000<deadline and out.tell()+err.tell()<=32768,'SDK_TARGET_DEADLINE_OR_REPORT_BOUND')
    if time.monotonic()-last>=.25:peak=max(peak,_scratch_bytes(scratch_roots,limit));last=time.monotonic()
    time.sleep(.01)
   child.wait(timeout=.1);peak=max(peak,_scratch_bytes(scratch_roots,limit));need(child.returncode==0,'SDK_TARGET_NONZERO');need(Q.j.linux_caps()['cgroup']==cap['cgroup'],'SDK_TARGET_CURRENT_CGROUP')
   remaining=[]
   for pid in Q.j.linux_caps()['pids']:
    try:
     text=Path('/proc',str(pid),'stat').read_text();fields=text[text.rfind(')')+2:].split()
     if int(fields[2])==child.pid:remaining.append(pid)
    except FileNotFoundError:pass
   need(not remaining,'SDK_CHILD_GROUP_NOT_NATURALLY_TERMINAL');need(time.monotonic_ns()//1000000<deadline,'SDK_TARGET_DEADLINE_AFTER_TERMINAL')
  except BaseException as exc:primary=exc
  finally:
   if child is not None and child.poll() is None:
    try:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=1)
    except BaseException:
     if primary is None:primary=Hold('SDK_OWNED_CHILD_TERMINAL_UNKNOWN')
  if primary is not None:raise primary
 body=(evidence/'stdout.log').read_bytes();stderr=(evidence/'stderr.log').read_bytes();need(len(body)+len(stderr)<=32768,'SDK_REPORT_BOUND');record={'exitCode':0,'timedOut':False,'heldBeforeExec':before,'sameCgroup':cap['cgroup'],'seconds':time.monotonic()-started,'maxObservedScratchAllocatedBytes':peak,'scratchCapBytes':limit,'naturalChildTerminal':True};_private_write(evidence/'process.json',(json.dumps(record,indent=2)+'\n').encode());return record,body

def run_curation_worker(spec,backend,R,Q):
 import os,sys,signal,zipfile,hashlib,shutil,contextlib
 M,A=method_modules();contract,profile=policies();gate=parent_admission(spec['curationAdmissionPath'],spec['curationAdmissionSHA256'],spec['expectedCommit']);manifest=validate_input_manifest(load_json(spec['curationInputManifestPath'],gate['inputManifestSHA256']),spec['expectedCommit']);root=Path(spec['root']);need(os.environ.get('GITHUB_RUN_ID')==gate['runId'] and os.environ.get('GITHUB_RUN_ATTEMPT')==gate['attempt'],'CURATION_EXACT_RUN')
 lease=load_json(manifest['leaseAdmissionPath'],gate['leaseAdmissionSHA256']);need(lease.get('sourceHEAD')==gate['sourceHEAD'] and lease.get('runId')==gate['runId'] and lease.get('attempt')==gate['attempt'] and lease.get('state')=='OWN_CANONICAL_LEASE_BOUND_TO_THIS_RUN','CURATION_CURRENT_LEASE_BRIDGE');ownerLimit=manifest['ownerScratchLimitBytes'];need(type(ownerLimit) is int and 0<ownerLimit<=2147483648,'CURATION_OWNER_SCRATCH_LIMIT')
 budget=R.Budget(spec);env=R.job_environment(root);(root/'home').mkdir(mode=0o700);env['HOME']=str(root/'home');R.bootstrap_identity();cpu=R.linux_cpu(root);R.f.cpu(cpu);host=R.host('linux-x64',root);source=R.source_context(spec['expectedCommit'],backend.run,env,budget,root,qualification=False);need(source['tree']==gate['sourceTree'],'CURATION_SOURCE_TREE');main=sys.modules['__main__'];need(Path(main.__file__).resolve()==R.ROOT/'tools/consume_dotnet11_host_fact.py','CURATION_FIXED_CALLER');context=main.own04_common_context(spec,source,host,{'controllerSha256':R.digest(main.__file__),'profileSha256':PROFILE_SHA,'producerFactsByRid':{'linux-x64':{'factSha256':'757abf2d3dde65d10cd895cfc97eaeccb7fc11e8685b94ad046e6a8ec8829007'}}},curation=True)
 inv=R.read(HERE/'sdk11-normal-inputs.lock.json')['rids']['linux-x64']['input'];allocationUnit=os.statvfs(root).f_frsize;need(allocationUnit>0,'ACTUAL_ALLOCATION_UNIT');sdkNeed=sum(((r['bytes']+allocationUnit-1)//allocationUnit)*allocationUnit if r['type']=='file' else allocationUnit for r in inv['members']);need(allocationUnit==4096,'UNSUPPORTED_SCRATCH_ALLOCATION_MODEL');required=sdkNeed+sum(profile['runtimeScratchAllocationsWithoutSDK'].values());need(os.statvfs(root).f_favail>=12000,'ACTUAL_SCRATCH_INODES');free=shutil.disk_usage(root).free;need(required<=min(ownerLimit,free),'ACTUAL_PRIVATE_SCRATCH_LEDGER');R.write(root/'curation-space-before-acquisition.json',{'allocationUnit':allocationUnit,'requiredBytes':required,'freeBytes':free,'applicableCap':ownerLimit})
 phase=root/'curation';phase.mkdir(mode=0o700);total={'bodyBytes':211463422};budget.stage(1,min(300,max(1,(spec['startTick']+360000-R.clock())//1000)));normal=R.load_module('check_dotnet11','d9c690d8c82825b018c04089c279036829d3baf2534c2634bba84910c415a37d');sdkDirectory=Path(os.environ['RUNNER_TEMP'])/('sdk11-normal-04-'+host['runId']+'-'+host['attempt']+'-curation');sdk,receipt=normal.transport('linux-x64',sdkDirectory,context);need(Path(sdk).is_relative_to(sdkDirectory),'OWN_SDK_ALLOCATION_SCOPE');R.write(root/'curation-sdk-input-receipt.json',receipt);need(R.digest(sdk/'sdk/11.0.100/NuGet.Packaging.dll')==PACKAGING_SHA,'CURATION_NUGET_PACKAGING_BINARY')
 budget.stage(2,max(1,(spec['startTick']+420000-R.clock())//1000));raw=_capsule(spec,manifest,contract,total,phase);roles=load_json(HERE/'producer04-linux-curation-cert-roles.json',profile['certificateRolesSHA256']);cms=[]
 for row in sorted(raw,key=lambda r:r['index']):
  with zipfile.ZipFile(row['path']) as z:
   item=z.getinfo('.signature.p7s');need(item.file_size<=2097152,'CURRENT_CMS_BOUND');b=z.read(item);need(digest(b)==roles['packageCMS'][row['index']]['sha256'],'CURRENT_CMS_BYTES');cms.append(b)
   retained=phase/'original-data';retained.mkdir(mode=0o700,exist_ok=True)
   with zipfile.ZipFile(row['path']) as z:
    for original in roles['packageOriginalData'][row['index']]:
     item=z.getinfo(original['path']);need(item.file_size==original['bytes']<=2097152,'ORIGINAL_NOTICE_DATA_BOUND');data=z.read(item);need(digest(data)==original['sha256'],'ORIGINAL_NOTICE_DATA_HASH');_private_write(retained/(str(row['index'])+'-'+str(original['memberIndex'])+'.data'),data)
 codepath=sdk/'sdk/11.0.100/trustedroots/codesignctl.pem';tsapath=sdk/'sdk/11.0.100/trustedroots/timestampctl.pem';need(R.digest(codepath)==profile['bundles'][0]['sha256'] and R.digest(tsapath)==profile['bundles'][1]['sha256'],'EXACT_SDK_ROOT_BUNDLES');override=Path('/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem');need(not override.exists() or (override.is_file() and not override.is_symlink() and R.digest(override)==profile['bundles'][0]['sha256']),'UNEXPECTED_EFFECTIVE_SYSTEM_CODESIGN_STORE')
 native=M.NativeCalls(spec,Q.j,phase);server=thread=None;primary=None;durable={}
 try:
  with native:
   version=native.version();ctx,aia,crls,responses=_metadata(spec,phase,contract,A,total,Q.j);need(R.clock()<spec['startTick']+420000,'ORIGINAL_METADATA420');budget.stage(3,max(1,(spec['startTick']+630000-R.clock())//1000));fixed=int(time.time());need(abs((fixed-ctx['utcNow'])-(time.monotonic_ns()-ctx['utcAnchorMonotonicNs'])/1e9)<=300,'CURRENT_UTC_MONOTONIC_ANCHOR');dates=[__import__('email.utils',fromlist=['parsedate_to_datetime']).parsedate_to_datetime(r['date']).timestamp() for r in ctx['records'] if r['url'].startswith('https://api.nuget.org/')];need(any(abs(fixed-d)<=300 for d in dates),'FIXED_TIME_FRESH_HTTPS_BINDING');paths,chains,certs,chainproof=M.prepare_chain_files(phase/'chain',cms,roles['certificatePoolSHA256'],codepath.read_bytes(),tsapath.read_bytes(),aia,crls,fixed)
   original=sum(p.stat().st_size for p in (phase/'metadata').rglob('*') if p.is_file());derived=sum(p.stat().st_size for p in (phase/'chain').rglob('*') if p.is_file());need(profile['durableGraphProofReserveBytes']==durable_proof_reserve() and profile['retainedProofReserveBeforeSDKBytes']==2097152+durable_proof_reserve(),'DURABLE_PROOF_RESERVE_IDENTITY');need(retention_ledger([original,derived],profile['retainedProofReserveBeforeSDKBytes'])['fits'],'ORIGINAL_METADATA_AND_PROOF8M_OVERFLOW');server,thread,dispatcher,port=_start_adapter(responses,ctx['advisoryIndex'],ctx['advisoryPages']);_private_write(phase/'nuget.audit.sources.config',config_bytes(str(phase),port));capture_durable(root,'curation/nuget.audit.sources.config',durable);M.close_external_sockets();snapshot=M.pid_snapshot(os.getpid(),spec['unit']);request={'purpose':PURPOSE,'unit':spec['unit'],'worker':snapshot,'uid':os.getuid(),'originalStartMonotonicNs':spec['startTick']*1000000,'sourceHEAD':gate['sourceHEAD'],'leaseAdmissionSHA256':gate['leaseAdmissionSHA256']};request['requestSHA256']=digest(json.dumps(request,sort_keys=True,separators=(',',':')).encode());R.write(root/'network-transition-request.json',request);os.kill(os.getpid(),signal.SIGSTOP);policy=R.read(root/'network-policy-applied.json');need(policy['requestSHA256']==request['requestSHA256'] and policy['sourceHEAD']==gate['sourceHEAD'] and policy['leaseAdmissionSHA256']==gate['leaseAdmissionSHA256'],'DENY_RESPONSE_IDENTITY');witness=M.network_witness(port,ctx['boundOfficialPeer'],snapshot,spec['unit'],policy);R.write(root/'curation-current-network-deny.json',witness);need(R.clock()<spec['startTick']+540000,'ORIGINAL_DENY540');supplement=native.verify(paths,fixed,chains,certs,witness)
   env.update({'DOTNET_ROOT':str(sdk),'DOTNET_ROOT_X64':str(sdk),'DOTNET_HOST_PATH':str(sdk/'dotnet'),'PATH':str(sdk)+os.pathsep+env['PATH'],'DOTNET_CLI_UI_LANGUAGE':'en-US','LANG':'C','LC_ALL':'C','DOTNET_NUGET_SIGNATURE_VERIFICATION':'true','NUGET_CERT_REVOCATION_MODE':'online','HTTP_PROXY':f'http://127.0.0.1:{port}','HTTPS_PROXY':f'http://127.0.0.1:{port}','NO_PROXY':'127.0.0.1,localhost','NUGET_PACKAGES':str(phase/'packages'),'NUGET_HTTP_CACHE_PATH':str(phase/'http-cache'),'NUGET_FALLBACK_PACKAGES':'','HOME':str(root/'home')});records=[];admitted={};mapping={'${SDK}':str(sdk),'${PHASE_ROOT}':str(phase),'${CHECKOUT}':str(R.ROOT)};vectors=command_plan(contract)
   def command(vector,stage):
    normal.inspect_sdk('linux-x64',sdk,context);argv=vector['argv']
    for key,val in mapping.items():argv=[str(x).replace(key,val) for x in argv]
    rec,out=_sdk_target(spec,Q,argv,R.ROOT,env,deadline_tick(spec['startTick'],R.clock(),stage,vector['secondsMax']),phase/vector['id'],[root,sdkDirectory],ownerLimit);need(not dispatcher.poisoned,'STATIC_ADAPTER_UNEXPECTED_REQUEST');stderr=(phase/vector['id']/'stderr.log').read_bytes();need(not stderr and len(out)<=32768,'SDK_STDERR_OR_REPORT_UNKNOWN');need(re.search(rb'\b(?:warning|error)\b|\bNU[0-9]{4}\b',out,re.I) is None,'SDK_WARNING_OR_AUDIT_ERROR');need(not any((R.ROOT/f).exists() for f in ['src/Admission/obj','tests/Admission.Tests/obj','src/Admission/bin','tests/Admission.Tests/bin']),'GRAPH_CHECKOUT_OUTPUT_FORBIDDEN');records.append({'id':vector['id'],'exitCode':rec['exitCode'],'processReceiptSHA256':R.digest(phase/vector['id']/'process.json'),'argvSHA256':digest(json.dumps(argv).encode())});return out
   for i,vector in enumerate(vectors[:3]):
    out=command(vector,630);row=contract['baseline']['rawInputs'][i];result=content_hash(out,row['id'],'11.0.0',0,row);admitted[row['id'].lower()]=result['normalizedNuGetContentHash'];records[-1]['normalized']=result
   advisory=A.advisory_guard(ctx,contract['baseline']['rawInputs'],total);need(R.clock()<spec['startTick']+630000,'ORIGINAL_SIGNATURE630');budget.stage(4,max(1,(spec['startTick']+810000-R.clock())//1000));(phase/'locks').mkdir(mode=0o700);(phase/'config').mkdir(mode=0o700)
   for flavor in ('net11','linux-x64'):_private_write(phase/'config'/('curation.'+flavor+'.props'),private_graph_props(str(R.ROOT),str(phase),flavor));capture_durable(root,'curation/config/curation.'+flavor+'.props',durable)
   lockproof=[];directPkgCount=0
   for vector in vectors[3:]:
    command(vector,810);lp=Path(vector['produces'].replace('${PHASE_ROOT}',str(phase)));lock=capture_durable(root,lp.relative_to(root).as_posix(),durable,json_data=True);metadata={};directPkgCount+=sum(1 for d in lock['dependencies'].values() for v in d.values() if v.get('type')=='Direct')
    for package,content in admitted.items():
     mp=phase/'packages'/package/'11.0.0/.nupkg.metadata'
     if mp.exists():metadata[package]=capture_durable(root,mp.relative_to(root).as_posix(),durable,json_data=True)
    need('Tests' not in vector['id'] or any(v.get('type')=='Project' and k.lower()=='admission' for d in lock['dependencies'].values() for k,v in d.items()),'GRAPH_REQUIRED_PROJECT_REFERENCE');lockproof.append({'lockSHA256':R.digest(lp),'identity':validate_lock(lock,admitted,str(phase/'raw'),metadata)});deps=[{'id':k,'version':v['resolved']} for d in lock['dependencies'].values() for k,v in d.items() if v.get('type')!='Project'];A.advisory_guard(ctx,deps,total)
   need(R.clock()<spec['startTick']+810000 and len(records)==7,'ORIGINAL_GRAPH810');budget.stage(5,max(1,(spec['startTick']+840000-R.clock())//1000));auditRoutes={'/vuln/index.json',*['/vuln/page/'+str(i)+'.json' for i in range(len(ctx['advisoryIndex']))]};served={e['routeSHA256'] for e in dispatcher.events if e['status']==200};auditComplete=all(digest(p.encode()) in served for p in auditRoutes);packageRefs=sum(1 for f in [R.ROOT/'Directory.Build.props',R.ROOT/'src/Admission/Admission.csproj',R.ROOT/'tests/Admission.Tests/Admission.Tests.csproj'] for n in ET.fromstring(f.read_bytes()).iter() if n.tag.split('}')[-1]=='PackageReference');need(auditComplete or (packageRefs==0 and directPkgCount==0),'SDK_AUDIT_CONSUMPTION_NOT_PROVEN');auditConsumption='CONSUMED_COMPLETE_OWN_STATIC_SNAPSHOT' if auditComplete else 'NOT_APPLICABLE_NO_PACKAGE_REFERENCE';proof={'state':'LINUX_CURATED_INPUT_GRAPH_CANDIDATE_NOT_PRODUCT_ADMITTED','source':source,'SDKInputReceiptSHA256':R.digest(root/'curation-sdk-input-receipt.json'),'version':version,'currentCRLSupplement':supplement,'chainInputProof':chainproof,'network':witness,'commands':records,'locks':lockproof,'durableInputs':durable,'nativeAdvisory':advisory,'SDKAuditConsumption':auditConsumption,'metadata':ctx['records'],'adapter':dispatcher.events,'SDK_READY':False,'WindowsQualification':False,'productAdmission':False};
  R.write(root/'curation-worker.json',proof)
 except BaseException as exc:
  primary=exc
  try:
   R.write(root/'curation-method-failure.json',{'state':'HOLD_NOT_INPUT_ADMITTED','durableInputs':durable,'causeCode':str(exc) if re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(exc)) else 'CURATION_PRIMARY_REDACTED','metadataRecords':ctx['records'] if 'ctx' in locals() else 'UNKNOWN_NOT_COMPLETED','SDK_READY':False})
  except BaseException:pass
 finally:
  def stop_adapter():
   if server is not None:server.shutdown();server.server_close();thread.join(timeout=2);need(not thread.is_alive(),'STATIC_ADAPTER_TERMINAL_UNKNOWN')
  if primary is not None:preserve_primary(primary,stop_adapter)
  else:stop_adapter()
 need(R.clock()<spec['startTick']+840000,'ORIGINAL_DURABLE840');signal.setitimer(signal.ITIMER_REAL,0)
