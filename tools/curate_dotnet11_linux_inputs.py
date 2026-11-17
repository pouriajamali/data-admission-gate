"""Own04 Linux curation SOURCE candidate; unresolved method fails before targets.

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
PROFILE_SHA='67d3f67a15f946e89d46c660fd71aa3d3a845dc574db255ce65e5a8db6c24afa'
PURPOSE='PRODUCER04_LINUX_INPUT_CURATION'
AUTHOR='9A1B131BEE0605433056A4EA3815478A8E177961A968C6C0027C1093D1FEB630'
REPOSITORY='1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D'
PACKAGING_SHA='d7523d3ce9764ca3f27595d66ee0d0e3f40174f688c775a2c327a0bb27ffc75b'
IDS=('Microsoft.AspNetCore.App.Runtime.linux-x64','Microsoft.NETCore.App.Host.linux-x64','Microsoft.NETCore.App.Runtime.linux-x64')
METHOD_BLOCKERS=(
 'CURRENT_CRL_SIGNATURE_FRESHNESS_AND_COMPLETE_CHAIN_COVERAGE_METHOD_UNBOUND',
 'SCOPED_KERNEL_DENY_TRANSITION_AND_POSITIVE_NEGATIVE_WITNESSES_UNIMPLEMENTED',
 'PROJECT10_ADVISORY_VERSION_RANGE_HELPER_CAUSAL_SOURCE_HANDOFF_MISSING',
)
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
 need(not any(re.search(r'\b(?:error|warning)\b|\bNU\d{4}\b|validation failed',x,re.I) for x in lines),'VERIFY_ISSUE_REQUIRES_HOLD')
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
 def __init__(self,responses):
  need(type(responses) is dict and len(responses)<=32,'STATIC_ROUTE_COUNT')
  need(all(type(k) is str and type(v) is bytes for k,v in responses.items()),'STATIC_ROUTE_TYPES')
  pki=policies()[0]['finiteMetadataAcquisition']['PKIExactObservedGETs']
  need(all(k in pki or re.fullmatch(r'/(?:v3/index\.json|vuln/index\.json|vuln/page/[0-7]\.json)',k) is not None for k in responses),'STATIC_CLOSED_ROUTE')
  need(sum(map(len,responses.values()))<=8388608,'STATIC_RETENTION_BOUND')
  self.responses=dict(responses);self.calls=0;self.poisoned=False;self.events=[]
 def reply(self,method,target,headers=None):
  self.calls+=1;headers={k.lower():v for k,v in (headers or {}).items()}
  ok=method=='GET' and self.calls<=512 and not any(k in headers for k in ['authorization','proxy-authorization','cookie','transfer-encoding']) and headers.get('content-length','0')=='0'
  ok=ok and type(target) is str and len(target)<=2048 and not any(ord(c)<33 for c in target) and not any(x in target for x in ['?','#','%','\\'])
  if not isinstance(target,str): ok=False;target='INVALID_NON_STRING_TARGET'
  if target.startswith('http://'):
   u=urlsplit(target);ok=ok and u.netloc==headers.get('host',u.netloc) and u.username is None
  elif target.startswith('/'):
   ok=ok and re.fullmatch(r'127\.0\.0\.1:[0-9]{4,5}',headers.get('host','')) is not None
  else: ok=False
  if ok and target=='http://ocsp.digicert.com': status,body=503,b''
  elif ok and target in self.responses: status,body=200,self.responses[target]
  else: self.poisoned=True;status,body=403,b''
  self.events.append({'method':'GET' if method=='GET' else 'DENIED','routeSHA256':digest(str(target).encode()),'status':status,'bytes':len(body)})
  if len(self.events)>512:self.events=self.events[:512]
  return status,body

def retention_ledger(original_sizes,proof_other_bytes):
 need(type(proof_other_bytes) is int and proof_other_bytes>=0 and all(type(n) is int and n>=0 for n in original_sizes),'RETENTION_INPUT')
 total=sum(original_sizes)+proof_other_bytes
 return {'originalBytes':sum(original_sizes),'otherProofBytes':proof_other_bytes,'requiredProofBytes':total,'maxProofBytes':8388608,'fits':total<=8388608,'beforeSDK':'HOLD' if total>8388608 else 'RETENTION_FITS_ONLY_NOT_METHOD_ACCEPTANCE'}
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
def method_feasibility():
 return {'state':'HOLD_METHOD','normalization':'IMPLEMENTED_CLI_CONTENT_HASH_PARSER_RELEASED_OUTPUT_UNOBSERVED','blockers':list(METHOD_BLOCKERS),'reason':'Official CLI detailed output supplies chain descriptions and revocation locations, but no source-bound per-certificate CRL signature/thisUpdate/nextUpdate/serial coverage report. Frozen proxy bytes plus exit0 are not that report. No eighth SDK helper, custom PKI or assumed proxy/CRL consumption is introduced. Scoped kernel transition is intentionally absent until a feasible complete method is reviewed.','SDKReady':False}
def require_method():
 need(not METHOD_BLOCKERS,'METHOD_FEASIBILITY_HOLD_BEFORE_TARGET_OR_NETWORK')
def validate_admission(gate,expected_head,profile_sha):
 required={'schema','state','purpose','sourceHEAD','sourceTree','contractSHA256','profileSHA256','inputManifestSHA256','runId','attempt','leaseAdmissionSHA256'}
 need(type(gate) is dict and set(gate)==required,'CURATION_GATE_SCHEMA')
 need(all(type(v) is str for v in gate.values()),'CURATION_GATE_VALUE_TYPES')
 need(gate['schema']=='producer04-linux-curation-execution-admission/v1' and gate['state']=='EXACT_SOURCE_RUNTIME_BOUND' and gate['purpose']==PURPOSE,'CURATION_GATE_STATE_PURPOSE')
 need(gate['sourceHEAD']==expected_head and re.fullmatch('[0-9a-f]{40}',expected_head or '') is not None,'CURATION_GATE_HEAD')
 need(gate['contractSHA256']==CONTRACT_SHA and gate['profileSHA256']==profile_sha,'CURATION_GATE_POLICY')
 need(re.fullmatch('[0-9a-f]{40}',gate['sourceTree']) is not None and all(re.fullmatch('[0-9a-f]{64}',gate[k]) is not None for k in ['inputManifestSHA256','leaseAdmissionSHA256']),'CURATION_GATE_IDENTITIES')
 need(all(re.fullmatch('[1-9][0-9]*',gate[k]) is not None for k in ['runId','attempt']),'CURATION_GATE_RUN')
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
 deadline_tick(spec['startTick'],runtime.clock(),60,1)
 require_method()
 raise Hold('CURATION_RUNTIME_UNREACHABLE_UNTIL_METHOD_SOURCE_REVIEW')
def preserve_primary(primary,cleanup):
 try: cleanup()
 except BaseException:
  if primary is None: raise
 if primary is not None: raise primary
