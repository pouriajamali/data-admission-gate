"""Three SOURCE-only causal groups for the observed chunked/gzip metadata case."""
from pathlib import Path
import argparse,ast,datetime,email.utils,gzip,hashlib,http.client,importlib.util,io,json,sys,tempfile,time,types
from unittest.mock import patch
def need(v,c):
 if not v:raise RuntimeError(c)
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def hold(code,fn):
 try:fn()
 except A.Hold as e:need(e.args==(code,),code);return e
 raise RuntimeError('EXPECTED_'+code)
URL='https://api.nuget.org/v3/index.json'
class Stream(io.BytesIO):pass
class Socket:
 def __init__(self,data):self.data=data
 def makefile(self,*a):
  stream=Stream(self.data);stream.raw=types.SimpleNamespace(_sock=types.SimpleNamespace(getpeername=lambda:('192.0.2.1',443),settimeout=lambda value:None));return stream
def response(body,headers):
 raw=b'HTTP/1.1 200 OK\r\nDate: '+email.utils.formatdate(time.time(),usegmt=True).encode()+b'\r\n'+headers+b'\r\n'+body;r=http.client.HTTPResponse(Socket(raw));r.begin();r.url=URL;return r
class Opener:
 def __init__(self,r):self.r=r
 def open(self,request,timeout):need(request.full_url==URL and 0<timeout<=10,'FIXED_FAKE_GET');return self.r
def wire(root,body,headers,mode=None,limit=8192):
 r=response(body,headers);ctx={'deadlineMonotonicNs':time.monotonic_ns()+10**10,'utcNow':int(time.time()),'requested':set(),'records':[]}
 if mode is not None:ctx['metadataFramingMode']=mode
 with patch.object(A.urllib.request,'build_opener',return_value=Opener(r)):entry,data=A._wire_request(ctx,URL,root/'wire.data',limit,{'bodyBytes':0},(URL,),True)
 return entry,data
def groups(root,B,P,C,S):
 # 1: Reproduce the actual header combination using real stdlib HTTPResponse,
 # synthetic bytes only, and verify compressed payload identity + strict decode.
 payload=b'{"resources":[]}';packed=gzip.compress(payload,mtime=0);chunks=b'%x\r\n'%len(packed)+packed+b'\r\n0\r\n\r\n';headers=b'Transfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n'
 d=root/'good';d.mkdir();entry,data=wire(d,chunks,headers,A.FULL_METADATA_FRAMING_MODE);need(data==packed and A.decode_json(data,'gzip',8192)==payload,'EXACT_COMPRESSED_PAYLOAD_AND_JSON');need(A.strict_json(payload)=={'resources':[]},'STRICT_JSON');need(entry['chunkFraming']=={'chunkCount':2,'framingBytesRead':len(chunks)-len(packed),'declaredDataBytes':len(packed),'terminated':True},'COMPLETE_BOUNDED_CHUNK_PROOF');need(entry['framing']['transferEncodingCategory']=='CHUNKED' and entry['framing']['noTransferEncoding'] is False,'OBSERVATION_NOT_WAIVED');need(entry['rawSHA256']==sha(packed),'ORIGINAL_PAYLOAD_HASH')
 d=root/'length';d.mkdir();e,b=wire(d,b'{}',b'Content-Length: 2\r\n',A.FULL_METADATA_FRAMING_MODE);need(b==b'{}' and 'chunkFraming' not in e,'ORIGINAL_LENGTH_PATH')
 for i,mode in enumerate((None,A.LEGACY_METADATA_FRAMING_MODE)):
  d=root/('legacy'+str(i));d.mkdir();hold('METADATA_HTTP_FRAMING',lambda:wire(d,chunks,headers,mode))
 hold('METADATA_GZIP_EOF',lambda:A.decode_json(packed[:-1],'gzip',8192))
 # 2: Ambiguous headers, extensions, trailers, malformed/short/incomplete data,
 # size overflow and unknown modes all HOLD, without reading a real transport.
 cases=[(chunks,headers+b'Content-Length: 2\r\n','METADATA_HTTP_FRAMING'),(chunks,headers+b'Transfer-Encoding: chunked\r\n','METADATA_HTTP_FRAMING'),(chunks,b'Transfer-Encoding: gzip, chunked\r\n','METADATA_HTTP_FRAMING'),(chunks,headers+b'Trailer: x\r\n','METADATA_HTTP_FRAMING'),(b'2;x=y\r\n{}\r\n0\r\n\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_SIZE_LINE'),(b'2\r\n{}XX0\r\n\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_DELIMITER'),(b'2\n{}\r\n0\r\n\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_SIZE_LINE'),(b'0\r\nSecret: no\r\n\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_TRAILER_OR_TERMINATOR'),(b'G\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_SIZE_LINE'),(b'3fff\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_BODY_BOUND'),(b'2\r\n{}\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_SIZE_LINE'),(b'0\r\n',b'Transfer-Encoding: chunked\r\n','METADATA_CHUNK_TRAILER_OR_TERMINATOR')]
 for i,(body,h,code) in enumerate(cases):
  d=root/('bad'+str(i));d.mkdir();hold(code,lambda:wire(d,body,h,A.FULL_METADATA_FRAMING_MODE))
 d=root/'mode';d.mkdir();hold('METADATA_FRAMING_MODE',lambda:wire(d,chunks,headers,'UNKNOWN'))
 # 3: Owned request serialization/cause binding, mandatory full-mode gate and
 # unchanged complete producer/advisory/native/SDK/default resource semantics.
 spec={'deadlineMonotonicNs':time.monotonic_ns()+10**10,'deadlineCode':'METADATA_REQUEST10_DEADLINE','utcNow':int(time.time()),'bodyBytesBefore':0,'url':URL,'wirePath':str(root/'child-wire'),'resultPath':str(root/'child-result.json'),'limit':8192,'allowedURLs':[URL],'jsonData':True,'metadataFramingMode':A.FULL_METADATA_FRAMING_MODE}
 with patch.object(A.urllib.request,'build_opener',return_value=Opener(response(chunks,headers))):A._owned_request_child(spec)
 result=json.loads((root/'child-result.json').read_bytes());need(result['state']=='COMPLETE' and result['entry']['chunkFraming']['terminated'] is True,'OWNED_COMPLETE_IS_NOT_INPUT_ADMISSION');trace=S.Trace();need(trace.bind(A,sha(Path(A.__file__).read_bytes()),'curation_advisory_source04'),'SOURCE_CLASS_BIND')
 d=root/'cause';d.mkdir();exc=hold('METADATA_HTTP_FRAMING',lambda:wire(d,chunks,headers+b'Content-Length: 2\r\n',A.FULL_METADATA_FRAMING_MODE));trace.capture(exc);need(trace.nodes[0]['code']=='METADATA_HTTP_FRAMING','SAFE_ORIGINAL_CAUSE')
 def funcs(raw):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 oldC=(B/'tools/curate_dotnet11_linux_inputs.py').read_bytes();newC=(P/'tools/curate_dotnet11_linux_inputs.py').read_bytes();old,new=funcs(oldC),funcs(newC)
 for name in old:
  if name not in ('_metadata','policies','validate_admission'):need(old[name]==new[name],'UNCHANGED_CURATION_'+name)
 oldA=funcs((B/'tools/curation_advisory_source04.py').read_bytes());newA=funcs(Path(A.__file__).read_bytes())
 for name in oldA:
  if name not in ('_wire_request','_owned_request_child','bounded_get'):need(oldA[name]==newA[name],'UNCHANGED_ADVISORY_'+name)
 oldfull=json.loads((B/'tools/producer04-linux-curation.profile.json').read_bytes());full=json.loads((P/'tools/producer04-linux-curation.profile.json').read_bytes());causal={'advisoryHelperSHA256','safeCauseHelperSHA256','public10ProvenanceSHA256','diagnosticProfileSHA256','metadataFramingMode'};need({k:v for k,v in oldfull.items() if k not in causal}=={k:v for k,v in full.items() if k not in causal},'CAPS_AND_BODY_AUDIT_COUNTS_UNCHANGED');need(full['metadataFramingMode']==A.FULL_METADATA_FRAMING_MODE and full['publicInputHelperSHA256']=='658448fc0e981c9b1bac9efab8ed18623d4980054cb7d2358c35efac88112bb0','RAW_TRANSPORT_UNCHANGED')
 oldcaller=(B/'tools/consume_dotnet11_host_fact.py').read_text();meta=json.loads((P.parent/'BUILD.json').read_bytes());expected=oldcaller.replace(meta['preimages']['tools/curate_dotnet11_linux_inputs.py'],meta['components']['curation']).replace(meta['preimages']['tools/curation_safe_cause04.py'],meta['components']['safeCause']);need(expected==(P/'tools/consume_dotnet11_host_fact.py').read_text(),'CALLER_HASHES_ONLY')
 gate={'schema':'producer04-linux-curation-execution-admission/v1','state':'EXACT_SOURCE_RUNTIME_BOUND','purpose':C.PURPOSE,'sourceHEAD':'a'*40,'sourceTree':'b'*40,'contractSHA256':C.CONTRACT_SHA,'amendmentSHA256':C.AMENDMENT_SHA,'profileSHA256':C.PROFILE_SHA,'inputManifestSHA256':'c'*64,'runId':'123','attempt':'1','leaseAdmissionSHA256':'d'*64,'dispatchNonce':'e'*32,'inputTransport':'PUBLIC_ORIGINALS_V1','publicTransportAmendmentSHA256':C.PUBLIC_TRANSPORT_SHA,'advisoryNamespaceAmendmentSHA256':C.NAMESPACE_AMENDMENT_SHA,'executionMode':C.FULL_EXECUTION_MODE,'diagnosticProfileSHA256':C.DIAGNOSTIC_PROFILE_SHA,'metadataFramingMode':C.METADATA_FRAMING_MODE};C.validate_admission(gate,'a'*40,C.PROFILE_SHA)
 try:C.validate_admission(dict(gate,metadataFramingMode='UNKNOWN'),'a'*40,C.PROFILE_SHA)
 except C.Hold as e:need(e.args==('METADATA_FRAMING_GATE',),'MANDATORY_FRAME_GATE')
 else:raise RuntimeError('MISSING_FRAME_GATE')
 return {'realStdlibParserSyntheticPayloadAndGzip':True,'malformedOrAmbiguousCases':len(cases),'legacyDiagnosticNoTEUnchanged':True,'fullMethodSignatureAuditNativeSDKFunctionsUnchanged':True,'capsAndOriginalBudgetUnchanged':True,'actualNetworkJobSignalsSDKNative':0}
def main():
 global A
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args();started=time.perf_counter();P=args.root/'post';B=args.root/'baseline';files=[P/'tools'/x for x in ('curation_advisory_source04.py','curate_dotnet11_linux_inputs.py','curation_safe_cause04.py','consume_dotnet11_host_fact.py','producer04-linux-curation.profile.json')]+[B/'tools'/x for x in ('curation_advisory_source04.py','curate_dotnet11_linux_inputs.py','consume_dotnet11_host_fact.py','producer04-linux-curation.profile.json')]+[args.root/'BUILD.json',Path(__file__)];inputbytes=sum(f.stat().st_size for f in files);need(inputbytes<=524288,'SOURCE_INPUT_CAP');A=load('curation_advisory_source04',P/'tools/curation_advisory_source04.py');C=load('curate_dotnet11_linux_inputs',P/'tools/curate_dotnet11_linux_inputs.py');S=load('curation_safe_cause04',P/'tools/curation_safe_cause04.py')
 with tempfile.TemporaryDirectory(dir=args.root) as tmp:evidence=groups(Path(tmp),B,P,C,S)
 elapsed=time.perf_counter()-started;need(elapsed<=30,'SOURCE_TIME_CAP');value={'schema':'producer04-strict-chunked-causal-fixtures/v1','state':'THREE_NEW_CAUSAL_GROUPS_PASS','groups':3,'optimize':sys.flags.optimize,'seconds':elapsed,'inputBytes':inputbytes,'sourceSHA256':{f.name:sha(f.read_bytes()) for f in files[:5]},'testSHA256':sha(Path(__file__).read_bytes()),'evidence':evidence,'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0,'healthyFullMethodOrDiagnosticReplay':0};raw=(json.dumps(value,indent=2)+'\n').encode();need(len(raw)<=32768,'SOURCE_OUTPUT_CAP');args.out.write_bytes(raw);print(json.dumps({'state':value['state'],'groups':3,'optimize':sys.flags.optimize,'seconds':round(elapsed,3),'inputBytes':inputbytes,'outputBytes':len(raw),'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0}))
if __name__=='__main__':main()
