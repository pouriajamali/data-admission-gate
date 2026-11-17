"""At most three bounded offline causal groups. No actual network/SDK/Job/signals."""
from pathlib import Path
import argparse,ast,email.utils,gzip,hashlib,http.client,importlib.util,io,json,sys,tempfile,time,types
from unittest.mock import patch
def check(v,c):
 if not v:raise RuntimeError(c)
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
URL='https://api.nuget.org/v3/index.json'
class Transport:
 def __init__(self):self.closed=False;self.timeoutCalls=0;self.closedTimeoutCalls=0
 def getpeername(self):return ('192.0.2.1',443)
 def settimeout(self,timeout):
  self.timeoutCalls+=1
  if self.closed:self.closedTimeoutCalls+=1;raise OSError(9,'SYNTHETIC_PRIVATE_EXCEPTION_MUST_NOT_ESCAPE')
class Stream(io.BytesIO):
 def close(self):self.transport.closed=True;super().close()
class Socket:
 def __init__(self,data):self.data=data;self.transport=Transport()
 def makefile(self,*unused):
  f=Stream(self.data);f.transport=self.transport;f.raw=types.SimpleNamespace(_sock=self.transport);return f
def response(body):
 raw=b'HTTP/1.1 200 OK\r\nDate: '+email.utils.formatdate(time.time(),usegmt=True).encode()+b'\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n'+body;sock=Socket(raw);r=http.client.HTTPResponse(sock);r.begin();r.url=URL;return r,sock.transport
class Opener:
 def __init__(self,r):self.r=r
 def open(self,request,timeout):check(request.full_url==URL and 0<timeout<=10,'FIXED_FAKE_REQUEST');return self.r
def payload1262():
 clear=b'{"resources":[]}';b=gzip.compress(clear,mtime=0);extra=b'f'*(1262-len(b)-1)+b'\0';packed=b[:3]+bytes([b[3]|8])+b[4:10]+extra+b[10:];check(len(packed)==1262 and gzip.decompress(packed)==clear,'VALID_1262_SYNTHETIC_GZIP');return clear,packed
def chunks(data):return b'%x\r\n'%len(data)+data+b'\r\n0\r\n\r\n'
def ctx():return {'deadlineMonotonicNs':time.monotonic_ns()+10**10,'utcNow':int(time.time()),'requested':set(),'records':[],'metadataFramingMode':'STRICT_SINGLE_CHUNKED_V1'}
def direct(module,root,body):
 r,t=response(body);context=ctx()
 with patch.object(module.urllib.request,'build_opener',return_value=Opener(r)):
  value=module._wire_request(context,URL,root/'wire',2097152,{'bodyBytes':0},(URL,),True)
 return value,context,t
def child(module,root,body):
 r,t=response(body);spec={'deadlineMonotonicNs':time.monotonic_ns()+10**10,'deadlineCode':'METADATA_REQUEST10_DEADLINE','utcNow':int(time.time()),'bodyBytesBefore':0,'url':URL,'wirePath':str(root/'wire'),'resultPath':str(root/'result.json'),'limit':2097152,'allowedURLs':[URL],'jsonData':True,'metadataFramingMode':'STRICT_SINGLE_CHUNKED_V1','currentRequestIndex':0}
 with patch.object(module.urllib.request,'build_opener',return_value=Opener(r)):module._owned_request_child(spec)
 return json.loads((root/'result.json').read_bytes()),t
def group1(old,new,root):
 clear,packed=payload1262();body=chunks(packed);r,t=response(body);context=ctx();cause=None
 with patch.object(old.urllib.request,'build_opener',return_value=Opener(r)):
  try:old._wire_request(context,URL,root/'old-wire',2097152,{'bodyBytes':0},(URL,),True)
  except OSError as e:cause=e
 check(type(cause) is OSError and cause.errno==9 and context['records'][0]['rawBytes']==1262 and context['records'][0]['state']=='RAW_PARTIAL' and t.closedTimeoutCalls==1,'REPRODUCED_CLOSED_TIMEOUT_AFTER_1262')
 p=root/'old-child';p.mkdir();prior,_=child(old,p,body);check(prior['state']=='HOLD' and prior['code']=='UNKNOWN_OR_REDACTED' and prior['entry']['rawBytes']==1262,'MATCH_EXISTING_RETAINED_FAILURE_SIGNATURE')
 p=root/'new-child';p.mkdir();good,transport=child(new,p,body);check(good['state']=='COMPLETE' and good['entry']['rawBytes']==1262 and transport.closed and transport.closedTimeoutCalls==0 and transport.timeoutCalls==1,'NO_TIMEOUT_ACCESS_AFTER_VALIDATED_ZERO_TERMINAL');check(good['entry']['chunkFraming']['terminated'] is True and good['entry']['chunkFraming']['declaredDataBytes']==1262,'COMPLETE_FRAME_REQUIRED');wire=(p/'wire').read_bytes();check(wire==packed and new.strict_json(new.decode_json(wire,'gzip',2097152-len(wire)))=={'resources':[]},'INDEPENDENT_WIRE_HASH_GZIP_JSON_SUCCESS');return {'offlineErrno':9,'reproducedBytes':1262,'oldClosedTransportAccesses':1,'newClosedTransportAccesses':0,'newCompleteGzipJSON':True,'historicalExceptionRecovered':False}
def group2(new,root):
 clear,packed=payload1262();bad=[('missing-zero',b'%x\r\n'%len(packed)+packed+b'\r\n','METADATA_CHUNK_SIZE_LINE'),('bad-terminator',b'%x\r\n'%len(packed)+packed+b'XX0\r\n\r\n','METADATA_CHUNK_DELIMITER'),('short-payload',b'4ee\r\nprivate','METADATA_INCOMPLETE_BODY'),('trailer',b'0\r\nPRIVATE_HEADER: no\r\n\r\n','METADATA_CHUNK_TRAILER_OR_TERMINATOR')]
 for name,body,code in bad:
  p=root/name;p.mkdir();result,_=child(new,p,body);check(result['state']=='HOLD' and result['code']==code,'MALFORMED_OR_SHORT_BODY_HOLD');check(result['entry']['failure']['operation']=='BODY_READ','FINITE_FAILURE_LOCATION');check('PRIVATE' not in json.dumps(result),'NO_SENSITIVE_EXCEPTION_OR_BODY_TEXT')
 for exc,operation,code,category,errno in [(OSError(9,'PRIVATE'),'BODY_SET_TIMEOUT','METADATA_SOCKET_IO','OS_ERROR',9),(ConnectionResetError(104,'PRIVATE'),'BODY_READ','METADATA_SOCKET_IO','OS_ERROR',104),(TimeoutError(110,'PRIVATE'),'BODY_READ','METADATA_TRANSPORT_TIMEOUT','TIMEOUT',110),(http.client.IncompleteRead(b'PRIVATE'),'BODY_READ','METADATA_INCOMPLETE_BODY','INCOMPLETE_BODY','UNKNOWN')]:
  value=new.safe_metadata_failure(exc,operation);check(value=={'code':code,'category':category,'errno':errno,'operation':operation} and 'PRIVATE' not in json.dumps(value),'EXACT_TRUSTED_TYPE_ERRNO_CATEGORY')
 foreign=type('OSError',(RuntimeError,),{});value=new.safe_metadata_failure(foreign('PRIVATE'),'foreign-private-location');check(value=={'code':'UNKNOWN_OR_REDACTED','category':'UNKNOWN','errno':'UNKNOWN','operation':'UNKNOWN'},'FOREIGN_CLASS_AND_LOCATION_REDACTED');return {'negativeCases':len(bad),'trustedFiniteCategories':4,'foreignSameNameDenied':True,'rawExceptionOrBodyOutput':False}
def group3(C,S,P,B,frozen,root):
 tools=root/'tools';tools.mkdir();(tools/'curation_advisory_source04.py').write_bytes((P/'tools/curation_advisory_source04.py').read_bytes());(tools/'curation_linux_method.py').write_bytes(frozen.read_bytes());C.HERE=tools;trace=S.Trace();factory=types.SimpleNamespace(STATE=trace)
 with patch.dict(sys.modules,{'__main__':types.SimpleNamespace(safe_cause_module=lambda:factory)}):
  _,first=C.method_modules();_,second=C.method_modules()
 check(first is not second and first.Hold is not second.Hold,'REAL_HELPER_RELOAD_CLASS_IDENTITIES');trace.capture(first.Hold('METADATA_CHUNK_DELIMITER'));check(trace.nodes[0]['code']=='METADATA_CHUNK_DELIMITER' and trace.nodes[0]['source']=='curation_advisory_source04','IMMEDIATE_ACTUAL_OBJECT_BIND_SURVIVES_RELOAD');other=S.Trace();check(other.bind(second,sha(Path(second.__file__).read_bytes()),'curation_advisory_source04'),'KNOWN_SOURCE_BIND');foreign=type('Hold',(RuntimeError,),{'__module__':second.__name__});other.capture(foreign('METADATA_CHUNK_DELIMITER'));check(other.nodes[0]['code']=='UNKNOWN_OR_REDACTED','SAME_MODULE_SAME_NAME_FOREIGN_HOLD_DENIED');trace.capture(RuntimeError('PRIVATE_SECONDARY'),True);check(trace.nodes[0]['code']=='METADATA_CHUNK_DELIMITER' and b'PRIVATE' not in trace.record() and len(trace.record())<=16384,'PRIMARY_PRESERVED_AND_BOUNDED')
 def funcs(p):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(p.read_bytes()).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
 old,new=funcs(B/'tools/curate_dotnet11_linux_inputs.py'),funcs(P/'tools/curate_dotnet11_linux_inputs.py')
 for name in old:
  if name not in ('method_modules','diagnostic_proof_payloads'):check(old[name]==new[name],'FULL_METHOD_UNCHANGED_'+name)
 oldfull=json.loads((B/'tools/producer04-linux-curation.profile.json').read_bytes());full=json.loads((P/'tools/producer04-linux-curation.profile.json').read_bytes());causal={'advisoryHelperSHA256','safeCauseHelperSHA256','public10ProvenanceSHA256','diagnosticProfileSHA256'};check({k:v for k,v in oldfull.items() if k not in causal}=={k:v for k,v in full.items() if k not in causal},'ALL_ORIGINAL_CAPS_AUDIT_GATES_UNCHANGED');return {'reloadActualClassPreserved':True,'foreignClassRejected':True,'fullProducerAndCapsUnchanged':True}
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args();D=args.root;P=D/'post';B=D/'baseline';started=time.perf_counter();files=[P/'tools'/n for n in ('curation_advisory_source04.py','curate_dotnet11_linux_inputs.py','curation_safe_cause04.py','consume_dotnet11_host_fact.py','producer04-linux-curation.profile.json')]+[B/'tools'/n for n in ('curation_advisory_source04.py','curate_dotnet11_linux_inputs.py','producer04-linux-curation.profile.json')]+[D/'frozen/curation_linux_method.py',Path(__file__)];inputs=sum(f.stat().st_size for f in files);check(inputs<=524288,'INPUT512K');old=load('baseline_transport04',B/'tools/curation_advisory_source04.py');new=load('curation_advisory_source04',P/'tools/curation_advisory_source04.py');C=load('curate_dotnet11_linux_inputs',P/'tools/curate_dotnet11_linux_inputs.py');S=load('curation_safe_cause04',P/'tools/curation_safe_cause04.py')
 with tempfile.TemporaryDirectory(dir=D) as tmp:
  root=Path(tmp);one=group1(old,new,root);two=group2(new,root);three=group3(C,S,P,B,D/'frozen/curation_linux_method.py',root)
 elapsed=time.perf_counter()-started;check(elapsed<=30,'SOURCE30S');result={'schema':'producer04-body-terminal-causal-fixtures/v1','state':'THREE_NEW_CAUSAL_GROUPS_PASS','groups':3,'optimize':sys.flags.optimize,'seconds':elapsed,'inputBytes':inputs,'sourceSHA256':{f.name:sha(f.read_bytes()) for f in files[:5]},'testSHA256':sha(Path(__file__).read_bytes()),'evidence':[one,two,three],'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0,'healthySDKFullMethodOrOnlineDiagnosticReplay':0};raw=(json.dumps(result,indent=2)+'\n').encode();check(len(raw)<=32768,'OUTPUT32K');args.out.write_bytes(raw);print(json.dumps({'state':result['state'],'groups':3,'optimize':sys.flags.optimize,'seconds':round(elapsed,3),'inputBytes':inputs,'outputBytes':len(raw),'actualHTTPDNSTLSJobSignalsSDKOpenSSLControllerCI':0}))
if __name__=='__main__':main()
