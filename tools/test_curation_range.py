"""Exactly eighteen new offline fixtures per mode; no old85, real prefix or Job."""
from pathlib import Path
import ast,copy,hashlib,io,json,os,sys,time,types

BASE=Path(__file__).resolve().parent
def get(name):
 p=BASE/(name+'.py.txt');p=p if p.is_file() else BASE/(name+'.py');raw=p.read_bytes();m=types.ModuleType(name);m.__file__=str(p);exec(compile(raw,str(p),'exec'),m.__dict__);return m,raw
R,rraw=get('curation_range_candidate');C,craw=get('curate_dotnet11_inputs');p=BASE/'producer04-runtime-range.profile.json.txt';p=p if p.is_file() else BASE/'producer04-runtime-range.profile.json';praw=p.read_bytes();PROFILE=json.loads(praw)
MODE=sys.argv[1];OUT=Path(sys.argv[2]);OUT.mkdir(parents=True,exist_ok=False);cases=[];start=time.monotonic();PREFIX=b'IMMUTABLE_PREFIX';SUFFIX=b'SUFFIX';H=lambda b:hashlib.sha256(b).hexdigest();H512=lambda b:hashlib.sha512(b).hexdigest()
input_bytes=len(rraw)+len(craw)+len(praw)+Path(__file__).stat().st_size
if input_bytes>524288:raise RuntimeError('INPUT_BOUND')
def check(v,code):
 if not v:raise RuntimeError(code)
class Headers(dict):
 def get_all(self,key):
  value=self.get(key);return value if isinstance(value,list) else [value] if value is not None else None
class Response:
 def __init__(self,p,body=SUFFIX,status=206,headers=None,url=None,error=None):self.status=status;self.url=url or p['url'];self.body=io.BytesIO(body);self.reads=0;self.error=error;self.headers=Headers({'Content-Range':p['expected206ContentRange'],'Content-Length':str(p['suffixBytes']),**(headers or {})})
 def geturl(self):return self.url
 def read(self,count):
  self.reads+=1
  if self.error:raise self.error
  return self.body.read(count)
 def __enter__(self):return self
 def __exit__(self,*args):return False
class Opener:
 def __init__(self,response):self.response=response;self.calls=0;self.headers={}
 def open(self,request,timeout):self.calls+=1;self.headers={k.lower():v for k,v in request.header_items()};return self.response

def setup(number,prefix=PREFIX):
 d=OUT/str(number);d.mkdir();old=d/'prefix.data';old.write_bytes(prefix);policy=copy.deepcopy(PROFILE['exactByteCandidate']);policy.update(immutablePrefixPath=str(old),prefixBytes=len(PREFIX),prefixSha256=H(PREFIX),suffixBytes=len(SUFFIX),wholeBytes=len(PREFIX)+len(SUFFIX),existingWholePolicySHA512=H512(PREFIX+SUFFIX),rangeRequest=f'bytes={len(PREFIX)}-{len(PREFIX)+len(SUFFIX)-1}',expected206ContentRange=f'bytes {len(PREFIX)}-{len(PREFIX)+len(SUFFIX)-1}/{len(PREFIX)+len(SUFFIX)}');return d,old,policy
old_builder=R.urllib.request.build_opener
def run_case(number,name,*,prefix=PREFIX,body=SUFFIX,status=206,headers=None,url=None,error=None,expected_error=None,zero_read=False,zero_get=False,stat_change=False,hash_false=False,existing_dest=False,close_error=False):
 d,old,policy=setup(number,prefix);destination=d/'fresh.data'
 if existing_dest:destination.write_bytes(b'EXISTING_DATA')
 before=old.read_bytes();before_stat=old.stat();resp=Response(policy,body,status,headers,url,error);op=Opener(resp);R.urllib.request.build_opener=lambda *a:op;saved_fstat=R.os.fstat;saved_close=R.os.close;fstat_calls=0
 if stat_change:
  def changed(fd):
   nonlocal fstat_calls
   info=saved_fstat(fd);fstat_calls+=1
   if fstat_calls==2:return types.SimpleNamespace(st_dev=info.st_dev,st_ino=info.st_ino,st_size=info.st_size,st_mtime_ns=info.st_mtime_ns+1,st_ctime_ns=info.st_ctime_ns)
   return info
  R.os.fstat=changed
 if close_error:
  def failing_close(fd):saved_close(fd);raise OSError('SYNTHETIC_CLOSE_FAILURE')
  R.os.close=failing_close
 result=None;thrown=None
 try:result=R.reconstruct(policy,destination,time.monotonic_ns()+20000000000,policy['prefixSha256'])
 except BaseException as exc:thrown=exc
 finally:R.os.fstat=saved_fstat;R.os.close=saved_close;R.urllib.request.build_opener=old_builder
 check(old.read_bytes()==before and old.stat().st_size==before_stat.st_size and old.stat().st_mtime_ns==before_stat.st_mtime_ns,'OLD_PREFIX_MUTATION')
 if expected_error:
  check(thrown is not None,'EXPECTED_REJECTION')
  if expected_error!='ANY':check(type(thrown).__name__=='RangeError' and str(thrown)==expected_error,'EXPECTED_TYPED_REJECTION')
 else:check(thrown is None,'UNEXPECTED_FIXTURE_EXCEPTION')
 if zero_read:check(resp.reads==0,'BODY_READ_BEFORE_HEADER_GATE')
 if zero_get:check(op.calls==0,'GET_BEFORE_PREFIX_OR_FRESH_GATE')
 if existing_dest:check(destination.read_bytes()==b'EXISTING_DATA','FRESH_FILE_OVERWRITE')
 if error is not None:check(thrown is error and 'SYNTHETIC_PRIVATE' not in json.dumps(C.cause(thrown)),'PRIMARY_MASKED_OR_RAW_DISCLOSURE')
 if result is not None:
  check(result['state']=='BYTE_CANDIDATE_UNTRUSTED' and result['HTTPRepresentationContinuity']=='UNKNOWN_WITHOUT_ORIGINAL_STRONG_VALIDATOR' and result['IfRangeSent'] is False and result['authenticity']==result['normalizedNuGetContentHash']=='UNKNOWN' and result['cryptographicAdmission'] is False,'ADMISSION_OR_CONTINUITY_FABRICATION');check('if-range' not in op.headers and op.headers['range']==policy['rangeRequest'],'GUESSED_VALIDATOR_OR_WRONG_RANGE')
  if hash_false:
   check(result['fullPolicyHashEquality'] is False,'MISMATCH_NOT_REPORTED')
   try:R.require_full_policy(result)
   except R.RangeError as exc:check(str(exc)=='RANGE_WHOLE_POLICY_HASH_MISMATCH','WRONG_FULL_HASH_GATE')
   else:raise RuntimeError('STRUCTURAL_INSPECTION_MUST_STAY_CLOSED')
   f=next(n for n in ast.parse(craw).body if isinstance(n,ast.FunctionDef) and n.name=='range_worker');gate=next(n for n in ast.walk(f) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='require_full_policy');inspection=next(n for n in ast.walk(f) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='inspect_one');check(gate.lineno<inspection.lineno,'ZIP_BEFORE_FULL_HASH_GATE')
  else:check(destination.read_bytes()==PREFIX+SUFFIX and result['rawSignedSHA256']==H(PREFIX+SUFFIX) and result['rawSignedSHA512']==H512(PREFIX+SUFFIX) and result['fullPolicyHashEquality'] is True,'ACTUAL_WHOLE_BYTE_HASH');R.require_full_policy(result)
 cases.append({'fixture':number,'case':name,'result':'PASS','mockGETs':op.calls,'mockBodyReads':resp.reads})

# 1 includes the explicit still-missing future runtime-gate boundary, no host API.
pending={'schema':'producer04-sdk0-discovery-handoff/v1','admission':'ROOT_ONLY_EXACT_RANGE_BYTE_CANDIDATE','mode':'range-candidate-sdk0','contractSha256':C.RANGE_CONTRACT_SHA,'profileSha256':C.RANGE_PROFILE_SHA}
try:C.bind_source(pending,PROFILE)
except C.AdmissionError as exc:check(str(exc)=='RANGE_RUNTIME_GATE_REQUIRED','FUTURE_RANGE_GATE_REQUIRED')
else:raise RuntimeError('UNAPPROVED_RANGE_ENTRY')
run_case(1,'positive206_untrusted_no_ifrange_and_future_gate_closed')
run_case(2,'200_rejected_zero_read',status=200,body=b'FULL_BODY_FORBIDDEN',expected_error='RANGE_STATUS_NOT_206',zero_read=True)
run_case(3,'416_rejected_zero_read',status=416,expected_error='RANGE_STATUS_NOT_206',zero_read=True)
run_case(4,'duplicate_content_range',headers={'Content-Range':['x','x']},expected_error='RANGE_CONTENT_RANGE',zero_read=True)
run_case(5,'mismatched_content_range',headers={'Content-Range':'bytes 0-0/1'},expected_error='RANGE_CONTENT_RANGE',zero_read=True)
run_case(6,'duplicate_content_length',headers={'Content-Length':['6','6']},expected_error='RANGE_CONTENT_LENGTH',zero_read=True)
run_case(7,'multipart_rejected',headers={'Content-Type':'multipart/byteranges; boundary=x'},expected_error='RANGE_MULTIPART_OR_TYPE',zero_read=True)
run_case(8,'transfer_encoding_rejected',headers={'Transfer-Encoding':'chunked'},expected_error='RANGE_TRANSFER_ENCODING',zero_read=True)
run_case(9,'nonidentity_rejected',headers={'Content-Encoding':'gzip'},expected_error='RANGE_ENCODING',zero_read=True)
run_case(10,'final_url_mismatch',url='https://invalid.example/forbidden',expected_error='RANGE_FINAL_URL',zero_read=True)
run_case(11,'prefix_size_guard',prefix=PREFIX+b'X',expected_error='RANGE_PREFIX_SIZE_IDENTITY',zero_get=True)
run_case(12,'prefix_hash_tamper_guard',prefix=b'X'+PREFIX[1:],expected_error='RANGE_PREFIX_HASH',zero_get=True)
run_case(13,'prefix_stat_identity_guard',stat_change=True,expected_error='RANGE_PREFIX_CHANGED',zero_get=True)
run_case(14,'short_suffix',body=SUFFIX[:-1],expected_error='RANGE_SUFFIX_SHORT')
run_case(15,'extra_suffix',body=SUFFIX+b'X',expected_error='RANGE_SUFFIX_EXTRA')
run_case(16,'wrong_full_hash_no_structural_inspection',body=b'X'+SUFFIX[1:],hash_false=True)
run_case(17,'fresh_excl_no_inplace_overwrite',existing_dest=True,expected_error='ANY',zero_get=True)
try:R.deadline(0)
except R.RangeError as exc:check(str(exc)=='RANGE_FILE_DEADLINE','ABSOLUTE_FILE_DEADLINE')
else:raise RuntimeError('DEADLINE_NOT_ENFORCED')
secret=RuntimeError('SYNTHETIC_PRIVATE_PATH_URL_ENV');run_case(18,'deadline_and_primary_cleanup_preservation',error=secret,close_error=True,expected_error='ANY')

elapsed=time.monotonic()-start;check(len(cases)==18 and elapsed<=30,'FIXTURE_COUNT_TIME');output={'schema':'producer04-range-new-offline-fixtures/v1','state':'EIGHTEEN_NEW_RANGE_FIXTURES_PASS','mode':MODE,'optimize':sys.flags.optimize,'fixtureCount':len(cases),'fixtures':cases,'inputBytes':input_bytes,'elapsedSeconds':elapsed,'rangeHelperSHA256':H(rraw),'controllerSHA256':H(craw),'rangeProfileSHA256':H(praw),'actualGET':0,'actualJob':0,'SDK':0,'old85Replay':0,'oldRawOrPrefixRead':0,'healthyFile01Reinspection':0};encoded=(json.dumps(output,indent=2)+'\n').encode();check(len(encoded)<=32768,'OUTPUT_BOUND');(OUT.parent/('RANGE-FIXTURE-'+MODE+'.json')).write_bytes(encoded)
print(json.dumps({k:v for k,v in output.items() if k!='fixtures'}))
