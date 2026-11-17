"""Adapted source DATA c49f: only seven inspected public10 patterns, own04 IO.
No import/execution of hosted_caps, borrowed contexts/caps, or implicit acquisition.
"""
from __future__ import annotations
import contextlib,datetime,email.utils,gzip,hashlib,ipaddress,json,re,time,urllib.request,zlib
import signal,threading,sys,os
from pathlib import Path
from urllib.parse import urlsplit
HANDOFF_SHA='c49f46dde2e3e0b36e0cf8c50c882f60a8434d9f6ed8a0cb378dd7c6df2701ca'
class Hold(RuntimeError):pass
def need(v,code,*redacted):
 if not v:raise Hold(code)
def sha(b):return hashlib.sha256(b).hexdigest()
NAMESPACE_AMENDMENT_SHA='c5bce32345d471e6f417a78fad5a89b2ec39eb70a2d2d2e4a3a79e56f4d61614'
ADVISORY_INDEX_URLS=('https://api.nuget.org/v3/vulnerabilities/index.json','https://api.nuget.org/v3-vulnerabilities/index.json')
ADVISORY_SUBTREES=('/v3/vulnerabilities/','/v3-vulnerabilities/')

def advisory_uri_shape(url,index=False):
 need(type(url) is str and 0<len(url)<=2048 and all(33<=ord(c)<127 for c in url),'METADATA_URL')
 u=urlsplit(url);need(url.startswith('https://api.nuget.org/') and u.scheme=='https' and u.netloc=='api.nuget.org' and not any(c in url for c in ('%','\\','?','#')),'METADATA_ORIGIN')
 prefix=next((p for p in ADVISORY_SUBTREES if u.path.startswith(p)),None);need(prefix is not None and '//' not in u.path and u.path.endswith('.json'),'METADATA_NAMESPACE');tail=u.path[len(prefix):];parts=tail.split('/');need(1<=len(parts)<=16 and all(1<=len(p)<=128 and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*',p) is not None and '..' not in p and not p.endswith('.') for p in parts),'METADATA_CANONICAL_SEGMENT')
 if index:need(url in ADVISORY_INDEX_URLS,'VULNERABILITY_INDEX_NOT_ALLOWLISTED')
 else:need(url not in ADVISORY_INDEX_URLS,'VULNERABILITY_PAGE_SELF_REFERENCE')
 return url

def advisory_index_url(url):return advisory_uri_shape(url,index=True)
def canonical_metadata_url(url):return advisory_uri_shape(url,index=False)

def select_advisory_index(resources):
 need(type(resources) is list,'VULNERABILITY_SERVICE_RESOURCES');eligible=[r for r in resources if type(r) is dict and r.get('@type')=='VulnerabilityInfo/6.7.0'];need(eligible,'VULNERABILITY_SUPPORTED_RESOURCE_MISSING');urls={advisory_index_url(r.get('@id')) for r in eligible};need(len(urls)==1,'VULNERABILITY_SERVICE_INDEX_AMBIGUOUS');return next(iter(urls))

def advisory_index_urls(pages,index_uri):
 advisory_index_url(index_uri);need(type(pages) is list and 1<=len(pages)<=8,'VULNERABILITY_PAGE_PARTITION')
 need(all(type(p) is dict and type(p.get('@id')) is str and type(p.get('@name')) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,64}',p['@name']) and type(p.get('@updated')) is str and 1<=len(p['@updated'])<=128 for p in pages),'VULNERABILITY_INDEX_SHAPE')
 urls=tuple(canonical_metadata_url(p['@id']) for p in pages)
 need(len(set(urls))==len(urls) and len({p['@name'] for p in pages})==len(pages),'VULNERABILITY_INDEX_AMBIGUOUS');return urls

def admit_metadata_url(url,allowed_urls):
 need(type(allowed_urls) is tuple and 1<=len(allowed_urls)<=8 and len(set(allowed_urls))==len(allowed_urls),'METADATA_URL_ALLOWLIST')
 for u in allowed_urls:canonical_metadata_url(u)
 canonical_metadata_url(url);need(url in allowed_urls,'METADATA_URL_NOT_IN_INDEX');return url


def stable_compare(version,bound):
 need(type(version) is str and re.fullmatch(r'\d+(?:\.\d+){0,3}',version) is not None,'SELECTED_VERSION_NOT_STABLE')
 m=re.fullmatch(r'(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?',bound);need(m is not None,'UNSUPPORTED_ADVISORY_VERSION')
 left=tuple(int(x) for x in version.split('.'));left+=(0,)*(4-len(left));right=tuple(int(x) for x in m[1].split('.'));right+=(0,)*(4-len(right))
 return (1 if left>right else -1) if left!=right else 1 if m[2] else 0
def in_range(version,text):
 need(type(text) is str and 0<len(text)<=512,'ADVISORY_RANGE')
 if text[0] not in '[(':return stable_compare(version,text)>=0
 need(text[-1] in ')]','ADVISORY_RANGE');inside=text[1:-1]
 if ',' not in inside:
  need(text[0]=='[' and text[-1]==']' and inside.strip(),'ADVISORY_EXACT_RANGE');return stable_compare(version,inside.strip())==0
 need(inside.count(',')==1,'ADVISORY_RANGE');low,high=[x.strip() for x in inside.split(',')]
 return (not low or stable_compare(version,low)>0 or (text[0]=='[' and stable_compare(version,low)==0)) and (not high or stable_compare(version,high)<0 or (text[-1]==']' and stable_compare(version,high)==0))
def vulnerability_page_entries(data):
 if type(data) is list:need(not data,'VULNERABILITY_PAGE_SHAPE');return {}
 need(type(data) is dict and all(type(k) is str and k==k.lower() and type(v) is list for k,v in data.items()),'VULNERABILITY_PAGE_SHAPE')
 need(all(type(i) is dict and type(i.get('versions')) is str and type(i.get('url','')) is str and type(i.get('severity')) is int and 0<=i['severity']<=3 for issues in data.values() for i in issues),'VULNERABILITY_PAGE_SHAPE');return data
def budget(ctx):need(time.monotonic_ns()<ctx['deadlineMonotonicNs'],ctx.get('deadlineCode','ORIGINAL_METADATA_DEADLINE'))
def strict_json(raw):
 def pairs(items):
  d={}
  for k,v in items:need(k not in d,'METADATA_DUPLICATE_KEY');d[k]=v
  return d
 try:return json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Hold('METADATA_NONFINITE')))
 except (UnicodeError,json.JSONDecodeError):raise Hold('METADATA_JSON_INVALID') from None
def decode_json(wire,encoding,limit):
 need(encoding in ('identity','gzip'),'METADATA_ENCODING')
 if encoding=='identity':need(len(wire)<=limit,'METADATA_COMBINED_BYTES_CAP');return wire
 d=zlib.decompressobj(31);parts=[];size=0;pending=wire
 while pending:
  part=d.decompress(pending,min(65536,limit-size+1));size+=len(part);need(size<=limit and not d.unused_data,'METADATA_GZIP_BOUND_OR_MEMBER');parts.append(part);nextdata=d.unconsumed_tail;need(part or len(nextdata)<len(pending),'METADATA_GZIP_PROGRESS');pending=nextdata
 need(d.eof and not d.unused_data and not d.unconsumed_tail,'METADATA_GZIP_EOF');return b''.join(parts)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):raise Hold('METADATA_REDIRECT')
def save(path,data):
 with Path(path).open('xb') as f:f.write(data)
METADATA_PRIMARY_CODES=('ABSENT', 'ADVISORY_COMPLETE_SNAPSHOT', 'ADVISORY_EXACT_RANGE', 'ADVISORY_RANGE', 'BODY_READ', 'BODY_SET_TIMEOUT', 'BODY_TERMINAL', 'CHUNKED', 'COMPLETE', 'CURRENT_ADVISORY_MATCH', 'DATE_GUARD', 'DECIMAL', 'DECODED_BEFORE_PARSE', 'DEFLATE', 'DIAGNOSTIC_ORIGINAL_DEADLINE', 'DUPLICATE', 'ENCODING_GUARD', 'FAILED_BEFORE_OPEN', 'FRAMING_GUARD', 'GZIP', 'HOLD', 'HTTP_ERROR', 'HTTP_PROTOCOL_ERROR', 'IDENTITY', 'INCOMPLETE_BODY', 'INVALID', 'JSON_PARSED_NOT_ADMITTED', 'LENGTH_GUARD', 'METADATA_BODY_BOUND', 'METADATA_CALLER_ORIGIN_BINDING', 'METADATA_CANONICAL_SEGMENT', 'METADATA_CHILD_HOLD', 'METADATA_CHILD_OUTPUT_UNEXPECTED', 'METADATA_CHILD_RECEIPT_IDENTITY', 'METADATA_CHILD_RESULT_BOUND', 'METADATA_CHILD_WIRE_BOUND', 'METADATA_CHILD_WIRE_HASH', 'METADATA_CHUNK_BODY_BOUND', 'METADATA_CHUNK_COUNT', 'METADATA_CHUNK_DELIMITER', 'METADATA_CHUNK_PARSER_IDENTITY', 'METADATA_CHUNK_SIZE_LINE', 'METADATA_CHUNK_TERMINAL', 'METADATA_CHUNK_TRAILER_OR_TERMINATOR', 'METADATA_CLOSED_ONCE', 'METADATA_COMBINED_BYTES_CAP', 'METADATA_DUPLICATE_KEY', 'METADATA_ENCODING', 'METADATA_FRAMING_MODE', 'METADATA_FRESHNESS', 'METADATA_GET', 'METADATA_GZIP_BOUND_OR_MEMBER', 'METADATA_GZIP_EOF', 'METADATA_GZIP_PROGRESS', 'METADATA_HTTP_DATE', 'METADATA_HTTP_ERROR', 'METADATA_HTTP_FRAMING', 'METADATA_HTTP_PROTOCOL', 'METADATA_HTTP_STATUS_OR_URL', 'METADATA_INCOMPLETE_BODY', 'METADATA_JSON_INVALID', 'METADATA_LENGTH', 'METADATA_LENGTH_MISMATCH', 'METADATA_NAMESPACE', 'METADATA_NONFINITE', 'METADATA_ORIGIN', 'METADATA_OWN_CHILD_CGROUP', 'METADATA_OWN_CHILD_FAILED', 'METADATA_OWN_CHILD_IDENTITY', 'METADATA_OWN_CHILD_TERMINAL', 'METADATA_OWN_MAIN_ALARM_REQUIRED', 'METADATA_PERIODIC_ALARM_UNSUPPORTED', 'METADATA_PHASE_IDENTITY', 'METADATA_REDIRECT', 'METADATA_REQUEST10_DEADLINE', 'METADATA_REQUEST_FILE', 'METADATA_REQUEST_FILE_HASH', 'METADATA_REQUEST_OUTPUT_SCOPE', 'METADATA_REQUEST_SOURCE', 'METADATA_REQUEST_SPEC_BOUND', 'METADATA_SOCKET_IO', 'METADATA_TLS_IO', 'METADATA_TRANSPORT_FAILURE', 'METADATA_TRANSPORT_TIMEOUT', 'METADATA_URL', 'METADATA_URL_ALLOWLIST', 'METADATA_URL_IO', 'METADATA_URL_NOT_IN_INDEX', 'MULTIPLE', 'NONE', 'NO_SELECTED_NUGET_ADVISORY_MATCH', 'NO_TRANSFER_ENCODING_V1', 'OBSERVED', 'OPEN', 'ORIGINAL_BODY_BUDGET', 'ORIGINAL_METADATA_DEADLINE', 'OS_ERROR', 'OTHER', 'OVER_LIMIT', 'PEER', 'RAW_COMPLETE', 'RAW_PARTIAL', 'RESPONSE', 'SAVE', 'SELECTED_VERSION_NOT_STABLE', 'SIGALRM', 'SOURCE_HOLD', 'STARTED', 'STATUS_GUARD', 'STRICT_SINGLE_CHUNKED_V1', 'TIMEOUT', 'TLS_ERROR', 'UNKNOWN', 'UNKNOWN_OR_REDACTED', 'UNSUPPORTED_ADVISORY_VERSION', 'URL_ERROR', 'VULNERABILITY_INDEX_AMBIGUOUS', 'VULNERABILITY_INDEX_NOT_ALLOWLISTED', 'VULNERABILITY_INDEX_NOT_DECLARED', 'VULNERABILITY_INDEX_SHAPE', 'VULNERABILITY_PAGE_PARTITION', 'VULNERABILITY_PAGE_SELF_REFERENCE', 'VULNERABILITY_PAGE_SHAPE', 'VULNERABILITY_PAGE_TUPLE_CHANGED', 'VULNERABILITY_SERVICE_INDEX_AMBIGUOUS', 'VULNERABILITY_SERVICE_RESOURCES', 'VULNERABILITY_SUPPORTED_RESOURCE_MISSING')

FRAMING_LIMIT=2097152
FRAMING_KEYS=('observationState','actualStatus','responseURLMatchesExpected','contentLengthHeaderCount','contentLengthShape','declaredContentLength','transferEncodingHeaderCount','transferEncodingCategory','contentEncodingHeaderCount','contentEncodingCategory','statusAllowed','urlAllowed','noTransferEncoding','headerCountsAllowed','applicationBodyBytesRead','primaryCode','sourceOperation','currentRequestIndex','elapsedNs')

def unknown_framing():
 return dict.fromkeys(FRAMING_KEYS,'UNKNOWN')

def framing_shape(value):
 if type(value) is not dict or set(value)!=set(FRAMING_KEYS):return False
 enums={'observationState':('OBSERVED','UNKNOWN'),'contentLengthShape':('ABSENT','DECIMAL','DUPLICATE','INVALID','OVER_LIMIT','UNKNOWN'),'transferEncodingCategory':('ABSENT','CHUNKED','IDENTITY','GZIP','DEFLATE','OTHER','MULTIPLE','UNKNOWN'),'contentEncodingCategory':('ABSENT','IDENTITY','GZIP','OTHER','MULTIPLE','UNKNOWN'),'sourceOperation':('METADATA_GET','UNKNOWN')}
 for key,allowed in enums.items():
  if type(value[key]) is not str or value[key] not in allowed:return False
 for key in ('responseURLMatchesExpected','statusAllowed','urlAllowed','noTransferEncoding','headerCountsAllowed'):
  if type(value[key]) is not bool and value[key]!='UNKNOWN':return False
 for key in ('contentLengthHeaderCount','transferEncodingHeaderCount','contentEncodingHeaderCount'):
  if not(type(value[key]) is int and 0<=value[key]<=100 or type(value[key]) is str and value[key] in ('OVER_LIMIT','UNKNOWN')):return False
 for key,bound in (('declaredContentLength',2097152),('applicationBodyBytesRead',536936448),('currentRequestIndex',22),('elapsedNs',10**15)):
  if not(type(value[key]) is int and 0<=value[key]<=bound or type(value[key]) is str and value[key] in (('OVER_LIMIT','UNKNOWN') if key=='declaredContentLength' else ('UNKNOWN',))):return False
 if not(type(value['actualStatus']) is int and 100<=value['actualStatus']<=599 or value['actualStatus']=='UNKNOWN'):return False
 if type(value['primaryCode']) is not str or value['primaryCode'] not in METADATA_PRIMARY_CODES:return False
 return len(json.dumps(value,separators=(',',':')).encode())<=16384

def framing_observation(response,url,index):
 """Only finite categories; raw header values are never returned or formatted."""
 out=unknown_framing()
 try:
  out.update(sourceOperation='METADATA_GET',currentRequestIndex=index,primaryCode='UNKNOWN',applicationBodyBytesRead=0)
  status=response.status;out['actualStatus']=status if type(status) is int and 100<=status<=599 else 'UNKNOWN';out['statusAllowed']=status==200 if type(status) is int else 'UNKNOWN'
  actual=response.geturl();match=actual==url if type(actual) is str and len(actual)<=256 else 'UNKNOWN';out.update(responseURLMatchesExpected=match,urlAllowed=match)
  def values(name):
   rows=response.headers.get_all(name,[])
   if type(rows) not in (list,tuple):raise ValueError
   return rows,len(rows) if len(rows)<=100 else 'OVER_LIMIT'
  lengths,n=values('Content-Length');transfer,t=values('Transfer-Encoding');encoding,e=values('Content-Encoding')
  out.update(contentLengthHeaderCount=n,transferEncodingHeaderCount=t,contentEncodingHeaderCount=e,noTransferEncoding=(t==0),headerCountsAllowed=(type(n) is int and n<=1 and type(e) is int and e<=1))
  if n=='OVER_LIMIT':out['contentLengthShape']='OVER_LIMIT';out['declaredContentLength']='OVER_LIMIT'
  elif n==0:out['contentLengthShape']='ABSENT'
  elif n>1:out['contentLengthShape']='DUPLICATE'
  else:
   v=lengths[0]
   if type(v) is not str or len(v)>256:out['contentLengthShape']='OVER_LIMIT' if type(v) is str else 'INVALID'
   elif re.fullmatch(r'0|[1-9][0-9]*',v) is None:out['contentLengthShape']='INVALID'
   else:
    over=len(v)>7 or len(v)==7 and v>'2097152';out['contentLengthShape']='OVER_LIMIT' if over else 'DECIMAL';out['declaredContentLength']='OVER_LIMIT' if over else int(v)
  def category(rows,count,tokens):
   if count==0:return 'ABSENT'
   if count=='OVER_LIMIT' or count>1:return 'MULTIPLE'
   v=rows[0]
   if type(v) is not str:return 'UNKNOWN'
   if len(v)>256:return 'OTHER'
   return tokens.get(v.lower(),'OTHER')
  out['transferEncodingCategory']=category(transfer,t,{'chunked':'CHUNKED','identity':'IDENTITY','gzip':'GZIP','deflate':'DEFLATE'})
  out['contentEncodingCategory']=category(encoding,e,{'identity':'IDENTITY','gzip':'GZIP'})
  out['observationState']='OBSERVED'
  return out if framing_shape(out) else unknown_framing()
 except BaseException:return unknown_framing()

def retain_framing(entry,code='UNKNOWN',started=None):
 """Observation failure cannot replace the original transport/guard exception."""
 try:
  value=entry.get('framing',unknown_framing());value['primaryCode']=code if code in METADATA_PRIMARY_CODES else 'UNKNOWN_OR_REDACTED'
  if type(started) is int:value['elapsedNs']=min(10**15,max(0,time.monotonic_ns()-started))
  entry['framing']=value if framing_shape(value) else unknown_framing()
 except BaseException:entry['framing']=unknown_framing()

def safe_metadata_code(exc):
 args=BaseException.args.__get__(exc)
 return args[0] if type(exc) is Hold and len(args)==1 and type(args[0]) is str and args[0] in METADATA_PRIMARY_CODES else 'UNKNOWN_OR_REDACTED'


FULL_METADATA_FRAMING_MODE='STRICT_SINGLE_CHUNKED_V1'
LEGACY_METADATA_FRAMING_MODE='NO_TRANSFER_ENCODING_V1'

def strict_chunk_left(response):
 """Strict bounded HTTP/1.1 chunk framing; no extensions, trailers or ambiguity."""
 need(time.monotonic_ns()<response.own04ChunkDeadline,'METADATA_REQUEST10_DEADLINE');current=response.chunk_left;proof=response.own04ChunkFraming
 if current:return current
 if current is not None:need(response._safe_read(2)==b'\r\n','METADATA_CHUNK_DELIMITER');proof['framingBytesRead']+=2
 line=response.fp.readline(19);proof['framingBytesRead']+=len(line);need(3<=len(line)<=18 and line.endswith(b'\r\n') and re.fullmatch(rb'[0-9a-fA-F]{1,16}\r\n',line) is not None,'METADATA_CHUNK_SIZE_LINE');size=int(line[:-2],16);proof['chunkCount']+=1;need(proof['chunkCount']<=65536,'METADATA_CHUNK_COUNT');need(size<=response.own04ChunkLimit-proof['declaredDataBytes'],'METADATA_CHUNK_BODY_BOUND')
 if size==0:
  ending=response.fp.readline(3);proof['framingBytesRead']+=len(ending);need(ending==b'\r\n','METADATA_CHUNK_TRAILER_OR_TERMINATOR');proof['terminated']=True;response._close_conn();response.chunk_left=None;return None
 proof['declaredDataBytes']+=size;response.chunk_left=size;return size

def admit_metadata_framing(response,mode,limit,deadline):
 import http.client,types
 need(mode in (LEGACY_METADATA_FRAMING_MODE,FULL_METADATA_FRAMING_MODE),'METADATA_FRAMING_MODE')
 transfer=response.headers.get_all('Transfer-Encoding',[]);lengths=response.headers.get_all('Content-Length',[])
 need(len(response.headers.get_all('Content-Encoding',[]))<=1 and len(lengths)<=1,'METADATA_HTTP_FRAMING')
 if not transfer:return False
 need(mode==FULL_METADATA_FRAMING_MODE and len(transfer)==1 and type(transfer[0]) is str and transfer[0].lower()=='chunked' and not lengths and not response.headers.get_all('Trailer',[]),'METADATA_HTTP_FRAMING')
 need(type(response) is http.client.HTTPResponse and response.chunked is True and response.length is None and response.chunk_left is None,'METADATA_CHUNK_PARSER_IDENTITY')
 response.own04ChunkFraming={'chunkCount':0,'framingBytesRead':0,'declaredDataBytes':0,'terminated':False};response.own04ChunkLimit=limit;response.own04ChunkDeadline=deadline;response._get_chunk_left=types.MethodType(strict_chunk_left,response);return True


def _wire_request(ctx,url,destination,limit,total,allowed_urls,json_data=False):
 """Own04 finite one-shot transport. Invoked only after exact runtime activation."""
 budget(ctx);need(url in allowed_urls and url not in ctx['requested'] and len(ctx['requested'])<23,'METADATA_CLOSED_ONCE')
 ctx['requested'].add(url);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());headers={'Accept-Encoding':'gzip' if json_data else 'identity','User-Agent':'producer04-input-curation/1'}
 entry={'url':url,'rawBytes':0,'state':'STARTED','framing':unknown_framing()};ctx['records'].append(entry)
 request_end=ctx['deadlineMonotonicNs'];entry['operation']='OPEN'
 with opener.open(urllib.request.Request(url,headers=headers),timeout=min(10,(request_end-time.monotonic_ns())/1e9)) as response:
  entry['operation']='RESPONSE';entry['framing']=framing_observation(response,url,ctx.get('currentRequestIndex',len(ctx['records'])-1))
  budget(ctx)
  entry['operation']='STATUS_GUARD';need(response.status==200 and response.geturl()==url,'METADATA_HTTP_STATUS_OR_URL')
  entry['operation']='FRAMING_GUARD';chunked=admit_metadata_framing(response,ctx.get('metadataFramingMode',LEGACY_METADATA_FRAMING_MODE),limit,ctx['deadlineMonotonicNs'])
  entry['operation']='ENCODING_GUARD';encoding=response.headers.get('Content-Encoding','identity').lower();need(encoding in (('identity','gzip') if json_data else ('identity',)),'METADATA_ENCODING')
  entry['operation']='DATE_GUARD';date=response.headers.get('Date');need(date is not None and len(response.headers.get_all('Date',[]))==1,'METADATA_HTTP_DATE')
  try:
   parsed=email.utils.parsedate_to_datetime(date);need(parsed.tzinfo is not None,'METADATA_HTTP_DATE');dt=parsed.timestamp()
  except (TypeError,ValueError):raise Hold('METADATA_HTTP_DATE') from None
  need(-300<=ctx['utcNow']-dt<=86400,'METADATA_FRESHNESS')
  entry['operation']='LENGTH_GUARD';length=response.headers.get('Content-Length');need(length is None or (re.fullmatch(r'0|[1-9][0-9]*',length) and int(length)<=limit),'METADATA_LENGTH')
  entry['operation']='PEER';sock=response.fp.raw._sock;peer=sock.getpeername();ip=ipaddress.ip_address(peer[0]);entry['peerIP']=str(ip);entry['peerPort']=peer[1]
  if url.startswith('https://api.nuget.org/') and peer[1]==443:ctx['boundOfficialPeer']=(str(ip),443)
  chunks=[];size=0
  while length is None or size<int(length):
   budget(ctx);remaining=(request_end-time.monotonic_ns())/1e9;need(remaining>0,'METADATA_REQUEST10_DEADLINE');entry['operation']='BODY_SET_TIMEOUT';sock.settimeout(remaining);entry['operation']='BODY_READ';piece=response.read(min(65536,limit-size+1));need(time.monotonic_ns()<request_end,'METADATA_REQUEST10_DEADLINE')
   if not piece:break
   size+=len(piece);entry['rawBytes']=size;entry['framing']['applicationBodyBytesRead']=size;entry['state']='RAW_PARTIAL';need(size<=limit,'METADATA_BODY_BOUND');total['bodyBytes']+=len(piece);need(total['bodyBytes']<=536870912,'ORIGINAL_BODY_BUDGET');chunks.append(piece)
   if chunked and response.own04ChunkFraming['terminated'] is True:
    need(response.isclosed() and response.own04ChunkFraming['declaredDataBytes']==size,'METADATA_CHUNK_TERMINAL');break
  entry['operation']='BODY_TERMINAL'
  if chunked:
   need(response.own04ChunkFraming['terminated'] is True and response.isclosed() and response.own04ChunkFraming['declaredDataBytes']==size,'METADATA_CHUNK_TERMINAL');entry['chunkFraming']=dict(response.own04ChunkFraming)
  need(length is None or size==int(length),'METADATA_LENGTH_MISMATCH');wire=b''.join(chunks)
  # Peer is recorded only when the underlying transport exposes it; never DNS re-resolve.
  entry.update(rawBytes=size,rawSHA256=sha(wire),encoding=encoding,date=date,lastModified=response.headers.get('Last-Modified'),cacheControl=response.headers.get('Cache-Control'),state='RAW_COMPLETE')
 entry['operation']='SAVE';budget(ctx);save(destination,wire);budget(ctx);return entry,wire
@contextlib.contextmanager
def absolute_request(ctx):
 """Parent alarm covers startup and terminal handling; HTTP runs in owned child."""
 need(hasattr(signal,'SIGALRM') and threading.current_thread() is threading.main_thread(),'METADATA_OWN_MAIN_ALARM_REQUIRED')
 started=time.monotonic_ns();previous_handler=signal.getsignal(signal.SIGALRM);previous=signal.getitimer(signal.ITIMER_REAL);need(previous[1]==0,'METADATA_PERIODIC_ALARM_UNSUPPORTED');old_end=started+int(previous[0]*1000000000) if previous[0]>0 else None;request_end=started+10000000000;end=min(request_end,ctx['deadlineMonotonicNs'],old_end if old_end is not None else request_end);code='ORIGINAL_METADATA_DEADLINE' if end<request_end else 'METADATA_REQUEST10_DEADLINE';need(time.monotonic_ns()<end,code)
 def expired(*unused):raise Hold(code)
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,max(0,(end-time.monotonic_ns())/1000000000));primary=None
 try:
  yield end,code
 except BaseException as exc:primary=exc;raise
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);now=time.monotonic_ns();signal.signal(signal.SIGALRM,previous_handler);signal.setitimer(signal.ITIMER_REAL,max(0,(old_end-time.monotonic_ns())/1000000000) if old_end is not None else 0)
  # Expiry wins even on open/header errors, zero-length bodies and return cleanup.
  if now>=end:raise Hold(code) from None

METADATA_FAILURE_OPERATIONS=('UNKNOWN','OPEN','RESPONSE','STATUS_GUARD','FRAMING_GUARD','ENCODING_GUARD','DATE_GUARD','LENGTH_GUARD','PEER','BODY_SET_TIMEOUT','BODY_READ','BODY_TERMINAL','SAVE')

def safe_metadata_failure(exc,operation):
 import http.client,urllib.error,ssl
 code=safe_metadata_code(exc);category='SOURCE_HOLD' if type(exc) is Hold else 'UNKNOWN';number='UNKNOWN';status='UNKNOWN';verify='UNKNOWN'
 if type(exc) is urllib.error.HTTPError:
  category='HTTP_ERROR';code='METADATA_HTTP_ERROR';value=exc.code
  if type(value) is int and 100<=value<=599:status=value
 elif type(exc) is urllib.error.URLError:
  category='URL_ERROR';code='METADATA_URL_IO';reason=exc.reason
  if type(reason) in (OSError,TimeoutError,ConnectionResetError,ConnectionAbortedError,BrokenPipeError):
   value=OSError.errno.__get__(reason)
   if type(value) is int and value in (1,2,5,9,12,13,22,24,28,32,60,104,110,111):number=value
 elif type(exc) in (ssl.SSLError,ssl.SSLEOFError,ssl.SSLZeroReturnError,ssl.SSLCertVerificationError):
  category='TLS_ERROR';code='METADATA_TLS_IO'
  if type(exc) is ssl.SSLCertVerificationError:
   value=getattr(exc,'verify_code',None)
   if type(value) is int and 0<=value<=1000:verify=value
 elif type(exc) in (OSError,TimeoutError,ConnectionResetError,ConnectionAbortedError,BrokenPipeError):
  category='TIMEOUT' if type(exc) is TimeoutError else 'OS_ERROR';code='METADATA_TRANSPORT_TIMEOUT' if category=='TIMEOUT' else 'METADATA_SOCKET_IO';value=OSError.errno.__get__(exc)
  if type(value) is int and value in (1,2,5,9,12,13,22,24,28,32,60,104,110,111):number=value
 elif type(exc) is http.client.IncompleteRead:category='INCOMPLETE_BODY';code='METADATA_INCOMPLETE_BODY'
 elif type(exc) in (http.client.BadStatusLine,http.client.LineTooLong,http.client.RemoteDisconnected):category='HTTP_PROTOCOL_ERROR';code='METADATA_HTTP_PROTOCOL'
 return {'code':code,'category':category,'errno':number,'httpStatus':status,'tlsVerifyCode':verify,'operation':operation if type(operation) is str and operation in METADATA_FAILURE_OPERATIONS else 'UNKNOWN'}



def _owned_request_child(spec):
 """Only the fixed one-shot public metadata operation; no stdout or SDK action."""
 ctx={'deadlineMonotonicNs':spec['deadlineMonotonicNs'],'deadlineCode':spec['deadlineCode'],'utcNow':spec['utcNow'],'currentRequestIndex':spec.get('currentRequestIndex',0),'metadataFramingMode':spec.get('metadataFramingMode',LEGACY_METADATA_FRAMING_MODE),'requested':set(),'records':[]};total={'bodyBytes':spec['bodyBytesBefore']};result=None;started=time.monotonic_ns()
 try:
  entry,wire=_wire_request(ctx,spec['url'],spec['wirePath'],spec['limit'],total,tuple(spec['allowedURLs']),spec['jsonData']);retain_framing(entry,'NONE',started);result={'state':'COMPLETE','entry':entry,'bodyBytesAfter':total['bodyBytes']}
 except BaseException as exc:
  entry=ctx['records'][-1] if ctx['records'] else {'operation':'OPEN'};failure=safe_metadata_failure(exc,entry.get('operation','UNKNOWN'));code=failure['code']
  if ctx['records']:ctx['records'][-1]['failure']=failure;retain_framing(ctx['records'][-1],code,started)
  result={'state':'HOLD','code':code,'entry':ctx['records'][-1] if ctx['records'] else {'url':spec['url'],'state':'FAILED_BEFORE_OPEN'}}
 save(spec['resultPath'],(json.dumps(result,separators=(',',':'))+'\n').encode())

def bounded_get(ctx,url,destination,limit,total,allowed_urls,json_data=False):
 """One held same-cgroup HTTP child, with a single absolute parent10s budget."""
 with absolute_request(ctx) as (end,deadline_code):
  budget(ctx);need(url in allowed_urls and url not in ctx['requested'] and len(ctx['requested'])<23,'METADATA_CLOSED_ONCE');ctx['requested'].add(url);job=ctx['ownedJob'];cap=job.linux_caps();work=Path(ctx['requestWorkRoot'])/('request-'+str(len(ctx['requested'])-1));work.mkdir(mode=0o700);wirepath=work/'wire.data';resultpath=work/'result.json';specpath=work/'request.json';work_end=end-200000000;need(time.monotonic_ns()<work_end,deadline_code)
  spec={'schema':'producer04-owned-http-request/v1','sourceSHA256':sha(Path(__file__).read_bytes()),'url':url,'allowedURLs':list(allowed_urls),'limit':limit,'jsonData':json_data,'utcNow':ctx['utcNow'],'deadlineMonotonicNs':end,'deadlineCode':deadline_code,'bodyBytesBefore':total['bodyBytes'],'currentRequestIndex':len(ctx['requested'])-1,'metadataFramingMode':ctx.get('metadataFramingMode',LEGACY_METADATA_FRAMING_MODE),'wirePath':str(wirepath),'resultPath':str(resultpath),'uid':cap['uid'],'gid':cap['gid'],'cgroup':cap['cgroup']};body=(json.dumps(spec,separators=(',',':'))+'\n').encode();need(len(body)<=65536,'METADATA_REQUEST_SPEC_BOUND');save(specpath,body)
  argv=[sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--owned-metadata-request',str(specpath),'--sha256',sha(body)]
  try:process=job.run(argv,ctx['requestCwd'],ctx['requestEnvironment'],work_end//1000000,work/'process')
  except BaseException:
   if time.monotonic_ns()>=work_end:raise Hold(deadline_code) from None
   raise Hold('METADATA_OWN_CHILD_FAILED') from None
  need(time.monotonic_ns()<end,deadline_code);need(process.get('exitCode')==0 and process.get('ownedChildGroupTerminal') is True,'METADATA_OWN_CHILD_TERMINAL');need((work/'process/stdout.log').stat().st_size==(work/'process/stderr.log').stat().st_size==0,'METADATA_CHILD_OUTPUT_UNEXPECTED');need(resultpath.stat().st_size<=32768,'METADATA_CHILD_RESULT_BOUND');result=strict_json(resultpath.read_bytes());entry=result.get('entry',{});entry['framing']=entry.get('framing') if framing_shape(entry.get('framing')) else unknown_framing();ctx['records'].append(entry)
  entry['ownedHTTP']={'deadlineMonotonicNs':end,'workDeadlineMonotonicNs':work_end,'terminalReserveWithin10Ns':200000000,'originalStageDeadlineMonotonicNs':ctx['deadlineMonotonicNs'],'processReceiptSHA256':sha((work/'process/process.json').read_bytes()),'resultSHA256':sha(resultpath.read_bytes()),'sourceSHA256':spec['sourceSHA256'],'sameCgroup':cap['cgroup']}
  if result.get('state')!='COMPLETE':
   code=result.get('code','METADATA_CHILD_HOLD');raise Hold(code if type(code) is str and code in METADATA_PRIMARY_CODES else 'UNKNOWN_OR_REDACTED')
  need(entry.get('url')==url and type(entry.get('rawBytes')) is int and 0<=entry['rawBytes']<=limit,'METADATA_CHILD_RECEIPT_IDENTITY');need(not wirepath.is_symlink() and wirepath.stat().st_size==entry['rawBytes'],'METADATA_CHILD_WIRE_BOUND');wire=wirepath.read_bytes();need(sha(wire)==entry['rawSHA256'] and result['bodyBytesAfter']==total['bodyBytes']+len(wire),'METADATA_CHILD_WIRE_HASH');total['bodyBytes']=result['bodyBytesAfter'];need(total['bodyBytes']<=536870912,'ORIGINAL_BODY_BUDGET')
  if url.startswith('https://api.nuget.org/') and entry.get('peerPort')==443:ctx['boundOfficialPeer']=(entry['peerIP'],443)
  need(time.monotonic_ns()<end,deadline_code);save(destination,wire);wirepath.unlink();need(time.monotonic_ns()<end,deadline_code);return entry,wire

def bounded_json_get(ctx,url,destination,limit,total,phase,allowed_urls=None):
 need(phase in ('service-index','repository-index','vulnerability-index','servicing') or re.fullmatch(r'vulnerability-page-[0-7]',phase),'METADATA_PHASE_IDENTITY')
 if phase=='vulnerability-index':
  declared=select_advisory_index(ctx.get('advisoryServiceResources'));need(url==ctx.get('advisoryIndexURI')==declared and (allowed_urls is None or allowed_urls==(declared,)),'VULNERABILITY_INDEX_NOT_DECLARED')
 elif phase.startswith('vulnerability-page-'):
  declared=select_advisory_index(ctx.get('advisoryServiceResources'));need(ctx.get('advisoryIndexURI')==declared,'VULNERABILITY_INDEX_NOT_DECLARED');closed=advisory_index_urls(ctx.get('advisoryIndex'),declared);need(type(ctx.get('advisoryPageURLs')) is tuple and ctx['advisoryPageURLs']==closed and allowed_urls==closed,'VULNERABILITY_PAGE_TUPLE_CHANGED');admit_metadata_url(url,closed)
 allowed=allowed_urls or (url,);need(url in ctx['allowedURLs'] and url in allowed,'METADATA_CALLER_ORIGIN_BINDING')
 entry,wire=bounded_get(ctx,url,Path(str(destination)+'.wire'),limit,total,allowed,json_data=True)
 decoded=decode_json(wire,entry['encoding'],limit-len(wire));total['bodyBytes']+=len(decoded);need(total['bodyBytes']<=536870912,'ORIGINAL_BODY_BUDGET');entry.update(decodedBytes=len(decoded),decodedSHA256=sha(decoded),phase=phase,state='DECODED_BEFORE_PARSE');save(destination,decoded)
 data=strict_json(decoded);budget(ctx);entry['state']='JSON_PARSED_NOT_ADMITTED';return dict(entry),data
def advisory_guard(ctx,specs,total):
 """Use already retained complete service/index/pages; no duplicate source10 GET."""
 declared=select_advisory_index(ctx.get('advisoryServiceResources'));need(ctx.get('advisoryIndexURI')==declared,'VULNERABILITY_INDEX_NOT_DECLARED');selected={x['id'].lower():x['version'] for x in specs};pages=ctx['advisoryPages'];urls=advisory_index_urls(ctx['advisoryIndex'],declared);need(type(ctx.get('advisoryPageURLs')) is tuple and ctx['advisoryPageURLs']==urls,'VULNERABILITY_PAGE_TUPLE_CHANGED')
 need(set(pages)==set(urls),'ADVISORY_COMPLETE_SNAPSHOT')
 for url in urls:
  admit_metadata_url(url,urls);data=vulnerability_page_entries(pages[url])
  for identity,version in selected.items():
   for issue in data.get(identity,[]):need(not in_range(version,issue['versions']),'CURRENT_ADVISORY_MATCH')
 return {'state':'NO_SELECTED_NUGET_ADVISORY_MATCH','selected':selected,'pageURLs':list(urls),'completePageHashes':{u:sha(json.dumps(pages[u],sort_keys=True,separators=(',',':')).encode()) for u in urls},'scope':'All matching low+ native/actual graph dependencies; not OS/general security certification','sourceHandoffSHA256':HANDOFF_SHA}

def _request_cli():
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('--owned-metadata-request',type=Path,required=True);parser.add_argument('--sha256',required=True);args=parser.parse_args();need(args.owned_metadata_request.is_absolute() and not args.owned_metadata_request.is_symlink() and args.owned_metadata_request.stat().st_size<=65536,'METADATA_REQUEST_FILE');body=args.owned_metadata_request.read_bytes();need(sha(body)==args.sha256,'METADATA_REQUEST_FILE_HASH');spec=strict_json(body);need(spec['schema']=='producer04-owned-http-request/v1' and spec['sourceSHA256']==sha(Path(__file__).read_bytes()),'METADATA_REQUEST_SOURCE');need(os.getuid()==spec['uid']>0 and os.getgid()==spec['gid'] and re.fullmatch('/system.slice/admission04-sdk11-ci-[0-9a-f]{32}\\.service',spec['cgroup']) is not None,'METADATA_OWN_CHILD_IDENTITY');need('0::'+spec['cgroup'] in Path('/proc/self/cgroup').read_text().splitlines(),'METADATA_OWN_CHILD_CGROUP');need(Path(spec['wirePath']).parent==Path(spec['resultPath']).parent==args.owned_metadata_request.parent,'METADATA_REQUEST_OUTPUT_SCOPE');_owned_request_child(spec)
if __name__=='__main__':_request_cli()
