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
def canonical_metadata_url(url):
 need(type(url) is str and len(url)<=2048 and not any(ord(c)<33 for c in url),'METADATA_URL')
 u=urlsplit(url);need(u.scheme=='https' and u.netloc=='api.nuget.org' and not u.query and not u.fragment and '%' not in url and '\\' not in url and '..' not in u.path.split('/') and '//' not in u.path,'METADATA_ORIGIN')
 need(u.path.startswith('/v3-vulnerabilities/') and u.path.endswith('.json'),'METADATA_NAMESPACE');return url
def advisory_index_urls(pages):
 need(type(pages) is list and 1<=len(pages)<=8,'VULNERABILITY_PAGE_PARTITION')
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
def _wire_request(ctx,url,destination,limit,total,allowed_urls,json_data=False):
 """Own04 finite one-shot transport. Invoked only after exact runtime activation."""
 budget(ctx);need(url in allowed_urls and url not in ctx['requested'] and len(ctx['requested'])<23,'METADATA_CLOSED_ONCE')
 ctx['requested'].add(url);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());headers={'Accept-Encoding':'gzip' if json_data else 'identity','User-Agent':'producer04-input-curation/1'}
 entry={'url':url,'rawBytes':0,'state':'STARTED'};ctx['records'].append(entry)
 request_end=ctx['deadlineMonotonicNs']
 with opener.open(urllib.request.Request(url,headers=headers),timeout=min(10,(request_end-time.monotonic_ns())/1e9)) as response:
  budget(ctx)
  need(response.status==200 and response.geturl()==url,'METADATA_HTTP_STATUS_OR_URL')
  need(not response.headers.get_all('Transfer-Encoding',[]) and len(response.headers.get_all('Content-Encoding',[]))<=1 and len(response.headers.get_all('Content-Length',[]))<=1,'METADATA_HTTP_FRAMING')
  encoding=response.headers.get('Content-Encoding','identity').lower();need(encoding in (('identity','gzip') if json_data else ('identity',)),'METADATA_ENCODING')
  date=response.headers.get('Date');need(date is not None and len(response.headers.get_all('Date',[]))==1,'METADATA_HTTP_DATE')
  try:
   parsed=email.utils.parsedate_to_datetime(date);need(parsed.tzinfo is not None,'METADATA_HTTP_DATE');dt=parsed.timestamp()
  except (TypeError,ValueError):raise Hold('METADATA_HTTP_DATE') from None
  need(-300<=ctx['utcNow']-dt<=86400,'METADATA_FRESHNESS')
  length=response.headers.get('Content-Length');need(length is None or (re.fullmatch(r'0|[1-9][0-9]*',length) and int(length)<=limit),'METADATA_LENGTH')
  sock=response.fp.raw._sock;peer=sock.getpeername();ip=ipaddress.ip_address(peer[0]);entry['peerIP']=str(ip);entry['peerPort']=peer[1]
  if url.startswith('https://api.nuget.org/') and peer[1]==443:ctx['boundOfficialPeer']=(str(ip),443)
  chunks=[];size=0
  while length is None or size<int(length):
   budget(ctx);remaining=(request_end-time.monotonic_ns())/1e9;need(remaining>0,'METADATA_REQUEST10_DEADLINE');sock.settimeout(remaining);piece=response.read(min(65536,limit-size+1));need(time.monotonic_ns()<request_end,'METADATA_REQUEST10_DEADLINE')
   if not piece:break
   size+=len(piece);entry['rawBytes']=size;entry['state']='RAW_PARTIAL';need(size<=limit,'METADATA_BODY_BOUND');total['bodyBytes']+=len(piece);need(total['bodyBytes']<=536870912,'ORIGINAL_BODY_BUDGET');chunks.append(piece)
  need(length is None or size==int(length),'METADATA_LENGTH_MISMATCH');wire=b''.join(chunks)
  # Peer is recorded only when the underlying transport exposes it; never DNS re-resolve.
  entry.update(rawBytes=size,rawSHA256=sha(wire),encoding=encoding,date=date,lastModified=response.headers.get('Last-Modified'),cacheControl=response.headers.get('Cache-Control'),state='RAW_COMPLETE')
 budget(ctx);save(destination,wire);budget(ctx);return entry,wire
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

def _owned_request_child(spec):
 """Only the fixed one-shot public metadata operation; no stdout or SDK action."""
 ctx={'deadlineMonotonicNs':spec['deadlineMonotonicNs'],'deadlineCode':spec['deadlineCode'],'utcNow':spec['utcNow'],'requested':set(),'records':[]};total={'bodyBytes':spec['bodyBytesBefore']};result=None
 try:
  entry,wire=_wire_request(ctx,spec['url'],spec['wirePath'],spec['limit'],total,tuple(spec['allowedURLs']),spec['jsonData']);result={'state':'COMPLETE','entry':entry,'bodyBytesAfter':total['bodyBytes']}
 except BaseException as exc:
  code=str(exc) if isinstance(exc,Hold) and re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(exc)) else 'METADATA_TRANSPORT_FAILURE';result={'state':'HOLD','code':code,'entry':ctx['records'][-1] if ctx['records'] else {'url':spec['url'],'state':'FAILED_BEFORE_OPEN'}}
 save(spec['resultPath'],(json.dumps(result,separators=(',',':'))+'\n').encode())

def bounded_get(ctx,url,destination,limit,total,allowed_urls,json_data=False):
 """One held same-cgroup HTTP child, with a single absolute parent10s budget."""
 with absolute_request(ctx) as (end,deadline_code):
  budget(ctx);need(url in allowed_urls and url not in ctx['requested'] and len(ctx['requested'])<23,'METADATA_CLOSED_ONCE');ctx['requested'].add(url);job=ctx['ownedJob'];cap=job.linux_caps();work=Path(ctx['requestWorkRoot'])/('request-'+str(len(ctx['requested'])-1));work.mkdir(mode=0o700);wirepath=work/'wire.data';resultpath=work/'result.json';specpath=work/'request.json';work_end=end-200000000;need(time.monotonic_ns()<work_end,deadline_code)
  spec={'schema':'producer04-owned-http-request/v1','sourceSHA256':sha(Path(__file__).read_bytes()),'url':url,'allowedURLs':list(allowed_urls),'limit':limit,'jsonData':json_data,'utcNow':ctx['utcNow'],'deadlineMonotonicNs':end,'deadlineCode':deadline_code,'bodyBytesBefore':total['bodyBytes'],'wirePath':str(wirepath),'resultPath':str(resultpath),'uid':cap['uid'],'gid':cap['gid'],'cgroup':cap['cgroup']};body=(json.dumps(spec,separators=(',',':'))+'\n').encode();need(len(body)<=65536,'METADATA_REQUEST_SPEC_BOUND');save(specpath,body)
  argv=[sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--owned-metadata-request',str(specpath),'--sha256',sha(body)]
  try:process=job.run(argv,ctx['requestCwd'],ctx['requestEnvironment'],work_end//1000000,work/'process')
  except BaseException:
   if time.monotonic_ns()>=work_end:raise Hold(deadline_code) from None
   raise Hold('METADATA_OWN_CHILD_FAILED') from None
  need(time.monotonic_ns()<end,deadline_code);need(process.get('exitCode')==0 and process.get('ownedChildGroupTerminal') is True,'METADATA_OWN_CHILD_TERMINAL');need((work/'process/stdout.log').stat().st_size==(work/'process/stderr.log').stat().st_size==0,'METADATA_CHILD_OUTPUT_UNEXPECTED');need(resultpath.stat().st_size<=32768,'METADATA_CHILD_RESULT_BOUND');result=strict_json(resultpath.read_bytes());entry=result.get('entry',{});ctx['records'].append(entry)
  entry['ownedHTTP']={'deadlineMonotonicNs':end,'workDeadlineMonotonicNs':work_end,'terminalReserveWithin10Ns':200000000,'originalStageDeadlineMonotonicNs':ctx['deadlineMonotonicNs'],'processReceiptSHA256':sha((work/'process/process.json').read_bytes()),'resultSHA256':sha(resultpath.read_bytes()),'sourceSHA256':spec['sourceSHA256'],'sameCgroup':cap['cgroup']}
  if result.get('state')!='COMPLETE':raise Hold(result.get('code','METADATA_CHILD_HOLD'))
  need(entry.get('url')==url and type(entry.get('rawBytes')) is int and 0<=entry['rawBytes']<=limit,'METADATA_CHILD_RECEIPT_IDENTITY');need(not wirepath.is_symlink() and wirepath.stat().st_size==entry['rawBytes'],'METADATA_CHILD_WIRE_BOUND');wire=wirepath.read_bytes();need(sha(wire)==entry['rawSHA256'] and result['bodyBytesAfter']==total['bodyBytes']+len(wire),'METADATA_CHILD_WIRE_HASH');total['bodyBytes']=result['bodyBytesAfter'];need(total['bodyBytes']<=536870912,'ORIGINAL_BODY_BUDGET')
  if url.startswith('https://api.nuget.org/') and entry.get('peerPort')==443:ctx['boundOfficialPeer']=(entry['peerIP'],443)
  need(time.monotonic_ns()<end,deadline_code);save(destination,wire);wirepath.unlink();need(time.monotonic_ns()<end,deadline_code);return entry,wire

def bounded_json_get(ctx,url,destination,limit,total,phase,allowed_urls=None):
 need(phase in ('service-index','repository-index','vulnerability-index','servicing') or re.fullmatch(r'vulnerability-page-[0-7]',phase),'METADATA_PHASE_IDENTITY')
 allowed=allowed_urls or (url,);need(url in ctx['allowedURLs'] and url in allowed,'METADATA_CALLER_ORIGIN_BINDING')
 entry,wire=bounded_get(ctx,url,Path(str(destination)+'.wire'),limit,total,allowed,json_data=True)
 decoded=decode_json(wire,entry['encoding'],limit-len(wire));total['bodyBytes']+=len(decoded);need(total['bodyBytes']<=536870912,'ORIGINAL_BODY_BUDGET');entry.update(decodedBytes=len(decoded),decodedSHA256=sha(decoded),phase=phase,state='DECODED_BEFORE_PARSE');save(destination,decoded)
 data=strict_json(decoded);budget(ctx);entry['state']='JSON_PARSED_NOT_ADMITTED';return dict(entry),data
def advisory_guard(ctx,specs,total):
 """Use already retained complete service/index/pages; no duplicate source10 GET."""
 selected={x['id'].lower():x['version'] for x in specs};pages=ctx['advisoryPages'];urls=advisory_index_urls(ctx['advisoryIndex'])
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
