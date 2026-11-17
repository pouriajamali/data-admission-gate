"""Adapted source DATA c49f: only seven inspected public10 patterns, own04 IO.
No import/execution of hosted_caps, borrowed contexts/caps, or implicit acquisition.
"""
from __future__ import annotations
import datetime,email.utils,gzip,hashlib,ipaddress,json,re,time,urllib.request,zlib
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
def budget(ctx):need(time.monotonic_ns()<ctx['deadlineMonotonicNs'],'ORIGINAL_METADATA_DEADLINE')
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
def bounded_get(ctx,url,destination,limit,total,allowed_urls,json_data=False):
 """Own04 finite one-shot transport. Invoked only after exact runtime activation."""
 budget(ctx);need(url in allowed_urls and url not in ctx['requested'] and len(ctx['requested'])<23,'METADATA_CLOSED_ONCE')
 ctx['requested'].add(url);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());headers={'Accept-Encoding':'gzip' if json_data else 'identity','User-Agent':'producer04-input-curation/1'}
 entry={'url':url,'rawBytes':0,'state':'STARTED'};ctx['records'].append(entry)
 request_end=min(ctx['deadlineMonotonicNs'],time.monotonic_ns()+10000000000)
 with opener.open(urllib.request.Request(url,headers=headers),timeout=min(10,(request_end-time.monotonic_ns())/1e9)) as response:
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
 save(destination,wire);return entry,wire
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
