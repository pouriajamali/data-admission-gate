"""One fixed runtime URL/prefix-plus-suffix candidate. No generic resume or trust API."""
from __future__ import annotations
import hashlib,os,re,stat,time,urllib.error,urllib.request
from pathlib import Path

URL='https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.runtime.linux-x64/11.0.0/microsoft.netcore.app.runtime.linux-x64.11.0.0.nupkg'
class RangeError(ValueError):pass
def need(value,code):
 if not value:raise RangeError(code)
def deadline(end_ns):need(time.monotonic_ns()<end_ns,'RANGE_FILE_DEADLINE')
def identity(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def object_identity(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
def regular(info):return stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not getattr(info,'st_file_attributes',0)&0x400

def policy_check(p):
 need(p['url']==URL and p['id']=='Microsoft.NETCore.App.Runtime.linux-x64' and p['rid']=='linux-x64' and p['version']=='11.0.0','RANGE_FIXED_INPUT_ONLY')
 need(type(p['prefixBytes']) is int and type(p['suffixBytes']) is int and 0<p['prefixBytes'] and 0<p['suffixBytes'] and p['prefixBytes']+p['suffixBytes']==p['wholeBytes']<=67108864,'RANGE_SIZE_POLICY')
 need(p['rangeRequest']==f"bytes={p['prefixBytes']}-{p['wholeBytes']-1}" and p['expected206ContentRange']==f"bytes {p['prefixBytes']}-{p['wholeBytes']-1}/{p['wholeBytes']}",'RANGE_HEADER_POLICY')
 need(re.fullmatch('[0-9a-f]{64}',p['prefixSha256']) is not None and re.fullmatch('[0-9a-f]{128}',p['existingWholePolicySHA512']) is not None,'RANGE_HASH_POLICY')

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise RangeError('RANGE_REDIRECT_FORBIDDEN')

def response_check(response,p):
 need(response.status==206,'RANGE_STATUS_NOT_206');need(response.geturl()==p['url'],'RANGE_FINAL_URL');headers=response.headers
 need(headers.get_all('Content-Range')==[p['expected206ContentRange']],'RANGE_CONTENT_RANGE')
 need(headers.get_all('Content-Length')==[str(p['suffixBytes'])],'RANGE_CONTENT_LENGTH')
 encoding=headers.get_all('Content-Encoding');need(encoding is None or encoding==['identity'],'RANGE_ENCODING')
 need(headers.get_all('Transfer-Encoding') is None,'RANGE_TRANSFER_ENCODING')
 types=headers.get_all('Content-Type');need(types is None or len(types)==1 and not types[0].split(';',1)[0].strip().lower().startswith('multipart/'),'RANGE_MULTIPART_OR_TYPE')

def reconstruct(p,destination,end_ns,held_prefix_sha256):
 """Caller holds the exact immutable prefix with the pinned0959 read-only handle."""
 policy_check(p);deadline(end_ns);prefix=Path(p['immutablePrefixPath']);destination=Path(destination)
 need(prefix.resolve()!=destination.resolve(),'RANGE_NO_INPLACE_OUTPUT');need(not prefix.is_symlink() and regular(prefix.lstat()),'RANGE_PREFIX_REGULAR');need(held_prefix_sha256==p['prefixSha256'],'RANGE_PREFIX_HELD_HASH')
 source_fd=output_fd=None;primary=None
 def put(raw):
  position=0
  while position<len(raw):
   deadline(end_ns);count=os.write(output_fd,raw[position:]);need(count>0,'RANGE_OUTPUT_WRITE');position+=count
 try:
  source_fd=os.open(prefix,os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0));before=os.fstat(source_fd);path_before=prefix.lstat();need(regular(before) and regular(path_before) and before.st_size==p['prefixBytes'] and object_identity(before)==object_identity(path_before),'RANGE_PREFIX_SIZE_IDENTITY')
  output_fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0),0o600);copied=0;prefix_hash=hashlib.sha256();full256=hashlib.sha256();full512=hashlib.sha512()
  while True:
   deadline(end_ns);block=os.read(source_fd,65536)
   if not block:break
   copied+=len(block);need(copied<=p['prefixBytes'],'RANGE_PREFIX_COPY_BOUND');prefix_hash.update(block);put(block);full256.update(block);full512.update(block)
  need(copied==p['prefixBytes'] and prefix_hash.hexdigest()==p['prefixSha256'],'RANGE_PREFIX_HASH');need(identity(os.fstat(source_fd))==identity(before) and identity(prefix.lstat())==identity(path_before),'RANGE_PREFIX_CHANGED')
  deadline(end_ns);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());request=urllib.request.Request(p['url'],headers={'Range':p['rangeRequest'],'Accept-Encoding':'identity','User-Agent':'producer04-exact-range-byte-candidate'},method='GET')
  try:response=opener.open(request,timeout=min(10,max(.001,(end_ns-time.monotonic_ns())/1e9)))
  except urllib.error.HTTPError as exc:
   try:exc.close()
   except Exception:pass
   raise RangeError('RANGE_STATUS_NOT_206') from None
  with response:
   response_check(response,p);suffix_count=0
   while suffix_count<p['suffixBytes']:
    deadline(end_ns);block=response.read(min(65536,p['suffixBytes']-suffix_count));need(block,'RANGE_SUFFIX_SHORT');suffix_count+=len(block);need(suffix_count<=p['suffixBytes'],'RANGE_SUFFIX_EXTRA');put(block);full256.update(block);full512.update(block)
   deadline(end_ns);need(response.read(1)==b'','RANGE_SUFFIX_EXTRA')
  need(identity(os.fstat(source_fd))==identity(before) and identity(prefix.lstat())==identity(path_before),'RANGE_PREFIX_CHANGED');os.fsync(output_fd);deadline(end_ns);need(os.fstat(output_fd).st_size==p['wholeBytes'],'RANGE_WHOLE_SIZE')
  return {'state':'BYTE_CANDIDATE_UNTRUSTED','id':p['id'],'version':p['version'],'rid':p['rid'],'transport':'PREFIX_PLUS_STRICT_RANGE_SUFFIX_CANDIDATE','HTTPRepresentationContinuity':'UNKNOWN_WITHOUT_ORIGINAL_STRONG_VALIDATOR','IfRangeSent':False,'GETs':1,'httpStatus':206,'observedSuffixBytes':suffix_count,'observedRawBytes':p['wholeBytes'],'rawSignedSHA256':full256.hexdigest(),'rawSignedSHA512':full512.hexdigest(),'feedDeclaredPolicySHA512':p['existingWholePolicySHA512'],'fullPolicyHashEquality':full512.hexdigest()==p['existingWholePolicySHA512'],'prefixCopiedBytes':copied,'prefixCopiedSHA256':prefix_hash.hexdigest(),'prefixStableIdentity':{'device':before.st_dev,'inode':before.st_ino,'bytes':before.st_size,'mtimeNs':before.st_mtime_ns,'fdCtimeNs':before.st_ctime_ns,'pathCtimeNs':path_before.st_ctime_ns,'sameAPIIdentityStable':True},'prefixMutation':False,'authenticity':'UNKNOWN','normalizedNuGetContentHash':'UNKNOWN','cryptographicAdmission':False}
 except BaseException as exc:
  primary=exc;raise
 finally:
  # Never remove or rewrite any data; close errors cannot mask an existing primary.
  close_error=None
  for fd in (output_fd,source_fd):
   if fd is not None:
    try:os.close(fd)
    except OSError as exc:
     if close_error is None:close_error=exc
  if close_error is not None and primary is None:raise close_error

def require_full_policy(receipt):
 need(receipt.get('fullPolicyHashEquality') is True,'RANGE_WHOLE_POLICY_HASH_MISMATCH')
