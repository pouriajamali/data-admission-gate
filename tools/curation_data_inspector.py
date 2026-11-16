"""Bounded ZIP/DER data inspection. No network, subprocess, extraction or trust API."""
from __future__ import annotations
import binascii,hashlib,json,re,stat,struct,unicodedata,zlib,xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

class DiscoveryError(ValueError):pass
def need(value,code):
 if not value:raise DiscoveryError(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def safe_cause(exc):
 code=str(exc) if isinstance(exc,DiscoveryError) else 'DETAIL_REDACTED'
 return {'type':type(exc).__name__ if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',type(exc).__name__) else 'UNKNOWN','code':code if re.fullmatch(r'[A-Z][A-Z0-9_]{0,95}',code) else 'DETAIL_REDACTED'}

def member_name(raw,utf8):
 need(0<len(raw)<=240 and b'\0' not in raw,'ZIP_NAME_BOUND')
 try:name=raw.decode('utf-8' if utf8 else 'cp437')
 except UnicodeError:raise DiscoveryError('ZIP_NAME_ENCODING')
 need(unicodedata.normalize('NFC',name)==name and not any(ord(c)<32 or ord(c)==127 for c in name),'ZIP_NAME_ENCODING')
 need('\\' not in name and ':' not in name and not name.startswith('/'),'ZIP_PATH_SEPARATOR')
 parts=name.rstrip('/').split('/');reserved={'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}
 need(all(p not in ('','.','..') and p==p.rstrip(' .') and p.split('.')[0].upper() not in reserved for p in parts),'ZIP_PATH_COMPONENT')
 return name

def extras(raw):
 result={};pos=0
 while pos<len(raw):
  need(pos+4<=len(raw),'ZIP_EXTRA_FRAME');tag,size=struct.unpack_from('<HH',raw,pos);pos+=4;need(pos+size<=len(raw) and tag not in result,'ZIP_EXTRA_FRAME');result[tag]=raw[pos:pos+size];pos+=size
 need(not (set(result)&{0x000d,0x5855,0x7075}),'ZIP_EXTRA_NAME_OR_TYPE_AMBIGUITY')
 return result

def zip64_values(extra,values):
 data=extras(extra).get(1,b'');pos=0;result=[]
 for value in values:
  if value==0xffffffff:
   need(pos+8<=len(data),'ZIP64_FRAME');value=struct.unpack_from('<Q',data,pos)[0];pos+=8
  result.append(value)
 return result

def read_at(stream,offset,size,file_size):
 need(type(offset) is int and type(size) is int and 0<=offset<=file_size and 0<=size<=file_size-offset,'ZIP_FRAME_RANGE')
 stream.seek(offset);raw=stream.read(size);need(len(raw)==size,'ZIP_TRUNCATED');return raw

def zip_layout(stream,file_size,profile,tick):
 need(22<=file_size<=profile['rawSingleMaxBytes'],'ZIP_RAW_BOUND');tail=read_at(stream,max(0,file_size-65557),min(file_size,65557),file_size);found=[];at=tail.find(b'PK\x05\x06')
 while at>=0:
  if at+22<=len(tail):
   row=struct.unpack_from('<4s4H2IH',tail,at)
   if at+22+row[7]==len(tail):found.append((file_size-len(tail)+at,row))
  at=tail.find(b'PK\x05\x06',at+1)
 need(len(found)==1,'ZIP_EOCD_FRAME');eocd,e=found[0];_,disk,cdisk,n1,count,cdsize,cdoffset,comment=e
 need(disk==cdisk==0 and n1==count and 0<count<=profile['membersPerArchiveMax'] and comment<=4096,'ZIP_EOCD_BOUND')
 need(cdoffset+cdsize==eocd and cdsize<=8*1024*1024,'ZIP_CENTRAL_FRAME');pos=cdoffset;rows=[];names=set();expanded=0
 for _ in range(count):
  tick();c=struct.unpack('<4s6H3I5H2I',read_at(stream,pos,46,file_size));need(c[0]==b'PK\x01\x02' and c[13]==0,'ZIP_CENTRAL_FRAME');nlen,xlen,clen=c[10:13];need(xlen<=16384 and clen<=4096,'ZIP_EXTRA_BOUND');raw=read_at(stream,pos+46,nlen+xlen+clen,file_size);name=member_name(raw[:nlen],bool(c[3]&0x800));fold=name.rstrip('/').casefold();need(fold not in names,'ZIP_NAME_COLLISION');names.add(fold)
  need(c[3]&~0x080e==0 and c[4] in (0,8) and c[2]<=45,'ZIP_UNSUPPORTED_FEATURE');usize,csize,offset=zip64_values(raw[nlen:nlen+xlen],[c[9],c[8],c[16]]);need(usize<=profile['expandedStreamSingleMaxBytes'] and csize<=file_size and offset<cdoffset,'ZIP_MEMBER_BOUND');expanded+=usize;need(expanded<=profile['expandedStreamSingleMaxBytes'],'ZIP_EXPANDED_ARCHIVE_BOUND')
  mode=c[15]>>16;kind=stat.S_IFMT(mode);directory=name.endswith('/');need(kind in (0,stat.S_IFREG,stat.S_IFDIR) and c[15]&0x400==0,'ZIP_LINK_REPARSE_TYPE');need(not (kind==stat.S_IFDIR and not directory) and not (kind==stat.S_IFREG and directory) and not (c[15]&0x10 and not directory),'ZIP_TYPE_MISMATCH');need(not directory or usize==0,'ZIP_DIRECTORY_BODY')
  rows.append({'path':name,'type':'directory' if directory else 'regular-data','zipMode':mode,'dosAttributes':c[15]&0xffff,'flags':c[3],'method':c[4],'dosTime':c[5],'dosDate':c[6],'crc32':c[7],'compressedBytes':csize,'bytes':usize,'localOffset':offset,'rawName':raw[:nlen],'versionNeeded':c[2]});pos+=46+nlen+xlen+clen
 need(pos==cdoffset+cdsize,'ZIP_CENTRAL_FRAME');ordered=sorted(rows,key=lambda r:r['localOffset']);need(ordered[0]['localOffset']==0,'ZIP_PREFIX_FORBIDDEN')
 for index,row in enumerate(ordered):
  tick();offset=row['localOffset'];local=struct.unpack('<4s5H3I2H',read_at(stream,offset,30,file_size));need(local[0]==b'PK\x03\x04' and local[1]==row['versionNeeded'] and local[2]==row['flags'] and local[3]==row['method'] and local[4]==row['dosTime'] and local[5]==row['dosDate'],'ZIP_LOCAL_CENTRAL_MISMATCH');nlen,xlen=local[9:11];need(xlen<=16384,'ZIP_EXTRA_BOUND');raw=read_at(stream,offset+30,nlen+xlen,file_size);need(raw[:nlen]==row['rawName'],'ZIP_LOCAL_NAME_MISMATCH');local_u,local_c=zip64_values(raw[nlen:],[local[8],local[7]]);start=offset+30+nlen+xlen;end=start+row['compressedBytes'];next_offset=ordered[index+1]['localOffset'] if index+1<len(ordered) else cdoffset;need(end<=next_offset,'ZIP_OVERLAP')
  if row['flags']&8:
   need(local[6] in (0,row['crc32']) and local_c in (0,row['compressedBytes']) and local_u in (0,row['bytes']),'ZIP_LOCAL_SIZE_MISMATCH');gap=next_offset-end;need(gap in (12,16,20,24),'ZIP_DESCRIPTOR_FRAME');dd=read_at(stream,end,gap,file_size)
   if gap in (16,24):need(dd[:4]==b'PK\x07\x08','ZIP_DESCRIPTOR_FRAME');dd=dd[4:]
   value=struct.unpack('<III' if len(dd)==12 else '<IQQ',dd);need(value==(row['crc32'],row['compressedBytes'],row['bytes']),'ZIP_DESCRIPTOR_MISMATCH')
  else:need(local[6]==row['crc32'] and local_c==row['compressedBytes'] and local_u==row['bytes'] and end==next_offset,'ZIP_LOCAL_SIZE_MISMATCH')
  row['payloadOffset']=start
 # A regular file may not also be an ancestor of another member.
 kinds={r['path'].rstrip('/').casefold():r['type'] for r in rows}
 for row in rows:
  parts=row['path'].rstrip('/').split('/')
  for i in range(1,len(parts)):need(kinds.get('/'.join(parts[:i]).casefold())!='regular-data','ZIP_FILE_DIRECTORY_COLLISION')
 return rows,expanded

def stream_member(stream,row,tick,retained_limit=0):
 stream.seek(row['payloadOffset']);remaining=row['compressedBytes'];actual=0;crc=0;h=hashlib.sha256();saved=bytearray();dec=zlib.decompressobj(-15) if row['method']==8 else None
 def consume(raw):
  nonlocal actual,crc
  actual+=len(raw);need(actual<=row['bytes'],'ZIP_EXPANDED_LENGTH');h.update(raw);crc=binascii.crc32(raw,crc)
  if retained_limit:
   need(len(saved)+len(raw)<=retained_limit,'RETAINED_DATA_BOUND');saved.extend(raw)
 while remaining:
  tick();raw=stream.read(min(65536,remaining));need(raw,'ZIP_TRUNCATED');remaining-=len(raw)
  if dec is None:consume(raw);continue
  pending=raw
  while pending:
   tick();before=len(pending);out=dec.decompress(pending,65536);pending=dec.unconsumed_tail;need(not dec.unused_data,'ZIP_DEFLATE_TRAILING_DATA');consume(out);need(out or len(pending)<before,'ZIP_DEFLATE_PROGRESS')
 if dec is not None:
  while not dec.eof:
   tick();out=dec.decompress(b'',65536);consume(out)
   if not out:break
  need(dec.eof and not dec.unused_data and not dec.unconsumed_tail,'ZIP_DEFLATE_EOF')
 need(actual==row['bytes'] and crc&0xffffffff==row['crc32'],'ZIP_CRC_OR_LENGTH');return h.hexdigest(),bytes(saved)

def der_tree(data,max_nodes=20000,max_depth=32):
 need(len(data)<=2097152,'CMS_BYTE_BOUND');nodes=0
 def parse(pos,stop,depth):
  nonlocal nodes
  need(depth<=max_depth and pos<stop,'CMS_DER_DEPTH_OR_FRAME');begin=pos;tag=data[pos];pos+=1;need(tag&31!=31,'CMS_HIGH_TAG_UNSUPPORTED');need(pos<stop,'CMS_DER_TRUNCATED');first=data[pos];pos+=1
  if first&128:
   n=first&127;need(1<=n<=4 and pos+n<=stop and data[pos]!=0,'CMS_DER_LENGTH');length=int.from_bytes(data[pos:pos+n],'big');pos+=n;need(length>=128,'CMS_DER_NONMINIMAL')
  else:length=first
  end=pos+length;need(end<=stop,'CMS_DER_RANGE');nodes+=1;need(nodes<=max_nodes,'CMS_NODE_BOUND');children=[]
  if tag&32:
   child=pos
   while child<end:
    node,child=parse(child,end,depth+1);children.append(node)
   need(child==end,'CMS_DER_RANGE')
  return (tag,begin,pos,end,children),end
 root,end=parse(0,len(data),0);need(end==len(data),'CMS_DER_TRAILING');return root

def oid(data,node):
 need(node[0]==6 and 0<node[3]-node[2]<=128,'CMS_OID_BOUND');values=[];value=0;ongoing=False
 for b in data[node[2]:node[3]]:
  value=(value<<7)|(b&127);need(value<2**63,'CMS_OID_BOUND');ongoing=bool(b&128)
  if not ongoing:values.append(value);value=0
 need(not ongoing and values,'CMS_OID_FRAME');first=values.pop(0);head=(0,first) if first<40 else (1,first-40) if first<80 else (2,first-80);return '.'.join(map(str,[*head,*values]))

def walk(node):
 yield node
 for child in node[4]:yield from walk(child)

def cms_data(raw):
 result={'state':'OBSERVED_UNVERIFIED','rawBytes':len(raw),'rawSHA256':sha(raw),'cryptographicTrust':'UNKNOWN','chain':'UNKNOWN','timestampTrust':'UNKNOWN','revocation':'UNKNOWN','normalizedNuGetHash':'UNKNOWN','certificates':[],'signedContainers':[],'observedPKIURLs':[]}
 try:
  root=der_tree(raw);cert_seen=set();containers=[]
  for node in walk(root):
   c=node[4]
   if node[0]==48 and len(c)==2 and c[0][0]==6 and oid(raw,c[0])=='1.2.840.113549.1.7.2' and c[1][0]==160:
    need(len(containers)<16,'CMS_CONTAINER_BOUND');containers.append(node)
  need(containers,'CMS_SIGNEDDATA_NOT_FOUND')
  for container in containers:
   wrapped=container[4][1][4];need(len(wrapped)==1 and wrapped[0][0]==48,'CMS_SIGNEDDATA_FRAME');fields=wrapped[0][4];need(len(fields)>=4,'CMS_SIGNEDDATA_FRAME');item={'sha256':sha(raw[container[1]:container[3]]),'bytes':container[3]-container[1],'digestAlgorithmOIDs':[],'signers':[],'state':'OBSERVED_UNVERIFIED'}
   need(len(fields[1][4])<=8,'CMS_ALGORITHM_BOUND')
   for alg in fields[1][4]:
    if alg[4] and alg[4][0][0]==6:item['digestAlgorithmOIDs'].append(oid(raw,alg[4][0]))
   for group in fields[3:-1]:
    if group[0]!=160:continue
    for cert in group[4]:
     if cert[0]!=48:continue
     digest=sha(raw[cert[1]:cert[3]])
     if digest in cert_seen:continue
     need(len(cert_seen)<32,'CMS_CERTIFICATE_BOUND');cert_seen.add(digest);record={'sha256':digest,'bytes':cert[3]-cert[1],'state':'OBSERVED_UNVERIFIED'};result['certificates'].append(record)
     # Decode only bounded URI-bearing extensions; never resolve any address.
     if not cert[4]:continue
     for extbox in cert[4][0][4]:
      if extbox[0]!=163:continue
      for extseq in extbox[4]:
       for ext in extseq[4]:
        if len(ext[4])<2 or ext[4][0][0]!=6:continue
        ext_oid=oid(raw,ext[4][0]);value=ext[4][-1]
        if ext_oid not in ('1.3.6.1.5.5.7.1.1','2.5.29.31') or value[0]!=4:continue
        nested=raw[value[2]:value[3]]
        try:parsed=der_tree(nested,2048,16)
        except DiscoveryError:continue
        for uri in walk(parsed):
         if uri[0]!=134:continue
         data=nested[uri[2]:uri[3]];need(len(data)<=2048 and all(32<=x<127 for x in data),'CMS_URI_BOUND');text=data.decode('ascii');u=urlsplit(text)
         if u.scheme not in ('http','https') or not u.hostname or u.username or u.password:continue
         entry={'extensionOID':ext_oid,'uri':text,'state':'OBSERVED_UNVERIFIED_NO_REQUEST'}
         if entry not in result['observedPKIURLs']:need(len(result['observedPKIURLs'])<64,'CMS_URI_COUNT');result['observedPKIURLs'].append(entry)
   signers=fields[-1];need(signers[0]==49 and len(signers[4])<=16,'CMS_SIGNER_BOUND')
   for signer in signers[4]:
    f=signer[4];need(signer[0]==48 and len(f)>=5,'CMS_SIGNER_FRAME');sig={'sidSHA256':sha(raw[f[1][1]:f[1][3]]),'signedAttributeOIDs':[],'unsignedAttributeOIDs':[],'state':'OBSERVED_UNVERIFIED'}
    for part in f:
     if part[0] in (160,161):
      need(len(part[4])<=64,'CMS_ATTRIBUTE_BOUND')
      for attr in part[4]:
       if attr[4] and attr[4][0][0]==6:sig['signedAttributeOIDs' if part[0]==160 else 'unsignedAttributeOIDs'].append(oid(raw,attr[4][0]))
    octets=[x for x in f if x[0]==4]
    if octets:sig['signatureValueSHA256']=sha(raw[octets[-1][2]:octets[-1][3]])
    item['signers'].append(sig)
   result['signedContainers'].append(item)
  result['parser']='BOUNDED_DER_STRUCTURAL_ONLY_NO_SIGNATURE_VALIDATION'
 except (DiscoveryError,ValueError,IndexError,UnicodeError) as exc:
  result.update(state='UNKNOWN_PARSER_OR_PROVENANCE',parserCause=safe_cause(exc))
 return result

def inspect_package(path,profile,tick,emit,retain,expected=None):
 """emit/retain are internal bounded sinks selected by the fixed controller, not CLI callbacks."""
 path=Path(path);file_size=path.stat().st_size;notices=notice_count=0;cms=None;nuspec=[];count=0
 with path.open('rb') as stream:
  rows,expanded=zip_layout(stream,file_size,profile,tick)
  for index,row in enumerate(rows):
   tick();name=row['path'];base=name.rstrip('/').split('/')[-1].lower();is_cms=name.lower()=='.signature.p7s';is_nuspec=base.endswith('.nuspec');is_notice=base.startswith(('license','licence','third-party-notice','third_party_notice','thirdpartynotice','notice'))
   limit=profile['CMSBytesPerPackageMax'] if is_cms else 262144 if is_nuspec else 524288 if is_notice else 0
   digest,data=stream_member(stream,row,tick,limit);manifest={k:row[k] for k in ['path','type','zipMode','dosAttributes','method','crc32','compressedBytes','bytes']};manifest['sha256']=digest;emit(manifest);count+=1
   if limit:
    if is_notice:notices+=len(data);notice_count+=1;need(notices<=2097152 and notice_count<=32,'NOTICES_AGGREGATE_BOUND')
    kind='cms' if is_cms else 'nuspec' if is_nuspec else 'notice';retained=retain(index,kind,data)
    if is_cms:need(cms is None,'CMS_DUPLICATE');cms={'data':retained,'inspection':cms_data(data)}
    elif is_nuspec:
     need(b'\0' not in data and b'<!DOCTYPE' not in data.upper() and b'<!ENTITY' not in data.upper(),'NUSPEC_DTD_OR_ENCODING');document=ET.fromstring(data);ids=[n.text for n in document.iter() if n.tag.split('}')[-1]=='id'];versions=[n.text for n in document.iter() if n.tag.split('}')[-1]=='version'];need(len(ids)==len(versions)==1 and type(ids[0]) is str and type(versions[0]) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',ids[0]) and re.fullmatch(r'[0-9A-Za-z.+-]{1,64}',versions[0]),'NUSPEC_IDENTITY')
     if expected:need(ids[0].lower()==expected['id'].lower() and versions[0]==expected['version'],'NUSPEC_EXPECTED_IDENTITY')
     nuspec.append({'data':retained,'id':ids[0],'version':versions[0],'state':'OBSERVED_UNVERIFIED_ORIGINAL_NUSPEC'})
 need(len(nuspec)==1,'NUSPEC_COUNT');return {'state':'STRUCTURAL_DATA_ONLY_NOT_ADMITTED','memberCount':count,'expandedStreamBytes':expanded,'nuspec':nuspec,'CMS':cms or {'state':'UNKNOWN_NOT_PRESENT'},'noticesRetainedBytes':notices,'normalizedContentHash':'UNKNOWN','packageTrust':'UNKNOWN','advisory':'UNKNOWN'}
