"""Finite original-eight-certificate CRL supplement and exact-own-unit deny.
Structural DER decoding is DATA only. Native OpenSSL/NuGet are crypto authority.
Import performs no OS commands, kernel calls, network, file reads or probing.
"""
from __future__ import annotations
import base64,contextlib,ctypes,datetime,errno,hashlib,ipaddress,json,os,platform,re,signal,socket,stat,subprocess,time
from pathlib import Path
AMENDMENT_SHA='0ced5ea8dfe74fed6125c0fba8f0398f592f1d395cca4aee061f3f10346e0770'
AUTHOR='9a1b131bee0605433056a4ea3815478a8e177961a968c6c0027c1093d1feb630'
REPOSITORY='1f4b311d9acc115c8dc8018b5a49e00fce6da8e2855f9f014ca6f34570bc482d'
CAPS={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'}
class Hold(RuntimeError):pass
def need(v,code):
 if not v:raise Hold(code)
def sha(b):return hashlib.sha256(b).hexdigest()
def tlv(data,pos=0,stop=None):
 stop=len(data) if stop is None else stop;begin=pos;need(pos+2<=stop,'DER_FRAME');tag=data[pos];pos+=1;need(tag&31!=31,'DER_HIGH_TAG');first=data[pos];pos+=1
 if first&128:
  n=first&127;need(1<=n<=4 and pos+n<=stop and data[pos]!=0,'DER_LENGTH');size=int.from_bytes(data[pos:pos+n],'big');pos+=n;need(size>=128,'DER_NONMINIMAL')
 else:size=first
 end=pos+size;need(end<=stop,'DER_FRAME');return (tag,begin,pos,end)
def children(data,node):
 need(node[0]&32,'DER_CONSTRUCTED');out=[];p=node[2]
 while p<node[3]:
  need(len(out)<20000,'DER_CHILD_BOUND');n=tlv(data,p,node[3]);out.append(n);p=n[3]
 need(p==node[3],'DER_FRAME');return out
def raw(data,n):return data[n[1]:n[3]]
def value(data,n):return data[n[2]:n[3]]
def oid(data,n):
 need(n[0]==6,'DER_OID');out=[];v=0
 for c in value(data,n):
  v=(v<<7)|(c&127);need(v<2**63,'DER_OID')
  if not c&128:out.append(v);v=0
 need(out and not value(data,n)[-1]&128,'DER_OID');x=out.pop(0);head=[0,x] if x<40 else [1,x-40] if x<80 else [2,x-80];return '.'.join(map(str,head+out))
def der_time(data,n):
 b=value(data,n);need(n[0] in (23,24),'DER_TIME');fmt='%y%m%d%H%M%SZ' if n[0]==23 else '%Y%m%d%H%M%SZ'
 need(re.fullmatch(rb'[0-9]{12}Z' if n[0]==23 else rb'[0-9]{14}Z',b) is not None,'DER_TIME')
 try:return int(datetime.datetime.strptime(b.decode(),fmt).replace(tzinfo=datetime.timezone.utc).timestamp())
 except ValueError:raise Hold('DER_TIME') from None
def extensions(data,node,critical=None):
 out={}
 for e in children(data,node):
  f=children(data,e);need(len(f) in (2,3) and f[-1][0]==4,'DER_EXTENSION');o=oid(data,f[0]);need(o not in out,'DER_EXTENSION_DUPLICATE');out[o]=value(data,f[-1])
  if len(f)==3:
   need(f[1][0]==1 and value(data,f[1])==b'\xff','DER_EXTENSION_CRITICAL_BOOLEAN')
   if critical is not None:critical.add(o)
 return out
def name_parts(data,node):
 labels={'2.5.4.6':'C','2.5.4.8':'ST','2.5.4.7':'L','2.5.4.10':'O','2.5.4.11':'OU','2.5.4.3':'CN','1.2.840.113549.1.9.1':'emailAddress'};items=[]
 for rdn in children(data,node):
  vals=children(data,rdn);need(len(vals)==1,'DN_MULTIVALUED_UNSUPPORTED');f=children(data,vals[0]);need(len(f)==2 and f[1][0] in (12,19,22),'DN_ENCODING');key=oid(data,f[0]);need(key in labels,'DN_ATTRIBUTE_UNSUPPORTED')
  try:text=value(data,f[1]).decode('ascii')
  except UnicodeError:raise Hold('DN_ENCODING') from None
  need(text and text==text.strip() and all(32<=ord(c)<127 for c in text),'DN_ESCAPING_UNSUPPORTED');items.append((labels[key],text))
 return items
def printed_name(text):
 """Accept only native simple/quoted/escaped DN fields, compare semantic parts."""
 fields=[];part='';quote=False;escape=False
 for c in text:
  if escape:part+='\\'+c;escape=False
  elif c=='\\':escape=True
  elif c=='"':quote=not quote;part+=c
  elif c==',' and not quote:fields.append(part.strip());part=''
  else:part+=c
 need(not quote and not escape,'OPENSSL_DN_FRAME');fields.append(part.strip());out=[]
 for f in fields:
  key,sep,v=f.partition('=');need(sep and key.strip() in ('C','ST','L','O','OU','CN','emailAddress'),'OPENSSL_DN_ATTRIBUTE');v=v.strip()
  if v.startswith('"'):need(v.endswith('"'),'OPENSSL_DN_FRAME');v=v[1:-1]
  v=re.sub(r'\\([,+=<>;"\\])',lambda m:m[1],v);need('\\' not in v and v,'OPENSSL_DN_ESCAPE');out.append((key.strip(),v))
 return out
def scope_fullnames(data,node):
 # RFC5280 6.3.3(b)(2): support only direct, all-reason fullName URI scope.
 # Any extra IDP flag/reasons/indirect form remains unsupported, not ignored.
 fields=children(data,node);need(len(fields)==1 and fields[0][0]==160,'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');names=children(data,fields[0]);need(len(names)==1 and names[0][0]==160,'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');items=children(data,names[0]);need(1<=len(items)<=8 and all(n[0]==134 for n in items),'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');uris=[value(data,n) for n in items];need(len(set(uris))==len(uris) and all(0<len(u)<=1024 and all(32<c<127 for c in u) for u in uris),'CRL_SCOPE_URI');return uris
def cert_dp_uris(ext):
 if '2.5.29.31' not in ext:return []
 data=ext['2.5.29.31'];root=tlv(data);need(root[0]==48 and root[3]==len(data),'CERT_DP_FRAME');points=children(data,root);need(1<=len(points)<=8,'CERT_DP_BOUND');out=[]
 for point in points:need(point[0]==48,'CERT_DP_FRAME');out.extend(scope_fullnames(data,point))
 return out
def certificate(data):
 need(len(data)<=32768,'CERTIFICATE_BOUND');n=tlv(data);need(n[0]==48 and n[3]==len(data),'CERTIFICATE_FRAME');f=children(data,n);need(len(f)==3,'CERTIFICATE_FRAME');t=children(data,f[0]);off=1 if t[0][0]==160 else 0;need(len(t)>=off+6,'CERTIFICATE_TBS');serial=t[off];issuer=t[off+2];valid=children(data,t[off+3]);subject=t[off+4]
 need(serial[0]==2 and len(valid)==2,'CERTIFICATE_SERIAL_VALIDITY');ext={}
 for box in t[off+6:]:
  if box[0]==163:
   seq=children(data,box);need(len(seq)==1,'CERTIFICATE_EXTENSIONS');ext=extensions(data,seq[0])
 ski=None;aki=None
 if '2.5.29.14' in ext:ski=value(ext['2.5.29.14'],tlv(ext['2.5.29.14'])).hex()
 if '2.5.29.35' in ext:
  b=ext['2.5.29.35'];ids=[value(b,x).hex() for x in children(b,tlv(b)) if x[0]==128];need(len(ids)<=1,'CERTIFICATE_AKI');aki=ids[0] if ids else None
 try:parts=name_parts(data,subject)
 except Hold:parts=None
 return {'sha256':sha(data),'der':data,'serialDER':raw(data,serial),'issuerDER':raw(data,issuer),'subjectDER':raw(data,subject),'subjectParts':parts,'crlDistributionPointExtension':ext.get('2.5.29.31'),'notBefore':der_time(data,valid[0]),'notAfter':der_time(data,valid[1]),'SKI':ski,'AKI':aki}
def pem(label,data):return ('-----BEGIN '+label+'-----\n').encode()+b'\n'.join(base64.b64encode(data)[i:i+64] for i in range(0,len(base64.b64encode(data)),64))+('\n-----END '+label+'-----\n').encode()
def bundle_certificates(blob):
 need(len(blob)<=2097152,'ROOT_BUNDLE_BOUND');blocks=re.findall(rb'-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----',blob);need(1<=len(blocks)<=1024,'ROOT_BUNDLE_FRAME');out={}
 for b in blocks:
  try:der=base64.b64decode(re.sub(rb'\s',b'',b),validate=True)
  except ValueError:raise Hold('ROOT_BUNDLE_BASE64') from None
  c=certificate(der);out[c['sha256']]=c
 return out
def cms_roles(blobs,approved_pool):
 """Exact issuer+serial SID mapping, including countersignatures and RFC3161."""
 certs={};containers=[];packages=[]
 for blob in blobs:
  need(len(blob)<=2097152,'CMS_BOUND');root=tlv(blob);need(root[3]==len(blob),'CMS_FRAME');found=[];nodes=0
  def walk(n,depth):
   nonlocal nodes
   nodes+=1;need(nodes<=20000 and depth<=32,'CMS_NODE_DEPTH_BOUND');ch=children(blob,n) if n[0]&32 else []
   if n[0]==48 and len(ch)==2 and ch[0][0]==6 and oid(blob,ch[0])=='1.2.840.113549.1.7.2' and ch[1][0]==160:found.append(n)
   for c in ch:walk(c,depth+1)
  walk(root,0);need(1<=len(found)<=16,'CMS_CONTAINERS');package=[]
  for node in found:
   ch=children(blob,node);wrap=children(blob,ch[1]);need(len(wrap)==1,'CMS_SIGNEDDATA');fields=children(blob,wrap[0]);need(len(fields)>=4 and fields[-1][0]==49,'CMS_SIGNEDDATA');ctype=oid(blob,children(blob,fields[2])[0]);role='timestamp' if ctype=='1.2.840.113549.1.9.16.1.4' else 'author'
   for group in fields[3:-1]:
    if group[0]==160:
     for certnode in children(blob,group):
      need(certnode[0]==48,'CMS_CERTIFICATE_CHOICE');c=certificate(raw(blob,certnode));certs[c['sha256']]=c
   def signer(si,which):
    f=children(blob,si);need(len(f)>=5 and f[1][0] in (48,128),'CMS_SID_KIND')
    if f[1][0]==48:
     sid=children(blob,f[1]);need(len(sid)==2 and sid[1][0]==2,'CMS_SID_FRAME');package.append({'role':which,'issuerDER':raw(blob,sid[0]),'serialDER':raw(blob,sid[1])})
    else:package.append({'role':which,'SKI':value(blob,f[1]).hex()})
    for attrbox in f:
     if attrbox[0]==161:
      for attr in children(blob,attrbox):
       af=children(blob,attr);need(len(af)==2,'CMS_ATTRIBUTE_FRAME')
       if oid(blob,af[0])=='1.2.840.113549.1.9.6':
        for cs in children(blob,af[1]):signer(cs,'repository')
   for si in children(blob,fields[-1]):signer(si,role)
  packages.append(package)
 need(set(certs)==set(approved_pool) and len(certs)==8,'EXACT_ORIGINAL_CERTIFICATE_POOL')
 result=[];tsa=set()
 for package in packages:
  roles={'author':set(),'repository':set(),'timestamp':set()}
  for item in package:
   matches=[c['sha256'] for c in certs.values() if (c['SKI']==item['SKI'] if 'SKI' in item else c['issuerDER']==item['issuerDER'] and c['serialDER']==item['serialDER'])];need(len(matches)==1,'CMS_SID_AMBIGUOUS_OR_MISSING');roles[item['role']].add(matches[0])
  need(roles['author']=={AUTHOR} and roles['repository']=={REPOSITORY} and 1<=len(roles['timestamp'])<=2,'CMS_ROLE_IDENTITY');tsa.update(roles['timestamp']);result.append({k:sorted(v) for k,v in roles.items()})
 need(1<=len(tsa)<=2,'TSA_ROLE_BOUND');return certs,result
def crl_data(data,fixed_time):
 need(len(data)<=16777216,'CRL_BOUND');root=tlv(data);need(root[0]==48 and root[3]==len(data),'CRL_FRAME');outer=children(data,root);need(len(outer)==3,'CRL_FRAME');f=children(data,outer[0]);off=1 if f[0][0]==2 else 0;need(len(f)>=off+4,'CRL_TBS');issuer=f[off+1];this=f[off+2];nxt=f[off+3];need(nxt[0] in (23,24),'CRL_NEXT_UPDATE_REQUIRED');ext={};critical=set()
 for n in f[off+4:]:
  if n[0]==160:
   seq=children(data,n);need(len(seq)==1,'CRL_EXTENSIONS');ext=extensions(data,seq[0],critical)
 need('2.5.29.27' not in ext,'CRL_INDIRECT_DELTA_OR_SCOPE_UNSUPPORTED');scope=[]
 need(not critical-{'2.5.29.28'},'CRL_UNKNOWN_CRITICAL_EXTENSION')
 need('2.5.29.28' not in ext or '2.5.29.28' in critical,'CRL_IDP_MUST_BE_CRITICAL')
 if '2.5.29.28' in ext:
  data_idp=ext['2.5.29.28'];node_idp=tlv(data_idp);need(node_idp[0]==48 and node_idp[3]==len(data_idp),'CRL_IDP_FRAME');scope=scope_fullnames(data_idp,node_idp)
 need('2.5.29.35' in ext,'CRL_AKI_REQUIRED');b=ext['2.5.29.35'];ids=[value(b,n).hex() for n in children(b,tlv(b)) if n[0]==128];need(len(ids)==1,'CRL_AKI_REQUIRED');start=der_time(data,this);end=der_time(data,nxt);need(start<=fixed_time+300 and end>fixed_time and start<end,'CRL_NOT_CURRENT')
 return {'der':data,'sha256':sha(data),'issuerDER':raw(data,issuer),'AKI':ids[0],'thisUpdate':start,'nextUpdate':end,'scopeURIs':scope,'signatureStatus':'UNVERIFIED_UNTIL_NATIVE_VERIFY'}
def coverage(certs,anchors,crls,leaves,fixed_time):
 groups={}
 for r in crls:groups.setdefault((r['issuerDER'],r['AKI']),set()).add(r['sha256'])
 need(all(len(v)==1 for v in groups.values()),'CRL_DUPLICATE_ISSUER_DISAGREES')
 pool=dict(anchors);pool.update(certs);chains={};used={}
 for leaf in leaves:
  need(leaf in certs,'LEAF_NOT_ORIGINAL');chain=[];seen=set();current=pool[leaf]
  while True:
   need(current['sha256'] not in seen and len(chain)<8,'CHAIN_LOOP_OR_BOUND');seen.add(current['sha256']);chain.append(current['sha256']);need(current['notBefore']<=fixed_time<=current['notAfter'],'CURRENT_CERTIFICATE_VALIDITY')
   if current['sha256'] in anchors:break
   parents=[c for c in pool.values() if c['subjectDER']==current['issuerDER'] and current['AKI'] is not None and c['SKI']==current['AKI']];trusted=[c for c in parents if c['sha256'] in anchors];parents=trusted if trusted else parents;need(len(parents)==1,'CHAIN_ISSUER_AMBIGUOUS_OR_MISSING');parent=parents[0]
   matches=[r for r in crls if r['issuerDER']==parent['subjectDER'] and r['AKI']==parent['SKI']];need(matches,'CRL_CHAIN_COVERAGE_MISSING');need(len({r['sha256'] for r in matches})==1,'CRL_DUPLICATE_ISSUER_DISAGREES');need(not matches[0].get('scopeURIs') or bool(set(matches[0]['scopeURIs'])&set(cert_dp_uris({'2.5.29.31':current['crlDistributionPointExtension']}) if current.get('crlDistributionPointExtension') else [])),'CRL_SCOPE_DOES_NOT_COVER_CERTIFICATE');used[current['sha256']]=matches[0]['sha256'];current=parent
  chains[leaf]=chain
 return {'chains':chains,'certificateToCRLSHA256':used,'state':'STRUCTURAL_CURRENT_COVERAGE_NATIVE_SIGNATURES_REQUIRED'}
def openssl_vectors(paths,fixed_time):
 need(type(fixed_time) is int and fixed_time>0,'CURRENT_UNIX_TIME');base=['/usr/bin/openssl','verify','-verbose','-show_chain','-x509_strict','-no-CAfile','-no-CApath','-no-CAstore'];common=['-untrusted',paths['intermediates'],'-CRLfile',paths['crls'],'-crl_check','-crl_check_all','-attime',str(fixed_time),'-purpose']
 need(1<=len(paths['tsaLeaves'])<=2 and len(set(paths['tsaLeaves']))==len(paths['tsaLeaves']),'TSA_LEAF_PATH_BOUND')
 return [base+['-trusted',paths['codeRoots']]+common+['any',paths['author'],paths['repository']],base+['-trusted',paths['timestampRoots']]+common+['timestampsign',*paths['tsaLeaves']]]
def verify_report(stdout,stderr,exit_code,leaves,chains,certs):
 need(exit_code==0 and not stderr and len(stdout)<=32768,'OPENSSL_VERIFY_EXIT_OR_REPORT');need(b'\0' not in stdout,'OPENSSL_REPORT_ENCODING')
 try:lines=stdout.decode('ascii').splitlines()
 except UnicodeError:raise Hold('OPENSSL_REPORT_ENCODING') from None
 at=0
 for path,fingerprint in leaves:
  need(at<len(lines) and lines[at]==path+': OK','OPENSSL_EXPECTED_LEAF_RESULT');at+=1;need(at<len(lines) and lines[at]=='Chain:','OPENSSL_CHAIN_REQUIRED');at+=1
  for depth,cid in enumerate(chains[fingerprint]):
   need(at<len(lines),'OPENSSL_CHAIN_INCOMPLETE');match=re.fullmatch(r'depth=([0-9]+): (.*?)(?: \(untrusted\))?',lines[at]);need(match is not None and int(match[1])==depth and certs[cid]['subjectParts'] is not None and printed_name(match[2])==certs[cid]['subjectParts'],'OPENSSL_CONSTRUCTED_CHAIN_MISMATCH');at+=1
 need(at==len(lines),'OPENSSL_EXTRA_OR_UNKNOWN_OUTPUT');return {'state':'ACTUAL_NATIVE_CURRENT_CRL_CHAIN_VERIFY_PASS','logSHA256':sha(stdout),'leafSHA256':[f for _,f in leaves]}
def version_report(stdout,stderr,exit_code):
 need(exit_code==0 and not stderr and len(stdout)<=16384 and re.fullmatch(rb'OpenSSL 3\.[0-9]+\.[0-9]+[^\r\n]*\n?',stdout) is not None,'OPENSSL3_VERSION_UNRECOGNIZED');return {'family':'OpenSSL3','reportSHA256':sha(stdout)}
@contextlib.contextmanager
def held_os_image(path):
 p=Path(path);allowed={'/usr/bin/openssl','/usr/lib/x86_64-linux-gnu/libcrypto.so.3','/lib/x86_64-linux-gnu/libcrypto.so.3'};need(str(p) in allowed,'FIXED_OS_IMAGE');resolved=p.resolve();need(str(resolved) in allowed,'OS_IMAGE_RESOLUTION');fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022 and before.st_nlink==1,'ROOT_OWNED_OS_IMAGE');need(os.read(fd,4)==b'\x7fELF','OS_IMAGE_ELF');os.lseek(fd,0,0);h=hashlib.sha256();readbytes=0
  while True:
   b=os.read(fd,65536)
   if not b:break
   h.update(b);readbytes+=len(b)
  need(readbytes==before.st_size,'OS_IMAGE_READ_LENGTH')
  record={'path':str(resolved),'sha256':h.hexdigest(),'device':before.st_dev,'inode':before.st_ino,'bytes':before.st_size};yield record
  after=os.fstat(fd);current=resolved.stat();need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and (after.st_dev,after.st_ino)==(current.st_dev,current.st_ino),'OS_IMAGE_CHANGED');record['stableAfter']=True
 finally:os.close(fd)
def os_environment(root):
 return {'PATH':'/usr/bin:/bin','HOME':str(Path(root)/'home'),'TMPDIR':str(Path(root)/'tmp'),'LANG':'C','LC_ALL':'C','OPENSSL_CONF':'/dev/null'}
def pid_snapshot(pid,unit):
 need(type(pid) is int and pid>1 and re.fullmatch(r'admission04-sdk11-ci-[0-9a-f]{32}',unit),'OWN_UNIT_IDENTITY');p=Path('/proc')/str(pid);row=(p/'stat').read_text();f=row[row.rfind(')')+2:].split();cg=(p/'cgroup').read_text().splitlines();expected='/system.slice/'+unit+'.service';need('0::'+expected in cg,'OWN_PID_CGROUP');root=Path('/sys/fs/cgroup')/expected.lstrip('/');limits={k:(root/k).read_text().strip() for k in CAPS};need(limits==CAPS,'OWN_PID_CAPS')
 st=p.stat();return {'pid':pid,'start':f[19],'state':f[0],'uid':st.st_uid,'gid':st.st_gid,'cgroup':expected,'limits':limits,'bootID':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
def validate_stopped(before,current):
 need(current['state'] in ('T','t') and all(before[k]==current[k] for k in ['pid','start','uid','gid','cgroup','limits','bootID']),'EXACT_STOPPED_GENERATION')
def bpf_query(cgroup):
 """Read-only BPF_PROG_QUERY for this exact directory, ingress+egress only."""
 need(platform.machine()=='x86_64' and re.fullmatch(r'/system.slice/admission04-sdk11-ci-[0-9a-f]{32}\.service',cgroup),'BPF_FIXED_NATIVE_CGROUP');fd=os.open('/sys/fs/cgroup'+cgroup,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 class Query(ctypes.Structure):_fields_=[('target_fd',ctypes.c_uint32),('attach_type',ctypes.c_uint32),('query_flags',ctypes.c_uint32),('attach_flags',ctypes.c_uint32),('prog_ids',ctypes.c_uint64),('prog_cnt',ctypes.c_uint32),('pad',ctypes.c_uint32),('prog_attach_flags',ctypes.c_uint64)]
 try:
  libc=ctypes.CDLL(None,use_errno=True);out={}
  for attach,name in [(0,'ingress'),(1,'egress')]:
   ids=(ctypes.c_uint32*64)();q=Query(fd,attach,0,0,ctypes.addressof(ids),64,0,0);rc=libc.syscall(ctypes.c_long(321),ctypes.c_int(16),ctypes.byref(q),ctypes.c_uint(ctypes.sizeof(q)));need(rc==0 and q.prog_cnt<=64,'BPF_QUERY_UNSUPPORTED_OR_FAILED');out[name]=list(ids)[:q.prog_cnt]
  return out
 finally:os.close(fd)
def policy_readback(props,unit,pid,cgroup,before_bpf,after_bpf):
 need(props.get('Id')==unit+'.service' and props.get('Description')==unit and props.get('ControlGroup')==cgroup and props.get('MainPID')==str(pid) and props.get('ActiveState')=='active','DENY_EXACT_UNIT_READBACK')
 deny=set(props.get('IPAddressDeny','').split());allow=set(props.get('IPAddressAllow','').split())
 need(deny in ({'any'},{'0.0.0.0/0','::/0'}) and allow in ({'localhost'},{'127.0.0.0/8','::1/128'}),'DENY_POLICY_READBACK')
 need(props.get('MemoryMax')=='4294967296' and props.get('MemorySwapMax')=='0' and props.get('TasksMax')=='64' and props.get('CPUQuotaPerSecUSec') in ('2s','2000000') and props.get('CPUQuotaPeriodUSec') in ('100ms','100000'),'DENY_CAPS_READBACK')
 need(all(after_bpf.get(k) and set(after_bpf[k])-set(before_bpf.get(k,[])) for k in ('ingress','egress')),'DENY_KERNEL_FILTER_NOT_NEW_OR_UNSUPPORTED')
 return {'policy':'deny-any-allow-localhost','kernelAttachment':after_bpf,'exactGeneration':True}
def scoped_parent_transition(request):
 """Trusted parent only. Never installs BPF or changes another unit/global policy."""
 need(os.geteuid()==0 and request.get('purpose')=='PRODUCER04_LINUX_INPUT_CURATION','TRUSTED_CURATION_PARENT_REQUIRED');before=request['worker'];unit=request['unit'];need(before['cgroup']=='/system.slice/'+unit+'.service' and before['uid']==request['uid']>0 and re.fullmatch('[0-9a-f]{40}',request['sourceHEAD']) and re.fullmatch('[0-9a-f]{64}',request['leaseAdmissionSHA256']),'DENY_EXACT_GENERATION');validate_stopped(before,pid_snapshot(before['pid'],unit));old=bpf_query(before['cgroup']);env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','SYSTEMD_PAGER':'cat','SYSTEMD_COLORS':'0'}
 now=time.monotonic_ns();need(0<=now-request['originalStartMonotonicNs']<540000000000,'DENY_ORIGINAL_STAGE540')
 call=subprocess.run(['/usr/bin/systemctl','set-property','--runtime',unit+'.service','IPAddressDeny=any','IPAddressAllow=localhost'],capture_output=True,env=env,timeout=min(5,(request['originalStartMonotonicNs']+540000000000-now)/1e9));need(call.returncode==0 and len(call.stdout)+len(call.stderr)<=16384,'DENY_SET_FAILED')
 keys='Id,Description,ControlGroup,MainPID,ActiveState,IPAddressDeny,IPAddressAllow,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,CPUQuotaPeriodUSec';show=subprocess.run(['/usr/bin/systemctl','show',unit+'.service','--property='+keys],capture_output=True,env=env,timeout=max(.001,min(5,(request['originalStartMonotonicNs']+540000000000-time.monotonic_ns())/1e9)));need(show.returncode==0 and len(show.stdout)+len(show.stderr)<=16384,'DENY_SHOW_FAILED');props={}
 for line in show.stdout.decode('ascii').splitlines():
  key,sep,val=line.partition('=');need(sep and key not in props,'DENY_PROPERTY_FORMAT');props[key]=val
 current=pid_snapshot(before['pid'],unit);validate_stopped(before,current);new=bpf_query(before['cgroup']);proof=policy_readback(props,unit,before['pid'],before['cgroup'],old,new);proof.update(worker=current,unit=unit,requestSHA256=request['requestSHA256'],sourceHEAD=request['sourceHEAD'],leaseAdmissionSHA256=request['leaseAdmissionSHA256']);return proof
def witness_result(positive,negative_errno,before,current,peer,policy):
 need(all(before[k]==current[k] for k in ['pid','start','uid','gid','cgroup','limits','bootID']),'DENY_WITNESS_GENERATION');need(positive==b'producer04-static-ready','DENY_LOOPBACK_POSITIVE');need(negative_errno in (errno.EPERM,errno.EACCES),'DENY_TIMEOUT_OR_UNREACHABLE_NOT_PROOF');need(policy.get('exactGeneration') is True and all(policy.get('kernelAttachment',{}).get(k) for k in ('ingress','egress')),'DENY_KERNEL_PROOF_REQUIRED');ip=ipaddress.ip_address(peer[0]);need(not ip.is_loopback and not ip.is_unspecified and peer[1]==443,'DENY_BOUND_OFFICIAL_PEER');return {'state':'OWN_CURRENT_KERNEL_DENY_AND_LOOPBACK_WITNESSED','errno':negative_errno,'peerIP':str(ip),'peerPort':443,'current':current,'kernelAttachment':policy['kernelAttachment']}
def network_witness(port,peer,before,unit,policy):
 started=time.monotonic();need(1024<=port<=65535,'DENY_OWN_ADAPTER_PORT');positive=b''
 with socket.create_connection(('127.0.0.1',port),timeout=1) as s:
  s.sendall((f'GET /ready HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n').encode());data=b''
  while len(data)<=2048:
   b=s.recv(2049-len(data))
   if not b:break
   data+=b
  need(data.startswith(b'HTTP/1.0 200 ') and b'\r\n\r\n' in data,'DENY_LOOPBACK_HTTP');positive=data.split(b'\r\n\r\n',1)[1]
 ip=ipaddress.ip_address(peer[0]);family=socket.AF_INET6 if ip.version==6 else socket.AF_INET
 with socket.socket(family,socket.SOCK_STREAM) as s:s.settimeout(max(.001,3-(time.monotonic()-started)));negative=s.connect_ex((str(ip),443))
 need(time.monotonic()-started<=3,'DENY_WITNESS_TIME');return witness_result(positive,negative,before,pid_snapshot(os.getpid(),unit),peer,policy)

class NativeCalls:
 """Exactly one version and two fixed verify operations, inside own held cgroup."""
 def __init__(self,spec,job,proof_root):
  self.spec=spec;self.job=job;self.root=Path(proof_root);self.calls=0;self.images=contextlib.ExitStack();self.identities=[];self.reports=[]
 def __enter__(self):
  try:self.identities=[self.images.enter_context(held_os_image('/usr/bin/openssl')),self.images.enter_context(held_os_image('/usr/lib/x86_64-linux-gnu/libcrypto.so.3'))];return self
  except BaseException as exc:self.images.close();raise Hold('OS_OPENSSL_BINARY_LIBCRYPTO_UNAVAILABLE') from exc
 def __exit__(self,*exc):return self.images.__exit__(*exc)
 def _run(self,argv,seconds,stage):
  need(self.calls<3 and argv[0]=='/usr/bin/openssl','FINITE_OPENSSL_COMMAND_BUDGET');self.calls+=1;start=time.monotonic();end=min(self.spec['startTick']*1000000+stage*1000000000,time.monotonic_ns()+seconds*1000000000);need(end>time.monotonic_ns(),'OPENSSL_ORIGINAL_STAGE');cap=self.job.linux_caps();directory=self.root/('openssl-'+str(self.calls));directory.mkdir(mode=0o700);child=None;primary=None;mapped=False
  with (directory/'stdout.log').open('xb') as out,(directory/'stderr.log').open('xb') as err:
   try:
    child,held=self.job.stopped_linux_child(argv,Path(self.spec['root']),os_environment(self.spec['root']),out,err,(),cap)
    while child.poll() is None:
     need(time.monotonic_ns()<end and out.tell()+err.tell()<=32768,'OPENSSL_TIME_OR_REPORT_BOUND')
     try:
      for line in Path('/proc',str(child.pid),'maps').read_text().splitlines():
       fields=line.split(None,5)
       if len(fields)==6 and fields[5] in ('/usr/lib/x86_64-linux-gnu/libcrypto.so.3','/lib/x86_64-linux-gnu/libcrypto.so.3'):
        st=Path(fields[5]).stat();mapped=mapped or st.st_ino==self.identities[1]['inode']
     except FileNotFoundError:pass
     time.sleep(.001)
    child.wait(timeout=.1);need(self.job.linux_caps()['cgroup']==cap['cgroup'],'OPENSSL_CURRENT_CGROUP_DRIFT')
   except BaseException as exc:primary=exc
   finally:
    if child is not None and child.poll() is None:
     try:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=1)
     except BaseException:
      if primary is None:primary=Hold('OPENSSL_OWNED_CHILD_TERMINAL_UNKNOWN')
   if primary is not None:raise primary
  stdout=(directory/'stdout.log').read_bytes();stderr=(directory/'stderr.log').read_bytes();need(len(stdout)+len(stderr)<=32768,'OPENSSL_REPORT_BOUND');rec={'argvSHA256':sha(json.dumps(argv,separators=(',',':')).encode()),'exitCode':child.returncode,'seconds':time.monotonic()-start,'held':held,'currentCgroup':cap['cgroup'],'binaryAndLibcrypto':self.identities,'libcryptoMappingObserved':mapped,'stdoutSHA256':sha(stdout),'stderrSHA256':sha(stderr),'reportBytes':len(stdout)+len(stderr)};self.reports.append(rec);return stdout,stderr,child.returncode
 def version(self):
  need(self.calls==0,'OPENSSL_VERSION_ONCE');return version_report(*self._run(['/usr/bin/openssl','version'],2,420))
 def verify(self,paths,fixed_time,chain_plan,allcerts,witness):
  need(self.calls==1 and witness.get('state')=='OWN_CURRENT_KERNEL_DENY_AND_LOOPBACK_WITNESSED','OPENSSL_VERIFY_REQUIRES_CURRENT_DENY');vectors=openssl_vectors(paths,fixed_time);leaves=[[(paths['author'],AUTHOR),(paths['repository'],REPOSITORY)],[(p,Path(p).stem) for p in paths['tsaLeaves']]];results=[]
  for argv,role in zip(vectors,leaves):results.append(verify_report(*self._run(argv,10,630),role,chain_plan,allcerts))
  need(any(r['libcryptoMappingObserved'] for r in self.reports[1:]),'OPENSSL_ACTUAL_LIBCRYPTO_MAPPING_UNOBSERVED');need(sum(r['reportBytes'] for r in self.reports)<=65536,'OPENSSL_COMBINED_REPORT_BOUND');return {'state':'ACTUAL_SUPPLEMENTAL_CURRENT_CRL_COVERAGE_PASS','results':results,'reports':self.reports,'authority':'Current X509/CRL supplement only; NuGet CMS/RFC3161/Content hash still required'}

def prepare_chain_files(root,cms_blobs,approved_pool,code_bundle,timestamp_bundle,aia_blobs,crl_blobs,fixed_time):
 root=Path(root);root.mkdir(mode=0o700);certs,roles=cms_roles(cms_blobs,approved_pool);code=bundle_certificates(code_bundle);tsa=bundle_certificates(timestamp_bundle);allanchors=dict(code);allanchors.update(tsa)
 for blob in aia_blobs:
  c=certificate(blob);need(c['sha256'] in certs or c['sha256'] in allanchors,'AIA_CERT_OUTSIDE_DECLARED_POOL_OR_SDK_ANCHORS')
 crls=[crl_data(b,fixed_time) for b in crl_blobs];need(crls,'CURRENT_CRLS_REQUIRED');timestamps=sorted({f for p in roles for f in p['timestamp']});codeplan=coverage(certs,code,crls,[AUTHOR,REPOSITORY],fixed_time);tsaplan=coverage(certs,tsa,crls,timestamps,fixed_time);plan=dict(codeplan['chains']);plan.update(tsaplan['chains']);allcerts=dict(allanchors);allcerts.update(certs)
 def write(name,blob):
  p=root/name
  with p.open('xb') as f:f.write(blob)
  p.chmod(0o400);return str(p)
 leafpaths={f:write(f+'.pem',pem('CERTIFICATE',certs[f]['der'])) for f in [AUTHOR,REPOSITORY,*timestamps]}
 paths={'codeRoots':write('code-roots.pem',code_bundle),'timestampRoots':write('timestamp-roots.pem',timestamp_bundle),'author':leafpaths[AUTHOR],'repository':leafpaths[REPOSITORY],'tsaLeaves':[leafpaths[f] for f in timestamps],'intermediates':write('untrusted.pem',b''.join(pem('CERTIFICATE',c['der']) for c in certs.values())),'crls':write('current-crls.pem',b''.join(pem('X509 CRL',r['der']) for r in {x['sha256']:x for x in crls}.values()))}
 proof={'state':'EXACT_ROLE_CURRENT_CRL_DATA_NATIVE_RESULTS_PENDING','roles':roles,'codeCoverage':codeplan,'timestampCoverage':tsaplan,'fixedCurrentUnixTime':fixed_time,'bundleSHA256':{'code':sha(code_bundle),'timestamp':sha(timestamp_bundle)},'inputCRLs':[{'sha256':r['sha256'],'AKI':r['AKI'],'issuerDER_SHA256':sha(r['issuerDER']),'thisUpdate':r['thisUpdate'],'nextUpdate':r['nextUpdate']} for r in crls],'fileSHA256':{k:sha(Path(p).read_bytes()) for k,p in paths.items() if isinstance(p,str)}}
 return paths,plan,allcerts,proof

def close_external_sockets():
 """Read only own FDs; ensure no connected external socket can cross transition."""
 import fcntl
 own={}
 for p in Path('/proc/self/fd').iterdir():
  try:
   target=os.readlink(p)
   if target.startswith('socket:['):own[target[8:-1]]=int(p.name)
  except FileNotFoundError:pass
 allowed=set()
 for name in ('tcp','tcp6'):
  for line in Path('/proc/self/net',name).read_text().splitlines()[1:]:
   fields=line.split();inode=fields[9]
   if inode not in own:continue
   remote,port=fields[2].split(':');rawip=bytes.fromhex(remote)
   if name=='tcp':rawip=rawip[::-1]
   else:rawip=b''.join(rawip[i:i+4][::-1] for i in range(0,16,4))
   ip=ipaddress.ip_address(rawip);need(ip.is_loopback or (ip.is_unspecified and port=='0000'),'PREFETCH_EXTERNAL_SOCKET_STILL_CONNECTED');allowed.add(inode)
 need(set(own)<=allowed,'PREFETCH_UNKNOWN_SOCKET_FD');need(all(fcntl.fcntl(fd,fcntl.F_GETFD)&fcntl.FD_CLOEXEC for fd in own.values()),'SOCKET_FD_INHERITANCE');return {'openOwnSockets':len(own),'connectedExternalSockets':0,'allCloseOnExec':True}

def _parent_cli():
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--deny-parent',type=Path,required=True);p.add_argument('--sha256',required=True);a=p.parse_args();path=a.deny_parent;need(path.is_absolute() and path.name=='network-transition-request.json' and not path.is_symlink() and path.stat().st_size<=16384,'DENY_REQUEST_FILE');body=path.read_bytes();need(sha(body)==a.sha256,'DENY_REQUEST_BYTES');request=json.loads(body);need(request.get('requestSHA256')==sha(json.dumps({k:v for k,v in request.items() if k!='requestSHA256'},sort_keys=True,separators=(',',':')).encode()),'DENY_REQUEST_CANONICAL_IDENTITY');need(path.stat().st_uid==request['uid'] and path.parent.stat().st_uid==request['uid'] and path.parent.stat().st_mode&0o777==0o700,'DENY_REQUEST_PRIVATE_OWNER');proof=scoped_parent_transition(request);print(json.dumps(proof,separators=(',',':')))
if __name__=='__main__':
 import sys
 try:_parent_cli()
 except BaseException as exc:
  code=str(exc) if isinstance(exc,Hold) and re.fullmatch('[A-Z][A-Z0-9_]{0,95}',str(exc)) else 'OWNED_DENY_PARENT_OS_OR_FORMAT_UNAVAILABLE'
  print(json.dumps({'state':'HOLD','code':code}));sys.exit(3)
