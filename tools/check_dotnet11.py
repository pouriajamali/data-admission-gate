"""Portable data-only SDK11 transport/identity guard; never executes the downloaded SDK."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,re,stat,struct,tarfile,time,unicodedata,urllib.request,zipfile
from pathlib import Path,PurePosixPath
RAW_MAX=512*1024**2;EXPANDED_MAX=4*1024**3;MEMBER_MAX=256*1024**2;COUNT_MAX=64000
ROOT=Path(__file__).resolve().parents[1]
LOCK=ROOT/'tools/dotnet11-inputs.lock.json'
INPUTS={'win-x64': {'url': 'https://builds.dotnet.microsoft.com/dotnet/Sdk/11.0.100/dotnet-sdk-11.0.100-win-x64.zip', 'sha512': '5cdd9122c84873f090038548ebe8a4786e5c50a6b1b9792ca2c6dab82fd74a0d7f1d6cdf59e7dcd25e4903dd44f37af5d7ed73ecd3bca4d0cce948b5572452c3'}, 'linux-x64': {'url': 'https://builds.dotnet.microsoft.com/dotnet/Sdk/11.0.100/dotnet-sdk-11.0.100-linux-x64.tar.gz', 'sha512': '1bec9cca2ec689b1e80245b84f2b53c9441d1aa6daccf2ceb27490768bffa95954fa585bd275def31069d874d543d9ba9e6591fe9ade2dbd9f34ec5c0fd0050c'}}
class AdmissionError(RuntimeError):pass

def need(value,reason):
 if not value:raise AdmissionError(reason)

def digest(path,algorithm='sha256'):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,algorithm).hexdigest()

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')

def member_path(name):
 need(isinstance(name,str) and len(name.encode('utf-8'))<=4096 and not any(ord(c)<32 or ord(c)==127 for c in name),'ARCHIVE_PATH_INVALID')
 need('\\' not in name and ':' not in name and not name.startswith('/') and unicodedata.normalize('NFC',name)==name,'ARCHIVE_PATH_INVALID')
 # A typed leading ./ and root directory entry are canonical TAR syntax, not traversal.
 if name.startswith('./'):name=name[2:]
 name=name.rstrip('/')
 if name in ('','.'):return ''
 parts=name.split('/');need(all(p not in ('','..','.') and not p.endswith((' ','.')) for p in parts),'ARCHIVE_PATH_INVALID')
 need(all(p.split('.')[0].upper() not in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]} for p in parts),'ARCHIVE_PATH_INVALID')
 need(not PurePosixPath(name).is_absolute(),'ARCHIVE_PATH_INVALID');return name

class Inventory:
 def __init__(self):self.seen={};self.members=[];self.total=0
 def add(self,name,size,kind,mode):
  need(kind in ('file','directory'),'ARCHIVE_SPECIAL_UNSUPPORTED');p=member_path(name)
  need(type(size) is int and 0<=size<=MEMBER_MAX and not(mode&0o7000),'ARCHIVE_LIMIT_EXCEEDED')
  if not p:
   need(kind=='directory' and size==0,'ARCHIVE_PATH_INVALID');need('' not in self.seen,'ARCHIVE_DUPLICATE_MEMBER');self.seen['']='directory'
   row={'path':'','type':'directory','bytes':0,'mode':mode&0o777};self.members.append(row);return row
  key=p.casefold();need(key not in self.seen,'ARCHIVE_DUPLICATE_MEMBER')
  for parent in PurePosixPath(p).parents:
   k=str(parent).casefold()
   if k!='.':need(self.seen.get(k)!='file','ARCHIVE_DUPLICATE_MEMBER')
  if kind=='file':need(not any(k.startswith(key+'/') for k in self.seen),'ARCHIVE_DUPLICATE_MEMBER')
  self.seen[key]=kind;self.total+=size;need(len(self.seen)<=COUNT_MAX and self.total<=EXPANDED_MAX,'ARCHIVE_LIMIT_EXCEEDED')
  row={'path':p,'type':kind,'bytes':size,'mode':mode&0o777};self.members.append(row);return row

def extract_members(archive,destination,rid):
 """Synthetic guard harness may call this parser; production requires extract_sdk raw admission first."""
 need(rid in INPUTS,'INPUT_IDENTITY_MISMATCH');dest=Path(destination);need(not dest.exists(),'OUTPUT_SCOPE_INVALID');dest.mkdir(parents=True)
 inv=Inventory();start=time.monotonic()
 def materialize(row,stream):
  if row is None:return
  p=dest/row['path'];need(p.resolve(strict=False).is_relative_to(dest.resolve()),'ARCHIVE_PATH_INVALID')
  if row['type']=='directory':p.mkdir(parents=True,exist_ok=True);return
  p.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();size=0
  with p.open('xb') as out:
   while True:
    need(time.monotonic()-start<=300,'ARCHIVE_LIMIT_EXCEEDED');data=stream.read(min(1024**2,row['bytes']-size+1))
    if not data:break
    size+=len(data);need(size<=row['bytes'],'ARCHIVE_LIMIT_EXCEEDED');out.write(data);h.update(data)
  need(size==row['bytes'],'ARCHIVE_LIMIT_EXCEEDED');row['sha256']=h.hexdigest()
  if os.name!='nt':p.chmod(row['mode'])
 if rid=='win-x64':
  with zipfile.ZipFile(archive) as z:
   need(len(z.infolist())<=COUNT_MAX,'ARCHIVE_LIMIT_EXCEEDED')
   for x in z.infolist():
    mode=x.external_attr>>16;kind=stat.S_IFMT(mode);need(not(x.flag_bits&1),'ARCHIVE_SPECIAL_UNSUPPORTED')
    need(kind!=stat.S_IFLNK,'ARCHIVE_LINK_UNSUPPORTED');need(kind in (0,stat.S_IFREG,stat.S_IFDIR),'ARCHIVE_SPECIAL_UNSUPPORTED')
    isdir=x.is_dir();need((kind!=stat.S_IFDIR or isdir) and (not isdir or x.file_size==0),'ARCHIVE_SPECIAL_UNSUPPORTED')
    row=inv.add(x.filename,x.file_size,'directory' if isdir else 'file',mode)
    if isdir:materialize(row,None)
    else:
     with z.open(x) as source:materialize(row,source)
 else:
  with gzip.open(archive,'rb') as gz,tarfile.open(fileobj=gz,mode='r|') as tar:
   for x in tar:
    need(not(x.issym() or x.islnk()),'ARCHIVE_LINK_UNSUPPORTED');need(x.isfile() or x.isdir(),'ARCHIVE_SPECIAL_UNSUPPORTED')
    row=inv.add(x.name,x.size,'directory' if x.isdir() else 'file',x.mode)
    if x.isdir():materialize(row,None)
    else:
     with tar.extractfile(x) as source:materialize(row,source)
   trailing=0
   while True:
    block=tar.fileobj.read(1024**2)
    if not block:break
    trailing+=len(block);need(trailing<=1024**2 and not any(block),'ARCHIVE_SPECIAL_UNSUPPORTED')
 return inv.members

def critical_names(rid):
 suffix='.exe' if rid=='win-x64' else ''
 native=['host/fxr/11.0.0/hostfxr.dll','shared/Microsoft.NETCore.App/11.0.0/coreclr.dll','shared/Microsoft.NETCore.App/11.0.0/clrjit.dll'] if suffix else ['host/fxr/11.0.0/libhostfxr.so','shared/Microsoft.NETCore.App/11.0.0/libcoreclr.so','shared/Microsoft.NETCore.App/11.0.0/libclrjit.so']
 return ['dotnet'+suffix,'sdk/11.0.100/dotnet.dll','sdk/11.0.100/Roslyn/bincore/csc.dll',*native]

def machine(path):
 with Path(path).open('rb') as f:
  header=f.read(64)
  if header[:2]==b'MZ':
   need(len(header)==64,'NATIVE_TARGET_UNSUPPORTED');f.seek(struct.unpack_from('<I',header,60)[0]);pe=f.read(6);need(pe[:4]==b'PE\0\0','NATIVE_TARGET_UNSUPPORTED');return ('PE',struct.unpack_from('<H',pe,4)[0])
  need(header[:4]==b'\x7fELF' and header[4:6]==b'\x02\x01','NATIVE_TARGET_UNSUPPORTED');return ('ELF',struct.unpack_from('<H',header,18)[0])

def verify_tree(root,members,rid,full=False):
 root=Path(root);files={x['path']:x for x in members if x['type']=='file'}
 names=files if full else critical_names(rid)
 for name in names:
  need(name in files,'SDK_MEMBER_MISMATCH');row=files[name];p=root/name
  need(p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes'] and digest(p)==row['sha256'],'SDK_MEMBER_MISMATCH')
  if os.name!='nt':need(stat.S_IMODE(p.stat().st_mode)==row['mode'],'SDK_MEMBER_MISMATCH')
 if full:
  actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()};need(actual==set(files),'SDK_MEMBER_MISMATCH')
  need(not any(p.is_symlink() for p in root.rglob('*')),'SDK_MEMBER_MISMATCH')
  directories={x['path'] for x in members if x['type']=='directory' and x['path']}
  for name in files:directories.update(str(p) for p in PurePosixPath(name).parents if str(p)!='.')
  need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()}==directories,'SDK_MEMBER_MISMATCH')
 need(machine(root/critical_names(rid)[0])==(('PE',0x8664) if rid=='win-x64' else ('ELF',62)),'NATIVE_TARGET_UNSUPPORTED')
 notices=[x for x in members if x['type']=='file' and re.match(r'(?i)(license|third.?party.?notices)',PurePosixPath(x['path']).name)]
 need(any(PurePosixPath(x['path']).name.lower()=='license.txt' for x in notices) and any('third' in PurePosixPath(x['path']).name.lower() for x in notices),'SDK_MEMBER_MISMATCH')
 need(any(n.startswith('packs/Microsoft.NETCore.App.Ref/11.0.0/ref/net11.0/') for n in files),'SDK_MEMBER_MISMATCH')
 return notices
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AdmissionError('SDK_TRANSPORT_REDIRECT_REJECTED')
def qualified(rid):
 lock=json.loads(LOCK.read_bytes());need(lock.get('state')=='QUALIFIED_SOURCE_HELD_CATALOG' and lock.get('sdk')=='11.0.100' and lock.get('runtime')=='11.0.0','SDK_CATALOG_NOT_QUALIFIED')
 target=lock.get('qualifiedCatalog',{}).get(rid);need(isinstance(target,dict) and target.get('raw',{}).get('sha512')==INPUTS[rid]['sha512'],'SDK_CATALOG_IDENTITY')
 need(hashlib.sha256(canonical(target['members'])).hexdigest()==target.get('memberManifestSha256'),'SDK_CATALOG_IDENTITY');return target

def transport(rid,directory):
 catalog=qualified(rid);temp=Path(os.environ.get('RUNNER_TEMP','')).resolve();need(bool(os.environ.get('RUNNER_TEMP')) and temp.is_dir(),'SDK_TRANSPORT_SCOPE')
 directory=Path(directory).absolute();need(directory.resolve(strict=False).is_relative_to(temp) and not directory.exists(),'SDK_TRANSPORT_SCOPE')
 for ancestor in directory.parents:
  if ancestor.exists():need(not ancestor.is_symlink() and not(getattr(ancestor.lstat(),'st_file_attributes',0)&1024),'SDK_TRANSPORT_SCOPE')
  if ancestor==temp:break
 directory.mkdir(parents=True,exist_ok=False);archive=directory/'official-archive';source=INPUTS[rid]
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());request=urllib.request.Request(source['url'],headers={'Accept-Encoding':'identity','User-Agent':'admission04-qualified-sdk-transport'})
 size=0;h=hashlib.sha512();started=time.monotonic()
 with opener.open(request,timeout=30) as response,archive.open('xb') as out:
  length=response.headers.get('Content-Length');need(response.status==200 and response.url==source['url'] and length and length.isdigit() and 0<int(length)<=RAW_MAX and not response.headers.get('Content-Range') and response.headers.get('Content-Encoding','identity')=='identity','SDK_TRANSPORT_IDENTITY')
  while True:
   need(time.monotonic()-started<=900,'SDK_TRANSPORT_WALL');block=response.read(1024**2)
   if not block:break
   size+=len(block);need(size<=RAW_MAX,'ARCHIVE_LIMIT_EXCEEDED');out.write(block);h.update(block)
 need(size==int(length) and h.hexdigest()==source['sha512'],'ARCHIVE_HASH_MISMATCH')
 destination=directory/'sdk';members=extract_members(archive,destination,rid);need(members==catalog['members'],'SDK_CATALOG_IDENTITY');verify_tree(destination,members,rid,full=True)
 # Ephemeral job environment only; no SDK cache/artifact upload or machine PATH install.
 envfile=os.environ.get('GITHUB_ENV');pathfile=os.environ.get('GITHUB_PATH');need(envfile and pathfile and '\n' not in str(destination) and '\r' not in str(destination),'SDK_TRANSPORT_SCOPE')
 with open(envfile,'a',encoding='utf-8',newline='\n') as f:f.write('DOTNET_ROOT='+str(destination)+'\nDOTNET_ROOT_X64='+str(destination)+'\n')
 with open(pathfile,'a',encoding='utf-8',newline='\n') as f:f.write(str(destination)+'\n')
 print(json.dumps({'state':'EXACT_SDK11_EPHEMERAL_TRANSPORT_VERIFIED','rid':rid,'archiveBytes':size,'archiveSha512':h.hexdigest(),'memberManifestSha256':catalog['memberManifestSha256'],'SDKExecutions':0,'SDKArtifactCacheUploads':0}))
def main():
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['inspect','transport']);parser.add_argument('--rid',choices=list(INPUTS),required=True);parser.add_argument('--root',type=Path);parser.add_argument('--directory',type=Path);args=parser.parse_args()
 if args.mode=='transport':need(args.directory is not None,'SDK_TRANSPORT_SCOPE');transport(args.rid,args.directory)
 else:
  need(args.root is not None,'SDK_MEMBER_MISMATCH');catalog=qualified(args.rid);verify_tree(args.root,catalog['members'],args.rid,full=True);print(json.dumps({'state':'SOURCE_HELD_SDK11_IDENTITY_VERIFIED','rid':args.rid,'SDKExecutions':0}))
if __name__=='__main__':main()
