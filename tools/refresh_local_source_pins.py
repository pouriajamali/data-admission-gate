"""Refresh only the dedicated local caller complete source table from staged blobs."""
import json,subprocess
from pathlib import Path
r=Path(__file__).resolve().parents[1];target='tools/producer04-local-source-pins.json';rows=[]
for line in subprocess.check_output(['git','-C',str(r),'ls-files','--stage','-z']).split(b'\0'):
 if not line:continue
 meta,name=line.split(b'\t',1);mode,blob,stage=meta.decode().split();name=name.decode();assert stage=='0' and mode in ('100644','100755')
 if name!=target:rows.append({'path':name,'mode':mode,'gitBlob':blob})
p=r/target;p.write_bytes((json.dumps({'schema':'sdk11-own-source-pins/v1','state':'EXACT_SOURCE_PINNED','projectId':'04','repository':'pouriajamali/data-admission-gate','sourcePins':rows},indent=2)+'\n').encode())
print('LOCAL_SOURCE_PINS',len(rows))
