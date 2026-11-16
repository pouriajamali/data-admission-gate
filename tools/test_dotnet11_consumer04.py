"""Six ownconsumer04 changed-boundary denials only; noSDK/network/oldtest replay."""
import argparse,hashlib,importlib.util,json,os,subprocess,sys
from pathlib import Path
p=Path(__file__).parent/'sdk11_ci_facts.py';spec=importlib.util.spec_from_file_location('factguard',p);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
SPAWNS=0
def forbidden(*args,**kwargs):
 global SPAWNS
 SPAWNS+=1;raise RuntimeError('SDK_SPAWN_FORBIDDEN')
subprocess.Popen=forbidden;os.system=forbidden
p=argparse.ArgumentParser();p.add_argument('--rid',required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args();rid=args.rid
cap={'kind':'actual-Windows-Job' if rid=='win-x64' else 'actual-Linux-cgroup-v2','memoryMax':4294967296,'tasksMax':64,'effectiveCpuCores':2,'swapMax':0,'uid':1001,'membershipBeforeExec':True,'heldChildIdentityBeforeExec':True};fact={'qualifiedOn':{'rid':rid,'hostClass':f.HOSTS[rid]},'tree':{'memberManifestSha256':f.MANIFESTS[rid]}};ad={'state':'ADMITTED_EXACT_SUPPORTED_HOST_CLASS','projectId':'04','rid':rid,'producerFactSha256':'a'*64,'admittedForHostClass':f.HOSTS[rid],'sourceCommit':'1'*40,'sourceTree':'2'*40,'contractSha256':'3'*64,'catalogManifestSha256':f.MANIFESTS[rid]};cur={'rid':rid,'hostClass':f.HOSTS[rid],'sourceCommit':'1'*40,'sourceTree':'2'*40,'contractSha256':'3'*64,'runId':'different-consumer','job':'verify','attempt':'2','caps':cap};cases=[('C01','CONSUMER_ADMISSION_REQUIRED',dict(ad,state='UNBOUND'),cur),('C02','CONSUMER_FACT_IDENTITY',dict(ad,producerFactSha256='b'*64),cur),('C03','CONSUMER_RID_MISMATCH',dict(ad,rid='other'),cur),('C04','CONSUMER_HOST_CLASS_MISMATCH',dict(ad,admittedForHostClass='WindowsLocal26H2'),cur),('C05','CONSUMER_SOURCE_CONTRACT',dict(ad,sourceTree='4'*40),cur),('C06','Q_PREEXEC_MEMBERSHIP',ad,dict(cur,caps=dict(cap,membershipBeforeExec=False)))];rows=[]
for name,literal,a,c in cases:
 try:f.consume(fact,a,c,'a'*64)
 except f.Denied as error:f.need(str(error)==literal,'CONSUMER_LITERAL_MISMATCH');rows.append({'id':name,'diagnostic':str(error)})
 else:raise RuntimeError('CONSUMER_DENIAL_MISSING')
f.need(len(rows)==6 and SPAWNS==0,'CONSUMER_SDK_FREE_GUARD');args.out.mkdir(parents=True,exist_ok=False);(args.out/'receipt.json').write_text(json.dumps({'count':6,'optimize':sys.flags.optimize,'candidateSpawns':SPAWNS,'cases':rows},indent=2)+'\n')
