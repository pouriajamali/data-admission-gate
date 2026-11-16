"""12 fixed SDK-free denials and1 different-job positivecontrol peractualmode."""
from __future__ import annotations
import argparse,copy,hashlib,importlib.util,json,os,socket,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=HERE/'sdk11_ci_facts.py'
if hashlib.sha256(p.read_bytes()).hexdigest()!='6bb0fe5199377dfdb0caed76cf274bcef631205648d9dbf0d67e1f43433e9a7e':raise RuntimeError('FACT_SOURCE_IDENTITY')
spec=importlib.util.spec_from_file_location('sdk11_ci_facts',p);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
p=HERE/'check_dotnet11.py'
if hashlib.sha256(p.read_bytes()).hexdigest()!='d9c690d8c82825b018c04089c279036829d3baf2534c2634bba84910c415a37d':raise RuntimeError('NORMAL_GUARD_SOURCE_IDENTITY')
spec=importlib.util.spec_from_file_location('normal_product_guard',p);normal=importlib.util.module_from_spec(spec);spec.loader.exec_module(normal)
SPAWNS=0;NETWORK=0
def denied_spawn(*args,**kwargs):
 global SPAWNS
 SPAWNS+=1;raise RuntimeError('CANDIDATE_SPAWN_FORBIDDEN')
def denied_network(*args,**kwargs):
 global NETWORK
 NETWORK+=1;raise RuntimeError('NETWORK_FORBIDDEN')
subprocess.Popen=denied_spawn;os.system=denied_spawn;os.execve=denied_spawn;os.execvpe=denied_spawn;socket.socket=denied_network

def main():
 p=argparse.ArgumentParser();p.add_argument('--rid',required=True,choices=list(f.HOSTS));p.add_argument('--out',type=Path,required=True);args=p.parse_args();rid=args.rid;rows=[]
 def reject(name,literal,call):
  try:call()
  except (f.Denied,normal.AdmissionError) as error:f.need(str(error)==literal,'WRONG_LITERAL_DIAGNOSTIC:'+name);rows.append({'id':name,'diagnostic':str(error)})
  else:raise RuntimeError('DENIAL_MISSING:'+name)
 c={'state':'REVIEWED_TYPED_ARCHIVE_INPUT_NOT_EXECUTED','purpose':'FIXED_CI_QUALIFICATION_ONLY','rid':rid,'sdk':'11.0.100','runtime':'11.0.0','url':f.RAW[rid][0],'bytes':f.RAW[rid][1],'sha512':f.RAW[rid][2],'memberManifestSha256':f.MANIFESTS[rid],'members':[]}
 reject('Q01-metadata-only','Q_CATALOG_STATE',lambda:f.catalog(dict(c,state='METADATA_ONLY_NOT_EXECUTABLE'),rid))
 fixture=HERE/'fixtures/windows_qualification_denials.json';f.need(fixture.stat().st_size<=1024 and hashlib.sha256(fixture.read_bytes()).hexdigest()=='d8b2b3bc9a95ba1e7ab9332f3fcef9826e7cbd9fd83059c7f2e0d475627aa13f','FIXTURE_IDENTITY');normal.LOCK=fixture
 reject('Q02-normal-product-rejects-reviewed-input','SDK_CATALOG_NOT_QUALIFIED',lambda:normal.qualified(rid))
 reject('Q03-rid','Q_CATALOG_RID',lambda:f.catalog(dict(c,rid='other-rid'),rid))
 reject('Q04-input-manifest','Q_CATALOG_IDENTITY',lambda:f.catalog(dict(c,memberManifestSha256='0'*64),rid))
 host={'hostClass':f.HOSTS[rid],'rid':rid,'architecture':'x64','instanceId':'synthetic-instance','imageVersion':'synthetic-only','imageOS':'win25' if rid=='win-x64' else 'ubuntu24','runId':'producer-old','job':'verify','repository':'pouriajamali/data-admission-gate','osVersion':'Windows Server 2025 Datacenter' if rid=='win-x64' else 'Ubuntu 24.04','kernelBuild':'26100.0','uid':1001,'gid':1001}
 reject('Q05-wrong-host-class','Q_HOST_CLASS',lambda:f.host(dict(host,hostClass='WindowsLocal26H2'),rid))
 reject('Q06-source','Q_SOURCE_IDENTITY',lambda:f.source('2'*40,'1'*40))
 cap={'kind':'actual-Windows-Job' if rid=='win-x64' else 'actual-Linux-cgroup-v2','memoryMax':4294967296,'tasksMax':64,'effectiveCpuCores':2,'swapMax':0,'uid':1001,'membershipBeforeExec':True,'heldChildIdentityBeforeExec':True}
 reject('Q07-missing-actual-cap','Q_ACTUAL_CAP_REQUIRED',lambda:f.caps(None,rid))
 reject('Q08-before-exec-membership','Q_PREEXEC_MEMBERSHIP',lambda:f.caps(dict(cap,membershipBeforeExec=False),rid))
 reject('Q09-cpu-v2','Q_CPU_V2_BEFORE_SDK',lambda:f.cpu({'features':[],'processorCount':1}))
 reject('Q10-owned-terminal','Q_TERMINAL_REQUIRED',lambda:f.terminal({'workerExitCode':0,'ownedPopulation':1,'supervisorObservedTerminal':True,'typedStopResult':'success'}))
 fact={'qualifiedOn':host,'tree':{'memberManifestSha256':f.MANIFESTS[rid]}};admit={'state':'ADMITTED_EXACT_SUPPORTED_HOST_CLASS','projectId':'04','rid':rid,'producerFactSha256':'a'*64,'admittedForHostClass':f.HOSTS[rid],'sourceCommit':'1'*40,'sourceTree':'2'*40,'contractSha256':'3'*64,'catalogManifestSha256':f.MANIFESTS[rid]};current={'rid':rid,'hostClass':f.HOSTS[rid],'sourceCommit':'1'*40,'sourceTree':'2'*40,'contractSha256':'3'*64,'runId':'consumer-different','job':'own-consumer-job','attempt':'2','caps':cap}
 reject('Q11-consumer-host-mismatch','CONSUMER_HOST_CLASS_MISMATCH',lambda:f.consume(fact,admit,dict(current,hostClass='UNSUPPORTED_LOCAL'), 'a'*64))
 if rid=='linux-x64':reject('Q12-root-worker-uid','Q_HOST_OS',lambda:f.host(dict(host,uid=0),rid))
 else:reject('Q12-transferable-ready','Q_TRANSFERABLE_READY_FORBIDDEN',lambda:f.validate_fact({'ready':True},{}))
 result=f.consume(fact,admit,current,'a'*64);f.need(result['producerQualifiedOn']['runId']!=result['currentExecution']['runId'],'WRONG_JOB_EQUALITY_RULE');f.need(len(rows)==12 and SPAWNS==NETWORK==0,'SDK_FREE_DENIAL_PROOF')
 args.out.mkdir(parents=True,exist_ok=False);value={'schema':'sdk11-ci-sdk-free-denials/v1','rid':rid,'state':'TWELVE_LITERAL_DENIALS_PASS','optimize':sys.flags.optimize,'count':12,'candidateSpawns':SPAWNS,'networkAttempts':NETWORK,'differentJobSameHostPositiveControls':1,'cases':rows,'scope':'Syntheticvaluevalidation only; no actualkernel/SDK/host qualification proof.'};(args.out/'receipt.json').write_text(json.dumps(value,indent=2)+'\n')
if __name__=='__main__':main()
