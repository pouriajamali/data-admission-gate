"""Fixed one-shot WindowsServer2025 SDK11 qualifier. Qualification-only, no genericexec."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,re,sys,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent
p=HERE/'sdk11_ci_runtime.py'
if hashlib.sha256(p.read_bytes()).hexdigest()!='86c9962ae2bf19a8e9977ccb98fa729efb539e8aeb063af170b799a58802f5e0':raise RuntimeError('RUNTIME_SOURCE_IDENTITY')
spec=importlib.util.spec_from_file_location('sdk11_ci_runtime',p);R=importlib.util.module_from_spec(spec);sys.modules[spec.name]=R;spec.loader.exec_module(R)
j=R.load_module('windows_qualification_job',R.PINS['jobHelperSha256'])
class Backend:
 def __init__(self,spec):self.spec=spec;self.counter=0
 def run(self,argv,cwd,env,deadline,evidence):return j.run_job(argv,cwd,env,deadline,evidence,inherited_job_name=self.spec['jobName'])
 def hold(self,p):return j.held_windows_image(p)
 def caps(self):
  R.f.need(os.getpid()==self.spec['workerPID'] and j._start_identity(os.getpid())==self.spec['workerStart'],'WORKER_CREATION_IDENTITY');cap=j.current_witness(self.spec['jobName']);self.counter+=1;file=Path(self.spec['root'])/('aggregate-witness-'+str(self.counter)+'.json');R.write(file,cap)
  return {'kind':'actual-Windows-Job','memoryMax':cap['memoryMax'],'tasksMax':cap['tasksMax'],'effectiveCpuCores':cap['effectiveCpuCores'],'swapMax':None,'membershipBeforeExec':bool(self.spec['beforeResume']['membership']),'heldChildIdentityBeforeExec':bool(self.spec['beforeResume']['retainedCreationHandles']),'uid':None,'gid':None,'kernelReadbackSha256':R.digest(file),'peakMemoryBytes':cap['peakMemoryBytes']}
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--expected-commit');parser.add_argument('--worker',type=Path);args=parser.parse_args();R.f.need(os.name=='nt','NAMED_WINDOWS_HOST_REQUIRED')
 if args.worker:
  s=R.read(args.worker);R.f.need(s['rid']=='win-x64' and s['purpose']=='FIXED_CI_QUALIFICATION_ONLY','FIXED_ROLE_REQUIRED');R.a.scoped(args.worker,Path(os.environ['RUNNER_TEMP']));boot=R.read(s['bootstrap']);R.f.need(Path(sys.executable).resolve()==Path(boot['pythonExe']).resolve() and R.digest(sys.executable)==boot['pythonExeSha256'] and boot['pythonVersion']=='3.12.10' and boot['pythonSignature']=='ValidPythonSoftwareFoundationWithTimestamp','PYTHON_TRUSTED_BOOTSTRAP_IDENTITY');R.f.need(R.digest(Path(sys.executable).parent/'python312.dll')==boot['pythonDllSha256'],'PYTHON_DLL_IDENTITY');R.worker(s,Backend(s));return
 R.f.source(os.environ.get('GITHUB_SHA'),args.expected_commit);R.f.need(os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Windows','NAMED_WINDOWS_HOST_REQUIRED')
 start=int(os.environ['SDK11_QUALIFICATION_START_TICK']);R.f.need(0<=R.clock()-start<60000,'STARTUP60_EXPIRED');temp=Path(os.environ['RUNNER_TEMP']).resolve();root=temp/('admission04-sdk11-win-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']);R.a.scoped(root,temp,absent=True);root.mkdir();bootstrap=Path(os.environ['SDK11_QUALIFICATION_BOOTSTRAP']);R.a.scoped(bootstrap,temp);boot=R.read(bootstrap);R.f.need(R.digest(sys.executable)==boot['pythonExeSha256'],'PYTHON_BOOTSTRAP_CHANGED')
 R.write(root/'stage-0.json',{'index':0,'startedTick':start,'deadlineTick':start+60000});private=root/'private-spec.json';value={'root':str(root),'rid':'win-x64','purpose':'FIXED_CI_QUALIFICATION_ONLY','expectedCommit':args.expected_commit,'startTick':start,'bootstrap':str(bootstrap)};name='Local\\admission04-sdk11-'+uuid.uuid4().hex
 env={k:v for k,v in os.environ.items() if not k.upper().endswith(('TOKEN','SECRET','PASSWORD'))};env['PYTHONDONTWRITEBYTECODE']='1'
 # The existing trusted image Python/shell before this call is a bounded bootstrap,
 # not claimed insideJob. Allworker/acquisition/extraction/tests/SDK descendants are.
 record=j.run_job([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(private)],R.ROOT,env,start+840000,root/'outer-job',job_name=name,ready_spec={'path':private,'value':value},stage_directory=root)
 R.f.need(record['actualCap']['activeProcessesAtTeardown']==0 and record['exitCode']==0,'OWNED_AGGREGATE_TERMINAL');terminal={'workerExitCode':0,'ownedPopulation':0,'supervisorObservedTerminal':True,'typedStopResult':'success','terminalEvidenceSha256':R.digest(root/'outer-job/process.json')};R.publish_proof(value,terminal,record['actualCap']['peakJobMemory'])
if __name__=='__main__':
 try:main()
 except BaseException as exc:
  R.capture_entry_failure(exc);raise
