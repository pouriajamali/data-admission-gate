"""Independent source/cap policy boundaries; no SDK/process/network work."""
import importlib.util,sys,unittest
from pathlib import Path
p=Path(__file__).with_name('local_sdk11_input.py');s=importlib.util.spec_from_file_location('local_sdk_input',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
def profile(project='04',rid='linux-x64',role='generic'):
 mem,tasks,cpu=m.MATRIX[project]
 if project=='06' and rid=='win-x64':mem,tasks,cpu=1073741824,16,1
 if project=='06' and role=='native-linux16':mem,tasks,cpu=4294967296,128,2
 v={'schema':'sdk11-own-normal-input-profile/v1','state':'ADMITTED_SOURCE_PROFILE','projectId':project,'repository':'pouriajamali/'+m.REPOS[project],'rowSeconds':m.C.BUDGETS[project],'memoryMaxBytes':mem,'tasksMax':tasks,'swapMaxBytes':0 if rid=='linux-x64' else None,'cpuQuotaMicros':cpu*100000,'cpuPeriodMicros':100000,'cpuCores':cpu,'localInputRoute':{'rid':rid,'role':role,'readOnlyExistingPool':True,'qualifiedFactSha256':m.FACTS[rid]}}
 if rid=='win-x64':v['localInputRoute'].update(authorityId=m.WINDOWS_AUTHORITIES.get(project),formalDotnet11Support='NOT_CONFIRMED')
 return v
class Policies(unittest.TestCase):
 def test01_does_not_borrow04_memory(self):
  v=profile('01');self.assertEqual(m.policy(v,'01','linux-x64')[0],2147483648);v['memoryMaxBytes']=4294967296
  with self.assertRaises(m.C.AdmissionError):m.policy(v,'01','linux-x64')
 def test06_windows_keeps_original_small_job(self):self.assertEqual(m.policy(profile('06','win-x64','R06_WINDOWS'),'06','win-x64'),(1073741824,16,1))
 def test06_windows_generic_producer_caps_denied(self):
  with self.assertRaises(m.C.AdmissionError):m.policy(profile('06','win-x64','generic'),'06','win-x64')
 def test06_cannot_borrow04_authority(self):
  v=profile('06','win-x64','R06_WINDOWS');v['localInputRoute']['authorityId']=m.WINDOWS_AUTHORITIES['04']
  with self.assertRaises(m.C.AdmissionError):m.policy(v,'06','win-x64')
 def test_retired_linux_r3_role_denied(self):
  with self.assertRaises(m.C.AdmissionError):m.policy(profile('06','linux-x64','R3'),'06','linux-x64')
 def test_native128_reserved_for_original_native16(self):self.assertEqual(m.policy(profile('06','linux-x64','native-linux16'),'06','linux-x64')[1],128)
 def test_generic06_cannot_increase64_to128(self):
  v=profile('06');v['tasksMax']=128
  with self.assertRaises(m.C.AdmissionError):m.policy(v,'06','linux-x64')
 def test_original_budget_not_renewed_or_grown(self):
  v=profile();v['rowSeconds']=901
  with self.assertRaises(m.C.AdmissionError):m.policy(v,'04','linux-x64')
 def test_no_owned_sdk_allocation(self):
  v=profile();v['localInputRoute']['readOnlyExistingPool']=False
  with self.assertRaises(m.C.AdmissionError):m.policy(v,'04','linux-x64')
 def test_no_official_windows_support_claim(self):
  v=profile('04','win-x64');v['localInputRoute']['formalDotnet11Support']='SUPPORTED'
  with self.assertRaises(m.C.AdmissionError):m.policy(v,'04','win-x64')
 def test05_windows_scope_not_inferred(self):
  with self.assertRaises(m.C.AdmissionError):m.policy(profile('05','win-x64'),'05','win-x64')
 def test_repository_misattribution_denied(self):
  v=profile();v['repository']='pouriajamali/fenced-shard-ownership-lab'
  with self.assertRaises(m.C.AdmissionError):m.policy(v,'04','linux-x64')
if __name__=='__main__':unittest.main()
