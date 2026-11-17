"""Only the fixed local console-mode delta; no runtime/SDK/old suite replay."""
import ast,hashlib,importlib.util,os,unittest
from pathlib import Path
from unittest import mock
r=Path(__file__).resolve().parent;p=r/'windows_qualification_job_local.py';sp=importlib.util.spec_from_file_location('localjob',p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
class Delta(unittest.TestCase):
 def test_only_selector_and_exact_flag_parameter_differ(self):
  raw=(r/'windows_qualification_job.py').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'0959e7cb097bb17d774ed0824bb7b9e95e1b94112d968d343fb9fca0fb5166ce');a=ast.parse(raw);b=ast.parse(p.read_bytes())
  class Restore(ast.NodeTransformer):
   def visit_FunctionDef(self,n):
    if n.name=='fixed_local_creation_flags':return None
    if n.name=='run_job':
     assert n.args.args[-1].arg=='local_console_mode' and n.args.defaults[-1].value is None;n.args.args.pop();n.args.defaults.pop();assert n.body[0].targets[0].id=='creation_flags';n.body.pop(0)
    return self.generic_visit(n)
   def visit_Call(self,n):
    if isinstance(n.func,ast.Attribute) and n.func.attr=='CreateProcessW':
     assert isinstance(n.args[5],ast.Name) and n.args[5].id=='creation_flags';n.args[5]=ast.parse('0x4|0x400|0x08000000',mode='eval').body
    return self.generic_visit(n)
  self.assertEqual(ast.dump(a,include_attributes=False),ast.dump(Restore().visit(b),include_attributes=False))
 def test_default_exactly_preserved(self):self.assertEqual(m.fixed_local_creation_flags(None,None,None,None),0x08000404)
 def test_detached_mask_is_fixed_with_only_suspended_unicode_detached(self):
  with mock.patch.dict(os.environ,{},clear=True):self.assertEqual(m.fixed_local_creation_flags('DETACHED_LOCAL_CONSOLE_FREE_V1','Local\\own',None,{'path':'own','value':{}}),0x40c)
 def test_arbitrary_or_conflicting_flags_denied(self):
  for v in [0x40c,'CREATE_NO_WINDOW','DETACHED_PROCESS|CREATE_NEW_CONSOLE','DETACHED_PROCESS|BREAKAWAY']:
   with self.assertRaises(m.CapError):m.fixed_local_creation_flags(v,'Local\\own',None,{'path':'own','value':{}})
 def test_hosted_mode_denied(self):
  with mock.patch.dict(os.environ,{'GITHUB_ACTIONS':'true'},clear=True):
   with self.assertRaises(m.CapError):m.fixed_local_creation_flags('DETACHED_LOCAL_CONSOLE_FREE_V1','Local\\own',None,{'path':'own','value':{}})
 def test_unheld_or_nested_main_denied(self):
  with mock.patch.dict(os.environ,{},clear=True):
   for name,inherited,ready in [('Local\\own','Local\\parent',{'path':'own','value':{}}),('Local\\own',None,None),(None,None,{'path':'own','value':{}})]:
    with self.assertRaises(m.CapError):m.fixed_local_creation_flags('DETACHED_LOCAL_CONSOLE_FREE_V1',name,inherited,ready)
if __name__=='__main__':unittest.main()
