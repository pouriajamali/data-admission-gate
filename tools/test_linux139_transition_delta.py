"""Only the Linux139 policy-child fault-isolation delta, no OS or SDK work."""
import ast,hashlib
from pathlib import Path
r=Path(__file__).resolve().parent
old=ast.parse((r/'curate_windows_inputs_local_linux.py').read_bytes());new=ast.parse((r/'diagnose_linux139_transition.py').read_bytes())
a=next(x for x in old.body if isinstance(x,ast.FunctionDef) and x.name=='run_parent');b=next(x for x in new.body if isinstance(x,ast.FunctionDef) and x.name=='run_parent')
class Restore(ast.NodeTransformer):
 def visit_Call(self,n):
  if isinstance(n.func,ast.Name) and n.func.id=='isolated_transition':
   assert len(n.args)==2 and n.args[0].id=='s' and n.args[1].id=='request';n.func=ast.Attribute(value=ast.Name(id='M',ctx=ast.Load()),attr='scoped_parent_transition',ctx=ast.Load());n.args=n.args[1:]
  return self.generic_visit(n)
 def visit_Constant(self,n):
  if n.value==45000:n.value=840000
  return n
assert ast.dump(a,include_attributes=False)==ast.dump(Restore().visit(b),include_attributes=False),'ALL_HELD_PIDFD_CAPS_REQUEST_IDENTITY_AND_CLEANUP_CONTROLS_MUST_REMAIN'
assert hashlib.sha256((r/'curation_linux_method.py').read_bytes()).hexdigest()=='e882af75dc56a5a0f9eb9b4101f2ccaf88141fa3ced9037ea0fd7b1eb357ed74'
assert not any(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr in ('native_prerequisites','inspect_sdk','transport') for x in ast.walk(new))
print('FAULT_ISOLATION_ONLY_ORIGINAL_PIDFD_CAPS_POLICY_IDENTITY_CLEANUP_PRESERVED_SDK0')
