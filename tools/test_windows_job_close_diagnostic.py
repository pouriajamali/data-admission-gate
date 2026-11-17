"""Ensure the diagnostic changes no frozen job controls or close calls."""
import ast,hashlib
from pathlib import Path
r=Path(__file__).resolve().parent
original=(r/'windows_qualification_job.py').read_bytes()
assert hashlib.sha256(original).hexdigest()=='0959e7cb097bb17d774ed0824bb7b9e95e1b94112d968d343fb9fca0fb5166ce'
a=ast.parse(original);b=ast.parse((r/'windows_job_close_diagnostic.py').read_bytes())
class StripObservations(ast.NodeTransformer):
 def visit_If(self,node):
  if isinstance(node.test,ast.Name) and node.test.id=='observe':return None
  return self.generic_visit(node)
 def visit_FunctionDef(self,node):
  if node.name=='run_job':
   assert node.args.args[-1].arg=='observe' and isinstance(node.args.defaults[-1],ast.Constant) and node.args.defaults[-1].value is None
   node.args.args.pop();node.args.defaults.pop()
  return self.generic_visit(node)
b=StripObservations().visit(b)
assert ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False),'DIAGNOSTIC_MUST_NOT_CHANGE_CONTROL_OR_HANDLE_RETENTION'
print('READONLY_JOB_OBSERVATIONS_ONLY_ALL_FROZEN_CONTROLS_AND_CLOSE_ORDER_PRESERVED')
