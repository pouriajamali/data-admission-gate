"""Kernel-output canary and original guard preservation; no live query/SDK."""
import ast,copy,ctypes,hashlib,struct,unittest
from pathlib import Path
r=Path(__file__).resolve().parent;old=(r/'curation_linux_method.py').read_bytes();new=(r/'local_linux_network_query.py').read_bytes();a=ast.parse(old);b=ast.parse(new)
def fun(t,n):return next(x for x in t.body if isinstance(x,ast.FunctionDef) and x.name==n)
def query_class(t):
 n=next(x for x in ast.walk(fun(t,'bpf_query')) if isinstance(x,ast.ClassDef) and x.name=='Query');ns={'ctypes':ctypes};exec(compile(ast.Module(body=[n],type_ignores=[]),'fixed-query-layout','exec'),ns);return ns['Query']
class Delta(unittest.TestCase):
 def test_revision_copy_exposes_old_overflow_and_is_inside_full_output(self):
  O=query_class(a);N=query_class(b);self.assertEqual(ctypes.sizeof(O),40);self.assertEqual(ctypes.sizeof(N),64);self.assertEqual(N.revision.offset,56)
  oldstore=bytearray(96);oldstore[40:]=b'\xa5'*56;oq=O.from_buffer(oldstore);struct.pack_into('<Q',oldstore,56,2);self.assertNotEqual(oldstore[40:],b'\xa5'*56)
  newstore=bytearray(96);newstore[64:]=b'\xa5'*32;nq=N.from_buffer(newstore);nq.target_fd=7;nq.attach_type=1;nq.prog_cnt=64;struct.pack_into('<Q',newstore,56,2);self.assertEqual(nq.revision,2);self.assertEqual(newstore[64:],b'\xa5'*32);self.assertEqual((nq.target_fd,nq.attach_type,nq.prog_cnt),(7,1,64))
 def test_complete_old_prefix_offsets_identical_and_optional_fields_zero(self):
  O=query_class(a);N=query_class(b)
  for name,ty in O._fields_:self.assertEqual(getattr(O,name).offset,getattr(N,name).offset)
  q=N(7,1,0,0,1234,64,0,0);self.assertEqual((q.link_ids,q.link_attach_flags,q.revision),(0,0,0))
 def test_every_query_and_policy_guard_preserved(self):
  self.assertEqual(hashlib.sha256(old).hexdigest(),'e882af75dc56a5a0f9eb9b4101f2ccaf88141fa3ced9037ea0fd7b1eb357ed74');q=copy.deepcopy(fun(b,'bpf_query'));c=next(x for x in q.body if isinstance(x,ast.ClassDef));fields=c.body[0].value;self.assertEqual([x.elts[0].value for x in fields.elts[-3:]],['link_ids','link_attach_flags','revision']);fields.elts=fields.elts[:-3];q.body=[x for x in q.body if not(isinstance(x,ast.Expr) and isinstance(x.value,ast.Call) and any(isinstance(y,ast.Constant) and y.value=='FULL_KERNEL_QUERY_OUTPUT_BUFFER64' for y in x.value.args))];self.assertEqual(ast.dump(fun(a,'bpf_query'),include_attributes=False),ast.dump(q,include_attributes=False));self.assertEqual(ast.dump(fun(a,'scoped_parent_transition'),include_attributes=False),ast.dump(fun(b,'scoped_parent_transition'),include_attributes=False))
if __name__=='__main__':unittest.main()
