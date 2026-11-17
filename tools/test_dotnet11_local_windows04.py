"""Experimental Windows04 boundary tests: no OS/SDK work."""
import importlib.util,sys,unittest
from pathlib import Path
p=Path(__file__).with_name('qualify_dotnet11_local_windows04.py');s=importlib.util.spec_from_file_location('local_windows04',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
class ExperimentalBoundary(unittest.TestCase):
 def call(self,**delta):
  v=dict(approved=True,version='26H2',build='26300.9974',machine='AMD64',product=1,ci=False);v.update(delta);return m.experimental_host(**v)
 def test_label_stays_experimental_and_scoped(self):
  v=self.call();self.assertEqual(v['projectId'],'04');self.assertEqual(v['formalDotnet11Support'],'NOT_CONFIRMED');self.assertFalse(v['CI'])
 def test_missing_approval_denied(self):
  with self.assertRaises(m.R.f.Denied):self.call(approved=False)
 def test_changed_build_denied(self):
  with self.assertRaises(m.R.f.Denied):self.call(build='26300.9999')
 def test_ci_environment_denied(self):
  with self.assertRaises(m.R.f.Denied):self.call(ci=True)
 def test_wrong_architecture_denied(self):
  with self.assertRaises(m.R.f.Denied):self.call(machine='ARM64')
 def test_server_identity_denied(self):
  with self.assertRaises(m.R.f.Denied):self.call(product=3)
if __name__=='__main__':unittest.main()
