"""Local host boundary tests; no SDK/network/process side effects."""
import importlib.util,sys,unittest
from pathlib import Path
p=Path(__file__).with_name('qualify_dotnet11_local_linux.py');s=importlib.util.spec_from_file_location('local_qualification',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
class HostBoundary(unittest.TestCase):
 def call(self,**delta):
  v=dict(release={'ID':'ubuntu','VERSION_ID':'24.04'},machine='x86_64',kernel='6.18.33.2-microsoft-standard-WSL2',pid1='systemd',uid=1000,gid=1000,github=False);v.update(delta);return m.local_host(**v)
 def test_observed_wsl_is_local(self):
  v=self.call();self.assertEqual(v['hostClass'],'LocalUbuntu24.04x64');self.assertTrue(v['WSL2Observed']);self.assertFalse(v['CI'])
 def test_ci_environment_rejected(self):
  with self.assertRaises(m.R.f.Denied):self.call(github=True)
 def test_wrong_distribution_rejected(self):
  with self.assertRaises(m.R.f.Denied):self.call(release={'ID':'debian','VERSION_ID':'13'})
 def test_root_rejected(self):
  with self.assertRaises(m.R.f.Denied):self.call(uid=0)
 def test_wrong_architecture_rejected(self):
  with self.assertRaises(m.R.f.Denied):self.call(machine='aarch64')
 def test_missing_systemd_rejected(self):
  with self.assertRaises(m.R.f.Denied):self.call(pid1='init')
if __name__=='__main__':unittest.main()
