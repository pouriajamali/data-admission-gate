"""Only additive Windows source-Git console policy delta; no child process runs."""
import ast,hashlib,importlib.util,subprocess,unittest
from pathlib import Path
from unittest import mock
r=Path(__file__).resolve().parent;sp=importlib.util.spec_from_file_location('localinputdelta',r/'local_sdk11_input.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
class Delta(unittest.TestCase):
 def test_frozen_git_body_unchanged_except_fixed_flags(self):
  raw=(r/'normal_windows_input.py').read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),'5bab5ee0f8fdd724706fad0735a81aa1d89e747cf651e9bb0a4760052fed6312')
  old=next(x for x in ast.parse(raw).body if isinstance(x,ast.FunctionDef) and x.name=='git');new=next(x for x in ast.parse((r/'local_sdk11_input.py').read_bytes()).body if isinstance(x,ast.FunctionDef) and x.name=='_windows_source_git');new.name='git';new.args.args.insert(0,ast.arg(arg='C'))
  calls=[n for n in ast.walk(new) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess' and n.func.attr=='run'];self.assertEqual(len(calls),1);flags=next(k for k in calls[0].keywords if k.arg=='creationflags');self.assertEqual(ast.dump(flags.value),ast.dump(ast.parse('0x8|0x400',mode='eval').body));calls[0].keywords.remove(flags);self.assertEqual(ast.dump(old,include_attributes=False),ast.dump(new,include_attributes=False))
 def test_fixed_argv_env_deadline_flags_for_all_existing_reads(self):
  cases=[('rev-parse','HEAD','HEAD^{tree}'),('status','--porcelain=v1','--untracked-files=all'),('ls-tree','-r','-z','HEAD'),('show','HEAD:tools/own.py')]
  env={'SystemRoot':'C:/Windows','WINDIR':'C:/Windows','TEMP':'own-temp','TMP':'own-tmp','HTTP_PROXY':'must-not-inherit','GIT_CONFIG_GLOBAL':'must-not-inherit'}
  with mock.patch.dict(m.os.environ,env,clear=True),mock.patch.object(m.C,'_remaining',return_value=3.5),mock.patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'ok',b'')) as run:
   for args in cases:
    self.assertEqual(m._windows_source_git(args,Path('C:/own'),123456),b'ok');a,k=run.call_args;self.assertEqual(a[0],['C:/Program Files/Git/cmd/git.exe','-C',str(Path('C:/own')),*args]);self.assertEqual(k['timeout'],3.5);self.assertEqual(k['creationflags'],0x408);self.assertEqual(k['creationflags']&(0x4|0x10|0x08000000|0x01000000|3),0);self.assertEqual({key.upper():value for key,value in k['env'].items()},{'SYSTEMROOT':'C:/Windows','WINDIR':'C:/Windows','TEMP':'own-temp','TMP':'own-tmp','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'NUL','GIT_TERMINAL_PROMPT':'0','GCM_INTERACTIVE':'Never'});self.assertTrue(k['capture_output']);self.assertNotIn('cwd',k)
 def test_original_timeout_ceiling10(self):
  with mock.patch.object(m.C,'_remaining',return_value=60),mock.patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:m._windows_source_git(('status',),Path('C:/own'),123);self.assertEqual(run.call_args.kwargs['timeout'],10)
 def test_nonzero_still_denied(self):
  with mock.patch.object(m.C,'_remaining',return_value=1),mock.patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'')):
   with self.assertRaises(m.C.AdmissionError):m._windows_source_git(('status',),Path('C:/own'),123)
 def test_combined_stdout_stderr_cap_still_denied(self):
  with mock.patch.object(m.C,'_remaining',return_value=1),mock.patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'12',b'34')):
   with self.assertRaises(m.C.AdmissionError):m._windows_source_git(('status',),Path('C:/own'),123,limit=3)
 def test_expired_deadline_spawns_nothing(self):
  with mock.patch.object(m.C,'_remaining',side_effect=m.C.AdmissionError('expired')),mock.patch.object(m.subprocess,'run') as run:
   with self.assertRaises(m.C.AdmissionError):m._windows_source_git(('status',),Path('C:/own'),123)
   run.assert_not_called()
 def test_source_router_uses_only_additive_fixed_function(self):
  n=next(x for x in ast.parse((r/'local_sdk11_input.py').read_bytes()).body if isinstance(x,ast.FunctionDef) and x.name=='source');calls=[x for x in ast.walk(n) if isinstance(x,ast.Call)];self.assertTrue(any(isinstance(x.func,ast.Name) and x.func.id=='_windows_source_git' for x in calls));self.assertFalse(any(isinstance(x.func,ast.Attribute) and isinstance(x.func.value,ast.Name) and x.func.value.id=='W' and x.func.attr=='git' for x in calls))
if __name__=='__main__':unittest.main()
