"""Data-only bounds of the narrower prepared CoreHost entry, no Ubuntu/SDK work."""
import ast,json,unittest
from pathlib import Path
r=Path(__file__).resolve().parent;t=ast.parse((r/'curate_windows_corehost_local_linux.py').read_bytes());profile=json.loads((r/'producer04-local-corehost-inputs.profile.json').read_bytes())
class Scope(unittest.TestCase):
 def test_only_two_existing_corehost_ids_and_no_restore_build_graph(self):
  ids=next(ast.literal_eval(x.value) for x in t.body if isinstance(x,ast.Assign) and any(isinstance(z,ast.Name) and z.id=='IDS' for z in x.targets));self.assertEqual(ids,['Microsoft.NETCore.App.Host.win-x64','Microsoft.NETCore.App.Runtime.win-x64']);self.assertEqual(profile['SDKCommandsMax'],2);self.assertEqual(profile['originalFiniteContractSDKCeiling'],6);self.assertFalse(any(isinstance(x,ast.Constant) and x.value in ('restore','build','publish','exec','--version','--info') for x in ast.walk(t)));calls=[x for x in ast.walk(t) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=='sdk'];self.assertEqual(len(calls),1);self.assertEqual(ast.literal_eval(ast.List(elts=calls[0].args[0].elts[:2],ctx=ast.Load())),['nuget','verify'])
 def test_recovery_hold_precedes_any_unit_root_creation(self):
  f=next(x for x in t.body if isinstance(x,ast.FunctionDef) and x.name=='main');guards=[x.lineno for x in ast.walk(f) if isinstance(x,ast.Constant) and x.value=='SOLE_RECOVERY_OWNER05_COMPLETION_NOTICE_REQUIRED'];mkdir=[x.lineno for x in ast.walk(f) if isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=='mkdir'];self.assertEqual(len(guards),1);self.assertTrue(mkdir and min(guards)<=min(mkdir));self.assertTrue(profile['recoveryOwner05CompletionNoticeRequired'])
 def test_live_denial_witness_remains_before_any_native_sdk(self):
  f=next(x for x in t.body if isinstance(x,ast.FunctionDef) and x.name=='worker');w=[x.lineno for x in ast.walk(f) if isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=='network_witness'];sdk=[x.lineno for x in ast.walk(f) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id=='sdk'];self.assertEqual(len(w),1);self.assertTrue(sdk and w[0]<min(sdk));self.assertFalse(any(isinstance(x,ast.Call) and isinstance(x.func,ast.Attribute) and x.func.attr=='native_prerequisites' for x in ast.walk(t)))
if __name__=='__main__':unittest.main()
