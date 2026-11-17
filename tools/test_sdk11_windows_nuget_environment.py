"""New NuGet environment regression: exercise actual environment builder only."""
import ast,tempfile
from pathlib import Path
from types import SimpleNamespace
p=Path(__file__).with_name('sdk11_ci_runtime.py');tree=ast.parse(p.read_text(encoding='utf-8'));fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='job_environment')
class Denied(Exception):pass
def need(value,code):
 if not value:raise Denied(code)
ambient={'SystemRoot':'C:/Windows','USERPROFILE':'C:/runner','PROGRAMFILES(X86)':'C:/ambient/private','APPDATA':'C:/ambient/user','TOKEN':'secret'}
env={'os':SimpleNamespace(name='nt',environ=ambient),'f':SimpleNamespace(need=need)}
exec(compile(ast.Module(body=[fn],type_ignores=[]),'<actual_job_environment>','exec'),env)
with tempfile.TemporaryDirectory() as temp:
 root=Path(temp);result=env['job_environment'](root)
 keys=('PROGRAMFILES(X86)','PROGRAMFILES','PROGRAMDATA','APPDATA','LOCALAPPDATA')
 assert all(Path(result[k]).is_relative_to(root) and Path(result[k]).is_dir() and not list(Path(result[k]).iterdir()) for k in keys)
 assert len({result[k] for k in keys})==5
 assert all('ambient' not in result[k] for k in keys) and 'TOKEN' not in result
 assert result['DOTNET_CLI_HOME']==str(root/'cli-home') and result['NUGET_PACKAGES']==str(root/'packages')
 assert result['DOTNET_MULTILEVEL_LOOKUP']=='0' and result['DOTNET_PROCESSOR_COUNT']=='2'
 # The original input-injection denials remain active before folder creation.
 ambient['DOTNET_STARTUP_HOOKS']='injected'
 try:env['job_environment'](root)
 except Denied as exc:assert str(exc)=='UNSAFE_RUNTIME_ENVIRONMENT'
 else:raise AssertionError('unsafe hook admitted')
print({'newEnvironmentAssertions':6,'SDKOrNativeOrNetwork':0})
