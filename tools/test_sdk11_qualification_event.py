"""New exact qualification-event cases; no SDK/native/network."""
import ast,os
from pathlib import Path
from types import SimpleNamespace
tree=ast.parse(Path(__file__).with_name('sdk11_ci_runtime.py').read_text(encoding='utf-8'))
fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='source_context')
class Denied(Exception):pass
def need(condition,code):
 if not condition:raise Denied(code)
class MissingGit:
 def __init__(self,*args):pass
 def is_file(self):return False
env={'os':SimpleNamespace(environ={},name='nt'),'Path':MissingGit,'read':lambda *args:event,'f':SimpleNamespace(need=need,source=lambda a,b:need(a==b,'SOURCE'))}
exec(compile(ast.Module(body=[fn],type_ignores=[]),'<qualification_event>','exec'),env)
base={'RUNNER_ENVIRONMENT':'github-hosted','GITHUB_REPOSITORY':'pouriajamali/data-admission-gate','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_EVENT_PATH':'event','GITHUB_REF':'refs/heads/codex/frl-required-windows-20261117'}
event={'inputs':{'mode':'sdk11-ci-qualification','expected_commit':'a'*40}}
cases=[({},None,'Q_BOOTSTRAP_GIT'),({'GITHUB_REF':'refs/heads/codex/sdk11-supported-ci-qualification-20261116'},None,'Q_BOOTSTRAP_GIT'),({'GITHUB_REF':'refs/heads/other'},None,'Q_QUALIFICATION_EVENT'),({'GITHUB_EVENT_NAME':'push'},None,'Q_QUALIFICATION_EVENT'),({},'ordinary','Q_QUALIFICATION_EVENT'),({'GITHUB_REPOSITORY':'other/repo'},None,'Q_HOST_IMAGE')]
for changes,mode,expected in cases:
 env['os'].environ=dict(base,**changes);event['inputs']['mode']=mode or 'sdk11-ci-qualification'
 try:env['source_context']('a'*40,None,None,None,None)
 except Denied as exc:assert str(exc)==expected,(changes,str(exc))
 else:raise AssertionError('guard did not stop')
print({'newEventAdmissionCases':len(cases),'SDKOrNativeOrNetwork':0})
