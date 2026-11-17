"""Only new bounded SDK-error redaction cases; no SDK/native/network."""
import ast,re
from pathlib import Path
p=Path(__file__).with_name('sdk11_ci_runtime.py');tree=ast.parse(p.read_text(encoding='utf-8'));fn=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='safe_sdk_messages');env={'re':re};exec(compile(ast.Module(body=[fn],type_ignores=[]),'<bounded_sdk_error_redaction>','exec'),env);f=env['safe_sdk_messages']
values=f([b'error NU1100 at C:/private/owned/qualification.csproj',b'https://user:secret@server.invalid/?token=private\npassword=hidden\x00\x1b[31mError'],Path('C:/private/owned'))
assert '<OWN_TEMP>' in values[0]['text'] and 'private/owned' not in values[0]['text']
assert '<URL>' in values[1]['text'] and 'user:secret' not in values[1]['text']
assert 'password=<REDACTED>' in values[1]['text'] and 'hidden' not in values[1]['text']
assert '\x00' not in values[1]['text'] and '\x1b' not in values[1]['text']
assert f([b'a'*8000,b'b'*8000],Path('/own'))[0]['text']==('a'*512)
assert f([b'\xff\xfe',b''],Path('/own'))[0]['text']=='??'
assert f([b'restore failed',b''],Path('/own'))[0]['text']=='restore failed'
print({'newDiagnosticCases':7,'SDKOrNativeOrNetwork':0,'actualFailureCauseStillUnknownUntilObserved':True})
