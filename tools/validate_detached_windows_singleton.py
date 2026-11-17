"""One live own-Job metadata capture, SDK/Git/network zero, whole <=30s.
Tracked source/helper/profile bound to exact signed current commit and pins.
One fixed local detached-launch delta; no permission/bootstrap/qualification change.
"""
import time
ENTRY_NS = time.monotonic_ns()
import ctypes, datetime, hashlib, importlib.util, json, os, pathlib, secrets, sys

BASE = pathlib.Path('C:/Users/Office/.codex/visualizations/2026/11/10/01a1c661-2773-7f81-9ae7-c5756abd8095/metadata-framing')
REPO = pathlib.Path('E:/Codex WorkSpace/Git Projects/data-admission-gate/shared-normal-windows-20261117/repo')
ROOT = BASE / 'detached-console-local-singleton-once-20261117'
LEASE = pathlib.Path('E:/Codex WorkSpace/Git Projects/portfolio-management/development-management-20261110/wave2-state/LOCAL-FIXTURE-LEASE.json')
PROFILE = REPO / 'tools/producer04-detached-local-singleton.profile.json'
SOURCE_PINS = REPO / 'tools/producer04-local-source-pins.json'
JOB_SHA = 'e14e6feb51d1dfd0ea1865df36a4432ccf397dcd19849038d9b4e69cf7402d1e'
PURPOSE = 'DETACHED_LOCAL_SINGLETON_VALIDATION_SDK_ZERO'
WHOLE_NS = 30_000_000_000
WORK_NS = 8_000_000_000

def need(value, code):
    if not value:
        raise RuntimeError(code)

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def read(path):
    raw = pathlib.Path(path).read_bytes()
    need(len(raw) <= 262144, 'BOUNDED_INPUT')
    return json.loads(raw)

def write(path, value):
    raw = (json.dumps(value, indent=2) + '\n').encode()
    need(len(raw) <= 262144, 'BOUNDED_OUTPUT')
    with pathlib.Path(path).open('xb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())

job_path = REPO / 'tools/windows_qualification_job_local.py'
need(digest(job_path) == JOB_SHA, 'UNCHANGED_EXISTING_JOB_HELPER')
module_spec = importlib.util.spec_from_file_location('existing_windows_job', job_path)
j = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(j)

def source_binding(expected):
    need(len(expected)==40 and all(x in '0123456789abcdef' for x in expected),'EXACT_COMMIT_ARGUMENT')
    need((REPO / '.git').read_text().strip() == 'gitdir: E:/Codex WorkSpace/Git Projects/data-admission-gate/repo/.git/worktrees/repo3','EXACT_WORKTREE_POINTER')
    gd=pathlib.Path('E:/Codex WorkSpace/Git Projects/data-admission-gate/repo/.git/worktrees/repo3')
    need((gd/'HEAD').read_text().strip()=='ref: refs/heads/codex/shared-normal-windows-20261117','EXACT_SOURCE_BRANCH')
    ref=pathlib.Path('E:/Codex WorkSpace/Git Projects/data-admission-gate/repo/.git/refs/heads/codex/shared-normal-windows-20261117')
    need(ref.read_text().strip()==expected,'EXACT_COMMITTED_CURRENT_SOURCE')
    pins=read(SOURCE_PINS);rows={x['path']:x for x in pins['sourcePins']}
    for p in [pathlib.Path(__file__),job_path,PROFILE]:
        rel=p.relative_to(REPO).as_posix();raw=p.read_bytes();need(rel in rows and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==rows[rel]['gitBlob'],'ACTUAL_CALLER_HELPER_PROFILE_PIN_BYTES')
    old=REPO/'tools/windows_qualification_job.py';need(digest(old)=='0959e7cb097bb17d774ed0824bb7b9e95e1b94112d968d343fb9fca0fb5166ce','HISTORICAL_DEFAULT_HELPER_IMMUTABLE')
    return {'commit':expected,'controllerSHA256':digest(__file__),'jobHelperSHA256':JOB_SHA,'historicalJobHelperSHA256':digest(old),'profileSHA256':digest(PROFILE),'sourcePinsSHA256':digest(SOURCE_PINS),'controllerAndHelperAndProfileRawBytesEqualOwnGitBlobPins':True,'GitExecutionsInWorker':0,'localMode':'DETACHED_LOCAL_CONSOLE_FREE_V1','creationFlags':0x40c}

def kernel():
    from ctypes import wintypes as W
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    specs = {
        'OpenJobObjectW': ([W.DWORD, W.BOOL, W.LPCWSTR], W.HANDLE),
        'QueryInformationJobObject': ([W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD, ctypes.c_void_p], W.BOOL),
        'OpenProcess': ([W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
        'IsProcessInJob': ([W.HANDLE, W.HANDLE, ctypes.POINTER(W.BOOL)], W.BOOL),
        'GetProcessTimes': ([W.HANDLE, *[ctypes.POINTER(W.FILETIME)] * 4], W.BOOL),
        'QueryFullProcessImageNameW': ([W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD)], W.BOOL),
        'WaitForSingleObject': ([W.HANDLE, W.DWORD], W.DWORD),
        'CloseHandle': ([W.HANDLE], W.BOOL),
    }
    for name, (args, result) in specs.items():
        f = getattr(k, name)
        f.argtypes, f.restype = args, result
    return k, W

def worker(spec_path):
    s = read(spec_path)
    need(s['purpose'] == PURPOSE and s['source'] == source_binding(s['source']['commit']), 'EXACT_SOURCE_CHANGED_CAPTURE')
    need(os.getpid() == s['workerPID'] and j._start_identity(os.getpid()) == s['workerStart'], 'ACTUAL_RETAINED_CREATION_IDENTITY')
    need(os.getppid() == s['supervisorPID'] and j._start_identity(os.getppid()) == s['supervisorStart'], 'ORIGINAL_PARENT_START')
    need(s['beforeResume']['membership'] and s['beforeResume']['retainedCreationHandles'], 'UNCHANGED_HELD_CREATION_OWNERSHIP')
    need(time.monotonic_ns() < s['workDeadlineNs'], 'ORIGINAL_CAPTURE_CLOCK')
    cap = j.current_witness(s['jobName'])
    need(cap['memoryMax'] == 4294967296 and cap['tasksMax'] == 64 and cap['effectiveCpuCores'] == 2, 'ORIGINAL_KERNEL_CAPS')
    k, W = kernel()
    class IDs(ctypes.Structure):
        _fields_ = [('Assigned', W.DWORD), ('Listed', W.DWORD), ('IDs', ctypes.c_size_t * 64)]
    def snapshot(h):
        ids = IDs()
        ctypes.set_last_error(0)
        ok = k.QueryInformationJobObject(h, 3, ctypes.byref(ids), ctypes.sizeof(ids), None)
        error = 0 if ok else ctypes.get_last_error()
        need(ok and ids.Assigned == ids.Listed and ids.Listed <= 64, 'COMPLETE_BOUNDED_OWN_JOB_PID_LIST_OS_' + str(error))
        return {'tickNs': time.monotonic_ns(), 'Assigned': int(ids.Assigned), 'Listed': int(ids.Listed), 'IDs': [int(x) for x in ids.IDs[:ids.Listed]]}
    hjob = None
    parent_handle = None
    parent_observation = None
    rows = []
    try:
        ctypes.set_last_error(0)
        hjob = k.OpenJobObjectW(4, False, s['jobName'])
        need(hjob, 'OWN_JOB_QUERY_HANDLE_OS_' + str(ctypes.get_last_error()))
        ctypes.set_last_error(0)
        parent_handle=k.OpenProcess(0x101000,False,s['supervisorPID']);need(parent_handle,'LIVE_PARENT_LIMITED_HANDLE')
        member=W.BOOL();need(k.IsProcessInJob(parent_handle,hjob,ctypes.byref(member)) and not member.value,'PARENT_MUST_STAY_OUTSIDE_OWN_JOB')
        times=[W.FILETIME() for _ in range(4)];need(k.GetProcessTimes(parent_handle,*[ctypes.byref(x) for x in times]),'PARENT_ACTUAL_START_READBACK');pstart='FILETIME:'+str((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime);pwait=int(k.WaitForSingleObject(parent_handle,0));need(pstart==s['supervisorStart'] and pwait==258,'SAME_LIVE_ORIGINAL_PARENT_START')
        parent_observation={'pid':s['supervisorPID'],'start':pstart,'outsideJob':True,'waitResult':pwait}
        before = snapshot(hjob)
        need(os.getpid() in before['IDs'], 'MAIN_MEMBER_IN_THIS_SNAPSHOT')
        for pid in before['IDs']:
            need(time.monotonic_ns() < s['workDeadlineNs'], 'ORIGINAL_CAPTURE_CLOCK')
            row = {'snapshotPID': pid, 'queryAccessMask': 0x101000, 'errors': [], 'captureHandleClosed': False}
            hp = None
            def failed(api):
                row['errors'].append({'api': api, 'osError': int(ctypes.get_last_error())})
            try:
                ctypes.set_last_error(0)
                hp = k.OpenProcess(0x101000, False, pid)
                if not hp:
                    failed('OpenProcess'); continue
                member = W.BOOL()
                ctypes.set_last_error(0)
                if not k.IsProcessInJob(hp, hjob, ctypes.byref(member)):
                    failed('IsProcessInJobBefore'); continue
                row['sameJobBefore'] = bool(member.value)
                if not member.value:
                    row['identityState'] = 'NOT_SAME_JOB_NOW_NO_IMAGE_READ_NO_REUSE_INFERENCE'; continue
                times = [W.FILETIME() for _ in range(4)]
                ctypes.set_last_error(0)
                if not k.GetProcessTimes(hp, *[ctypes.byref(x) for x in times]):
                    failed('GetProcessTimes'); continue
                row['processStart'] = 'FILETIME:' + str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
                ctypes.set_last_error(0)
                wait = int(k.WaitForSingleObject(hp, 0))
                row['waitResult'] = wait
                if wait not in (0, 258):
                    failed('WaitForSingleObject'); continue
                row['signaled'] = wait == 0
                image = ctypes.create_unicode_buffer(1024)
                length = W.DWORD(1024)
                ctypes.set_last_error(0)
                if not k.QueryFullProcessImageNameW(hp, 0, image, ctypes.byref(length)):
                    failed('QueryFullProcessImageNameW'); continue
                need(0 < length.value < 1024, 'BOUNDED_IMAGE_LENGTH')
                row['image'] = image.value
                ctypes.set_last_error(0)
                if not k.IsProcessInJob(hp, hjob, ctypes.byref(member)):
                    failed('IsProcessInJobAfter'); continue
                row['sameJobAfter'] = bool(member.value)
                row['identityState'] = 'OBSERVED_ON_SAME_OPEN_HANDLE' if member.value else 'MEMBERSHIP_CHANGED_NOT_INFERRED'
            finally:
                if hp:
                    ctypes.set_last_error(0)
                    row['captureHandleClosed'] = bool(k.CloseHandle(hp))
                    if not row['captureHandleClosed']: failed('CloseHandle')
                else:
                    row['captureHandleClosed'] = True
                rows.append(row)
        after = snapshot(hjob)
    finally:
        if parent_handle:need(k.CloseHandle(parent_handle),'OWN_PARENT_QUERY_HANDLE_CLOSE')
        if hjob:
            need(k.CloseHandle(hjob), 'OWN_QUERY_JOB_HANDLE_CLOSE')
    predicate = before['Assigned'] == before['Listed'] == 1 and before['IDs'][0] == os.getpid()
    write(ROOT / 'LIVE-MEMBERS-WORKER-FACT.json', {'schema': 'live-own-job-member-metadata/v1', 'state': 'DETACHED_LOCAL_SINGLETON_OBSERVED_NO_SDK_ADMISSION' if predicate else 'HOLD_DETACHED_SINGLETON_STILL_FALSE', 'source': s['source'], 'mainPID': os.getpid(), 'mainStart': s['workerStart'], 'jobName': s['jobName'], 'actualCaps': cap, 'heldBeforeResume': s['beforeResume'], 'parent':parent_observation, 'beforeMemberCapture': before, 'members': rows, 'afterAllCaptureProcessHandlesClosed': after, 'originalSingletonPredicate': predicate, 'normalInputAdmission': False, 'SDK': 0, 'Git': 0, 'network': 0, 'Actions': 0, 'launchPolicyChange': 'Fixed local DETACHED mask0x40c only; historical default unchanged', 'wholeDeadlineNs': s['wholeDeadlineNs'], 'workDeadlineNs': s['workDeadlineNs'], 'scope': 'Same live Job snapshot and retained limited-query handles only. No commandline, credentials, memory, arbitrary process kill or inference about prior PID identities. Linux139/nativeCoreHost unresolved.'})

    need(predicate,'UNCHANGED_SINGLETON_GUARD_DENIED_AFTER_FIXED_DETACHED_MODE')

def parent(expected):
    need(not ROOT.exists(), 'ONE_FRESH_CAPTURE_NO_RETRY')
    source = source_binding(expected)
    need(digest(LEASE.with_name('LEASE-PROTOCOL.json')) == '9120ca49a0d46673053aa0ec0cdbbc6f00731d71ea0b57ddab09e8fc3ac3ac8b', 'UNCHANGED_CANONICAL_PROTOCOL')
    boot = read(BASE / 'local-windows04-qualification-once-20261117/bootstrap.json')
    need(boot['PSFSignaturesValidWithTimestamps'] and digest(sys.executable) == boot['pythonExeSha256'] and digest(pathlib.Path(sys.executable).parent / 'python312.dll') == boot['pythonDllSha256'], 'REUSE_EXISTING_BOOTSTRAP_BYTES_NO_QUALIFICATION')
    lease = {'projectId': '04', 'randomToken': secrets.token_hex(16), 'ownerOS': 'Windows', 'ownerPID': os.getpid(), 'ownerProcessStartIdentity': j._start_identity(os.getpid()), 'phase': PURPOSE, 'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'receiptDirectory': str(ROOT)}
    try:
        with LEASE.open('x', encoding='utf-8', newline='\n') as out:
            json.dump(lease, out); out.flush(); os.fsync(out.fileno())
    except FileExistsError:
        print(json.dumps({'state': 'LEASE_BUSY_CAPTURE_NOT_STARTED', 'SDK': 0})); return
    ROOT.mkdir()
    write(ROOT / 'LEASE.json', lease)
    whole = ENTRY_NS + WHOLE_NS
    work = ENTRY_NS + WORK_NS
    need(time.monotonic_ns() < work, 'PREPARATION_WITHIN_ORIGINAL_WORK_CLOCK')
    deadline = j.tick() + max(1, (work - time.monotonic_ns()) // 1_000_000)
    s = {'purpose': PURPOSE, 'source': source, 'workDeadlineNs': work, 'wholeDeadlineNs': whole, 'supervisorPID': os.getpid(), 'supervisorStart': j._start_identity(os.getpid())}
    env = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT', 'USERPROFILE') if k in os.environ}
    env.update(PATH='C:/Windows/System32;C:/Windows', PYTHONDONTWRITEBYTECODE='1')
    record = error = None
    try:
        record = j.run_job([sys.executable, '-I', '-S', '-B', str(pathlib.Path(__file__).resolve()), '--worker', str(ROOT / 'private-spec.json')], REPO, env, deadline, ROOT / 'outer-job', job_name='Local\\admission04-input-' + secrets.token_hex(12), ready_spec={'path': ROOT / 'private-spec.json', 'value': s}, local_console_mode='DETACHED_LOCAL_CONSOLE_FREE_V1')
    except BaseException as exc:
        error = {'type': type(exc).__name__, 'code': str(exc)[:180]}
    if record is None and (ROOT / 'outer-job/process.json').is_file():
        record = read(ROOT / 'outer-job/process.json')
    terminal = bool(record and record['actualCap']['activeProcessesAtTeardown'] == 0)
    good = bool(terminal and record['exitCode'] == 0 and not record['timedOut'] and (ROOT / 'LIVE-MEMBERS-WORKER-FACT.json').is_file() and error is None)
    elapsed = (time.monotonic_ns() - ENTRY_NS) / 1e9
    need(time.monotonic_ns() < whole, 'ORIGINAL_WHOLE30_NOT_EXTENDED')
    write(ROOT / 'FINAL-RECEIPT.json', {'state': 'DETACHED_LOCAL_SINGLETON_VALIDATED_NO_SDK_ADMISSION' if good else 'HOLD', 'source': source, 'elapsedSeconds': elapsed, 'wholeSecondsMax': 30, 'workSecondsMax': 8, 'terminalReserveSeconds': 22, 'record': record, 'error': error, 'ownedPopulation': 0 if terminal else 'UNKNOWN', 'SDK': 0, 'Git': 0, 'network': 0, 'Actions': 0, 'consumerAdmission': False, 'productAdmission': False})
    if terminal:
        need(read(LEASE) == lease, 'ONLY_EXACT_OWN_LEASE_RELEASE')
        LEASE.unlink()
        write(ROOT / 'LEASE-RELEASED.json', {'state': 'EXACT_OWN_LEASE_RELEASED_AFTER_ACTUAL_TERMINAL', 'terminalSHA256': digest(ROOT / 'FINAL-RECEIPT.json'), 'tokenSHA256': hashlib.sha256(lease['randomToken'].encode()).hexdigest()})
    print(json.dumps({'state': 'DETACHED_LOCAL_SINGLETON_VALIDATED_NO_SDK_ADMISSION' if good else 'HOLD', 'receipt': str(ROOT / 'FINAL-RECEIPT.json'), 'elapsedSeconds': elapsed, 'ownedPopulation': 0 if terminal else 'UNKNOWN', 'SDK': 0, 'Git': 0, 'network': 0}))
    if not good: raise SystemExit(1)

if __name__ == '__main__':
    need(os.name == 'nt', 'WINDOWS_ONLY')
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        need(pathlib.Path(sys.argv[2]) == ROOT / 'private-spec.json', 'EXACT_CAPTURE_SPEC')
        worker(pathlib.Path(sys.argv[2]))
    else:
        need(len(sys.argv) == 3 and sys.argv[1]=='--expected-commit', 'EXACT_COMMITTED_SOURCE_REQUIRED')
        parent(sys.argv[2])
