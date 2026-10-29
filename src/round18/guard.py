"""Read-only archived vendor guard including all preceding rounds."""
import json
import os
from pathlib import Path
import sys
from src.round16.guard import install as archived_install

COORDINATOR_JOBS = frozenset({'science', 'tests', 'legacy', 'guards'})
NATIVE_MODULES = frozenset({'pythoncom', 'win32com', 'comtypes', 'win32event', 'winreg',
    'native_components', 'stk_adapter', 'stk_geometry', 'native', 'verification_store'})


def coordinator_command_allowed(argv, work, cwd):
    """Only this run's frozen workers and its two known Python probes."""
    from .binding import ROOT
    from .supervise import PROBE_CODE, PROBE_MODES
    work = Path(work).resolve()
    try:
        if not isinstance(argv, (list, tuple)) or not argv or argv[0] != sys.executable:
            return False
        argv = list(argv)
        if len(argv) == 12 and argv[:7] == [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.worker', '--work']:
            out = Path(argv[9]).resolve()
            return (argv[7] == str(work) and argv[8] == '--out' and argv[10] == '--job'
                and argv[11] in COORDINATOR_JOBS and out.name == 'output'
                and out.parent.parent == work/'attempts' and Path(cwd).resolve() == ROOT)
        if len(argv) == 8 and argv[:6] == [sys.executable, '-X', 'utf8', '-B', '-c', PROBE_CODE] and argv[7] in PROBE_MODES:
            folder = work/'supervision'/argv[7]
            return argv[6] == str(folder/'created_pid.json') and Path(cwd).resolve() == folder
    except (TypeError, ValueError, OSError):
        return False
    return False


def install_coordinator_guard(work):
    """Keep parent orchestration offline while supervising exact Python jobs."""
    import ctypes
    import importlib.abc
    from .binding import ROOT
    # Load the immutable probe definition before installing the audit hook.
    from .supervise import PROBE_CODE
    work = Path(work).resolve()
    log = work/'coordinator_guard.jsonl'
    busy = [False]
    parser = [None]

    def command_args(value):
        if isinstance(value, (list, tuple)):
            return list(value)
        if os.name != 'nt' or not isinstance(value, str):
            return []
        if parser[0] is None:
            split = ctypes.windll.shell32.CommandLineToArgvW
            split.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
            split.restype = ctypes.POINTER(ctypes.c_wchar_p)
            free = ctypes.windll.kernel32.LocalFree
            free.argtypes = [ctypes.c_void_p]
            parser[0] = (split, free)
        split, free = parser[0]
        count = ctypes.c_int()
        pointer = split(value, ctypes.byref(count))
        if not pointer:
            return []
        try:
            return [pointer[i] for i in range(count.value)]
        finally:
            free(pointer)

    def record(kind, detail):
        if busy[0]:
            return
        busy[0] = True
        try:
            with log.open('a', encoding='utf8') as stream:
                stream.write(json.dumps(dict(kind=kind, pid=os.getpid(), detail=detail), ensure_ascii=False)+'\n')
        finally:
            busy[0] = False

    def deny(reason, target):
        record('unexpected_denial', dict(reason=reason, target=str(target)[:1000]))
        raise PermissionError('ROUND18_GUARD_'+reason)

    def writable(value):
        if isinstance(value, int) or value is None or os.fsdecode(value).lower() == 'nul':
            return True
        return Path(os.fsdecode(value)).resolve().is_relative_to(work)

    class NativeFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if set(fullname.lower().split('.')) & NATIVE_MODULES:
                deny('NATIVE_IMPORT', fullname)

    def audit(event, args):
        if busy[0]:
            return
        if event == 'import' and set(args[0].lower().split('.')) & NATIVE_MODULES:
            deny('NATIVE_IMPORT', args[0])
        if event == 'subprocess.Popen':
            argv = command_args(args[1])
            if not coordinator_command_allowed(argv, work, args[2]):
                deny('UNAPPROVED_SUBPROCESS', argv)
            record('allowed_offline_subprocess', dict(argv=argv, cwd=str(args[2])))
        if event in {'os.system', 'os.startfile', 'os.startfile/2', 'os.posix_spawn', 'os.spawn', 'os.exec', 'os.fork', 'os.forkpty'}:
            deny('EXTERNAL_ACTIVATION', event)
        if event.startswith('socket.'):
            deny('NETWORK', event)
        if event == 'exec' and not args[0].co_filename.startswith('<'):
            path = Path(args[0].co_filename).resolve()
            if path.stem.lower() in NATIVE_MODULES or (path.is_relative_to(ROOT/'work')
                and any(p.lower() in {'vendor', 'materialized'} for p in path.parts)):
                deny('VENDOR_EXECUTION', path)
        if event == 'open':
            path, mode, flags = args
            writing = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            if writing and not writable(path):
                deny('WRITE_SCOPE', path)
        if event in {'os.remove', 'os.rmdir', 'os.mkdir', 'os.chmod', 'os.utime'} and not writable(args[0]):
            deny('MUTATION_SCOPE', args[0])
        if event in {'os.rename', 'os.replace', 'os.link', 'os.symlink'} and not all(writable(path) for path in args[:2]):
            deny('MUTATION_SCOPE', args[:2])

    sys.meta_path.insert(0, NativeFinder())
    sys.addaudithook(audit)
    record('guard_installed', dict(profile='ROUND18_COORDINATOR_OFFLINE_GUARD_V1', write_root=str(work),
        native_activation_budget=0, native_imports_denied=True, network_denied=True,
        vendor_execution_denied=True, allowed_worker_jobs=sorted(COORDINATOR_JOBS),
        probes='Only the two exact own-Python process-tree probe commands'))
    return dict(installed=True, log=str(log), native_activation_count=0)


def install(work, log, old_vendor, controlled=False):
    lock = archived_install(work, log, old_vendor, controlled)
    history = Path(work).resolve().parents[1]
    roots = [history/'round16', history/'round17']

    def audit(event, args):
        if event != 'exec' or args[0].co_filename.startswith('<'):
            return
        path = Path(args[0].co_filename).resolve()
        if any(path.is_relative_to(root) for root in roots) and 'materialized' in path.parts:
            with Path(log).open('a', encoding='utf8') as stream:
                stream.write(json.dumps(dict(kind='expected_denial' if controlled else 'unexpected_denial',
                    pid=os.getpid(), controlled=controlled,
                    detail=dict(reason='VENDOR_EXECUTION', target=str(path))))+'\n')
            raise PermissionError('ROUND18_GUARD_VENDOR_EXECUTION')

    sys.addaudithook(audit)
    return lock
