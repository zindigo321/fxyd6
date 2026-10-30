"""Process-local Python audit protection for each ROUND19 execution role.

This is Python audit protection, not operating-system isolation.  Network
events, native imports, vendor execution and writes outside the named roots
are denied.  Child creation requires an exact registered argv/cwd pair.
"""
import argparse
import ctypes
import importlib.abc
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
NATIVE_MODULES = frozenset({'pythoncom', 'win32com', 'comtypes', 'win32event',
    'winreg', 'native_components', 'stk_adapter', 'stk_geometry', 'native', 'verification_store'})
ROLES = ('coordinator', 'science', 'tests', 'guards', 'regression', 'export_launcher', 'export_child', 'finalizer')
COORDINATOR_JOBS = frozenset({'science', 'tests', 'legacy', 'guards'})


def command_args(value):
    if isinstance(value, (list, tuple)):
        return list(value)
    if os.name != 'nt' or not isinstance(value, str):
        return []
    split = ctypes.windll.shell32.CommandLineToArgvW
    split.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    split.restype = ctypes.POINTER(ctypes.c_wchar_p)
    free = ctypes.windll.kernel32.LocalFree
    free.argtypes = [ctypes.c_void_p]
    count = ctypes.c_int()
    pointer = split(value, ctypes.byref(count))
    if not pointer:
        return []
    try:
        return [pointer[i] for i in range(count.value)]
    finally:
        free(pointer)


def register_command(commands, argv, cwd, work, destination=None):
    """Register the complete command before the auditable Popen boundary."""
    argv = list(argv)
    work, cwd = Path(work).resolve(), Path(cwd).resolve()
    if not argv or argv[0] != sys.executable:
        raise ValueError('ROUND19_COMMAND_INTERPRETER')
    if not cwd.is_relative_to(work) and cwd != ROOT:
        raise ValueError('ROUND19_COMMAND_CWD')
    for option in ('--work', '--out', '--result'):
        if option in argv:
            position = argv.index(option)
            if position + 1 >= len(argv) or not Path(argv[position+1]).resolve().is_relative_to(work):
                raise ValueError('ROUND19_COMMAND_WORK_SCOPE')
    if '--destination' in argv:
        position = argv.index('--destination')
        if destination is None or position+1 >= len(argv) or Path(argv[position+1]).resolve() != Path(destination).resolve():
            raise ValueError('ROUND19_COMMAND_DESTINATION')
    row = dict(argv=argv, cwd=str(cwd), work=str(work),
               destination=str(Path(destination).resolve()) if destination is not None else None)
    commands.append(row)
    return row


def command_allowed(argv, cwd, commands, work=None, destination=None):
    try:
        if not isinstance(argv, (list, tuple)) or not argv or argv[0] != sys.executable or cwd is None:
            return False
        actual_cwd = Path(cwd).resolve()
        for row in commands:
            if row['argv'] != list(argv) or Path(row['cwd']).resolve() != actual_cwd:
                continue
            if work is not None and Path(row['work']).resolve() != Path(work).resolve():
                continue
            if destination is not None and row.get('destination') != str(Path(destination).resolve()):
                continue
            return True
    except (KeyError, TypeError, ValueError, OSError):
        return False
    return False


def coordinator_command_allowed(argv, work, cwd):
    """Default static worker/probe policy, also checked against exact args."""
    from .supervise import PROBE_CODE, PROBE_MODES
    try:
        work = Path(work).resolve()
        if not isinstance(argv, (list, tuple)) or not argv or argv[0] != sys.executable:
            return False
        argv = list(argv)
        if len(argv) == 12 and argv[:7] == [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round19.worker', '--work']:
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


def install(work, log, old_vendor=None, controlled=False, *, role='science', commands=None,
            destination=None, write_roots=None, coordinator_defaults=False):
    work, log = Path(work).resolve(), Path(log).resolve()
    if role not in ROLES:
        raise ValueError('ROUND19_UNKNOWN_GUARD_ROLE')
    if role in {'export_child', 'finalizer'} and commands:
        raise ValueError('ROUND19_TERMINAL_ROLE_HAS_CHILDREN')
    commands = [] if commands is None else commands
    roots = [Path(p).resolve() for p in (write_roots or [work])]
    if destination is not None and Path(destination).resolve() not in roots:
        roots.append(Path(destination).resolve())
    log.parent.mkdir(parents=True, exist_ok=True)
    busy, locked = [False], [False]
    vendor_roots = [work/'vendor', work/'materialized']
    if old_vendor is not None:
        vendor_roots.append(Path(old_vendor).resolve())

    def record(kind, detail):
        if busy[0]:
            return
        busy[0] = True
        try:
            with log.open('a', encoding='utf8') as stream:
                stream.write(json.dumps(dict(kind=kind, role=role, pid=os.getpid(), controlled=controlled,
                    detail=detail), ensure_ascii=False)+'\n')
        finally:
            busy[0] = False

    def deny(reason, target):
        record('expected_denial' if controlled else 'unexpected_denial',
               dict(reason=reason, target=str(target)[:1000]))
        raise PermissionError('ROUND19_GUARD_'+reason)

    def writable(value):
        if isinstance(value, int) or value is None or os.fsdecode(value).lower() == 'nul':
            return True
        path = Path(os.fsdecode(value)).resolve()
        return any(path.is_relative_to(root) for root in roots) and not (
            locked[0] and any(path.is_relative_to(root) for root in vendor_roots))

    def vendor(value):
        path = Path(value).resolve()
        return any(path.is_relative_to(root) for root in vendor_roots) or (
            path.is_relative_to(ROOT/'work') and any(part.lower() in {'vendor', 'materialized'} for part in path.parts))

    class NativeFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if set(fullname.lower().split('.')) & NATIVE_MODULES:
                deny('NATIVE_IMPORT', fullname)

    def audit(event, args):
        if busy[0]:
            return
        if event == 'import' and set(args[0].lower().split('.')) & NATIVE_MODULES:
            deny('NATIVE_IMPORT', args[0])
        if event.startswith('socket.'):
            deny('NETWORK', event)
        if event == 'subprocess.Popen':
            argv = command_args(args[1])
            allowed = role not in {'export_child', 'finalizer'} and command_allowed(
                argv, args[2], commands, work=work, destination=destination)
            if coordinator_defaults:
                allowed = allowed or coordinator_command_allowed(argv, work, args[2])
            # Windows Popen reports executable=None when argv[0] selects it.
            # In that case the already exact argv[0] binding is authoritative.
            allowed = allowed and (args[0] is None or args[0] == sys.executable)
            if not allowed:
                deny('UNAPPROVED_SUBPROCESS', argv)
            record('allowed_offline_subprocess', dict(argv=argv, cwd=str(args[2])))
        if event in {'os.system', 'os.startfile', 'os.startfile/2', 'os.posix_spawn', 'os.spawn',
                     'os.exec', 'os.fork', 'os.forkpty'}:
            deny('EXTERNAL_ACTIVATION', event)
        if event == 'exec' and not args[0].co_filename.startswith('<'):
            filename = args[0].co_filename
            if vendor(filename) or Path(filename).stem.lower() in NATIVE_MODULES:
                deny('VENDOR_EXECUTION', filename)
        if event == 'open':
            path, mode, flags = args
            writing = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or flags & (
                os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            if writing and not writable(path):
                deny('WRITE_SCOPE', path)
        if event in {'os.remove', 'os.rmdir', 'os.mkdir', 'os.chmod', 'os.utime'} and not writable(args[0]):
            # Export may create only missing ancestor directories, never write files there.
            ancestor_mkdir = event == 'os.mkdir' and destination is not None and Path(args[0]).resolve() in Path(destination).resolve().parents
            if not ancestor_mkdir:
                deny('MUTATION_SCOPE', args[0])
        if event in {'os.rename', 'os.replace', 'os.link', 'os.symlink'} and not all(writable(path) for path in args[:2]):
            deny('MUTATION_SCOPE', args[:2])

    sys.meta_path.insert(0, NativeFinder())
    sys.addaudithook(audit)
    record('guard_installed', dict(profile='ROUND19_PYTHON_AUDIT_V1', role=role,
        write_roots=list(map(str, roots)), native_activation_budget=0,
        native_imports_denied=True, network_denied=True, network_policy='all socket.* audit events',
        vendor_execution_denied=True, operating_system_isolation=False,
        subprocess_policy='none' if role in {'export_child','finalizer'} else 'complete registered argv/interpreter/cwd/work/destination'))
    return lambda: locked.__setitem__(0, True)


def install_coordinator_guard(work, commands=None):
    install(work, Path(work)/'coordinator_guard.jsonl', role='coordinator',
            commands=commands, coordinator_defaults=True)
    return dict(installed=True, log=str(Path(work)/'coordinator_guard.jsonl'),
                profile='ROUND19_PYTHON_AUDIT_V1', operating_system_isolation=False, native_activation_count=0)


def probe_current_role(work, out, role, destination=None):
    """Run in an isolated child; synthetic audit events cannot send traffic."""
    from src.round13.common import require, write
    work, out = Path(work).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    install(work, out/'guard.jsonl', controlled=True, role=role, destination=destination)
    events = ['socket.__new__', 'socket.connect', 'socket.bind', 'socket.sendto',
              'socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostname',
              'socket.gethostbyaddr', 'socket.getnameinfo', 'socket.sethostname']
    checked = []
    for event in events:
        try:
            sys.audit(event, None, ('example.invalid', 0))
        except PermissionError as exc:
            require(str(exc) == 'ROUND19_GUARD_NETWORK', 'ROUND19_PROBE_NETWORK_WRONG_DENIAL')
            checked.append(event)
        else:
            raise ValueError('ROUND19_PROBE_NETWORK_ALLOWED:'+event)
    # Exercise actual public APIs: both are rejected before network operations.
    import socket
    for name, call in [('socket.socket', lambda: socket.socket()),
                       ('socket.getaddrinfo', lambda: socket.getaddrinfo('example.invalid', 9))]:
        try:
            call()
        except PermissionError as exc:
            require(str(exc) == 'ROUND19_GUARD_NETWORK', 'ROUND19_PROBE_REAL_API_WRONG_DENIAL')
            checked.append(name)
        else:
            raise ValueError('ROUND19_PROBE_REAL_API_ALLOWED:'+name)
    for name, call, reason in [
        ('write_outside', lambda: (work.parent/'round19_forbidden_probe').write_text('no', encoding='utf8'), 'WRITE_SCOPE'),
        ('child', lambda: sys.audit('subprocess.Popen', sys.executable, [sys.executable,'-c','pass'], str(ROOT), {}), 'UNAPPROVED_SUBPROCESS'),
        ('native_import', lambda: __import__('comtypes'), 'NATIVE_IMPORT'),
        ('vendor_exec', lambda: exec(compile('pass',str(ROOT/'work/round18/probe/materialized/probe.py'),'exec'),{}), 'VENDOR_EXECUTION')]:
        try:
            call()
        except PermissionError as exc:
            require(str(exc) == 'ROUND19_GUARD_'+reason, 'ROUND19_PROBE_WRONG_DENIAL:'+name)
            checked.append(name)
        else:
            raise ValueError('ROUND19_PROBE_ALLOWED:'+name)
    allowed = out/'allowed_export.json'
    write(allowed, dict(中文='合法导出成功', role=role))
    require('合法导出成功' in allowed.read_text(encoding='utf8'), 'ROUND19_PROBE_LEGAL_EXPORT')
    result = dict(status='PASS', role=role, checked=checked, controlled_rejections=len(checked),
        no_network_requests_performed=True, actual_native_activation_count=0,
        allowed_write_readback=True, subprocess_creation_allowed=False,
        scope='Process-local Python audit guard; not operating-system isolation')
    write(out/'probe_result.json', result)
    return result


def run_guard_probes(work, out, life, allowlist=None):
    from src.round13.common import require, write, read, record
    from .supervise import run
    import subprocess
    import time
    work, out = Path(work).resolve(), Path(out).resolve()
    commands = [] if allowlist is None else allowlist
    result_rows = []
    for role in ROLES:
        life.check(True)
        folder = out/'roles'/role
        folder.parent.mkdir(parents=True, exist_ok=True)
        destination = out/'authorized_destination'
        argv = [sys.executable,'-X','utf8','-B','-m','src.round19.guard',
                '--probe','--work',str(work),'--out',str(folder),'--role',role,
                '--destination',str(destination)]
        register_command(commands, argv, ROOT, work, destination)
        start = time.perf_counter()
        with (out/(role+'_stdout.log')).open('wb') as stdout, (out/(role+'_stderr.log')).open('wb') as stderr:
            proc = run(argv,cwd=ROOT,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),
                       stdout=stdout,stderr=stderr,timeout=life.timeout())
        require(proc.returncode == 0, 'ROUND19_ROLE_GUARD_PROBE_FAILED:'+role)
        row = read(folder/'probe_result.json')
        require(row['status'] == 'PASS' and row['role'] == role, 'ROUND19_ROLE_GUARD_PROBE_BINDING')
        row.update(argv=argv,cwd=str(ROOT),exit_code=proc.returncode,timeout=False,wall_s=time.perf_counter()-start,
                   stdout=record(out/(role+'_stdout.log')),stderr=record(out/(role+'_stderr.log')))
        result_rows.append(row)
    result = dict(status='PASS', roles=result_rows, roles_verified=len(result_rows),
        controlled_rejections=sum(r['controlled_rejections'] for r in result_rows),
        actual_native_activation_count=0, no_network_requests_performed=True)
    write(out/'guard_roles_verification.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--probe', action='store_true', required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--role', choices=ROLES, required=True)
    parser.add_argument('--destination')
    args = parser.parse_args()
    print(json.dumps(probe_current_role(args.work,args.out,args.role,args.destination),ensure_ascii=False))
