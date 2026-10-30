"""Standalone supplement copied beside unchanged historical sitecustomize.

Every nested historical mechanism command must equal one of the complete
finite fixture schemas below, including interpreter, cwd and all output paths.
The only non-Python exception is the exact Windows `cmd.exe /c ver` command
used by platform.platform(); it does not inspect or activate STK.
"""
import ctypes
import json
import os
from pathlib import Path
import sys

READ_UTF8_CODE = 'from pathlib import Path;import sys;print(Path(sys.argv[1]).read_text(encoding="utf-8"))'
SCALAR_CODES = frozenset({'raise SystemExit(1)', 'raise SystemExit(7)', 'import time;time.sleep(30)'})


def parse_command(value):
    if isinstance(value,(tuple,list)):
        return list(value)
    if os.name != 'nt' or not isinstance(value,str):
        return []
    split = ctypes.windll.shell32.CommandLineToArgvW
    split.argtypes = [ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)]
    split.restype = ctypes.POINTER(ctypes.c_wchar_p)
    free = ctypes.windll.kernel32.LocalFree
    free.argtypes = [ctypes.c_void_p]
    count=ctypes.c_int(); pointer=split(value,ctypes.byref(count))
    if not pointer:
        return []
    try:
        return [pointer[i] for i in range(count.value)]
    finally:
        free(pointer)


def command_allowed(argv,cwd,roots,repo,executable=None):
    """Validate every token; no unconsumed arguments or foreign paths survive."""
    try:
        if not isinstance(argv,(list,tuple)) or not argv or not all(isinstance(x,str) for x in argv):
            return False
        argv=list(argv); repo=Path(repo).resolve(); roots=[Path(p).resolve() for p in roots]
        if Path(cwd or Path.cwd()).resolve() != repo:
            return False
        def inside(value):
            path=Path(value).resolve()
            return any(path.is_relative_to(root) for root in roots)
        cmd=Path(os.environ.get('SystemRoot','C:/Windows'))/'System32/cmd.exe'
        if Path(argv[0]).resolve() == cmd.resolve():
            return (argv == [argv[0],'/c','ver'] and
                    (executable is None or Path(executable).resolve() == cmd.resolve()))
        if argv[0] != sys.executable or executable not in (None,sys.executable):
            return False
        if len(argv)==5 and argv[1:3]==['-m','src.round2.probe']:
            return inside(argv[3]) and argv[4] in {'missing','corrupt','timeout','pass'}
        if len(argv)>=7 and argv[1:4]==['-m','src.round2.worker','--output']:
            if not inside(argv[4]) or argv[5]!='--stage':
                return False
            stage,extra=argv[6],argv[7:]
            if stage in {'data','generate'}:
                return not extra
            return stage=='environment' and extra in [[],['--skip-stk'],
                ['--probe-fault','missing'],['--probe-fault','error'],
                ['--skip-stk','--probe-fault','missing'],['--skip-stk','--probe-fault','error']]
        script=Path(argv[1]) if len(argv)>1 else Path()
        script=(script if script.is_absolute() else repo/script).resolve()
        if len(argv)>=6 and script==repo/'tools/run_round2.py':
            return (argv[2]=='--output' and inside(argv[3]) and argv[4]=='--mechanism-test' and
                argv[5:] in [['--probe-fault','missing','--skip-stk'],['--probe-fault','error'],
                             ['--stage-fault','generate:timeout']])
        if len(argv)==3 and argv[1]=='-c':
            return argv[2] in SCALAR_CODES
        if len(argv)==4 and argv[1:3]==['-c',READ_UTF8_CODE]:
            return inside(argv[3])
    except (OSError,TypeError,ValueError):
        return False
    return False


def install():
    roots=[Path(p).resolve() for p in json.loads(os.environ['ROUND9_WRITE_ROOTS'])]
    repo=Path(os.environ['ROUND19_LEGACY_REPO']).resolve()
    log=Path(os.environ['ROUND9_GUARD_LOG'])
    # platform.platform() normally asks socket.gethostname() for a local node.
    # Use the process's existing Windows environment value so the historical
    # environment fixture can run while every socket audit event stays denied.
    import platform
    platform._node = lambda default='': os.environ.get('COMPUTERNAME',default)
    busy=[False]
    def record(kind,detail):
        if busy[0]:
            return
        busy[0]=True
        try:
            with log.open('a',encoding='utf8') as stream:
                stream.write(json.dumps(dict(pid=os.getpid(),kind=kind,detail=detail),ensure_ascii=False)+'\n')
        finally:
            busy[0]=False
    def audit(event,args):
        if busy[0]:
            return
        if event.startswith('socket.'):
            record('denied',dict(code='ROUND19_NETWORK',event=event))
            raise PermissionError('ROUND19_GUARD_NETWORK')
        if event=='subprocess.Popen':
            argv=parse_command(args[1])
            if not command_allowed(argv,args[2],roots,repo,args[0]):
                record('denied',dict(code='ROUND19_LEGACY_EXACT_CHILD',argv=argv,executable=args[0],cwd=str(args[2])))
                raise PermissionError('ROUND19_GUARD_UNAPPROVED_SUBPROCESS')
            record('round19_exact_allowed_child',dict(argv=argv,executable=args[0],
                cwd=str(Path(args[2] or Path.cwd()).resolve()),work_roots=list(map(str,roots)),
                destination_paths=[argv[p+1] for p,t in enumerate(argv[:-1]) if t in {'--output','--result'}],
                historical_platform_fixture_exception=Path(argv[0]).name.lower()=='cmd.exe'))
    sys.addaudithook(audit)
    record('round19_socket_guard_installed',dict(network_policy='all socket.* audit events',
        child_policy='Complete finite historical fixture argv/interpreter/cwd/output schemas',repo=str(repo),
        write_roots=list(map(str,roots)),historical_non_python_exception='exact System32/cmd.exe /c ver for platform.platform only',
        platform_node_source='Local COMPUTERNAME environment; standard-library platform._node adapter avoids socket.gethostname',
        native_activation_count=0))
