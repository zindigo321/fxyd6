"""Process-inherited offline guard for the audited regression entrypoints."""
import ctypes, json, os, sys
from pathlib import Path

def install():
    roots=[Path(x).resolve() for x in json.loads(os.environ['ROUND10_WRITE_ROOTS'])]
    log=Path(os.environ['ROUND10_GUARD_LOG'])
    allowed_reads={str(Path(p).resolve()).casefold() for p in json.loads(os.environ.get('ROUND10_READ_WHITELIST','[]'))}
    read_isolation=bool(allowed_reads)
    system_roots=[Path(sys.prefix).resolve(),Path(sys.base_prefix).resolve()]
    code_root=Path(__file__).resolve().parents[2]
    observed_reads=set()
    split=ctypes.windll.shell32.CommandLineToArgvW
    split.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)]
    split.restype=ctypes.POINTER(ctypes.c_wchar_p)
    free=ctypes.windll.kernel32.LocalFree
    free.argtypes=[ctypes.c_void_p]
    def command_args(value):
        if isinstance(value,(list,tuple)):return list(value)
        count=ctypes.c_int();ptr=split(value,ctypes.byref(count))
        if not ptr:return []
        try:return [ptr[i] for i in range(count.value)]
        finally:free(ptr)
    def record(kind,detail):
        with log.open('a',encoding='utf-8') as f:
            f.write(json.dumps(dict(pid=os.getpid(),kind=kind,detail=str(detail)),ensure_ascii=False)+'\n')
    def inside(p):
        if isinstance(p,int) or p is None:return True
        if os.fsdecode(p).lower()=='nul':return True
        return any(Path(os.fsdecode(p)).resolve().is_relative_to(r) for r in roots)
    def audit(event,args):
        reason=None
        if event=='import' and args[0].split('.')[0] in {'pythoncom','win32com','comtypes','win32event','winreg'}:
            reason='NATIVE_IMPORT'
        elif event=='subprocess.Popen':
            argv=command_args(args[1])
            tail=argv[1:]
            while tail[:1] in (['-B'],['-u']):tail=tail[1:]
            if tail[:2]==['-X','utf8']:tail=tail[2:]
            allowed=False
            if Path(argv[0]).resolve()==Path(sys.executable).resolve():
                if tail[:2]==['-m','src.round2.probe']:allowed=True
                elif tail[:2]==['-m','src.round2.worker'] and '--stage' in tail:
                    stage=tail[tail.index('--stage')+1]
                    allowed=stage in {'data','generate'} or stage=='environment' and os.environ.get('ROUND10_REGRESSION')=='1'
                elif tail and tail[0].replace('\\','/').endswith('tools/run_round2.py'):
                    allowed='--mechanism-test' in tail and ('--skip-stk' in tail or '--probe-fault' in tail or '--stage-fault' in tail)
                elif tail and tail[0].replace('\\','/').endswith('tools/run_round10.py'):
                    allowed=len(tail)==4 and tail[1:3]==['--regression-worker','--result'] and inside(tail[3]) and inside(tail[0])
                    allowed |= (len(tail)==4 and tail[1:3] in (['--validate-worker','--run-spec'],['--candidate-worker','--run-spec']) and inside(tail[3]) and tail[0]==os.environ.get('ROUND10_VALIDATOR_ENTRY'))
                    allowed |= (len(tail)==4 and tail[1:3]==['--guard-probe','--result'] and inside(tail[3]) and tail[0]==os.environ.get('ROUND10_VALIDATOR_ENTRY'))
                elif tail and tail[0].replace('\\','/').endswith('tools/run_round9.py'):
                    allowed=len(tail)==4 and tail[1:3]==['--regression-worker','--result'] and inside(tail[3]) and inside(tail[0])
                elif tail[:1]==['-c']:
                    allowed=tail[1] in {'raise SystemExit(1)','raise SystemExit(7)','import time;time.sleep(30)',
                        'from pathlib import Path;import sys;print(Path(sys.argv[1]).read_text(encoding="utf-8"))'}
            if Path(argv[0]).name.lower()=='cmd.exe' and tail==['/c','ver']:allowed=True
            if read_isolation:allowed=False
            if not allowed:reason='UNAPPROVED_SUBPROCESS'
            else:record('allowed_offline_subprocess',argv)
        elif event in {'os.system','os.startfile','os.startfile/2','os.posix_spawn','os.spawn','socket.connect'}:
            reason='EXTERNAL_ACTIVATION'
        elif event=='open':
            path,mode,flags=args
            writing=(isinstance(mode,str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)
            if writing and not inside(path):reason='WRITE_OUTSIDE_ROUND10'
            elif not writing and read_isolation and not isinstance(path,int):
                resolved=Path(os.fsdecode(path)).resolve();key=str(resolved).casefold()
                code_read=resolved.is_relative_to(code_root) and resolved.suffix in {'.py','.pyc','.pyd','.dll'}
                system_read=any(resolved.is_relative_to(r) for r in system_roots)
                if key not in allowed_reads and not inside(path) and not code_read and not system_read:
                    reason='CANDIDATE_FORBIDDEN_READ'
                elif key in allowed_reads and key not in observed_reads:
                    observed_reads.add(key);record('allowed_candidate_input_read',str(resolved))
        elif event in {'os.remove','os.rmdir','os.mkdir','os.chmod','os.utime'}:
            if not inside(args[0]):reason='MUTATION_OUTSIDE_ROUND10'
        elif event in {'os.rename','os.link','os.symlink'}:
            if not all(inside(p) for p in args[:2]):reason='MUTATION_OUTSIDE_ROUND10'
        if reason:
            record('denied',dict(code=reason,event=event,target=str(args[1] if event=='subprocess.Popen' else args[0])[:500]))
            raise PermissionError('ROUND10_'+reason)
    sys.addaudithook(audit)
    record('guard_installed',dict(write_roots=list(map(str,roots)),native_activation_budget=0))
