"""Process-local audit guard installed inside every round13 offline worker."""
import importlib.abc
import json
import os
from pathlib import Path
import sys

FORBIDDEN = {'pythoncom','win32com','comtypes','win32event','winreg','native_components','stk_adapter','stk_geometry','native','verification_store'}


def install(work, log, controlled=False):
    root = Path(work).resolve(); vendor = root/'vendor'; log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    busy = [False]
    def record(kind, detail):
        if busy[0]:
            return
        busy[0] = True
        try:
            with log.open('a', encoding='utf8') as f:
                f.write(json.dumps(dict(pid=os.getpid(), kind=kind, detail=detail, controlled=controlled), ensure_ascii=False)+'\n')
        finally:
            busy[0] = False
    def deny(reason, target):
        record('expected_denial' if controlled else 'unexpected_denial', dict(reason=reason, target=str(target)[:500]))
        raise PermissionError('ROUND13_GUARD_'+reason)
    def writable(path):
        if isinstance(path, int) or path is None:
            return True
        p = Path(os.fsdecode(path)).resolve()
        return p.is_relative_to(root) and not p.is_relative_to(vendor)
    class NativeFinder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if set(fullname.lower().split('.')) & FORBIDDEN:
                deny('NATIVE_IMPORT', fullname)
    sys.meta_path.insert(0, NativeFinder())
    def audit(event,args):
        if busy[0]:
            return
        if event == 'import' and set(args[0].lower().split('.')) & FORBIDDEN:
            deny('NATIVE_IMPORT', args[0])
        if event in {'subprocess.Popen','os.system','os.startfile','os.startfile/2','os.posix_spawn','os.spawn'}:
            deny('UNAPPROVED_SUBPROCESS', event)
        if event.startswith('socket.'):
            deny('NETWORK', event)
        if event in {'ctypes.dlopen','ctypes.dlsym','ctypes.call_function'}:
            deny('NATIVE_CALL', event)
        if event == 'exec':
            filename = args[0].co_filename
            if not filename.startswith('<'):
                file = Path(filename).resolve()
                if file.is_relative_to(vendor) or file.stem.lower() in FORBIDDEN:
                    deny('VENDOR_EXECUTION', filename)
        if event == 'open':
            path, mode, flags = args
            writing = (isinstance(mode,str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)
            if writing and not writable(path):
                deny('WRITE_SCOPE', path)
        if event in {'os.remove','os.rmdir','os.mkdir','os.chmod','os.utime'} and not writable(args[0]):
            deny('MUTATION_SCOPE',args[0])
        if event in {'os.rename','os.link','os.symlink'} and not all(writable(p) for p in args[:2]):
            deny('MUTATION_SCOPE',args[:2])
    sys.addaudithook(audit)
    record('guard_installed',dict(write_root=str(root), vendor_read_only=True, native_budget=0, child_processes='none'))
