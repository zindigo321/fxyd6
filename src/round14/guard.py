"""Extend the existing offline guard to both immutable library locations."""
import json
import os
from pathlib import Path
import sys
from src.round13.guard import install as install_existing


def install(work, log, old_vendor, controlled=False):
    work, log = Path(work).resolve(), Path(log)
    install_existing(work, log, controlled)
    frozen = [Path(old_vendor).resolve(), work/'materialized', work/'vendor']
    locked = [False]
    busy = [False]

    def deny(reason, target):
        if not busy[0]:
            busy[0] = True
            try:
                with log.open('a', encoding='utf8') as stream:
                    stream.write(json.dumps(dict(kind='expected_denial' if controlled else 'unexpected_denial',
                        pid=os.getpid(), controlled=controlled, detail=dict(reason=reason,target=str(target))))+'\n')
            finally:
                busy[0] = False
        raise PermissionError('ROUND14_GUARD_'+reason)

    def inside(value):
        if isinstance(value, int) or value is None:
            return False
        p = Path(os.fsdecode(value)).resolve()
        return any(p.is_relative_to(root) for root in frozen)

    def audit(event, args):
        if busy[0]:
            return
        if event == 'exec' and not args[0].co_filename.startswith('<') and inside(args[0].co_filename):
            deny('VENDOR_EXECUTION', args[0].co_filename)
        if locked[0] and event == 'open':
            path, mode, flags = args
            writing = (isinstance(mode,str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)
            if writing and inside(path):
                deny('IMMUTABLE_INPUT_WRITE', path)
        if locked[0] and event in {'os.remove','os.rmdir','os.mkdir','os.chmod','os.utime'} and inside(args[0]):
            deny('IMMUTABLE_INPUT_MUTATION', args[0])
        if event in {'os.rename','os.link','os.symlink'} and any(inside(p) for p in args[:2]):
            deny('IMMUTABLE_INPUT_MUTATION', args[:2])
    sys.addaudithook(audit)
    return lambda: locked.__setitem__(0, True)
