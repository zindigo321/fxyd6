"""Read-only archived vendor guard including all preceding rounds."""
import json
import os
from pathlib import Path
import sys
from src.round16.guard import install as archived_install


def install(work, log, old_vendor, controlled=False):
    lock = archived_install(work, log, old_vendor, controlled)
    history = Path(work).resolve().parents[1]
    root = history/'round16'

    def audit(event, args):
        if event != 'exec' or args[0].co_filename.startswith('<'):
            return
        path = Path(args[0].co_filename).resolve()
        if path.is_relative_to(root) and 'materialized' in path.parts:
            with Path(log).open('a', encoding='utf8') as stream:
                stream.write(json.dumps(dict(kind='expected_denial' if controlled else 'unexpected_denial',
                    pid=os.getpid(), controlled=controlled,
                    detail=dict(reason='VENDOR_EXECUTION', target=str(path))))+'\n')
            raise PermissionError('ROUND17_GUARD_VENDOR_EXECUTION')

    sys.addaudithook(audit)
    return lock
