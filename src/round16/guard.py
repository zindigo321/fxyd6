"""Offline audit guard; historical extracted assets remain byte evidence."""
import json
from pathlib import Path
import sys
from src.round14.guard import install as archived_install


def install(work, log, old_vendor, controlled=False):
    lock = archived_install(work, log, old_vendor, controlled)
    history = Path(work).resolve().parents[1]
    roots = [history / 'round14', history / 'round15']

    def audit(event, args):
        if event != 'exec' or args[0].co_filename.startswith('<'):
            return
        path = Path(args[0].co_filename).resolve()
        if any(path.is_relative_to(root) for root in roots) and 'materialized' in path.parts:
            with Path(log).open('a', encoding='utf8') as stream:
                stream.write(json.dumps(dict(kind='expected_denial' if controlled else 'unexpected_denial',
                    controlled=controlled, detail=dict(reason='VENDOR_EXECUTION', target=str(path)))) + '\n')
            raise PermissionError('ROUND16_GUARD_VENDOR_EXECUTION')

    sys.addaudithook(audit)
    return lock
