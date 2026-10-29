"""Reuse the existing offline guard and protect prior materialized inputs."""
import os
import json
from pathlib import Path
import sys
from src.round14.guard import install as historical_install


def install(work,log,old_vendor,controlled=False):
    lock=historical_install(work,log,old_vendor,controlled)
    old=Path(work).resolve().parents[1]/'round14'
    def audit(event,args):
        if event=='exec' and not args[0].co_filename.startswith('<'):
            path=Path(args[0].co_filename).resolve()
            if path.is_relative_to(old) and 'materialized' in path.parts:
                with Path(log).open('a',encoding='utf8') as stream:
                    stream.write(json.dumps(dict(kind='expected_denial' if controlled else 'unexpected_denial',
                        controlled=controlled,detail=dict(reason='VENDOR_EXECUTION',target=str(path))))+'\n')
                raise PermissionError('ROUND15_GUARD_VENDOR_EXECUTION')
    sys.addaudithook(audit)
    return lock
