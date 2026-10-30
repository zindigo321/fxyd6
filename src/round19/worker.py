"""Isolated source-bound R19 scientific and regression jobs."""
import argparse
import io
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest

from src.round13.common import read, write, require, fingerprint, sha
from .binding import ROOT, verify_sources
from .control import Lifecycle, classify


def records(path):
    with Path(path).open(encoding='utf8') as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def tests_job(work, out):
    tmp=out/'tmp'; tmp.mkdir()
    os.environ.update({key:str(tmp) for key in ['ROUND19_TEST_ROOT','ROUND18_TEST_ROOT',
        'ROUND17_TEST_ROOT','ROUND16_TEST_ROOT','ROUND15_TEST_ROOT','ROUND14_TEST_ROOT',
        'ROUND13_TEST_ROOT','TMP','TEMP']})
    import tempfile
    tempfile.tempdir=str(tmp)
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_round19*.py')
    stream=io.StringIO()
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    (out/'tests.log').write_text(stream.getvalue(),encoding='utf8')
    data=dict(status='PASS' if result.wasSuccessful() and not result.skipped else 'FAIL',
        tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped))
    write(out/'tests.json',data)
    require(data['status']=='PASS','ROUND19_NEW_TEST_FAILURE')
    return data


def main():
    p=argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument('--work',required=True);p.add_argument('--out',required=True)
    p.add_argument('--job',required=True,choices=['tests','guards','legacy','science'])
    args=p.parse_args();work=Path(args.work).resolve();out=Path(args.out).resolve()
    require(work.is_relative_to(ROOT/'work/round19') and out.parent.parent==work/'attempts'
        and out.name=='output','ROUND19_WORKER_SCOPE')
    out.mkdir(); life=Lifecycle(work/'lifecycle.json')
    started=time.perf_counter();cpu=time.process_time()
    import datetime
    start_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
    from src.round13.resources import SelfMemory
    memory=SelfMemory()
    cfg=read(ROOT/'configs/round19.json');allowlist=[]
    if args.job=='legacy':
        lock=lambda:None
    else:
        from .guard import install
        lock=install(work,out/'guard.jsonl',Path(cfg['k13_work'])/'vendor',
            controlled=args.job=='guards',role=args.job,commands=allowlist)
    rows=read(out.parent/'consumer_code.json')
    contract_sha256=sha(out.parent/'consumer_contract.json') if (out.parent/'consumer_contract.json').exists() else None
    try:
        life.check(True); verify_sources(rows,lambda:life.check(True))
        if contract_sha256 is not None:
            require(sha(work/'frozen/contract.json')==contract_sha256,'ROUND19_ATTEMPT_CONTRACT_MISMATCH')
        if args.job=='science':
            from .science import science_job
            result=science_job(work,out,life,lock)
        elif args.job=='tests':
            result=tests_job(work,out)
        elif args.job=='legacy':
            from .regression import run_regressions
            result=run_regressions(work,out,life,commands=allowlist)
        else:
            from .guard import run_guard_probes
            result=run_guard_probes(work,out,life,allowlist=allowlist)
        events=[]
        for name in ['guard.jsonl','parent_guard.jsonl','regression_guard.jsonl']:
            if (out/name).exists():events.extend(records(out/name))
        unexpected=[r for r in events if r.get('kind') in {'unexpected_denial','denied'}]
        require(not unexpected,'ROUND19_GUARD_UNEXPECTED_DENIAL')
        write(out/'guard_audit.json',dict(status='PASS',unexpected_denials=0,
            expected_controlled_rejections=sum(r.get('kind')=='expected_denial' for r in events),
            logged_events=len(events),native_activation_count=0,
            protection_scope='Python audit and module finder; no OS isolation claim'))
        verify_sources(rows,lambda:life.check(True)); life.check(True);code=0
        if contract_sha256 is not None:
            require(sha(work/'frozen/contract.json')==contract_sha256,'ROUND19_ATTEMPT_CONTRACT_CHANGED')
    except Exception as exc:
        level=classify(exc); code=1 if level=='FAIL' else 2
        result=dict(status=level,error=str(exc))
        write(out/'failure_state.json',dict(**result,exit_code=code))
        (out/'error.log').write_text(traceback.format_exc(),encoding='utf8')
    result.update(exit_code=code,worker_wall_s=time.perf_counter()-started,
        worker_cpu_s=time.process_time()-cpu,memory=memory.sample(),job=args.job,
        start_utc=start_utc,end_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        argv=list(sys.orig_argv),cwd=str(Path.cwd()),shell_used=False,shell_exit_code=None,
        attempt_id=out.parent.name,consumer_identity=fingerprint(rows),contract_sha256=contract_sha256)
    write(out/'job_result.json',result);print(json.dumps(result,ensure_ascii=False),flush=True)
    return code


if __name__=='__main__':
    raise SystemExit(main())
