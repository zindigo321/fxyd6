"""Coordinator: each long worker has a real remaining-budget timeout."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import zipfile
from .common import read, write, require, record
from .control import Lifecycle, Status, BudgetExceeded, classify

ROOT=Path(__file__).resolve().parents[2]
ACTIVE_WORK=None


def code_files():
    return sorted([p for p in (ROOT/'src/round13').rglob('*.py')] + list((ROOT/'tests').glob('test_round13*.py')) + [ROOT/'tools/run_round13.py',ROOT/'configs/round13.json'] + ([ROOT/'docs/round13.md'] if (ROOT/'docs/round13.md').exists() else []))


def invoke(work,job,extra=None):
    life=Lifecycle(work/'lifecycle.json');life.check()
    attempt=work/'attempts'/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+job+'_'+uuid.uuid4().hex[:6])
    attempt.mkdir(parents=True)
    manifest=[record(p,life.check) for p in code_files()]
    write(attempt/'consumer_code.json',manifest)
    with zipfile.ZipFile(attempt/'consumer_code.zip','w',zipfile.ZIP_DEFLATED) as z:
        for p in code_files():z.write(p,p.relative_to(ROOT).as_posix())
    out=attempt/'output'
    argv=[sys.executable,'-X','utf8','-B','-m','src.round13.worker','--work',str(work),'--out',str(out),'--job',job]+(extra or [])
    started=time.perf_counter();timedout=False
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8')
    with (attempt/'stdout.log').open('wb') as stdout,(attempt/'stderr.log').open('wb') as stderr:
        try:
            proc=subprocess.run(argv,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,timeout=max(.001,life.remaining()))
            code=proc.returncode
        except subprocess.TimeoutExpired:
            timedout=True;code=2
    data=dict(command=argv,python_exit_code=code,supervised_wall_s=time.perf_counter()-started,timeout=timedout,lifecycle_elapsed_upper_bound_s=life.elapsed(),phase_remaining_s=life.remaining(),code_manifest=manifest)
    write(attempt/'command_result.json',data)
    result=read(out/'job_result.json') if (out/'job_result.json').exists() else dict(status='BLOCKED' if timedout else 'FAIL',exit_code=code,error='TIMEOUT' if timedout else 'WORKER_NO_RESULT')
    try:
        life.check()
        for row in manifest:require(record(row['path'],life.check)==row,'CONSUMER_CODE_CHANGED_DURING_JOB')
    except BudgetExceeded as exc:
        if result.get('exit_code')==1:
            result.setdefault('additional_reasons',[]).append(str(exc))
        else:
            result.update(status='BLOCKED',exit_code=2,error=str(exc))
    write(attempt/'supervised_result.json',result)
    print(json.dumps(dict(job=job,output=str(out),result=result),ensure_ascii=False))
    return out,result


def new_work():
    now=time.time();work=ROOT/'work/round13'/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+uuid.uuid4().hex[:8])
    work.mkdir(parents=True)
    write(work/'lifecycle.json',dict(recorded_start_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),start_epoch=now,pre_record_preparation_upper_bound_seconds=0,
        total_limit_seconds=7200,phase_limits=dict(input=1200,implementation_replay=3000,validation=1800,seal_export=900,correction=300),phase='input',phase_start_epoch=now))
    return work


def main():
    global ACTIVE_WORK
    entry=time.perf_counter();p=argparse.ArgumentParser()
    p.add_argument('--work');p.add_argument('--mode',choices=['all','evaluate-existing','check','tests','legacy','guards','seal','verify-seal'],default='all')
    p.add_argument('--case');p.add_argument('--request');p.add_argument('--main-out');p.add_argument('--seal-dir')
    p.add_argument('--review-revision',action='store_true',help='Rerun after a reviewed code correction, retaining all prior seals and the same lifecycle budget')
    a=p.parse_args();work=Path(a.work).resolve() if a.work else new_work()
    ACTIVE_WORK=work
    require(work.is_relative_to(ROOT/'work/round13'),'WORK_ROOT_SCOPE')
    if a.mode=='verify-seal':
        from .seal import verify_seal
        result=verify_seal(Path(a.seal_dir));print(json.dumps(result,ensure_ascii=False));return result['exit_code']
    sealed=Path(read(work/'latest_delivery.json')['path']) if (work/'latest_delivery.json').exists() else work/'delivery'
    if (sealed/'receipt.json').exists() and not a.review_revision:
        from .seal import verify_seal
        result=verify_seal(sealed);print(json.dumps(result,ensure_ascii=False));return result['exit_code']
    if not (work/'input_binding.json').exists():
        from .prepare import prepare
        prepare(work)
    life=Lifecycle(work/'lifecycle.json');life.check()
    if a.mode in ['all','evaluate-existing']:
        require(a.mode=='all' or a.case in read(ROOT/'configs/round13.json')['cases'],'EXPLICIT_CASE_REQUIRED')
        extra=(['--case',a.case] if a.case else [])+(['--request',a.request] if a.request else [])
        out,result=invoke(work,'replay',extra)
        if a.mode=='evaluate-existing' or result['exit_code']:
            return result['exit_code']
        write(work/'latest_main.json',dict(path=str(out)))
    if a.mode=='all':
        if life.data['phase']=='implementation_replay':life.phase('validation')
        for job,extra in [('check',['--main-out',str(out)]),('tests',[]),('guards',[]),('legacy',[])]:
            jobout,result=invoke(work,job,extra)
            write(work/('latest_'+job+'.json'),dict(path=str(jobout)))
            if result['exit_code']:return result['exit_code']
        life=Lifecycle(work/'lifecycle.json')
        if life.data['phase']=='validation':life.phase('seal_export')
        from .seal import seal
        return seal(work,entry)
    if a.mode in ['check','tests','legacy','guards']:
        extra=['--main-out',a.main_out] if a.mode=='check' else []
        out,result=invoke(work,a.mode,extra);write(work/('latest_'+a.mode+'.json'),dict(path=str(out)));return result['exit_code']
    if a.mode=='seal':
        life.phase('seal_export')
        from .seal import seal
        return seal(work,entry)
    return 0


def cli():
    """Completion evidence is outside the seal and binds it after final readback."""
    start=time.perf_counter();code=1;error=None
    try:
        code=main()
    except Exception as exc:
        import traceback
        error=dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc())
        code=2 if classify(exc)=='BLOCKED' else 1
        print(json.dumps(dict(status='BLOCKED' if code==2 else 'FAIL',error=error),ensure_ascii=False))
    # Explicit --work invocations have a known destination even on failure.
    if ACTIVE_WORK is not None:
        work=ACTIVE_WORK
        if work.is_relative_to(ROOT/'work/round13') and work.exists():
            record_path=work/'entry_records'/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+uuid.uuid4().hex[:6]+'.json')
            data=dict(command=[sys.executable,*sys.argv],python_exit_code=code,error=error,entry_end_to_end_s=time.perf_counter()-start,
                      measurement_boundary='entry through all jobs, final seal readback and result; completion-file write excluded',
                      lifecycle_elapsed_upper_bound_s=Lifecycle(work/'lifecycle.json').elapsed())
            if (work/'latest_delivery.json').exists():
                from .common import sha
                delivery=Path(read(work/'latest_delivery.json')['path']);data['sealed_manifest_sha256']=sha(delivery/'artifact_manifest.json');data['delivery']=str(delivery)
            write(record_path,data)
    return code
