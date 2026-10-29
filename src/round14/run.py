"""Default offline coordinator with a true parent-enforced shared deadline."""
import argparse
import datetime
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from src.round13.common import read,write,require,fingerprint,record
from .binding import ROOT,freeze,verify_sources,artifacts,manifest,source_files
from .control import Lifecycle,Status,classify

ACTIVE_WORK=None


def utc_id():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+uuid.uuid4().hex[:6]


def initialize_work():
    work=ROOT/'work/round14'/utc_id();work.mkdir(parents=True)
    start=time.time();write(work/'lifecycle.json',dict(start_epoch=start,
        recorded_start_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        total_limit_seconds=7200,compute_limit_seconds=6600,pre_record_preparation_upper_bound_seconds=0))
    cfg=read(ROOT/'configs/round14.json');original=Path(cfg['k13_work'])/'old_code_before.json'
    old=read(original)['files'];k13=sorted([p for p in (ROOT/'src/round13').rglob('*.py')]+
        list((ROOT/'tests').glob('test_round13*.py'))+[ROOT/'tools/run_round13.py',ROOT/'configs/round13.json',ROOT/'docs/round13.md'])
    rows=[dict(record(r['path']),relative_path=Path(r['path']).relative_to(ROOT).as_posix()) for r in old]
    rows += [dict(record(p),relative_path=p.relative_to(ROOT).as_posix()) for p in k13]
    write(work/'starting_tracked_manifest.json',dict(files=rows,allowed_modified=['src/round13/run.py','src/round13/seal.py']))
    with zipfile.ZipFile(work/'starting_tracked_source.zip','w',zipfile.ZIP_DEFLATED) as z:
        for row in rows:z.write(row['path'],row['relative_path'])
    env=dict(os.environ,GIT_OPTIONAL_LOCKS='0')
    for name,args in {'head':['rev-parse','HEAD'],'branch':['branch','--show-current'],
                      'status':['status','--porcelain=v1','-uall'],'tracked_diff':['diff','--no-ext-diff'],
                      'staged_diff':['diff','--cached','--no-ext-diff']}.items():
        p=subprocess.run(['git','-c','safe.directory=G:/fmb666',*args],cwd=ROOT,env=env,capture_output=True,timeout=30)
        (work/('starting_git_'+name+'.txt')).write_bytes(p.stdout+p.stderr)
    write(work/'initial_scope.json',dict(round=14,native_activation_count=0,git_write_operations=0))
    return work


def invoke(work,job,rows):
    life=Lifecycle(work/'lifecycle.json');timeout=life.timeout();verify_sources(rows,lambda:life.check(True))
    attempt=work/'attempts'/(utc_id()+'_'+job);attempt.mkdir(parents=True)
    write(attempt/'consumer_code.json',rows);shutil.copyfile(work/'frozen/consumer_code.zip',attempt/'consumer_code.zip')
    out=attempt/'output';argv=[sys.executable,'-X','utf8','-B','-m','src.round14.worker',
        '--work',str(work),'--out',str(out),'--job',job]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8',GIT_OPTIONAL_LOCKS='0')
    start=time.perf_counter();timedout=False
    with (attempt/'stdout.log').open('wb') as stdout,(attempt/'stderr.log').open('wb') as stderr:
        try:proc=subprocess.run(argv,cwd=ROOT,env=env,stdout=stdout,stderr=stderr,timeout=min(timeout,life.timeout()));code=proc.returncode
        except subprocess.TimeoutExpired:timedout=True;code=2
    result=read(out/'job_result.json') if (out/'job_result.json').exists() else dict(
        status='BLOCKED' if timedout else 'FAIL',exit_code=code if code else 1,error='TIMEOUT' if timedout else 'NO_WORKER_RESULT')
    if (out/'failure_state.json').exists() and read(out/'failure_state.json')['status']=='FAIL':
        result.update(read(out/'failure_state.json'));code=1
    # A completed or preserved scientific FAIL dominates a later timeout.
    if timedout and (out/'error.log').exists() and result.get('status')=='FAIL':code=1
    if code and result.get('exit_code')==0:result.update(status='FAIL',exit_code=1,error='CHILD_EXIT_MISMATCH')
    try:verify_sources(rows,lambda:life.check(True))
    except Exception as exc:
        level=classify(exc)
        if level=='FAIL' or result.get('status')!='FAIL':result.update(status=level,exit_code=1 if level=='FAIL' else 2,error=str(exc))
    write(attempt/'supervised_result.json',result)
    command=dict(command=argv,python_exit_code=code,supervised_result_exit_code=result['exit_code'],job=job,
        timeout=timedout,enforced_timeout_s=timeout,attempt_id=attempt.name,output=str(out),code_manifest=rows,
        supervised_wall_s=time.perf_counter()-start,lifecycle_elapsed_s=life.elapsed(),output_artifacts=artifacts(out))
    write(attempt/'command_result.json',command)
    print(__import__('json').dumps(dict(job=job,attempt=str(attempt),result=result),ensure_ascii=False),flush=True)
    return attempt,result


def main():
    global ACTIVE_WORK
    entry=time.perf_counter();p=argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument('--work');p.add_argument('--verify-seal');p.add_argument('--new-attempt',action='store_true')
    # Explicit unsupported research parameters fail parsing; a new scientific contract requires a new run.
    a=p.parse_args()
    from .seal import independent_readback,seal
    if a.verify_seal:
        result=independent_readback(Path(a.verify_seal));print(__import__('json').dumps(result,ensure_ascii=False));return result['exit_code']
    cfg=read(ROOT/'configs/round14.json')
    prepared=ROOT/cfg['prepared_work']
    work=Path(a.work).resolve() if a.work else prepared if prepared.exists() else initialize_work()
    require(work.is_relative_to(ROOT/'work/round14'),'ROUND14_WORK_SCOPE');ACTIVE_WORK=work
    if (work/'latest_delivery.json').exists() and not a.new_attempt:
        result=independent_readback(Path(read(work/'latest_delivery.json')['path']))
        result['historical_reentry']=True;print(__import__('json').dumps(result,ensure_ascii=False));return result['exit_code']
    life=Lifecycle(work/'lifecycle.json');life.check(True)
    if (work/'frozen').exists():
        require(a.new_attempt,'EXISTING_UNSEALED_RUN_REQUIRES_EXPLICIT_NEW_ATTEMPT')
        dest=work/'frozen_history'/utc_id();dest.parent.mkdir(exist_ok=True);shutil.move(str(work/'frozen'),str(dest))
    from .inputs import metadata
    meta=metadata(cfg,work,lambda:life.check(True))
    rows=freeze(work,cfg,meta,lambda:life.check(True))
    selected={};status=Status()
    for job in ['science','tests','legacy','guards']:
        try:
            attempt,result=invoke(work,job,rows);selected[job]=attempt
            status.add(result['status'],job+': '+result.get('error','completed'))
            if result['exit_code']:break
        except Exception as exc:
            status.add(classify(exc),str(exc));break
    if set(selected)!={'science','tests','legacy','guards'} and status.value=='PASS':status.add('BLOCKED','Required jobs incomplete')
    result=seal(work,selected,status.value,status.reasons,entry)
    print(__import__('json').dumps(result,ensure_ascii=False));return result['exit_code']


def cli():
    start=time.perf_counter();code=1;error=None
    try:code=main()
    except Exception as exc:
        import traceback
        code=2 if classify(exc)=='BLOCKED' else 1;error=dict(type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc())
        print(__import__('json').dumps(dict(status='BLOCKED' if code==2 else 'FAIL',error=error),ensure_ascii=False))
        if ACTIVE_WORK is not None and ACTIVE_WORK.exists() and not (ACTIVE_WORK/'latest_delivery.json').exists():
            from .seal import seal_early_prefix
            try:seal_early_prefix(ACTIVE_WORK,'BLOCKED' if code==2 else 'FAIL',error)
            except Exception as seal_error:print('PREFIX_SEAL_ERROR',str(seal_error))
    if ACTIVE_WORK is not None:
        work=ACTIVE_WORK;data=dict(command=[sys.executable,*sys.argv],python_exit_code=code,error=error,
            entry_end_to_end_s=time.perf_counter()-start,lifecycle_elapsed_upper_bound_s=Lifecycle(work/'lifecycle.json').elapsed(),
            scope='Actual entry completion; excludes later external export; no double counting of worker wall time')
        if (work/'latest_delivery.json').exists():data['delivery']=read(work/'latest_delivery.json')
        write(work/'transport'/('entry_'+utc_id()+'.json'),data)
    return code
