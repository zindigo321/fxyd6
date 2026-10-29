"""Shared-deadline coordinator; all real candidates follow an immutable freeze."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from src.round13.common import read, write, require, fingerprint
from .binding import ROOT, freeze, verify_sources, artifacts, manifest, source_files
from .control import Lifecycle, Status, classify

ACTIVE_WORK = None
ACTIVE_SELECTED = {}
ACTIVE_STATUS = None


def utc_id():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+uuid.uuid4().hex[:6]


def invoke(work, job, rows, snapshot=None):
    life = Lifecycle(work/'lifecycle.json')
    verify_sources(rows, lambda: life.check(True))
    timeout = life.timeout()
    attempt = work/'attempts'/(utc_id()+'_'+job)
    attempt.mkdir(parents=True)
    write(attempt/'consumer_code.json', rows)
    shutil.copyfile(snapshot or work/'frozen/consumer_code.zip', attempt/'consumer_code.zip')
    out = attempt/'output'
    argv = [sys.executable, '-X', 'utf8', '-B', '-m', 'src.round18.worker',
            '--work', str(work), '--out', str(out), '--job', job]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONIOENCODING='utf-8', GIT_OPTIONAL_LOCKS='0')
    start = time.perf_counter()
    timedout = False
    from .supervise import run as supervised_run
    with (attempt/'stdout.log').open('wb') as stdout, (attempt/'stderr.log').open('wb') as stderr:
        try:
            actual_timeout = min(timeout, life.timeout())
            proc = supervised_run(argv, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                  timeout=actual_timeout)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            timedout, code = True, None
    result = read(out/'job_result.json') if (out/'job_result.json').exists() else dict(
        status='BLOCKED' if timedout else 'FAIL', exit_code=2 if timedout else code or 1,
        error='TIMEOUT' if timedout else 'NO_WORKER_RESULT')
    if (out/'failure_state.json').exists() and read(out/'failure_state.json')['status'] == 'FAIL':
        result.update(read(out/'failure_state.json'))
    if code and result.get('exit_code') == 0:
        result.update(status='FAIL', exit_code=1, error='CHILD_EXIT_MISMATCH')
    try:
        verify_sources(rows, lambda: life.check(True))
    except Exception as exc:
        level = classify(exc)
        if level == 'FAIL' or result.get('status') != 'FAIL':
            result.update(status=level, exit_code=1 if level == 'FAIL' else 2, error=str(exc))
    write(attempt/'supervised_result.json', result)
    command = dict(command=argv, python_exit_code=code, supervised_result_exit_code=result['exit_code'],
        job=job, timeout=timedout, enforced_timeout_s=actual_timeout, attempt_id=attempt.name, output=str(out),
        code_manifest=rows, supervised_wall_s=time.perf_counter()-start,
        lifecycle_elapsed_s=life.elapsed(), output_artifacts=artifacts(out),
        process_tree_supervision='Windows Job Object; suspended assignment; kill-on-close')
    write(attempt/'command_result.json', command)
    print(json.dumps(dict(job=job, attempt=str(attempt), result=result), ensure_ascii=False), flush=True)
    return attempt, result


def main():
    global ACTIVE_WORK, ACTIVE_SELECTED, ACTIVE_STATUS
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--work')
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--new-attempt', action='store_true')
    parser.add_argument('--verify-seal')
    args = parser.parse_args()
    from .seal import independent_readback, seal
    if args.verify_seal:
        result = independent_readback(Path(args.verify_seal))
        print(json.dumps(result, ensure_ascii=False))
        return result['exit_code']
    cfg = read(ROOT/'configs/round18.json')
    work = Path(args.work or ROOT/cfg['prepared_work']).resolve()
    require(work.is_relative_to(ROOT/'work/round18') and work.is_dir(), 'ROUND18_WORK_SCOPE')
    ACTIVE_WORK = work
    from .guard import install_coordinator_guard
    install_coordinator_guard(work)
    life = Lifecycle(work/'lifecycle.json')
    life.check(True)
    if (work/'latest_delivery.json').exists() and not args.new_attempt:
        result = independent_readback(Path(read(work/'latest_delivery.json')['path']))
        print(json.dumps(result, ensure_ascii=False))
        return result['exit_code']
    if args.preflight:
        require(not (work/'frozen').exists(), 'PREFLIGHT_MUST_PRECEDE_FREEZE')
        pre = work/('preflight_'+utc_id())
        pre.mkdir()
        rows = manifest(source_files(work), lambda: life.check(True))
        write(pre/'consumer_code.json', rows)
        with zipfile.ZipFile(pre/'consumer_code.zip', 'w', zipfile.ZIP_DEFLATED) as z:
            for row in rows:
                z.write(row['path'], row['relative_path'])
        attempt, result = invoke(work, 'tests', rows, pre/'consumer_code.zip')
        write(pre/'result.json', dict(attempt=str(attempt), result=result,
            frozen_scientific_contract=False, real_candidate_evaluations=0))
        return result['exit_code']
    if (work/'frozen').exists():
        require(args.new_attempt, 'EXISTING_FREEZE_REQUIRES_NEW_ATTEMPT')
        dest = work/'frozen_history'/utc_id()
        require((work/'frozen').resolve().is_relative_to(work) and dest.resolve().is_relative_to(work), 'FROZEN_HISTORY_SCOPE')
        dest.parent.mkdir(exist_ok=True)
        shutil.move(str(work/'frozen'), str(dest))
        if (work/'supervision').exists():
            supervision_history = work/'supervision_history'/utc_id()
            require((work/'supervision').resolve().is_relative_to(work) and
                supervision_history.resolve().is_relative_to(work), 'SUPERVISION_HISTORY_SCOPE')
            supervision_history.parent.mkdir(exist_ok=True)
            shutil.move(str(work/'supervision'), str(supervision_history))
    from .inputs import metadata
    meta = metadata(cfg, work, lambda: life.check(True))
    rows = freeze(work, cfg, meta, lambda: life.check(True))
    selected, state = {}, Status()
    ACTIVE_SELECTED = selected
    ACTIVE_STATUS = state
    try:
        from .supervise import verify_process_tree
        verify_process_tree(work/'supervision', life)
        for job in ['tests', 'guards', 'legacy', 'science']:
            attempt, result = invoke(work, job, rows)
            selected[job] = attempt
            state.add(result['status'], job+': '+result.get('error', 'completed'))
            if result['exit_code']:
                break
    except Exception as exc:
        state.add(classify(exc), str(exc))
    if set(selected) != {'tests', 'guards', 'science', 'legacy'} and state.value == 'PASS':
        state.add('BLOCKED', 'Required jobs incomplete')
    result = seal(work, selected, state.value, state.reasons)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result['exit_code']


def cli():
    start = time.perf_counter()
    code, error = 1, None
    try:
        code = main()
    except Exception as exc:
        import traceback
        code = 1 if ACTIVE_STATUS is not None and ACTIVE_STATUS.value == 'FAIL' else 2 if classify(exc) == 'BLOCKED' else 1
        error = dict(type=type(exc).__name__, message=str(exc), traceback=traceback.format_exc())
        print(json.dumps(dict(status='BLOCKED' if code == 2 else 'FAIL', error=error), ensure_ascii=False), flush=True)
        if ACTIVE_WORK and not (ACTIVE_WORK/'latest_delivery.json').exists():
            from .seal import seal
            try:
                seal(ACTIVE_WORK, ACTIVE_SELECTED, 'BLOCKED' if code == 2 else 'FAIL', [error])
            except Exception as closure_error:
                print('PREFIX_SEAL_ERROR', str(closure_error), flush=True)
    if ACTIVE_WORK:
        write(ACTIVE_WORK/'transport'/('entry_'+utc_id()+'.json'), dict(
            command=[sys.executable, *sys.argv], python_exit_code=code, error=error,
            entry_end_to_end_s=time.perf_counter()-start,
            lifecycle_elapsed_upper_bound_s=Lifecycle(ACTIVE_WORK/'lifecycle.json').elapsed(),
            scope='Actual entry completion; later export is timed separately without adding overlapping worker time'))
    return code
