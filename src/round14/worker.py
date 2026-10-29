"""Supervised jobs; scientific work has no native/network/process capability."""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
import numpy as np
from src.round13.common import read, write, require, sha, fingerprint, record
from .control import Lifecycle, classify
from .binding import ROOT, verify_sources


def append(path, obj):
    with Path(path).open('a',encoding='utf8') as stream:
        stream.write(json.dumps(obj,ensure_ascii=False,allow_nan=False)+'\n')


def save_details(out, name, report, hits, lib):
    write(out/(name+'.json'), report)
    np.save(out/(name+'_first_hits.npy'),hits,allow_pickle=False)
    with (out/(name+'_first_hits.csv')).open('w',encoding='utf8',newline='') as stream:
        writer=csv.writer(stream);writer.writerow(['point_id','latitude_deg','longitude_deg','in_provisional_mask','first_hit_s'])
        for n,(coord,keep,value) in enumerate(zip(lib.coords,lib.keep,hits)):
            writer.writerow([n,repr(float(coord[0])),repr(float(coord[1])),bool(keep),repr(float(value)) if np.isfinite(value) else ''])
    restored=np.load(out/(name+'_first_hits.npy'),allow_pickle=False)
    require(np.array_equal(restored,hits),'FIRST_HIT_DETAILS_READBACK')


def baseline_assertions(report, k13):
    from .checker import _differences
    for domain in ['full_grid','effective_grid']:
        require(not _differences(k13[domain],report[domain],1e-6),'K13_BASELINE_'+domain)
    require(not _differences(k13['regional']['pooled_internal'],report['regional']['pooled_internal'],1e-6),'K13_BASELINE_GAPS')
    # Declared historical anchors are assertions only, never output values.
    mask=report['effective_grid']; gaps=report['regional']['pooled_internal']
    for actual,expected in [(mask['T90_s'],283728.33914436615),(mask['T100_s'],595089.2108747589),
                            (gaps['mean_s'],9413.983168107336),(gaps['max_s'],172730.31608610202)]:
        require(actual is not None and abs(actual-expected)<=1e-6,'BASELINE_ANCHOR_DIFFERENCE')
    require(mask['covered']==43070 and mask['uncovered']==0 and report['full_grid']['uncovered']==354
            and report['full_grid']['T100_s'] is None and gaps['gap_count']==172,'BASELINE_COUNTS')
    longest=report['regional']['longest_internal_gap']
    require(longest['target']=='YangtzeRiverDelta_Island_2'
            and all(abs(a-b)<=1e-6 for a,b in zip(longest['endpoints_s'],[69292.439694662,242022.755780764])), 'BASELINE_LONGEST_GAP')


def export_orbits(out, selected, lib):
    from src.round13.inputs import state_key, ORBIT_FIELDS
    rows=[]
    for n,index in enumerate(selected['indices'],1):
        rows.append(dict(sat_id=f'Sat{n:03d}',**{k:repr(float(lib.assets[index]['row'][k])) for k in ORBIT_FIELDS}))
    path=out/'selected_orbits.csv'
    with path.open('w',encoding='utf8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=['sat_id',*ORBIT_FIELDS]);writer.writeheader();writer.writerows(rows)
    with path.open(encoding='utf8',newline='') as stream:
        restored=list(csv.DictReader(stream))
    for index,row in zip(selected['indices'],restored):
        require(state_key(row)==lib.states[index],'ORBIT_CSV_STATE_READBACK')
        require(all(float(row[k]).hex()==float(lib.assets[index]['row'][k]).hex() for k in ORBIT_FIELDS),'ORBIT_CSV_FLOAT_BITS')
    write(out/'selected_orbits_protocol.json',dict(label='保存组件库组合候选，未做新整星座 STK 验证',
        source='archived_component_composition',identity=selected['identity'],indices=selected['indices'],
        float_roundtrip_verified=True,whole_constellation_STK_verified=False,new_native_validation_performed=False,
        protocol=lib.evidence['protocol'],csv=record(path)))


def science_job(work,out,life,lock_inputs):
    from .inputs import load
    from .science import evaluate,neighborhood,select,summarize_completion
    from .checker import IndependentChecker,verify_baseline_whole
    cfg=read(ROOT/'configs/round14.json'); check=lambda:life.check(True)
    lib=load(cfg,work,check)
    try:
        lock_inputs()
        write(out/'asset_context_verification.json',lib.evidence)
        write(out/'input_identity.json',dict(status='PASS',archive=record(cfg['archive'],check),
            original_manifest_sha256=cfg['manifest_sha256'],loaded_members=dict(lib.arc.used)))
        declared=read(work/'frozen/contract.json')['neighborhood']
        require(neighborhood(lib.baseline_indices,lib.donor_indices,lib.states)==declared==lib.neighborhood,'FROZEN_NEIGHBORHOOD_CHANGED')
        baseline,hits=evaluate(lib.baseline_indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states)
        checker=IndependentChecker(lib.baseline_indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states)
        bcheck=checker.verify(lib.baseline_indices,baseline,hits)
        write(out/'baseline_checker.json',bcheck); require(bcheck['status']=='PASS','BASELINE_CHECKER_MISMATCH')
        whole=verify_baseline_whole(baseline,hits,lib.baseline_whole['hits'],lib.baseline_whole['intervals'],lib.targets)
        write(out/'baseline_whole_readback.json',whole); require(whole['status']=='PASS','BASELINE_WHOLE_MISMATCH')
        baseline_assertions(baseline,lib.k13_baseline)
        write(out/'baseline_provenance.json',dict(historical_whole=lib.baseline_whole['provenance'],
            historical_whole_verified=True,new_native_validation_performed=False,
            note='Historical whole provenance retained separately from new component compositions'))
        save_details(out,'baseline',baseline,hits,lib)
        reports=[];checks=[]
        for position,item in enumerate(declared,1):
            check()
            report,point_values=evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
            report.update(remove=item['remove'],add=item['add'])
            require(report['identity']==item['identity'],'CANDIDATE_IDENTITY')
            # The independent checker sees every full-point vector before it is discarded.
            checked=checker.verify(item['indices'],report,point_values,baseline,item['remove'],item['add'])
            append(out/'candidates.jsonl',report);append(out/'checker.jsonl',checked)
            reports.append(report);checks.append(checked)
            write(out/'progress.json',dict(evaluated=position,verified=sum(c['status']=='PASS' for c in checks),
                declared=896,completed=False,optimization_outcome='PARTIAL_NOT_CONCLUDED'))
            require(checked['status']=='PASS','ALL_CANDIDATE_CHECKER_MISMATCH')
        completion=summarize_completion(declared,reports,checks)
        require(completion['completed'] and len(reports)==896 and len(checks)==896,'INCOMPLETE_CARTESIAN_ENUMERATION')
        chosen=select(reports);ranking=checker.selection([r['identity'] for r in reports])
        require(ranking['selected_identity']==(chosen['identity'] if chosen else None),'INDEPENDENT_SELECTION_MISMATCH')
        terminal=checker.verify_completion(lib.donor_indices,declared,reports,checks,ranking['selected_identity'])
        write(out/'independent_terminal_verification.json',terminal)
        require(terminal['status']=='PASS','INDEPENDENT_CARTESIAN_COMPLETENESS')
        write(out/'independent_selection.json',ranking)
        chosen=chosen or baseline
        full_selected,selected_hits=evaluate(chosen['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
        if chosen is baseline:
            full_selected=baseline
        selected_check=checker.verify(chosen['indices'],full_selected,selected_hits,baseline if chosen is not baseline else None,
            chosen.get('remove'),chosen.get('add'))
        require(selected_check['status']=='PASS','SELECTED_READBACK_MISMATCH')
        save_details(out,'selected',full_selected,selected_hits,lib)
        write(out/'selected_checker.json',selected_check)
        if chosen is not baseline:export_orbits(out,full_selected,lib)
        preservation=lib.preserve();write(out/'source_preservation.json',preservation)
        write(out/'enumeration_completion.json',completion)
        write(out/'progress.json',completion)
        comparison={t:dict(baseline=baseline['regional']['targets'][t]['boundary_inclusive'],
            selected=full_selected['regional']['targets'][t]['boundary_inclusive'],
            baseline_edges=baseline['regional']['targets'][t]['boundary_segments'],
            selected_edges=full_selected['regional']['targets'][t]['boundary_segments']) for t in lib.targets}
        write(out/'boundary_tradeoffs.json',comparison)
        write(out/'optimization.json',dict(**completion,selected_identity=chosen['identity'],
            retained_baseline=chosen is baseline,qualified_count=ranking['qualified_count'],
            baseline_identity=baseline['identity'],limitations='Finite one-swap neighborhood only; unofficial mask and unconfirmed rule revisions',
            historically_seen_candidates=[dict(identity=r['identity'],seen_in_pinned_baseline=r['identity']==baseline['identity'],
                presence_outside_pinned_baseline='NOT_ASSERTED') for r in reports],
            history_comparison_scope='Pinned baseline whole identity only; historical presence beyond pinned identities not asserted'))
        return dict(status='PASS',assets=60,baseline_replayed=1,candidates=896,verified_candidates=896,
            point_values_independently_compared=897*cfg['raw_point_count'],optimization_outcome=completion['optimization_outcome'])
    finally:
        lib.close()


def tests_job(work,out):
    tmp=out/'tmp';tmp.mkdir();os.environ.update(ROUND14_TEST_ROOT=str(tmp),ROUND13_TEST_ROOT=str(tmp),TMP=str(tmp),TEMP=str(tmp))
    import tempfile
    tempfile.tempdir=str(tmp)
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_round14*.py')
    stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    (out/'tests.log').write_text(stream.getvalue(),encoding='utf8')
    data=dict(status='PASS' if result.wasSuccessful() and not result.skipped else 'FAIL',tests=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped))
    write(out/'tests.json',data);require(data['status']=='PASS','ROUND14_TEST_FAILURE')
    return data


def legacy_job(work,out,life):
    from src.round9 import regression
    from src.round10.binding import bind
    cfg=read(ROOT/'configs/round14.json');prior=Path(cfg['prior'])/'executed_closure'
    frozen142=read(prior/'starting_code_manifest.json')['files']
    require(len(frozen142)==142,'FROZEN142_COUNT')
    for row in frozen142:require(record(row['path'])==row,'FROZEN142_CHANGED')
    write(out/'binding_subset142.json',frozen142)
    binding,cases=bind(Path(read(ROOT/'configs/round12.json')['k9']),ROOT,frozen142,out,out)
    require(binding['status']==cases['status']=='PASS' and len(cases['cases'])==26,'HISTORICAL_BINDING_COUNTEREXAMPLES')
    # The current two repairs are included; new R14 tests are explicitly excluded.
    before=read(work/'starting_tracked_manifest.json')['files']
    subset=[record(ROOT/r['relative_path']) for r in before]
    require(len(subset)==168,'REGRESSION_SUBSET168_COUNT');write(out/'regression_subset168.json',subset)
    original_run=regression.subprocess.run
    def observed_run(argv,**kwargs):
        if '--regression-worker' not in argv:return original_run(argv,**kwargs)
        repo=out/'regression/repo'
        def snapshot():
            mapping=[]
            for row in subset:
                rel=Path(row['path']).relative_to(ROOT);dest=repo/rel;actual=record(dest)
                require((actual['bytes'],actual['sha256'])==(row['bytes'],row['sha256']),'REGRESSION_COPY_VERSION_MISMATCH')
                mapping.append(dict(relative_path=rel.as_posix(),source=row,executed_copy=actual))
            return mapping
        write(out/'regression_mapping_before.json',snapshot())
        kwargs['timeout']=min(kwargs.get('timeout',170),life.timeout())
        try:return original_run(argv,**kwargs)
        finally:write(out/'regression_mapping_after.json',snapshot())
    regression.subprocess.run=observed_run
    try:result=regression.run_regression(ROOT,out,subset)
    finally:regression.subprocess.run=original_run
    require(result['status']=='PASS' and result['tests']==202 and not any(result[k] for k in ['failures','errors','skipped']),'ORIGINAL_202_TEST_FAILURE')
    for row in subset:require(record(row['path'])==row,'REGRESSION_SOURCE_CHANGED')
    write(out/'historical_reuse.json',dict(status='REUSED',not_rerun=['historical77','historical49'],
        stage_map=binding['historical_stage_map'],K12=dict(status='BLOCKED',exit_code=2,units=0,cost='NOT_RUN')))
    return dict(status='PASS',regression_tests=202,binding_counterexamples=26,regression=result)


def guards_job(work,out,lock_inputs):
    from src.round13.worker import guards_job as existing_probes
    result=existing_probes(work,out)
    lock_inputs()
    probes=[]
    for name,reason,action in [
        ('materialized_write','IMMUTABLE_INPUT_WRITE',lambda:(work/'materialized/probe.txt').write_text('denied')),
        ('old_vendor_execution','VENDOR_EXECUTION',lambda:exec(compile('pass',str(Path(read(ROOT/'configs/round14.json')['k13_work'])/'vendor/probe.py'),'exec'),{}))]:
        try:action()
        except PermissionError as exc:require(str(exc)=='ROUND14_GUARD_'+reason,'WRONG_ROUND14_GUARD_REASON');probes.append(dict(name=name,reason=reason))
        else:raise ValueError('GUARD_PROBE_NOT_REJECTED')
    write(out/'round14_guard_counterexamples.json',dict(status='PASS',cases=probes,actual_native_activation_count=0))
    result['controlled_rejections']+=len(probes)
    return result


def main():
    p=argparse.ArgumentParser(allow_abbrev=False);p.add_argument('--work',required=True);p.add_argument('--out',required=True)
    p.add_argument('--job',required=True,choices=['science','tests','legacy','guards']);a=p.parse_args()
    work,out=Path(a.work).resolve(),Path(a.out).resolve()
    require(out.is_relative_to(work/'attempts') and out.name=='output','WORKER_OUTPUT_SCOPE');out.mkdir()
    start=time.perf_counter();cpu=time.process_time();life=Lifecycle(work/'lifecycle.json')
    from src.round13.resources import SelfMemory
    memory=SelfMemory();cfg=read(ROOT/'configs/round14.json')
    if a.job=='legacy':
        os.environ.update(ROUND9_WRITE_ROOTS=json.dumps([str(work)]),ROUND9_GUARD_LOG=str(out/'parent_guard.jsonl'))
        from src.round9.guard import install
        install();lock=lambda:None
    else:
        from .guard import install
        lock=install(work,out/'guard.jsonl',Path(cfg['k13_work'])/'vendor',controlled=a.job=='guards')
    rows=read(out.parent/'consumer_code.json')
    try:
        life.check(True);verify_sources(rows,lambda:life.check(True))
        if a.job=='science':result=science_job(work,out,life,lock)
        elif a.job=='tests':result=tests_job(work,out)
        elif a.job=='guards':result=guards_job(work,out,lock)
        else:result=legacy_job(work,out,life)
        verify_sources(rows,lambda:life.check(True));life.check(True);code=0
    except Exception as exc:
        level=classify(exc);code=2 if level=='BLOCKED' else 1
        result=dict(status=level,error=str(exc));write(out/'failure_state.json',dict(**result,exit_code=code))
        (out/'error.log').write_text(traceback.format_exc(),encoding='utf8')
    result.update(exit_code=code,worker_wall_s=time.perf_counter()-start,worker_cpu_s=time.process_time()-cpu,
        memory=memory.sample(),job=a.job,attempt_id=out.parent.name,consumer_identity=fingerprint(rows))
    write(out/'job_result.json',result);print(json.dumps(result,ensure_ascii=False));return code


if __name__=='__main__':raise SystemExit(main())
