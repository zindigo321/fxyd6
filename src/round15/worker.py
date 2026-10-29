"""Supervised certificate-assisted scientific and validation jobs."""
import argparse
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
import numpy as np
from src.round13.common import read,write,require,record,fingerprint
from .binding import ROOT,verify_sources
from .control import Lifecycle,classify


def records(path):
    with Path(path).open(encoding='utf8') as stream:
        for line in stream:
            if line.strip():yield json.loads(line)


def science_job(work,out,life,lock):
    from .inputs import load,pool_diagnostic
    from .science import iter_candidates,prove_gap,classify as partition,certificate_record,evaluate,select
    from .checker import IndependentChecker,neighborhood_summary,compact_report,verify_baseline_whole
    from src.round14.worker import save_details,baseline_assertions,export_orbits
    from src.round14.checker import _differences
    check=lambda:life.check(True);cfg=read(ROOT/'configs/round15.json');lib=load(cfg,work,check)
    try:
        lock();write(out/'asset_context_verification.json',lib.evidence)
        write(out/'input_identity.json',dict(status='PASS',archive=record(cfg['archive'],check),used_members=dict(lib.arc.used)))
        frozen=read(work/'frozen/contract.json')['metadata']
        require(lib.baseline_indices==frozen['baseline_indices'] and lib.donor_indices==frozen['donor_indices']
                and {str(i):s for i,s in lib.states.items()}==frozen['states'],'FROZEN_POOL_CHANGED')
        baseline,bhits=evaluate(lib.baseline_indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states)
        checker=IndependentChecker(lib);bcheck=checker.verify(lib.baseline_indices,baseline,bhits)
        write(out/'baseline_checker.json',bcheck);require(bcheck['status']=='PASS','BASELINE_CHECKER')
        whole=verify_baseline_whole(baseline,bhits,lib.baseline_whole['hits'],lib.baseline_whole['intervals'],lib.targets)
        write(out/'baseline_whole_readback.json',whole);require(whole['status']=='PASS','BASELINE_WHOLE')
        baseline_assertions(baseline,lib.k13_baseline)
        for key in ['full_grid','effective_grid','regional']:
            require(not _differences(lib.r14_baseline[key],baseline[key],1e-6),'R14_BASELINE_REPLAY')
        save_details(out,'baseline',baseline,bhits,lib)
        write(out/'baseline_provenance.json',dict(historical_whole=lib.baseline_whole['provenance'],
            historical_whole_verified=True,new_native_validation_performed=False,transferred_to_new_compositions=False))
        diagnostic=pool_diagnostic(lib,bhits);write(out/'raw_domain_354_point_diagnostic.json',diagnostic)
        proof=prove_gap(lib,baseline);write(out/'gap_proof.json',proof)
        independent_proof=checker.verify_gap_proof(proof,baseline);write(out/'independent_gap_proof.json',independent_proof)
        require(independent_proof['status']=='PASS','GAP_PROOF_INDEPENDENT_MISMATCH')
        independent_space=neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states,check)
        for key in ['declared_candidates','unique_identities','identity_order_sha256','pair_order_sha256']:
            require(independent_space[key]==frozen['space_summary'][key],'INDEPENDENT_SPACE_MISMATCH')
        write(out/'independent_space_definition.json',independent_space)
        count=dict(declared_candidates=independent_space['declared_candidates'],fully_evaluated=0,
            fully_independently_verified=0,certificate_rejected=0,certificate_independently_verified=0,
            unprocessed=independent_space['declared_candidates'],unknown=0,qualified_count=0,retained_baseline=True)
        best=None;best_hits=None;branch_best={};partitions={'A':0,'B':0,'C':0};begin=time.perf_counter()
        names=['ledger','candidates','candidate_summary','checker','certificates','certificate_checker']
        with ExitStack() as stack:
            streams={name:stack.enter_context((out/(name+'.jsonl')).open('w',encoding='utf8')) for name in names}
            def emit(name,obj):streams[name].write(json.dumps(obj,ensure_ascii=False,allow_nan=False,separators=(',',':'))+'\n')
            for item in iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states,check):
                part=partition(item,proof);require(checker.partition(item)==part,'PARTITION_MAIN_CHECKER_DISAGREEMENT')
                partitions[part]+=1
                if part=='C':
                    cert=certificate_record(item,proof);checked=checker.verify_certificate(item,cert,proof)
                    emit('certificates',cert);emit('certificate_checker',checked)
                    count['certificate_rejected']+=1
                    require(checked['status']=='PASS','CERTIFICATE_CHECK_FAILED')
                    count['certificate_independently_verified']+=1
                    emit('ledger',dict(item,partition=part,processing_state='PROVEN_NO_SUBSTANTIVE_TMAX_IMPROVEMENT',
                        certificate_sha256=fingerprint(cert),proof_sha256=proof['proof_sha256']))
                else:
                    check();report,hits=evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
                    report.update(remove=item['remove'],add=item['add'],ordinal=item['ordinal'],partition=part)
                    require(report['identity']==item['identity'],'CANDIDATE_IDENTITY')
                    checked=checker.verify(item['indices'],report,hits,baseline,item['remove'],item['add'])
                    emit('candidates',report);emit('candidate_summary',compact_report(report));emit('checker',checked)
                    count['fully_evaluated']+=1;require(checked['status']=='PASS','CANDIDATE_POINT_OR_REGION_CHECK_FAILED')
                    count['fully_independently_verified']+=1
                    emit('ledger',dict(item,partition=part,processing_state='FULLY_EVALUATED_AND_INDEPENDENTLY_VERIFIED',
                        main_output_sha256=checked['main_output_sha256'],checker_output_sha256=checked['checker_output_sha256']))
                    if report['qualified_improvement']:
                        count['qualified_count']+=1
                        chosen=select([report]+([best] if best else []))
                        if chosen is report:best=report;best_hits=hits.copy()
                        prior=branch_best.get(part);branch_best[part]=select([report]+([prior] if prior else []))
                count['unprocessed']=count['declared_candidates']-count['fully_evaluated']-count['certificate_rejected']
                if item['ordinal']%1024==0 or (part!='C' and count['fully_evaluated']%128==0):
                    check()
                    for stream in streams.values():stream.flush()
                    write(out/'progress.json',dict(count,completed=False,partitions=partitions,
                        scientific_wall_s=time.perf_counter()-begin,optimization_outcome='PARTIAL_NOT_CONCLUDED'))
        choice=checker.selection();require(choice['selected_identity']==(best['identity'] if best else None),'INDEPENDENT_SELECTION')
        write(out/'independent_selection.json',choice)
        terminal=checker.verify_completion(records(out/'ledger.jsonl'),records(out/'candidate_summary.jsonl'),
            records(out/'checker.jsonl'),records(out/'certificates.jsonl'),records(out/'certificate_checker.jsonl'),choice['selected_identity'],check)
        write(out/'independent_terminal_verification.json',terminal);require(terminal['status']=='PASS','EXACT_SPACE_COMPLETION')
        for key in count:require(terminal[key]==count[key] if key!='retained_baseline' else terminal[key]==(best is None),'COMPLETION_COUNT_BINDING:'+key)
        count['retained_baseline']=best is None
        require(count['unprocessed']==count['unknown']==0 and partitions=={'A':11718,'B':465,'C':175305},'PARTITION_COMPLETENESS')
        selected=best or baseline;selected_hits=best_hits if best else bhits
        save_details(out,'selected',selected,selected_hits,lib)
        selected_check=checker.verify(selected['indices'],selected,selected_hits,baseline if best else None,
            selected.get('remove'),selected.get('add'))
        require(selected_check['status']=='PASS','SELECTED_FULL_READBACK');write(out/'selected_checker.json',selected_check)
        if best:export_orbits(out,selected,lib)
        for part,report in branch_best.items():write(out/('partition_'+part+'_best_qualified.json'),report)
        write(out/'boundary_tradeoffs.json',dict(baseline=baseline['regional'],selected=selected['regional'],
            internal_and_boundary_objectives_distinct=True,boundary_is_primary_constraint=False))
        preservation=lib.preserve()
        from .inputs import prior_binding
        preservation['r14_prior_binding_after']=prior_binding(cfg,check)
        write(out/'source_preservation.json',preservation)
        outcome='FEASIBLE_IMPROVEMENT_FOUND' if best else 'NO_FEASIBLE_IMPROVEMENT_IN_DECLARED_TWO_SWAP_NEIGHBORHOOD'
        completion=dict(count,completed=True,partitions=partitions,optimization_outcome=outcome,selected_identity=selected['identity'])
        write(out/'enumeration_completion.json',completion);write(out/'progress.json',completion)
        return dict(status='PASS',assets=60,baseline_replayed=1,**completion,
            point_values_independently_compared=(count['fully_independently_verified']+1)*cfg['raw_point_count'])
    finally:lib.close()


def tests_job(work,out):
    tmp=out/'tmp';tmp.mkdir();os.environ.update(ROUND15_TEST_ROOT=str(tmp),ROUND14_TEST_ROOT=str(tmp),ROUND13_TEST_ROOT=str(tmp),TMP=str(tmp),TEMP=str(tmp))
    import tempfile
    tempfile.tempdir=str(tmp)
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_round15*.py');stream=io.StringIO()
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    (out/'tests.log').write_text(stream.getvalue(),encoding='utf8');data=dict(status='PASS' if result.wasSuccessful() and not result.skipped else 'FAIL',
        tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped))
    write(out/'tests.json',data);require(data['status']=='PASS','ROUND15_NEW_TEST_FAILURE');return data


def main():
    p=argparse.ArgumentParser(allow_abbrev=False);p.add_argument('--work',required=True);p.add_argument('--out',required=True)
    p.add_argument('--job',required=True,choices=['science','tests','legacy','guards']);a=p.parse_args()
    work,out=Path(a.work).resolve(),Path(a.out).resolve();require(out.is_relative_to(work/'attempts') and out.name=='output','WORKER_OUTPUT_SCOPE');out.mkdir()
    life=Lifecycle(work/'lifecycle.json');start=time.perf_counter();cpu=time.process_time();cfg=read(ROOT/'configs/round15.json')
    from src.round13.resources import SelfMemory
    memory=SelfMemory()
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
        elif a.job=='legacy':
            from .regression import run_regressions
            result=run_regressions(work,out,life)
        else:
            from src.round14.worker import guards_job
            result=guards_job(work,out,lock)
            old_probe=work.parents[1]/'round14'/'probe'/'materialized'/'harmless_probe.py'
            try:exec(compile('pass',str(old_probe),'exec'),{})
            except PermissionError as exc:require(str(exc)=='ROUND15_GUARD_VENDOR_EXECUTION','WRONG_R15_VENDOR_GUARD')
            else:raise ValueError('R15_PRIOR_VENDOR_GUARD_FAILED')
            write(out/'round15_guard_counterexamples.json',dict(status='PASS',probe='prior_R14_materialized_execution',
                actual_native_activation_count=0,controlled_rejections=1))
            result['controlled_rejections']+=1
        verify_sources(rows,lambda:life.check(True));life.check(True);code=0
    except Exception as exc:
        level=classify(exc);code=1 if level=='FAIL' else 2;result=dict(status=level,error=str(exc))
        write(out/'failure_state.json',dict(**result,exit_code=code));(out/'error.log').write_text(traceback.format_exc(),encoding='utf8')
    result.update(exit_code=code,worker_wall_s=time.perf_counter()-start,worker_cpu_s=time.process_time()-cpu,
        memory=memory.sample(),job=a.job,attempt_id=out.parent.name,consumer_identity=fingerprint(rows))
    write(out/'job_result.json',result);print(json.dumps(result,ensure_ascii=False));return code


if __name__=='__main__':raise SystemExit(main())
