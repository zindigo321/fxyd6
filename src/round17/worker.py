"""Offline scientific worker and isolated validation jobs."""
import argparse
from contextlib import ExitStack
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
from src.round13.common import read, write, require, record, fingerprint
from .binding import ROOT, verify_sources
from .control import Lifecycle, classify


def records(path):
    with Path(path).open(encoding='utf8') as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def export_mixed_orbits(out, selected, lib):
    from src.round13.inputs import state_key, ORBIT_FIELDS
    rows = []
    for n, index in enumerate(selected['indices'], 1):
        rows.append(dict(sat_id=f'Sat{n:03d}', catalog_index=index,
            **{key: repr(float(lib.assets[index]['row'][key])) for key in ORBIT_FIELDS},
            fixed_remove=1284, fixed_add=705, second_remove=selected['remove'], second_add=selected['add'],
            research_scope='conditional_saved_mixed_altitude_fixed_anchor_repair'))
    path = out/'selected_orbits.csv'
    with path.open('w', encoding='utf8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with path.open(encoding='utf8', newline='') as stream:
        restored = list(csv.DictReader(stream))
    require(len(restored) == 28, 'ORBIT_CSV_COUNT')
    for index, row in zip(selected['indices'], restored):
        require(int(row['catalog_index']) == index and state_key(row) == lib.states[index], 'ORBIT_CSV_STATE')
        require(all(float(row[k]).hex() == float(lib.assets[index]['row'][k]).hex() for k in ORBIT_FIELDS), 'ORBIT_CSV_FLOAT_BITS')
    write(out/'selected_orbits_protocol.json', dict(identity=selected['identity'], indices=selected['indices'],
        remove_pair=selected['remove_pair'], add_pair=selected['add_pair'], float_roundtrip_verified=True,
        source='archived_component_composition', whole_constellation_STK_verified=False,
        new_native_validation_performed=False, official_acceptance=False, csv=record(path)))


def science_job(work, out, life, lock):
    from .inputs import load, pool_diagnostic
    from .science import iter_candidates, evaluate, select, anchor_replay, ThresholdGate
    from .checker import IndependentChecker, neighborhood_summary, compact_report, verify_baseline_whole
    from src.round14.worker import save_details, baseline_assertions
    from src.round14.checker import _differences
    check = lambda: life.check(True)
    cfg = read(ROOT/'configs/round17.json')
    lib = load(cfg, work, check)
    count = None
    try:
        lock()
        write(out/'asset_context_verification.json', lib.evidence)
        write(out/'input_identity.json', dict(status='PASS', archive=record(cfg['archive'], check), used_members=dict(lib.arc.used)))
        frozen = read(work/'frozen/contract.json')['metadata']
        require(lib.baseline_indices == frozen['baseline_indices'] and lib.donor_indices == frozen['donor_indices']
            and {str(i): s for i, s in lib.states.items()} == frozen['states'], 'FROZEN_POOL_CHANGED')
        baseline, bhits = evaluate(lib.baseline_indices, lib.rows, lib.intervals, lib.keep, lib.targets, lib.states)
        checker = IndependentChecker(lib)
        bcheck = checker.verify(lib.baseline_indices, baseline, bhits)
        write(out/'baseline_checker.json', bcheck)
        require(bcheck['status'] == 'PASS', 'BASELINE_CHECKER')
        whole = verify_baseline_whole(baseline, bhits, lib.baseline_whole['hits'], lib.baseline_whole['intervals'], lib.targets)
        write(out/'baseline_whole_readback.json', whole)
        require(whole['status'] == 'PASS', 'BASELINE_WHOLE')
        baseline_assertions(baseline, lib.k13_baseline)
        for old in [lib.r14_baseline, lib.r15_baseline, read(Path(cfg['r16_delivery'])/'sealed/science/baseline.json')]:
            for key in ['full_grid', 'effective_grid', 'regional']:
                require(not _differences(old[key], baseline[key], 1e-6), 'HISTORICAL_BASELINE_REPLAY')
        save_details(out, 'baseline', baseline, bhits, lib)
        write(out/'baseline_provenance.json', dict(status='PASS', historical_whole=lib.baseline_whole['provenance'],
            historical_whole_verified=True, new_native_validation_performed=False, transferred_to_new_compositions=False))
        write(out/'checkpoint_baseline.json', dict(status='PASS', identity=baseline['identity'], lifecycle_elapsed_s=life.elapsed()))
        old_anchors = lib.r16_anchor_records
        selection, anchor, ahits = anchor_replay(lib, baseline, old_anchors, check)
        write(out/'anchor_selection.json', selection)
        acheck = checker.verify(anchor['indices'], anchor, ahits, baseline)
        write(out/'anchor_checker.json', acheck)
        require(acheck['status'] == 'PASS', 'ANCHOR_CHECKER')
        save_details(out, 'anchor', anchor, ahits, lib)
        # Independently replay every old anchor; none contributes to the new space count.
        old_checks = []
        independent_anchor_ranking = []
        for old in old_anchors:
            check()
            replay, hits = evaluate(old['indices'], lib.rows, lib.intervals, lib.keep, lib.targets, lib.states, baseline)
            checked = checker.verify(old['indices'], replay, hits, baseline)
            require(checked['status'] == 'PASS', 'FIVE_ANCHOR_INDEPENDENT_REPLAY')
            old_checks.append(dict(add=old['add'], identity=replay['identity'], checker=checked))
            independently_replayed, independent_hits = checker.recompute(old['indices'], baseline)
            c90 = int(np.count_nonzero(independent_hits[lib.keep] <= baseline['effective_grid']['T90_s']+1e-6))
            ranked = next(r for r in selection['ranked'] if r['add'] == old['add'])
            require(c90 == ranked['on_time_count'] and 38763-c90 == ranked['shortfall_points'], 'ANCHOR_SHORTFALL_INDEPENDENT')
            independent_anchor_ranking.append(dict(add=old['add'], identity=old['identity'], c90=c90,
                shortfall_points=38763-c90, T90_excess_s=independently_replayed['effective_grid']['T90_s']-baseline['effective_grid']['T90_s']))
        independent_anchor_ranking.sort(key=lambda r: (r['shortfall_points'], r['T90_excess_s'], r['identity']))
        require(independent_anchor_ranking[0]['add'] == 705, 'ANCHOR_SELECTION_INDEPENDENT')
        write(out/'five_anchor_checker.json', dict(status='PASS', checked=old_checks,
            independent_ranking=independent_anchor_ranking, selected_add=705, new_candidate_count=0))
        write(out/'checkpoint_anchor.json', dict(status='PASS', identity=anchor['identity'], lifecycle_elapsed_s=life.elapsed()))
        write(out/'expanded_pool_raw_domain_diagnostic.json', pool_diagnostic(lib, bhits))
        space = neighborhood_summary(lib.baseline_indices, lib.donor_indices, lib.states, check)
        for key in ['declared_candidates', 'unique_identities', 'identity_order_sha256', 'pair_order_sha256']:
            require(space[key] == frozen['space_summary'][key], 'INDEPENDENT_SPACE_MISMATCH')
        write(out/'independent_space_definition.json', space)
        gate = ThresholdGate(lib, baseline, check)
        thresholds = frozen['original_reference_thresholds']
        require(gate.tau100 == thresholds['tau100'] and gate.tau90 == thresholds['tau90']
            and gate.k90 == thresholds['k90'], 'FROZEN_EXACT_THRESHOLDS_CHANGED')
        write(out/'necessary_gate_context.json', gate.evidence())
        independent_gate = checker.verify_gate_evidence(gate.evidence())
        write(out/'independent_necessary_gate_context.json', independent_gate)
        require(independent_gate['status'] == 'PASS', 'INDEPENDENT_EXCLUSIVE_POINT_SETS')
        count = dict(declared_candidates=57834, fully_evaluated=0, fully_independently_verified=0,
            T100_certificate_rejected=0, T100_certificate_verified=0,
            T90_certificate_rejected=0, T90_certificate_verified=0,
            unprocessed=57834, unknown=0, qualified_count=0, retained_baseline=True)
        best = best_hits = None
        begin = time.perf_counter()
        names = ['ledger', 'candidates', 'candidate_summary', 'checker', 't100_certificates',
                 't100_certificate_checker', 't90_certificates', 't90_certificate_checker']
        with ExitStack() as stack:
            streams = {name: stack.enter_context((out/(name+'.jsonl')).open('w', encoding='utf8')) for name in names}
            def emit(name, obj):
                streams[name].write(json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(',', ':'))+'\n')
            for item in iter_candidates(lib.baseline_indices, lib.donor_indices, lib.states, check):
                part, cert = gate.classify(item)
                require(checker.partition(item) == part, 'INDEPENDENT_PARTITION_MISMATCH')
                if part in {'T100', 'T90'}:
                    checked = checker.verify_certificate(item, cert)
                    emit(part.lower()+'_certificates', cert)
                    emit(part.lower()+'_certificate_checker', checked)
                    count[part+'_certificate_rejected'] += 1
                    require(checked['status'] == 'PASS', 'NEGATIVE_CERTIFICATE_CHECK_FAILED')
                    count[part+'_certificate_verified'] += 1
                    emit('ledger', dict(item, partition=part, processing_state=part+'_CERTIFICATE_REJECTED',
                        certificate_sha256=fingerprint(cert), checker_output_sha256=fingerprint(checked)))
                    if count[part+'_certificate_verified'] % 1024 == 1:
                        write(out/'checkpoint_certificate.json', dict(status='PASS', partition=part,
                            verified=count[part+'_certificate_verified'], ordinal=item['ordinal'], lifecycle_elapsed_s=life.elapsed()))
                else:
                    check()
                    report, hits = evaluate(item['indices'], lib.rows, lib.intervals, lib.keep, lib.targets, lib.states, baseline)
                    report.update({k: v for k, v in item.items() if k not in {'identity', 'indices'}})
                    report['partition'] = 'FULL'
                    require(report['identity'] == item['identity'], 'CANDIDATE_IDENTITY')
                    checked = checker.verify(item['indices'], report, hits, baseline, item['remove_pair'], item['add_pair'])
                    emit('candidates', report)
                    emit('candidate_summary', compact_report(report))
                    emit('checker', checked)
                    count['fully_evaluated'] += 1
                    require(checked['status'] == 'PASS', 'FULL_POINT_OR_REGION_CHECK_FAILED')
                    count['fully_independently_verified'] += 1
                    emit('ledger', dict(item, partition=part, processing_state='FULLY_EVALUATED_AND_INDEPENDENTLY_VERIFIED',
                        main_output_sha256=checked['main_output_sha256'], checker_output_sha256=checked['checker_output_sha256']))
                    if count['fully_independently_verified'] % 128 == 1:
                        write(out/'checkpoint_full.json', dict(status='PASS', verified=count['fully_independently_verified'],
                            ordinal=item['ordinal'], lifecycle_elapsed_s=life.elapsed()))
                    if report['qualified_improvement']:
                        count['qualified_count'] += 1
                        chosen = select([report]+([best] if best else []))
                        if chosen is report:
                            best, best_hits = report, hits.copy()
                count['unprocessed'] = 57834-count['fully_evaluated']-count['T100_certificate_rejected']-count['T90_certificate_rejected']
                if item['ordinal'] % 1024 == 0 or (part == 'FULL' and count['fully_evaluated'] % 128 == 0):
                    check()
                    for stream in streams.values():
                        stream.flush()
                    write(out/'progress.json', dict(count, completed=False,
                        scientific_wall_s=time.perf_counter()-begin, optimization_outcome='PARTIAL_NOT_CONCLUDED'))
        chosen = checker.selection()
        require(chosen['selected_identity'] == (best['identity'] if best else None), 'INDEPENDENT_SELECTION')
        chosen['status'] = 'PASS'
        write(out/'independent_selection.json', chosen)
        terminal = checker.verify_completion(*[records(out/(name+'.jsonl')) for name in
            ['ledger', 'candidate_summary', 'checker', 't100_certificates', 't100_certificate_checker',
             't90_certificates', 't90_certificate_checker']], chosen['selected_identity'], check)
        write(out/'independent_terminal_verification.json', terminal)
        require(terminal['status'] == 'PASS', 'EXACT_SPACE_COMPLETION')
        count['retained_baseline'] = best is None
        for key in count:
            require(terminal[key] == count[key], 'COMPLETION_COUNT_BINDING:'+key)
        selected, shits = best or baseline, best_hits if best else bhits
        save_details(out, 'selected', selected, shits, lib)
        scheck = checker.verify(selected['indices'], selected, shits, baseline if best else None)
        write(out/'selected_checker.json', scheck)
        require(scheck['status'] == 'PASS', 'SELECTED_READBACK')
        if best:
            export_mixed_orbits(out, selected, lib)
        def heights(indices):
            return sorted({float(lib.assets[i]['row']['altitude_km']) for i in indices})
        write(out/'research_scope.json', dict(status='PASS', conditional_mixed_altitude_research=True,
            baseline_altitudes_km=heights(baseline['indices']), anchor_altitudes_km=heights(anchor['indices']),
            selected_altitudes_km=heights(selected['indices']), donor_pool_altitudes_km=heights(lib.donor_indices),
            official_acceptance=False, active_protocol_change_authorized=False,
            new_native_validation_performed=False, whole_constellation_STK_verified=False))
        write(out/'boundary_tradeoffs.json', dict(baseline=baseline['regional'], selected=selected['regional'],
            boundary_is_primary_constraint=False, internal_and_boundary_objectives_distinct=True))
        preservation = lib.preserve()
        for name in ['asset_verification.jsonl', 'input_asset_verification.jsonl']:
            if (work/name).is_file():
                import shutil
                shutil.copyfile(work/name, out/name)
        write(out/'source_preservation.json', preservation)
        outcome = 'FEASIBLE_IMPROVEMENT_FOUND' if best else 'NO_FEASIBLE_IMPROVEMENT_IN_DECLARED_ANCHOR_REPAIR_NEIGHBORHOOD'
        completion = dict(count, completed=True, optimization_outcome=outcome, selected_identity=selected['identity'],
            scientific_wall_s=time.perf_counter()-begin)
        write(out/'enumeration_completion.json', completion)
        write(out/'progress.json', completion)
        return dict(status='PASS', assets=2171, baseline_replayed=1, anchor_replayed=1, **completion)
    except BaseException:
        if count is not None:
            count['unknown'] = (count['fully_evaluated']-count['fully_independently_verified']+
                count['T100_certificate_rejected']-count['T100_certificate_verified']+
                count['T90_certificate_rejected']-count['T90_certificate_verified'])
            write(out/'progress.json', dict(count, completed=False, optimization_outcome='PARTIAL_NOT_CONCLUDED'))
        raise
    finally:
        lib.close()


def tests_job(work, out):
    tmp = out/'tmp'
    tmp.mkdir()
    os.environ.update({k: str(tmp) for k in ['ROUND17_TEST_ROOT', 'ROUND16_TEST_ROOT', 'ROUND15_TEST_ROOT',
        'ROUND14_TEST_ROOT', 'ROUND13_TEST_ROOT', 'TMP', 'TEMP']})
    import tempfile
    tempfile.tempdir = str(tmp)
    suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'), pattern='test_round17*.py')
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    (out/'tests.log').write_text(stream.getvalue(), encoding='utf8')
    data = dict(status='PASS' if result.wasSuccessful() and not result.skipped else 'FAIL', tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
    write(out/'tests.json', data)
    require(data['status'] == 'PASS', 'ROUND17_NEW_TEST_FAILURE')
    return data


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--work', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--job', required=True, choices=['science', 'tests', 'legacy', 'guards'])
    args = parser.parse_args()
    work, out = Path(args.work).resolve(), Path(args.out).resolve()
    require(out.is_relative_to(work/'attempts') and out.name == 'output', 'WORKER_OUTPUT_SCOPE')
    out.mkdir()
    life = Lifecycle(work/'lifecycle.json')
    start, cpu = time.perf_counter(), time.process_time()
    cfg = read(ROOT/'configs/round17.json')
    from src.round13.resources import SelfMemory
    memory = SelfMemory()
    if args.job == 'legacy':
        os.environ.update(ROUND9_WRITE_ROOTS=json.dumps([str(work)]), ROUND9_GUARD_LOG=str(out/'parent_guard.jsonl'))
        from src.round9.guard import install
        install()
        lock = lambda: None
    else:
        from .guard import install
        lock = install(work, out/'guard.jsonl', Path(cfg['k13_work'])/'vendor', controlled=args.job == 'guards')
    rows = read(out.parent/'consumer_code.json')
    try:
        life.check(True)
        verify_sources(rows, lambda: life.check(True))
        if args.job == 'science':
            result = science_job(work, out, life, lock)
        elif args.job == 'tests':
            result = tests_job(work, out)
        elif args.job == 'legacy':
            from .regression import run_regressions
            result = run_regressions(work, out, life)
        else:
            from src.round14.worker import guards_job
            result = guards_job(work, out, lock)
            probe = work.parents[1]/'round16/probe/materialized/harmless_probe.py'
            try:
                exec(compile('pass', str(probe), 'exec'), {})
            except PermissionError as exc:
                require(str(exc) == 'ROUND17_GUARD_VENDOR_EXECUTION', 'WRONG_R17_VENDOR_GUARD')
            else:
                raise ValueError('ROUND17_PRIOR_VENDOR_GUARD_FAILED')
            result['controlled_rejections'] += 1
            write(out/'round17_guard_counterexamples.json', dict(status='PASS', controlled_rejections=1, actual_native_activation_count=0))
        verify_sources(rows, lambda: life.check(True))
        life.check(True)
        code = 0
    except Exception as exc:
        level = classify(exc)
        code = 1 if level == 'FAIL' else 2
        result = dict(status=level, error=str(exc))
        write(out/'failure_state.json', dict(**result, exit_code=code))
        (out/'error.log').write_text(traceback.format_exc(), encoding='utf8')
    result.update(exit_code=code, worker_wall_s=time.perf_counter()-start, worker_cpu_s=time.process_time()-cpu,
        memory=memory.sample(), job=args.job, attempt_id=out.parent.name, consumer_identity=fingerprint(rows))
    write(out/'job_result.json', result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
