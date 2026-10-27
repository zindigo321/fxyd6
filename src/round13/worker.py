"""Short supervised jobs. The coordinator grants no native or network capability."""
import argparse
import copy
import io
import json
import os
from pathlib import Path
import sys
import time
import traceback
import unittest
import numpy as np
from .common import read, write, require, record
from .control import Lifecycle
from .archive import Archive
from .inputs import Inputs
from .protocol import build_protocols, compatibility
from .replay import evaluate_existing
from .checker import verify_report, independent_compatibility

ROOT = Path(__file__).resolve().parents[2]


def replay_job(work, out, case=None, request=None):
    cfg = read(ROOT/'configs/round13.json'); life = Lifecycle(work/'lifecycle.json')
    arc = Archive(cfg, work/'vendor', life.check, extract=False)
    try:
        matrix = build_protocols(arc, cfg, ROOT)
        write(out/'protocol_matrix.json', matrix)
        write(out/'normalized_schema.json',dict(schema_version=1,record_source='archive_replay',
            required_physical_fields=['time','frame','earth_eop','fov_half_deg','attitude_installation','coordinates','mask','regional','sampling','orbit_identity','producer_protocol_hash','coverage_scope'],
            identities=['producer_code_identity','consumer_code_identity','provenance'],
            evidence_types=['saved_whole_constellation','historical_global_array'],
            first_hits=dict(csv_no_hit='',npy_no_hit='positive_infinity',finite_time_unit='seconds_from_epoch',invalid=['NaN','negative_infinity','negative_time','beyond_window']),
            domains=dict(raw_points=cfg['raw_point_count'],provisional_mask_points=cfg['mask_point_count'],mask_official=False),
            tolerances=dict(time_absolute_seconds=cfg['absolute_time_tolerance_s'],classification='exact',counts='exact'),
            incompatible_status='NOT_COMPUTABLE_FROM_FROZEN_EVIDENCE',missing_library_status='UNAVAILABLE_FROM_FROZEN_LIBRARY'))
        inputs = Inputs(arc, cfg)
        from .common import fingerprint
        consumer_identity=fingerprint(read(out.parent/'consumer_code.json'))
        cases = [case] if case else list(cfg['cases'])
        results = {}
        for cid in cases:
            life.check()
            desc = matrix['cases'][cid]
            evaluated = evaluate_existing(inputs, cid, desc, requested=request)
            if isinstance(evaluated, dict):
                results[cid] = evaluated
            else:
                results[cid], order = evaluated
                np.save(out/(cid+'_coordinate_permutation.npy'), order, allow_pickle=False)
            results[cid]['consumer_code_identity']=consumer_identity
            write(out/(cid+'.json'), results[cid])
        # Concrete incompatible requests, each based on an actual accepted descriptor.
        source = matrix['cases']['team_competition_N28']
        variations = dict(narrow_fov=('fov_half_deg',[0.001622,0.81]), old_16_points=('coverage_scope','diagnostic_sample_only'),
                          regional_grid=('regional',dict(kind='point_grid',spacing_deg=0.1)), new_time=('time',['2028',604800]),
                          changed_height=('regional',dict(kind='AreaTarget',height=0)), changed_eop=('earth_eop',dict(EOP='new')),
                          new_coordinates=('coordinates',dict(points=[[0,0]])))
        gates = dict(positive_control=compatibility(source,source), counterexamples={})
        for name,(field,value) in variations.items():
            requested = copy.deepcopy(source); requested[field] = value
            actual = compatibility(source,requested); independent = independent_compatibility(source,requested)
            require(actual['status'] == independent['status'] == 'NOT_COMPUTABLE_FROM_FROZEN_EVIDENCE' and actual['incompatible_fields'] == independent['incompatible_fields'] == [field], 'INCOMPATIBILITY_HANDLING_FAILURE')
            gates['counterexamples'][name] = dict(requested=requested, result=actual, checker=independent)
        write(out/'incompatible_requests.json',gates)
        write(out/'results.json',results)
        write(out/'source_preservation.json',arc.preserve())
        return dict(status='PASS', cases=len(cases), read_counts={k:r.get('read_counts') for k,r in results.items()})
    finally:
        arc.close()


def check_job(work, out, main_out):
    cfg = read(ROOT/'configs/round13.json'); life = Lifecycle(work/'lifecycle.json')
    arc = Archive(cfg,work/'vendor',life.check,extract=False)
    try:
        observed_protocols=build_protocols(arc,cfg,ROOT)
        require(observed_protocols==read(main_out/'protocol_matrix.json'),'REPORT_PROTOCOL_MATRIX_FORGED')
        write(out/'protocol_matrix_readback.json',observed_protocols)
        protocols = observed_protocols['cases']
        inputs = Inputs(arc,cfg); results = read(main_out/'results.json')
        checks = {}
        from .common import fingerprint
        consumer_identity=fingerprint(read(main_out.parent/'consumer_code.json'))
        for cid, result in results.items():
            life.check()
            require(result.get('consumer_code_identity')==consumer_identity,'REPORT_CONSUMER_CODE_IDENTITY')
            checks[cid] = verify_report(inputs,cid,result,protocols[cid])
            write(out/(cid+'.json'),checks[cid])
        write(out/'checks.json',checks)
        write(out/'source_preservation.json',arc.preserve())
        require(all(r['status']=='PASS' for r in checks.values()), 'INDEPENDENT_NUMERICAL_MISMATCH')
        return dict(status='PASS',cases=len(checks),differences=0)
    finally:
        arc.close()


def legacy_job(work, out):
    from src.round9.regression import run_regression
    from src.round10.binding import bind
    cfg = read(ROOT/'configs/round12.json')
    frozen149 = read(work/'old_code_before.json')['files']
    prior = Path(read(ROOT/'configs/round13.json')['prior'])/'executed_closure'
    frozen142 = read(prior/'starting_code_manifest.json')['files']
    for row in frozen149:
        require(record(row['path'])==row,'OLD_CODE_CHANGED_BEFORE_REGRESSION')
    binding, cases = bind(Path(cfg['k9']), ROOT, frozen142, out, out)
    require(binding['status']=='PASS' and cases['status']=='PASS' and len(cases['cases'])==26, 'OLD_FIXED_BINDING_FAILURE')
    # Original driver accepts an explicit frozen manifest; its unchanged worker discovers all 149 tests.
    regression = run_regression(ROOT,out,frozen149)
    require(regression['status']=='PASS' and regression['tests']==149 and not regression['skipped'],'OLD_149_TEST_FAILURE')
    for row in frozen149:
        require(record(row['path'])==row,'OLD_CODE_CHANGED_AFTER_REGRESSION')
    anchors = read(prior/'anchors.json')
    for key in ['K11_zip','K11_completion']:
        require(record(anchors[key]['path'])==anchors[key], 'K11_ANCHOR_CHANGED')
    for row in anchors['K11_scripts']:
        require(record(row['path'])==row,'K11_SCRIPT_CHANGED')
    write(out/'frozen_chain.json',dict(status='PASS', K10_to_K12_additions=7, K12_to_K13_old_unchanged=149,
          K11_anchors=anchors, old_stage_map=binding['historical_stage_map'], reused='Old 77/49 and historical seal/clock findings retained; not rerun'))
    return dict(status='PASS',regression_tests=149,binding_counterexamples=26,regression=regression)


def tests_job(work, out):
    os.environ['ROUND13_TEST_ROOT'] = str(out)
    suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_round13*.py')
    stream = io.StringIO(); result = unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    (out/'tests.log').write_text(stream.getvalue(),encoding='utf8')
    data = dict(status='PASS' if result.wasSuccessful() and not result.skipped else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped))
    write(out/'tests.json',data)
    require(data['status']=='PASS','ROUND13_TEST_FAILURE')
    return data


def guards_job(work,out):
    import importlib
    import socket
    import subprocess
    from .control import Status,classify,BudgetExceeded
    positive=out/'positive.txt';positive.write_text('permitted',encoding='utf8')
    require(positive.read_text()=='permitted','GUARD_POSITIVE_CONTROL')
    attempts=[]
    probes=[('dynamic_native_import','NATIVE_IMPORT',lambda:importlib.import_module('native_components')),
            ('dynamic_stk_import','NATIVE_IMPORT',lambda:importlib.import_module('src.round2.stk_geometry')),
            ('com_import','NATIVE_IMPORT',lambda:importlib.import_module('win32com.client')),
            ('network','NETWORK',lambda:socket.socket()),
            ('subprocess','UNAPPROVED_SUBPROCESS',lambda:subprocess.run([sys.executable,'-c','pass'],check=True)),
            ('vendor_write','WRITE_SCOPE',lambda:(work/'vendor/denied-test.txt').write_text('forbidden')),
            ('outside_write','WRITE_SCOPE',lambda:(ROOT/'denied-round13-test.txt').write_text('forbidden')),
            ('vendor_dynamic_execution','VENDOR_EXECUTION',lambda:exec(compile('pass',str(work/'vendor/harmless_probe.py'),'exec'),{}))]
    for name,reason,fn in probes:
        try:fn()
        except PermissionError as exc:
            require(str(exc)=='ROUND13_GUARD_'+reason,'WRONG_GUARD_REJECTION_REASON')
            attempts.append(dict(name=name,status='PASS',reason=reason,positive_control=True))
        else:raise ValueError('GUARD_FAILED_TO_REJECT: '+name)
    status=Status();status.add(classify(PermissionError('ROUND13_GUARD_NATIVE_IMPORT')),'normal-flow violation');status.add(classify(BudgetExceeded()),'later timeout')
    require(status.value=='FAIL' and status.exit_code==1,'FAIL_DOWNGRADED_AFTER_TIMEOUT')
    write(out/'guard_counterexamples.json',dict(status='PASS',positive_control=True,cases=attempts,normal_flow_fail_then_timeout=dict(status=status.value,exit_code=status.exit_code)))
    return dict(status='PASS',controlled_rejections=len(attempts),native_activations=0)


def main():
    p=argparse.ArgumentParser();p.add_argument('--work',required=True);p.add_argument('--out',required=True)
    p.add_argument('--job',choices=['replay','check','tests','legacy','guards'],required=True);p.add_argument('--main-out');p.add_argument('--case');p.add_argument('--request')
    a=p.parse_args();work=Path(a.work).resolve();out=Path(a.out).resolve()
    require(out.is_relative_to(work) and not out.is_relative_to(work/'vendor'),'WORKER_OUTPUT_SCOPE')
    out.mkdir(parents=True,exist_ok=False)
    cpu=time.process_time();start=time.perf_counter();life=Lifecycle(work/'lifecycle.json')
    from .resources import SelfMemory
    memory=SelfMemory()
    if a.job != 'legacy':
        from .guard import install
        install(work,out/'guard.jsonl',controlled=a.job=='guards')
    else:
        # Same audited guard and controlled detector used by the frozen suite.
        os.environ.update(ROUND9_WRITE_ROOTS=json.dumps([str(work)]),ROUND9_GUARD_LOG=str(out/'parent_guard.jsonl'))
        from src.round9.guard import install
        install()
    try:
        life.check()
        if a.job=='replay': result=replay_job(work,out,a.case,read(a.request) if a.request else None)
        elif a.job=='check': result=check_job(work,out,Path(a.main_out))
        elif a.job=='tests': result=tests_job(work,out)
        elif a.job=='guards': result=guards_job(work,out)
        else: result=legacy_job(work,out)
        life.check();code=0
    except Exception as exc:
        from .control import classify
        level=classify(exc);code=2 if level=='BLOCKED' else 1
        result=dict(status=level,error=str(exc));(out/'error.log').write_text(traceback.format_exc(),encoding='utf8')
    result.update(worker_wall_s=time.perf_counter()-start,worker_cpu_s=time.process_time()-cpu,
                  memory=memory.sample(),exit_code=code)
    write(out/'job_result.json',result); print(json.dumps(result,ensure_ascii=False));return code


if __name__=='__main__':
    raise SystemExit(main())
