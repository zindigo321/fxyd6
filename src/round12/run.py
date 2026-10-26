"""Bounded closure of an expired preparation attempt; no scientific fallback."""
import ast
import datetime
import difflib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import time
import unittest
import zipfile
from src.round2.evidence import code_manifest, canonical
from src.round8.common import file_record, read, write
from src.round10.resources import usage
from .control import Deadline, DeadlineExceeded, Status, classify

ROOT = Path(__file__).resolve().parents[2]


def utc_epoch(text):
    return datetime.datetime.fromisoformat(text).timestamp()


def main():
    entry_start = time.monotonic()
    cfg = read(ROOT / 'configs/round12.json'); work = Path(cfg['work'])
    out = work / 'deliveries' / 'blocked_attempt'
    if (out / 'receipt.json').exists():
        result = read(out / 'final_status.json')
        print(json.dumps({'sealed_attempt': str(out), 'status': result['status'], 'exit_code': result['exit_code'], 'reexecuted': False}))
        return result['exit_code']
    out.mkdir(parents=True, exist_ok=False)
    os.environ.update(ROUND10_WRITE_ROOTS=json.dumps([str(work)]), ROUND10_GUARD_LOG=str(work / 'closure_guard.jsonl'))
    from src.round10.guard import install
    install()
    protocol = read(work / 'lifecycle_protocol.json')
    status = Status()
    # Closure uses the existing 600-second cap, starting when closure was announced.
    closure_start = utc_epoch('2026-10-26T10:52:24+00:00')
    closure_deadline_epoch = min(closure_start + protocol['stage_caps_s']['seal'], protocol['start_epoch'] + protocol['total_cap_s'])
    close = Deadline(closure_deadline_epoch)
    stages = dict(freeze_model='BLOCKED', implementation_main='NOT_RUN', independent_reference='NOT_RUN')
    details = {'original_regression': {'status': 'NOT_RUN'}, 'new_control_tests': {'status': 'NOT_RUN'}, 'binding_cases': {'status': 'NOT_RUN'}}
    before = code_manifest()
    write(out / 'code_manifest.json', {'files': before, 'sha256': hashlib.sha256(canonical(before)).hexdigest()})
    with zipfile.ZipFile(out / 'code_snapshot.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        for row in before: z.write(row['path'], Path(row['path']).relative_to(ROOT).as_posix())
    direct = {}; busy = [False]

    def observe(event, args):
        if busy[0] or event != 'open' or not isinstance(args[0], (str, bytes, os.PathLike)): return
        path = Path(os.fsdecode(args[0])).resolve()
        mode, flags = args[1:]
        writing = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT)
        if writing or path.is_relative_to(work) or path.is_relative_to(Path(sys.prefix)) or not path.is_file(): return
        if str(path) in direct: return
        busy[0] = True
        try: direct[str(path)] = file_record(path)
        finally: busy[0] = False
    sys.addaudithook(observe)
    worker_start = time.monotonic()
    try:
        try: Deadline(protocol['stage_deadlines_epoch']['freeze_model']).check()
        except DeadlineExceeded:
            status.add('BLOCKED', 'FREEZE_MODEL_STAGE_DEADLINE_EXCEEDED_BEFORE_CONTRACT')
        else:
            raise ValueError('ATTEMPT_EXPECTED_TO_BE_EXPIRED')
        close.check()
        starting = read(work / 'starting_code_manifest.json')
        old = starting['files']; current = {r['path']: r for r in before}
        if len(old) != 142 or hashlib.sha256(canonical(old)).hexdigest() != '81a5255a31d9e4e27303065c4617fe8df2afb62f6bbf69d108b974cfbf4c65f2':
            raise ValueError('K10_MANIFEST_IDENTITY')
        if any(current.get(r['path']) != r for r in old): raise ValueError('OLD_CODE_BYTES_CHANGED')
        additions = [Path(r['path']).relative_to(ROOT).as_posix() for r in before if r['path'] not in {x['path'] for x in old}]
        def allowed(n):
            return (n.startswith('src/round12/') and n.endswith('.py') or n.startswith('tests/test_round12') and n.endswith('.py') or n in {'tools/run_round12.py', 'configs/round12.json', 'docs/round12.md'})
        if not all(map(allowed, additions)): raise ValueError('ADDITION_OUTSIDE_ROUND12')
        for row in old:
            p = Path(row['path'])
            if p.suffix == '.py':
                tree = ast.parse(p.read_text(encoding='utf-8-sig'))
                if any(isinstance(n, (ast.Import, ast.ImportFrom)) and 'round12' in ast.unparse(n) for n in ast.walk(tree)):
                    raise ValueError('OLD_CODE_IMPORTS_ROUND12')
        write(out / 'K10_to_K12_transition.json', {'status': 'PASS', 'unchanged_old_files': len(old), 'allowed_additions': additions})
        diff = []
        for n in additions:
            diff.extend(difflib.unified_diff([], (ROOT / n).read_text(encoding='utf8').splitlines(True), fromfile='/dev/null', tofile=n))
        (out / 'K10_to_K12.diff').write_text(''.join(diff), encoding='utf8')
        anchors = read(work / 'anchors.json'); k10 = Path(anchors['K10'])
        if read(k10 / 'code_manifest.json')['files'] != old: raise ValueError('K10_ANCHOR_CODE')
        with zipfile.ZipFile(k10 / 'code_snapshot.zip') as z:
            expected = {Path(r['path']).relative_to(ROOT).as_posix(): r for r in old}
            if set(z.namelist()) != set(expected): raise ValueError('K10_SNAPSHOT_MEMBERS')
            for n, r in expected.items():
                if hashlib.sha256(z.read(n)).hexdigest() != r['sha256']: raise ValueError('K10_SNAPSHOT_BYTES')
        for key in ['K11_zip', 'K11_completion']:
            if file_record(anchors[key]['path']) != anchors[key]: raise ValueError(key + '_BYTES')
        with zipfile.ZipFile(anchors['K11_zip']['path']) as z:
            manifest_bytes = z.read('transport_manifest.json'); transport = json.loads(manifest_bytes)
            receipt = json.loads(z.read('transport_receipt.json'))
            if hashlib.sha256(manifest_bytes).hexdigest() != receipt['manifest_sha256']: raise ValueError('K11_TRANSPORT_RECEIPT')
            members = {r['path'] for r in transport['files']}
            if set(z.namelist()) != members | {'transport_manifest.json', 'transport_receipt.json'}: raise ValueError('K11_TRANSPORT_MEMBERS')
            for row in transport['files']:
                n = row['path']; p = Path(n)
                if p.is_absolute() or '..' in p.parts: raise ValueError('K11_TRANSPORT_TRAVERSAL')
                b = z.read(n)
                if len(b) != row['bytes'] or hashlib.sha256(b).hexdigest() != row['sha256']: raise ValueError('K11_TRANSPORT_BYTES')
        write(out / 'K11_binding.json', {'status': 'PASS', 'members': 81, 'relative_transport_files': len(members), 'anchors': anchors, 'completion_outside_zip': True})
        audit = Path('G:/gpt-file/Codex/2026-10-26/pass-0-5036-54-185-044/outputs/round11_audit')
        for n in ['audit_and_next_steps.md', 'independent_artifact_audit.json', 'independent_behavior_checks.json', 'independent_budget_and_scope_review.json', 'independent_source_semantics.json']:
            (out / n).write_bytes((audit / n).read_bytes())
        plan = read(Path(cfg['k9']) / 'source_read_plan.json')
        sources = read(work / 'source_records.json')
        for row in sources.values():
            actual = file_record(row['path'])
            if actual != row: raise ValueError('SOURCE_CHANGED')
            bound = plan[row['path']]['expected']
            if any(actual[k] != bound[k] for k in ('bytes', 'sha256')): raise ValueError('K9_SOURCE_BINDING')
        write(out / 'source_binding.json', {'status': 'PASS', 'sources': sources, 'trajectory_scope': 'Sat001 only; shape and numerical validation NOT_RUN'})
        close.check()
        from src.round10.binding import bind
        binding, cases = bind(Path(cfg['k9']), ROOT, old, out, work)
        details['binding_cases'] = cases
        if binding['status'] != 'PASS' or cases['status'] != 'PASS': raise ValueError('BINDING_FAILED')
        close.check()
        stream = io.StringIO()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_round12*.py'))
        (out / 'control_tests.log').write_text(stream.getvalue(), encoding='utf8')
        details['new_control_tests'] = dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped), scope='Lifecycle/state only. No numerical reference implementation exists.')
        if not result.wasSuccessful() or result.skipped: raise ValueError('CONTROL_TEST_FAILURE')
        close.check()
        if closure_deadline_epoch - time.time() < 180: raise DeadlineExceeded('INSUFFICIENT_CLOSURE_TIME_FOR_REGRESSION')
        from src.round9.regression import run_regression
        details['original_regression'] = run_regression(ROOT, work, old)
        if details['original_regression']['status'] != 'PASS' or details['original_regression']['tests'] != 135: raise ValueError('OLD_REGRESSION_FAILED')
    except Exception as e:
        level, reason = classify(e); status.add(level, reason + ': ' + str(e))
        import traceback
        (out / 'error.log').write_text(traceback.format_exc(), encoding='utf8')
    worker_wall = time.monotonic() - worker_start
    # Final checks cannot downgrade an earlier FAIL.
    try:
        close.check()
        after = code_manifest()
        if before != after: raise ValueError('FROZEN_CODE_CHANGED')
        prior = dict(direct)
        for path, row in prior.items():
            if file_record(path) != row: raise ValueError('DIRECT_SOURCE_CHANGED: ' + path)
        write(out / 'source_preservation.json', {'status': 'PASS', 'files': list(prior.values()), 'scope': 'Only files actually opened during closure; not all historical evidence'})
        write(out / 'code_preservation.json', {'status': 'PASS', 'total_files': len(before), 'old_files': 142})
        guard_rows = [json.loads(x) for x in (work / 'closure_guard.jsonl').read_text(encoding='utf8').splitlines()]
        if any(r['kind'] == 'denied' for r in guard_rows): raise ValueError('UNEXPECTED_GUARD_DENIAL')
    except Exception as e:
        level, reason = classify(e); status.add(level, reason + ': ' + str(e))
    shutil.copyfile(work / 'closure_guard.jsonl', out / 'closure_guard.jsonl')
    for n in ['lifecycle_protocol.json', 'starting_code_manifest.json', 'starting_code_snapshot.zip', 'starting_git.json', 'anchors.json', 'source_records.json', 'source_structure.json', 'prepare.py']:
        shutil.copyfile(work / n, out / n)
    write(out / 'checks.json', details)
    final = dict(status=status.value, exit_code=status.exit_code, reasons=status.reasons,
                 reference_model_contract='NOT_COMPLETED', reference_halfspace_certification='NOT_RUN', reference_candidate_coverage='NOT_RUN', reference_candidate_cost_reduction='NOT_RUN', offline_engineering_acceptance='BLOCKED',
                 historical_STK_certification='UNRESOLVED', official_readiness='UNRESOLVED', official_score=None, next_scientific_run_gate='BLOCKED', historical_coverage='REUSED_NOT_REVALIDATED',
                 expected_processed_cells=276480, actual_processed_cells=0, independent_endpoint_checks=0, frozen_node_driven_reference_rejections=0, true_STK_certified_rejections=0,
                 local_candidate_pair_seconds=None, full_candidate_pair_seconds=None, net_reduction_pair_seconds=None, candidate_windows=0, access_executed=False, event_count=None,
                 fresh_native_validation_performed=False, round12_native_activation_count=0, git_write_operations=0,
                 historical_stage_map={'S':'FAIL/1','V':'BLOCKED/1','K8':'PASS/0','K9':'PASS/0','K10':'PASS/0','K11':'NO_GO/BLOCKED/2'},
                 historical_notes='Old round8 seal defect retained; 4780 runtime versus 4351 matched/429 unread independently is REUSED. Old 77/49 and K10 53/53 fallback are REUSED.',
                 delivery=str(out), preferred_export=str(cfg['output']), export_status='WRITE_PROBE_PASSED_EXPORT_PENDING_OUTSIDE_SEAL',
                 stages=stages, scientific_worker_wall_s=None, closure_worker_wall_s=worker_wall, entry_elapsed_to_status_s=time.monotonic()-entry_start,
                 lifecycle_elapsed_to_status_s=time.time()-protocol['start_epoch'], closure_deadline_epoch=closure_deadline_epoch,
                 parent_resources=usage(), subprocess_resources_scope='Old regression subprocess logs/results; parent resource totals exclude children')
    if status.value == 'FAIL': final['offline_engineering_acceptance'] = 'FAIL'
    write(out / 'final_status.json', final)
    (out / 'report.md').write_text('# 第十二轮：BLOCKED，参考模型实验未开始\n\n'
        '冻结/模型合同阶段900秒截止点已超过，停止后续实验。当前入口只核验预算拒绝、历史绑定和控制逻辑。\n\n'
        '目标276,480单元；实际处理0，参考拒绝0，独立端点验算0。未生成模型合同、p/n、证书、台账或候选；小域与全域成本、净减少均未测量。不能据此判断参考模型无收益或不可行。\n\n'
        '检查详情见checks.json。新测试只覆盖状态和deadline，不代表数值证书测试。原135项使用冻结142文件的隔离副本和既有离线模拟；旧26绑定反例由未修改的round9固定检查器运行。\n\n'
        '历史STK认证和官方准备UNRESOLVED，评分null，下一科学入口BLOCKED。原生激活0，Git写入0。K11的NO_GO及包外最终记录保持原字节。\n\n'
        '时间包含09:50:42 UTC之前的60秒保守准备记账；长间隔没有剔除。进程内用单调时钟；父子耗时不重复相加。三种口径及阶段超限见final_status.json、receipt.json。后续导出记录位于原封存外。\n', encoding='utf8')
    try: close.check()
    except DeadlineExceeded as e:
        status.add('BLOCKED', str(e)); final.update(status=status.value, exit_code=status.exit_code, reasons=status.reasons); write(out / 'final_status.json', final)
    manifest = {'files': [dict(path=p.relative_to(out).as_posix(), bytes=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(out.rglob('*')) if p.is_file()]}
    write(out / 'artifact_manifest.json', manifest)
    for row in manifest['files']:
        b = (out / row['path']).read_bytes()
        if len(b) != row['bytes'] or hashlib.sha256(b).hexdigest() != row['sha256']: raise ValueError('SEAL_READBACK_FAILURE')
    receipt = dict(status='PASS', meaning='Byte readback only; scientific attempt BLOCKED', manifest_sha256=hashlib.sha256((out / 'artifact_manifest.json').read_bytes()).hexdigest(), files=len(manifest['files']), process_exit_code=status.exit_code,
                   entry_end_to_end_s=time.monotonic()-entry_start, lifecycle_elapsed_s=time.time()-protocol['start_epoch'], closure_elapsed_s=time.time()-closure_start,
                   command=[sys.executable, '-X', 'utf8', '-B', str(ROOT / 'tools/run_round12.py')], shell_propagation='exit $LASTEXITCODE')
    write(out / 'receipt.json', receipt)
    print(json.dumps(dict(status=status.value, exit_code=status.exit_code, delivery=str(out), receipt=receipt), ensure_ascii=False))
    return status.exit_code
