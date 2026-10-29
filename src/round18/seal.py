"""Immutable R18 scientific closure with exact file manifests and one-way receipt."""
import hashlib
import json
from pathlib import Path
import shutil
import time
import zipfile
from src.round13.archive import safe_name, safe_inventory
from src.round13.common import read, write, require, sha, fingerprint
from .binding import verify_sources, verify_attempt, artifacts
from .control import Lifecycle

PROFILE = 'ROUND18_V1'
DECLARED = 231066
FLAGS = dict(active_protocol_change_authorized=False, official_readiness='UNRESOLVED', official_score=None,
    next_scientific_run_gate='BLOCKED_PENDING_RULE_CONFIRMATION', native_activation_count=0,
    git_write_operations=0, new_native_validation_performed=False,
    whole_constellation_STK_verified=False, source='archived_component_composition')
COUNT_KEYS = ['declared_candidates', 'fully_evaluated', 'fully_independently_verified',
    'T100_certificate_rejected', 'T100_certificate_verified', 'T90_certificate_rejected',
    'T90_certificate_verified', 'unprocessed', 'unknown', 'qualified_count', 'retained_baseline']


def durable_records(path):
    """An interrupted final line is the only recoverable JSONL damage."""
    path = Path(path)
    if not path.exists():
        return
    with path.open(encoding='utf8') as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                if line.endswith('\n') or stream.read(1):
                    raise


def prefix_counts(science):
    science = Path(science)
    seen, checked, qualified = {}, {}, set()
    ledger_ids = set()
    for ordinal, row in enumerate(durable_records(science/'ledger.jsonl')):
        require(row['identity'] not in ledger_ids, 'PREFIX_DUPLICATE_LEDGER_IDENTITY')
        require(row.get('ordinal') == ordinal, 'PREFIX_LEDGER_NOT_CONTIGUOUS')
        ledger_ids.add(row['identity'])
    for name, kind in [('candidate_summary', 'FULL'), ('t100_certificates', 'T100'), ('t90_certificates', 'T90')]:
        for row in durable_records(science/(name+'.jsonl')):
            identity = row['identity']
            require(identity not in seen, 'PREFIX_DUPLICATE_PROCESSED_IDENTITY')
            seen[identity] = kind
            if row.get('qualified_improvement'):
                qualified.add(identity)
    for name, kind in [('checker', 'FULL'), ('t100_certificate_checker', 'T100'), ('t90_certificate_checker', 'T90')]:
        for row in durable_records(science/(name+'.jsonl')):
            identity = row['identity']
            require(identity not in checked, 'PREFIX_DUPLICATE_CHECKED_IDENTITY')
            if row.get('status') == 'PASS' and not row.get('differences'):
                checked[identity] = kind
    require(len(seen) <= DECLARED, 'PREFIX_EXCESS_RECORDS')
    verified = {i for i in seen if checked.get(i) == seen[i] and i in ledger_ids}
    return dict(declared_candidates=DECLARED,
        fully_evaluated=sum(k == 'FULL' for k in seen.values()),
        fully_independently_verified=sum(seen[i] == 'FULL' for i in verified),
        T100_certificate_rejected=sum(k == 'T100' for k in seen.values()),
        T100_certificate_verified=sum(seen[i] == 'T100' for i in verified),
        T90_certificate_rejected=sum(k == 'T90' for k in seen.values()),
        T90_certificate_verified=sum(seen[i] == 'T90' for i in verified),
        unprocessed=DECLARED-len(seen), unknown=len(seen)-len(verified),
        qualified_count=len(qualified & verified), retained_baseline=True)


def terminal(folder, check=lambda: None, prefix=False):
    from .checker import terminal_verification
    meta = read(folder/'frozen/contract.json')['metadata']
    science = folder/'science'
    selected = read(science/'independent_selection.json')['selected_identity'] if (science/'independent_selection.json').exists() else None
    streams = [durable_records(science/(name+'.jsonl')) for name in
        ['ledger', 'candidate_summary', 'checker', 't100_certificates', 't100_certificate_checker',
         't90_certificates', 't90_certificate_checker']]
    return terminal_verification(meta['baseline_indices'], meta['donor_indices'],
        {int(i): s for i, s in meta['states'].items()}, *streams, selected, check=check, prefix=prefix)


def report_text(final, folder):
    lines = ['# 第十八轮剩余四个近可行锚点的第二次替换修复', '',
        f'工程状态 {final["status"]}；研究进程退出码 {final["exit_code"]}。',
        f'研究结论：{final["optimization_outcome"]}。', '',
        f'声明 {DECLARED}；完整精算 {final["fully_evaluated"]} / 独立核对 {final["fully_independently_verified"]}；',
        f'T100证书 {final["T100_certificate_rejected"]} / 独立核验 {final["T100_certificate_verified"]}；',
        f'T90证书 {final["T90_certificate_rejected"]} / 独立核验 {final["T90_certificate_verified"]}；',
        f'未处理 {final["unprocessed"]}，UNKNOWN {final["unknown"]}，合格改善 {final["qualified_count"]}。', '',
        '固定删除原基线1284及其余27颗原基线之一，新增无序二元对至少含28/218/1801/2021之一且不含705；两个锚点同时出现只计一次。',
        '四锚点仍不可行；所有约束、必要门和改善始终参照原基线，未放宽T90或Tavg。R17真实Tavg超额0.096904477770秒仍为拒绝。',
        '处理顺序为T100必要门、T90必要门、完整精算。证书只证明对应必要约束失败；未计算的完整指标保持null/NOT_EVALUATED。']
    science = folder/'science'
    if (science/'baseline.json').exists():
        baseline = read(science/'baseline.json')
        selected = read(science/'selected.json') if (science/'selected.json').exists() else baseline
        lines += ['', '| 指标 | 原基线 | 最终选择 |', '|---|---:|---:|']
        getters = [('mask覆盖', lambda r: f'{r["effective_grid"]["covered"]}/{r["effective_grid"]["points"]}'),
            ('原域覆盖', lambda r: f'{r["full_grid"]["covered"]}/{r["full_grid"]["points"]}'),
            ('mask T90秒', lambda r: r['effective_grid']['T90_s']),
            ('mask T100秒', lambda r: r['effective_grid']['T100_s']),
            ('原域 T90秒', lambda r: r['full_grid']['T90_s']),
            ('原域 T100秒', lambda r: r['full_grid']['T100_s']),
            ('内部池化Tavg秒', lambda r: r['regional']['pooled_internal']['mean_s']),
            ('内部Tmax秒', lambda r: r['regional']['pooled_internal']['max_s'])]
        for name, getter in getters:
            lines.append(f'| {name} | {getter(baseline)} | {getter(selected)} |')
        lines += ['', f'保留原基线：{final["retained_baseline"]}；最终identity `{selected["identity"]}`。', '',
            '| 对象 | 原基线最长内部gap及端点秒 | 选中最长内部gap及端点秒 | 原基线首尾秒 | 选中首尾秒 |',
            '|---|---|---|---|---|']
        for target, before in baseline['regional']['targets'].items():
            after = selected['regional']['targets'][target]
            edges = lambda r: [p[1]-p[0] for p in r['boundary_segments']]
            lines.append(f'| {target} | {before["internal"]["max_s"]}/{before["internal"]["longest_endpoints_s"]} | {after["internal"]["max_s"]}/{after["internal"]["longest_endpoints_s"]} | {edges(before)} | {edges(after)} |')
        lines += ['', f'包含边界的池化敏感性：原基线 {baseline["regional"]["pooled_boundary_inclusive"]}；选中 {selected["regional"]["pooled_boundary_inclusive"]}。',
            '首尾空窗单列，未加入主目标及可行门。']
    if (science/'five_anchor_union_completion.json').exists():
        union = read(science/'five_anchor_union_completion.json')
        if union['status'] == 'PASS':
            lines += ['', 'R17的57834项明确REUSED；本轮231066项为新增处理。独立重建并核验两者无交、五锚点修复精确并集288900项。',
                      '该附加结论绑定R17原三层交付及源码身份，不把历史处理冒充本轮精算。']
        else:
            lines += ['', '五锚点并集附加核验未通过，文件仅作为失败证据，不作REUSED完整并集结论。']
    clock = read(folder/'lifecycle.json')
    lines += ['', f'计时原记录epoch={clock["record_epoch"]}，准备offset={clock["preparation_offset_seconds"]}秒；effective_start_epoch={clock["effective_start_epoch"]}。',
        'start_epoch已回拨包含准备；所有elapsed、父进程timeout及6600/7200截止仅使用有效起点，父子重叠时间不累加。',
        '研究允许各资产保存高度500至700km下的条件性混合高度；原基线692.8318965760104km。',
        '两轴半角0.81°、直接AreaTarget Access、暂定mask和正式混合高度可采纳性仍未确认；EOP止2019而场景为2027。',
        '保存资产数据不证明连续几何完备性或物理不可达。结论仅覆盖声明的剩余四锚点修复邻域，不扩至第三换、新锚点或完整catalog双换。',
        '原生激活0；Git写操作0；新组合仅来自archived_component_composition，未做新整星座STK验证。',
        'K12继续BLOCKED/2、0单元、成本NOT_RUN；R14/R15/R16/R17的PASS及0改善仅保留为历史。',
        '交付包含正式选中attempt的完整源码和日志。预检及准备诊断（含已修正编码名称错误）的完整快照/日志保留原work；historical_attempts_index.json列出位置和摘要，不将索引冒充完整日志。', '',
        f'入口封存时累计墙钟 {final["lifecycle_elapsed_at_seal_s"]:.3f} 秒；完整入口、研究Shell、导出进程和最终传输计时在封存外单向绑定。']
    return '\n'.join(lines)+'\n'


def independent_readback(folder, check=lambda: None):
    folder = Path(folder).resolve()
    receipt, manifest = read(folder/'receipt.json'), read(folder/'artifact_manifest.json')
    require(receipt['profile'] == manifest['profile'] == PROFILE and
            receipt['manifest_sha256'] == sha(folder/'artifact_manifest.json', check), 'SEAL_RECEIPT_BINDING')
    names = set()
    for row in manifest['files']:
        check()
        name = safe_name(row['path'])
        lexical, path = folder/name, (folder/name).resolve()
        require(name.casefold() not in names and path.is_relative_to(folder) and not lexical.is_symlink(), 'SEAL_MEMBER_SCOPE')
        require(all(not p.is_symlink() for p in lexical.parents if p.is_relative_to(folder)), 'SEAL_PARENT_LINK')
        names.add(name.casefold())
        require(path.is_file() and path.stat().st_size == row['bytes'] and sha(path, check) == row['sha256'], 'SEAL_MEMBER_BYTES')
    require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()} ==
            {r['path'] for r in manifest['files']} | {'artifact_manifest.json', 'receipt.json'}, 'SEAL_EXACT_SET')
    final = read(folder/'final_status.json')
    require(final['status'] == receipt['status'] and final['exit_code'] == receipt['exit_code'] ==
            {'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[final['status']], 'SEAL_STATUS_EXIT')
    require(all(final.get(k) == v for k, v in FLAGS.items()), 'SEAL_SCOPE_FLAGS')
    require(final['declared_candidates'] == DECLARED, 'SEAL_DECLARED')
    if final['status'] == 'PASS':
        completed = terminal(folder, check)
        require(completed['status'] == 'PASS' and all(completed[k] == final[k] for k in COUNT_KEYS), 'SEAL_EXACT_SPACE')
        require(final['unprocessed'] == final['unknown'] == 0, 'SEAL_INCOMPLETE')
        rows = read(folder/'frozen/consumer_code.json')
        require(fingerprint(rows) == read(folder/'frozen/contract.json')['source_manifest_identity'], 'SEAL_SOURCE_IDENTITY')
        with zipfile.ZipFile(folder/'frozen/consumer_code.zip') as snapshot:
            safe_inventory(snapshot.infolist())
            require(set(snapshot.namelist()) == {r['relative_path'] for r in rows}, 'SEAL_SOURCE_SET')
            for row in rows:
                blob = snapshot.read(row['relative_path'])
                require(len(blob) == row['bytes'] and hashlib.sha256(blob).hexdigest() == row['sha256'], 'SEAL_SOURCE_ZIP')
        bindings = read(folder/'consumer_version_binding.json')['selected']
        require(set(bindings) == {'science', 'tests', 'legacy', 'guards'}, 'SEAL_JOB_SET')
        for job, binding in bindings.items():
            history = folder/'attempt_history'/binding['attempt_id']
            command = read(history/'command_result.json')
            result = read(folder/job/'job_result.json')
            require(read(history/'consumer_code.json') == command['code_manifest'] == rows, 'SEAL_ATTEMPT_SOURCE')
            require(result == read(history/'supervised_result.json') and result['status'] == 'PASS' and result['exit_code'] == 0
                and result['job'] == job and result['attempt_id'] == history.name and result['consumer_identity'] == fingerprint(rows), 'SEAL_WORKER_BINDING')
            require(command['command'] == binding['command'] and command['python_exit_code'] == 0 and not command['timeout'], 'SEAL_COMMAND_BINDING')
            require(artifacts(folder/job, check) == command['output_artifacts'] and
                fingerprint(command['output_artifacts']) == binding['output_artifacts_identity'] and
                sha(history/'consumer_code.zip', check) == binding['code_snapshot_sha256'], 'SEAL_OUTPUT_BINDING')
            require(read(folder/job/'guard_audit.json')['status'] == 'PASS' and
                    read(folder/job/'guard_audit.json')['unexpected_denials'] == 0, 'SEAL_WORKER_GUARD_AUDIT')
        tests, legacy = read(folder/'tests/job_result.json'), read(folder/'legacy/job_result.json')
        require(tests['tests'] > 0 and tests['failures'] == tests['errors'] == tests['skipped'] == 0, 'SEAL_TESTS')
        require(legacy['regression_tests'] == 202 and legacy['round14_tests'] == 89 and
            legacy['round15_tests'] == 66 and legacy['round16_tests'] == 30 and legacy['round17_tests'] == 31 and legacy['original_test_total'] == 418 and
            legacy['binding_counterexamples'] == 26, 'SEAL_HISTORICAL_TESTS')
        require(read(folder/'supervision/process_tree_verification.json')['status'] == 'PASS', 'SEAL_SUPERVISION')
        coordinator_events = list(durable_records(folder/'coordinator_guard.jsonl'))
        require(any(r.get('kind') == 'guard_installed' for r in coordinator_events)
                and not any(r.get('kind') in {'unexpected_denial','denied'} for r in coordinator_events),
                'SEAL_COORDINATOR_GUARD')
        for name in ['asset_context_verification', 'baseline_checker', 'baseline_whole_readback', 'baseline_r17_readback', 'anchor_checker',
                     'source_preservation', 'independent_terminal_verification', 'independent_necessary_gate_context',
                     'four_anchor_checker', 'five_anchor_union_completion', 'independent_selection']:
            require(read(folder/('science/'+name+'.json'))['status'] == 'PASS', 'SEAL_SCIENCE_GATE:'+name)
    return dict(status=final['status'], exit_code=final['exit_code'], verified_members=len(manifest['files']),
        manifest_sha256=receipt['manifest_sha256'], delivery=str(folder), reexecuted=False)


def seal(work, selected, status, reasons):
    work = Path(work)
    life = Lifecycle(work/'lifecycle.json')
    check = lambda: life.check(False)
    check()
    folder = work/('sealed' if not (work/'sealed').exists() else 'sealed_'+str(time.time_ns()))
    folder.mkdir()
    for name in ['frozen', 'supervision']:
        if (work/name).exists():
            shutil.copytree(work/name, folder/name)
    for path in work.glob('starting_*'):
        if path.is_file():
            shutil.copyfile(path, folder/path.name)
    if (work/'coordinator_guard.jsonl').exists():
        shutil.copyfile(work/'coordinator_guard.jsonl', folder/'coordinator_guard.jsonl')
    historical = []
    selected_paths = {Path(p).resolve() for p in selected.values()}
    for attempt in sorted((work/'attempts').glob('*')):
        if attempt.resolve() not in selected_paths:
            command = read(attempt/'command_result.json') if (attempt/'command_result.json').exists() else {}
            result = read(attempt/'supervised_result.json') if (attempt/'supervised_result.json').exists() else {}
            historical.append(dict(path=str(attempt), attempt_id=attempt.name, job=command.get('job'),
                status=result.get('status'), exit_code=result.get('exit_code'), selected=False, full_exported=False,
                disposition='RETAINED_ONLY_IN_ORIGINAL_WORK',
                files=artifacts(attempt, check), summary_is_not_complete_exported_log=True))
    if (work/'preparation').exists():
        historical.append(dict(path=str(work/'preparation'), disposition='RETAINED_ONLY_IN_ORIGINAL_WORK',
            files=artifacts(work/'preparation', check), summary_is_not_complete_exported_log=True))
    write(folder/'historical_attempts_index.json', dict(status='PASS', histories=historical,
        selected_attempts_exported_in_full=True, prior_failures_not_erased=True))
    shutil.copyfile(work/'lifecycle.json', folder/'lifecycle.json')
    rows = read(work/'frozen/consumer_code.json') if (work/'frozen/consumer_code.json').exists() else []
    bound = {}
    for job, attempt in selected.items():
        check()
        if status == 'PASS':
            bound[job] = verify_attempt(attempt, rows, check)
        shutil.copytree(attempt/'output', folder/job)
        history = folder/'attempt_history'/attempt.name
        history.mkdir(parents=True)
        for name in ['consumer_code.json', 'consumer_code.zip', 'command_result.json', 'supervised_result.json', 'stdout.log', 'stderr.log']:
            if (attempt/name).exists():
                shutil.copyfile(attempt/name, history/name)
    write(folder/'consumer_version_binding.json', dict(status='PASS' if status == 'PASS' else status, selected=bound))
    count = prefix_counts(folder/'science')
    if status != 'PASS' and (folder/'science/ledger.jsonl').exists() and (folder/'frozen/contract.json').exists():
        prefix_audit = terminal(folder, check, prefix=True)
        write(folder/'prefix_verification.json', prefix_audit)
        count = {k: prefix_audit[k] for k in COUNT_KEYS}
        if prefix_audit['status'] == 'FAIL':
            status = 'FAIL'
            reasons = list(reasons)+['Independent prefix verification failed']
    if status == 'PASS':
        completed = terminal(folder, check)
        require(completed['status'] == 'PASS', 'TERMINAL_VERIFICATION_FAILED')
        count = {k: completed[k] for k in COUNT_KEYS}
        verify_sources(rows, check)
    outcome = ('FEASIBLE_IMPROVEMENT_FOUND' if count['qualified_count'] else
        'NO_FEASIBLE_IMPROVEMENT_IN_DECLARED_REMAINING_FOUR_ANCHOR_REPAIR_NEIGHBORHOOD') if status == 'PASS' else 'PARTIAL_NOT_CONCLUDED'
    final = dict(FLAGS, **count, profile=PROFILE, status=status,
        exit_code={'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[status], reasons=reasons,
        optimization_outcome=outcome, lifecycle_elapsed_at_seal_s=life.elapsed(),
        K12=dict(status='BLOCKED', exit_code=2, units=0, cost='NOT_RUN'),
        historical_rounds=dict(R14='PASS, 0 improvement', R15='PASS, 0 improvement', R16='PASS, 0 improvement', R17='PASS, 0 improvement'))
    final['declared'] = DECLARED
    final['retained_original_baseline'] = count['retained_baseline']
    if (folder/'science/five_anchor_union_completion.json').exists():
        final['five_anchor_union_completion'] = read(folder/'science/five_anchor_union_completion.json')
        final['historical_candidates_reused'] = 57834 if final['five_anchor_union_completion']['status'] == 'PASS' else 0
    for name in ['baseline', 'selected']:
        if (folder/('science/'+name+'.json')).exists():
            report = read(folder/('science/'+name+'.json'))
            final[name+'_identity'] = report['identity']
            final[name+'_metrics'] = dict(mask=report['effective_grid'], raw=report['full_grid'],
                pooled_internal=report['regional']['pooled_internal'],
                pooled_boundary_inclusive=report['regional']['pooled_boundary_inclusive'])
    write(folder/'timings.json', dict(worker_wall_s={job: read(attempt/'output/job_result.json').get('worker_wall_s')
        for job, attempt in selected.items() if (attempt/'output/job_result.json').exists()},
        lifecycle_elapsed_upper_bound_s=life.elapsed(), overlapping_worker_walls_added=False,
        boundary='Seal timing; actual entry, research Shell, export child and final transport recorded outside seal'))
    write(folder/'final_status.json', final)
    report = report_text(final, folder)
    (folder/'report.md').write_text(report, encoding='utf8')
    require((folder/'report.md').read_text(encoding='utf8') == report, 'REPORT_UTF8_READBACK')
    entries = [dict(path=p.relative_to(folder).as_posix(), bytes=p.stat().st_size, sha256=sha(p, check))
               for p in sorted(folder.rglob('*')) if p.is_file()]
    write(folder/'artifact_manifest.json', dict(profile=PROFILE, files=entries))
    write(folder/'receipt.json', dict(profile=PROFILE, status=status, exit_code=final['exit_code'],
        manifest_sha256=sha(folder/'artifact_manifest.json', check), receipt_self_hashed=False))
    audit = independent_readback(folder, check)
    write(work/'latest_delivery.json', dict(path=str(folder), **audit))
    return audit
