"""Independent ROUND16 closure, exact member manifest and one-way receipt."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
import zipfile

from src.round13.archive import safe_name, safe_inventory
from src.round13.common import read, write, require, sha, fingerprint
from .binding import verify_sources, verify_attempt, artifacts
from .control import Lifecycle

PROFILE = 'ROUND16_V1'
DECLARED = 60004
FLAGS = dict(active_protocol_change_authorized=False, official_readiness='UNRESOLVED', official_score=None,
    next_scientific_run_gate='BLOCKED_PENDING_RULE_CONFIRMATION', native_activation_count=0,
    git_write_operations=0, new_native_validation_performed=False,
    whole_constellation_STK_verified=False, source='archived_component_composition')
GATES = ['input_identity', 'asset_context_verification', 'baseline_replay', 'neighborhood_definition',
    'gap_certificate_verification', 'enumeration_completion', 'independent_all_candidate_verification',
    'consumer_version_binding', 'regression', 'offline_research_acceptance']
COUNT_KEYS = ['declared_candidates', 'fully_evaluated', 'fully_independently_verified', 'certificate_rejected',
    'certificate_independently_verified', 'unprocessed', 'unknown', 'qualified_count', 'retained_baseline']


def independent_readback(folder, check=lambda: None):
    from .worker import records
    folder = Path(folder).resolve()
    receipt, manifest = read(folder/'receipt.json'), read(folder/'artifact_manifest.json')
    require(receipt['profile'] == manifest['profile'] == PROFILE and
            receipt['manifest_sha256'] == sha(folder/'artifact_manifest.json', check), 'SEAL_RECEIPT_BINDING')
    names = set()
    for row in manifest['files']:
        check(); name = safe_name(row['path']); lexical = folder/name; path = lexical.resolve()
        require(name.casefold() not in names and path.is_relative_to(folder) and not lexical.is_symlink()
                and all(not p.is_symlink() for p in lexical.parents if p.is_relative_to(folder)), 'SEAL_MEMBER_SCOPE')
        names.add(name.casefold())
        require(path.is_file() and path.stat().st_size == row['bytes'] and sha(path, check) == row['sha256'],
                'SEAL_MEMBER_BYTES')
    require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()} ==
            {row['path'] for row in manifest['files']} | {'artifact_manifest.json', 'receipt.json'},
            'SEAL_EXACT_MEMBER_SET')
    final = read(folder/'final_status.json')
    require(final['status'] == receipt['status'] and final['exit_code'] == receipt['exit_code'] and
            {'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[final['status']] == final['exit_code'], 'SEAL_STATUS_EXIT')
    require(all(final.get(k) == v for k, v in FLAGS.items()), 'SEAL_SCOPE_FLAGS')
    require(final['declared_candidates'] == DECLARED, 'SEAL_DECLARED_SPACE')
    if final['status'] == 'PASS':
        require(all(final.get(g) == 'PASS' for g in GATES), 'SEAL_PASS_GATES')
        from .checker import terminal_verification
        contract = read(folder/'frozen/contract.json'); meta = contract['metadata']; science = folder/'science'
        terminal = terminal_verification(meta['baseline_indices'], meta['donor_indices'],
            {int(i): s for i, s in meta['states'].items()}, records(science/'ledger.jsonl'),
            records(science/'candidates.jsonl'), records(science/'checker.jsonl'),
            records(science/'certificates.jsonl'), records(science/'certificate_checker.jsonl'),
            read(science/'independent_selection.json')['selected_identity'], proof=read(science/'gap_proof.json'), check=check)
        require(terminal['status'] == 'PASS' and all(terminal[k] == final[k] for k in COUNT_KEYS),
                'SEAL_EXACT_SPACE_TERMINAL')
        require(final['fully_evaluated'] == final['fully_independently_verified'] == 6244 and
                final['certificate_rejected'] == final['certificate_independently_verified'] == 53760 and
                final['unprocessed'] == final['unknown'] == 0, 'SEAL_EXPECTED_PARTITION_ASSERTION')
        require(read(science/'independent_terminal_verification.json')['baseline_checked'] is True and
                read(science/'baseline_checker.json')['status'] == 'PASS' and
                read(science/'independent_gap_proof.json')['status'] == 'PASS' and
                read(science/'source_preservation.json')['status'] == 'PASS' and
                read(science/'asset_context_verification.json')['status'] == 'PASS', 'SEAL_INPUT_BASELINE_PROOF')
        tests, legacy = read(folder/'tests/job_result.json'), read(folder/'legacy/job_result.json')
        require(tests['tests'] > 0 and tests['failures'] == tests['errors'] == tests['skipped'] == 0 and
                legacy['regression_tests'] == 202 and legacy['round14_tests'] == 89 and
                legacy['round15_tests'] == 66 and legacy['original_test_total'] == 357 and
                legacy['binding_counterexamples'] == 26, 'SEAL_TESTS')
        frozen = read(folder/'frozen/consumer_code.json')
        require(fingerprint(frozen) == contract['source_manifest_identity'], 'SEAL_SOURCE_IDENTITY')
        with zipfile.ZipFile(folder/'frozen/consumer_code.zip') as snapshot:
            safe_inventory(snapshot.infolist())
            require(set(snapshot.namelist()) == {row['relative_path'] for row in frozen}, 'SEAL_SOURCE_SET')
            for row in frozen:
                check(); blob = snapshot.read(row['relative_path'])
                require(len(blob) == row['bytes'] and hashlib.sha256(blob).hexdigest() == row['sha256'],
                        'SEAL_SOURCE_SNAPSHOT')
        bound = read(folder/'consumer_version_binding.json')['selected']
        require(set(bound) == {'science', 'tests', 'legacy', 'guards'}, 'SEAL_JOB_SET')
        for job, binding in bound.items():
            history = folder/'attempt_history'/binding['attempt_id']; command = read(history/'command_result.json')
            require(read(history/'consumer_code.json') == command['code_manifest'] == frozen, 'SEAL_ATTEMPT_SOURCE')
            require(command['job'] == job and command['attempt_id'] == binding['attempt_id'] and
                    command['timeout'] is False and command['python_exit_code'] == 0, 'SEAL_ATTEMPT_COMMAND')
            source_out = Path(command['output']); source_work = source_out.parent.parent.parent
            require(command['command'] == binding['command'] == [sys.executable, '-X', 'utf8', '-B', '-m',
                    'src.round16.worker', '--work', str(source_work), '--out', str(source_out), '--job', job],
                    'SEAL_COMPLETE_COMMAND')
            result = read(folder/job/'job_result.json')
            require(read(history/'supervised_result.json') == result and command['supervised_result_exit_code'] == 0 and
                    result['attempt_id'] == binding['attempt_id'] and result['job'] == job and
                    result['consumer_identity'] == fingerprint(frozen), 'SEAL_SUPERVISED_WORKER_BINDING')
            require(sha(history/'consumer_code.zip', check) == binding['code_snapshot_sha256'], 'SEAL_ATTEMPT_ZIP')
            require(artifacts(folder/job, check) == command['output_artifacts'] and
                    fingerprint(command['output_artifacts']) == binding['output_artifacts_identity'],
                    'SEAL_ATTEMPT_OUTPUTS')
    return dict(status=final['status'], exit_code=final['exit_code'], verified_members=len(manifest['files']),
                manifest_sha256=receipt['manifest_sha256'], delivery=str(folder), reexecuted=False)


def durable_records(path):
    """Only a final interrupted JSONL line may be omitted from prefix recovery."""
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
    science = Path(science); seen, verified, qualified = {}, {}, set()
    full = 'candidate_summary' if (science/'candidate_summary.jsonl').exists() else 'candidates'
    for name, kind in [(full, 'full'), ('certificates', 'cert')]:
        for row in durable_records(science/(name+'.jsonl')):
            require(row['identity'] not in seen, 'PREFIX_DUPLICATE_PROCESSED_IDENTITY')
            seen[row['identity']] = kind
            if row.get('qualified_improvement'):
                qualified.add(row['identity'])
    for name, kind in [('checker', 'full'), ('certificate_checker', 'cert')]:
        for row in durable_records(science/(name+'.jsonl')):
            if row.get('status') == 'PASS':
                require(row['identity'] not in verified, 'PREFIX_DUPLICATE_CHECKED_IDENTITY')
                verified[row['identity']] = kind
    require(len(seen) <= DECLARED, 'PREFIX_EXCESS_RECORDS')
    return dict(declared_candidates=DECLARED, fully_evaluated=sum(k == 'full' for k in seen.values()),
        fully_independently_verified=sum(k == 'full' and seen.get(i) == k for i, k in verified.items()),
        certificate_rejected=sum(k == 'cert' for k in seen.values()),
        certificate_independently_verified=sum(k == 'cert' and seen.get(i) == k for i, k in verified.items()),
        unprocessed=DECLARED-len(seen), unknown=len(set(seen)-set(verified)),
        qualified_count=len(qualified & set(verified)), retained_baseline=True)


def report_text(final, science, tests, legacy, timing):
    text = ['# 第十六轮完整保存 catalog 的 N28 单星替换离线研究', '',
        f'工程状态 {final["status"]}，退出码 {final["exit_code"]}。',
        f'研究结论：{final["optimization_outcome"]}。', '',
        f'声明 {final["declared_candidates"]}；精算 {final["fully_evaluated"]}，精算独立核对 {final["fully_independently_verified"]}；证书排除 {final["certificate_rejected"]}，证书独立核验 {final["certificate_independently_verified"]}；未处理 {final["unprocessed"]}，UNKNOWN {final["unknown"]}。',
        '完整空间是原基线28颗星中删除1颗、加入2143个非基线保存资产之一，共60004个唯一组合；包含历史896个同高度单换，本轮重新处理。',
        '合同要求从2171份原区域payload重建223个bridge donor，6244个候选完整精算；其余1920个donor形成53760个证书候选。单删仍保留空窗前后访问，本轮没有R15双换的465个边界例外。',
        '证书只证明不能通过保守至少1秒的Tmax改善门；证书候选完整指标、首访和可行性均为NOT_EVALUATED/null。以上预期分区仅在完整运行与独立核验通过时成立。']
    if science and (science/'asset_context_verification.json').exists():
        evidence = read(science/'asset_context_verification.json')
        text += ['', f'全资产输入门：{evidence.get("status")}。元数据、区域区间和全部global NPZ/矩阵行按本轮记录分别验证；独立审计的原区域诊断未冒充global验证。详见science/asset_context_verification.json。']
    if science and (science/'baseline.json').exists():
        baseline = read(science/'baseline.json')
        selected = read(science/'selected.json') if (science/'selected.json').exists() else baseline
        text += ['', '| 指标 | 基线 | 选中 |', '|---|---:|---:|']
        getters = [('mask覆盖', lambda r: f'{r["effective_grid"]["covered"]}/{r["effective_grid"]["points"]}'),
            ('原域覆盖', lambda r: f'{r["full_grid"]["covered"]}/{r["full_grid"]["points"]}'),
            ('mask T90 s', lambda r: r['effective_grid']['T90_s']),
            ('mask T100 s', lambda r: r['effective_grid']['T100_s']),
            ('原域 T90 s', lambda r: r['full_grid']['T90_s']),
            ('原域 T100 s', lambda r: r['full_grid']['T100_s']),
            ('池化内部Tavg s', lambda r: r['regional']['pooled_internal']['mean_s']),
            ('内部Tmax s', lambda r: r['regional']['pooled_internal']['max_s'])]
        for name, getter in getters:
            text.append(f'| {name} | {getter(baseline)} | {getter(selected)} |')
        reduction = baseline['regional']['pooled_internal']['max_s']-selected['regional']['pooled_internal']['max_s']
        text += ['', f'合格改善数 {final["qualified_count"]}；保留基线 {final["retained_baseline"]}；Tmax减少 {reduction!r} 秒；保守至少1秒改善 {bool(selected["qualified_improvement"])}。',
            f'选中identity `{selected["identity"]}`；删除 {selected.get("remove")}，新增 {selected.get("add")}。',
            '', '| 对象 | 基线最长内部gap/端点 s | 选中最长内部gap/端点 s | 基线首/尾 s | 选中首/尾 s |',
            '|---|---|---|---|---|']
        for target, b in baseline['regional']['targets'].items():
            s = selected['regional']['targets'][target]
            edges = lambda obj: [pair[1]-pair[0] for pair in obj['boundary_segments']]
            text.append(f'| {target} | {b["internal"]["max_s"]}/{b["internal"]["longest_endpoints_s"]} | {s["internal"]["max_s"]}/{s["internal"]["longest_endpoints_s"]} | {edges(b)} | {edges(s)} |')
        text += ['', f'包含边界的池化敏感性：基线 {baseline["regional"]["pooled_boundary_inclusive"]}；选中 {selected["regional"]["pooled_boundary_inclusive"]}。',
            '首尾空窗单列，未加入主目标或可行门。全部2171资产的原域并集与旧60资产354点集合重新比较，不按结果修改冻结mask，不沿用旧池无法补齐这些点的结论。']
        if (science/'research_scope.json').exists():
            text += ['', f'高度与条件研究范围：{read(science/"research_scope.json")}。']
    text += ['', f'回归实际运行：旧202项 {legacy.get("old_tests",0)}，R14项 {legacy.get("round14_tests",0)}，R15项 {legacy.get("round15_tests",0)}；历史绑定反例 {legacy.get("binding_counterexamples",0)}；R16新增 {tests.get("tests",0)}。',
        '203个旧消费文件保持原字节；168/185/203三个历史回归子集及142文件绑定子集分别映射并核对运行前后字节，不与完整R16清单强行判等。',
        '独立checker共享已验证输入schema、坐标、mask及状态identity格式；首访最小值、次序统计、区间并集、bridge/两侧证明、可行门、排序及最终选择分别实现。',
        f'计时边界：{timing}。科学worker、完整入口和至导出累计单列，父子墙钟不相加；完整入口和Shell退出记录留在传输层。',
        '本轮允许500至700km的原始保存资产，组成27颗基线星加1颗可能异高度的星。混合高度仅是有条件离线研究假设；若正式要求全部同高度，本轮结果只作敏感性研究。',
        '新组合source=archived_component_composition，new_native_validation_performed=false，whole_constellation_STK_verified=false；基线历史整星座来源不转移。',
        '两轴半角0.81°及直接AreaTarget Access仍未获用户规则确认。EOP止2019而场景2027、mask非官方、保存结果不证明连续几何完备性等限制保留。',
        'active_protocol_change_authorized=false；official_readiness=UNRESOLVED；official_score=null；next_scientific_run_gate=BLOCKED_PENDING_RULE_CONFIRMATION。原生激活0，Git写操作0。',
        'K12仍BLOCKED/2、0单元、成本NOT_RUN；历史R14/R15 PASS及0改善保留。结论仅限声明的完整catalog单换邻域，不证明全catalog最优或同高度全空间无解；完成后停止。']
    errors = [row for row in final.get('reasons', []) if row.get('status') != 'PASS']
    if errors:
        text += ['', f'未完成/失败证据：{errors}']
    return '\n'.join(text)+'\n'


def write_report(path, content):
    Path(path).write_text(content, encoding='utf8')
    require(Path(path).read_text(encoding='utf8') == content, 'REPORT_UTF8_READBACK')


def seal(work, selected, status, reasons, entry_start):
    work = Path(work); life = Lifecycle(work/'lifecycle.json'); life.check()
    rows = read(work/'frozen/consumer_code.json'); verify_sources(rows, life.check)
    out = work/('sealed' if not (work/'sealed').exists() else 'sealed_'+str(time.time_ns())); out.mkdir()

    def checked_copy(src, dst):
        with Path(src).open('rb') as source, Path(dst).open('wb') as target:
            while chunk := source.read(1024*1024):
                life.check(); target.write(chunk)
        return str(dst)

    for name in ['frozen', 'frozen_history', 'starting_code_manifest.json', 'starting_code_snapshot.zip',
                 'starting_scope.json', 'lifecycle.json']:
        path = work/name
        if path.is_dir():
            shutil.copytree(path, out/name, copy_function=checked_copy)
        elif path.is_file():
            checked_copy(path, out/name)
    for path in work.glob('preflight*'):
        if path.is_dir():
            shutil.copytree(path, out/path.name, copy_function=checked_copy)
    for pattern in ['starting_git_*', 'preparation_*']:
        for path in work.glob(pattern):
            if path.is_file():
                checked_copy(path, out/path.name)
    bindings, history = {}, []
    for attempt in sorted((work/'attempts').iterdir()) if (work/'attempts').exists() else []:
        dest = out/'attempt_history'/attempt.name; dest.mkdir(parents=True)
        for path in attempt.iterdir():
            if path.is_file():
                checked_copy(path, dest/path.name)
        if attempt not in selected.values() and (attempt/'output').exists():
            shutil.copytree(attempt/'output', dest/'output', copy_function=checked_copy)
        history.append(dict(attempt_id=attempt.name,
            command=read(attempt/'command_result.json') if (attempt/'command_result.json').exists() else None))
    for job, attempt in selected.items():
        if status == 'PASS':
            bindings[job] = verify_attempt(attempt, rows, life.check)
        if (attempt/'output').exists():
            shutil.copytree(attempt/'output', out/job, copy_function=checked_copy)
    write(out/'attempts.json', history)
    write(out/'consumer_version_binding.json', dict(status=status, profile=PROFILE, selected=bindings))
    science = out/'science' if (out/'science').exists() else None
    complete = read(science/'enumeration_completion.json') if science and (science/'enumeration_completion.json').exists() else {}
    count = {key: complete.get(key, True if key == 'retained_baseline' else DECLARED if key in
             ['declared_candidates', 'unprocessed'] else 0) for key in COUNT_KEYS}
    if status != 'PASS' and science:
        count = prefix_counts(science)
    tests = read(out/'tests/job_result.json') if (out/'tests/job_result.json').exists() else {}
    legacy = read(out/'legacy/job_result.json') if (out/'legacy/job_result.json').exists() else {}
    timing = dict(worker_wall_s={job: read(attempt/'output/job_result.json').get('worker_wall_s')
        for job, attempt in selected.items() if (attempt/'output/job_result.json').exists()},
        entry_to_pre_receipt_s=time.perf_counter()-entry_start, lifecycle_elapsed_upper_bound_s=life.elapsed(),
        boundary='Report/status before final member readback; actual entry/export completion outside seal',
        overlapping_walls_added=False)
    write(out/'timings.json', timing)
    final = dict(status=status, exit_code={'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[status], **FLAGS, **count,
        **{gate: 'PASS' if status == 'PASS' else 'NOT_ACCEPTED' for gate in GATES},
        optimization_outcome=complete.get('optimization_outcome', 'PARTIAL_NOT_CONCLUDED') if status == 'PASS'
            else 'PARTIAL_NOT_CONCLUDED', reasons=reasons, consumer_binding_profile=PROFILE,
        historical_K12=dict(status='BLOCKED', exit_code=2, units=0, cost='NOT_RUN'),
        historical_R14=dict(status='PASS', qualified_count=0), historical_R15=dict(status='PASS', qualified_count=0))
    write(out/'final_status.json', final)
    write_report(out/'report.md', report_text(final, science, tests, legacy, timing))
    verify_sources(rows, life.check)
    members = [dict(path=path.relative_to(out).as_posix(), bytes=path.stat().st_size, sha256=sha(path, life.check))
               for path in sorted(out.rglob('*')) if path.is_file()]
    write(out/'artifact_manifest.json', dict(profile=PROFILE, files=members))
    for row in members:
        require((out/row['path']).stat().st_size == row['bytes'] and sha(out/row['path'], life.check) == row['sha256'],
                'SEAL_FINAL_READBACK')
    write(out/'receipt.json', dict(profile=PROFILE, status=status, exit_code=final['exit_code'],
        manifest_sha256=sha(out/'artifact_manifest.json'), member_count=len(members), receipt_self_hashed=False))
    result = independent_readback(out, life.check)
    write(work/'latest_delivery.json', dict(path=str(out), manifest_sha256=result['manifest_sha256']))
    return result


def seal_early_prefix(work, status, error, selected=None):
    work = Path(work); out = work/('sealed_prefix_'+str(time.time_ns())); out.mkdir()
    for name in ['frozen', 'frozen_history', 'starting_code_manifest.json', 'starting_code_snapshot.zip',
                 'starting_scope.json', 'lifecycle.json']:
        path = work/name
        if path.is_dir():
            shutil.copytree(path, out/name)
        elif path.is_file():
            shutil.copyfile(path, out/name)
    chosen = dict(selected or {})
    history = []
    for attempt in sorted((work/'attempts').iterdir(), key=lambda path: path.stat().st_mtime_ns) if (work/'attempts').exists() else []:
        if not attempt.is_dir():
            continue
        shutil.copytree(attempt, out/'attempt_history'/attempt.name)
        command = read(attempt/'command_result.json') if (attempt/'command_result.json').exists() else None
        job_result = read(attempt/'output/job_result.json') if (attempt/'output/job_result.json').exists() else None
        job = (command or job_result or {}).get('job')
        if job and selected is None:
            chosen[job] = attempt
        history.append(dict(attempt_id=attempt.name, command=command, result=job_result))
    for job, attempt in chosen.items():
        require(job in {'science', 'tests', 'legacy', 'guards'}, 'PREFIX_JOB_SCOPE')
        path = Path(attempt)/'output'
        if path.is_dir():
            shutil.copytree(path, out/job)
    write(out/'attempts.json', history)
    write(out/'consumer_version_binding.json', dict(status=status, profile=PROFILE,
        selected={}, failed_prefix_selected_attempts={job: Path(path).name for job, path in chosen.items()},
        accepted_completed_binding=False))
    count = {key: True if key == 'retained_baseline' else DECLARED if key in
             ['declared_candidates', 'unprocessed'] else 0 for key in COUNT_KEYS}
    science = out/'science' if (out/'science').is_dir() else None
    if science:
        count = prefix_counts(science)
    final = dict(status=status, exit_code=1 if status == 'FAIL' else 2, **FLAGS, **count,
        optimization_outcome='PARTIAL_NOT_CONCLUDED', reasons=[dict(status=status, error=error)],
        **{gate: 'NOT_ACCEPTED' for gate in GATES})
    write(out/'final_status.json', final); write(out/'failure.json', error)
    tests = read(out/'tests/job_result.json') if (out/'tests/job_result.json').exists() else {}
    legacy = read(out/'legacy/job_result.json') if (out/'legacy/job_result.json').exists() else {}
    write_report(out/'report.md', report_text(final, science, tests, legacy, {}))
    members = [dict(path=path.relative_to(out).as_posix(), bytes=path.stat().st_size, sha256=sha(path))
               for path in sorted(out.rglob('*')) if path.is_file()]
    write(out/'artifact_manifest.json', dict(profile=PROFILE, files=members))
    for row in members:
        require(sha(out/row['path']) == row['sha256'], 'PREFIX_READBACK')
    write(out/'receipt.json', dict(profile=PROFILE, status=status, exit_code=final['exit_code'],
        manifest_sha256=sha(out/'artifact_manifest.json'), receipt_self_hashed=False))
    result = independent_readback(out)
    write(work/'latest_delivery.json', dict(path=str(out), manifest_sha256=result['manifest_sha256']))
    return result
