"""Round14 closure; reports precede an exact member set and one-way receipt."""
import json
from pathlib import Path
import shutil
import time
import zipfile
from src.round13.archive import safe_name
from src.round13.common import read, write, require, sha, fingerprint
from .binding import ROOT, verify_sources, verify_attempt
from .control import Lifecycle

FLAGS=dict(active_protocol_change_authorized=False,official_readiness='UNRESOLVED',official_score=None,
    next_scientific_run_gate='BLOCKED_PENDING_RULE_CONFIRMATION',native_activation_count=0,
    git_write_operations=0,new_native_validation_performed=False)
GATES=['input_identity','asset_context_verification','baseline_replay','neighborhood_definition',
       'enumeration_completion','independent_all_candidate_verification','consumer_version_binding',
       'regression','offline_research_acceptance']


def lines(path):
    return [json.loads(s) for s in Path(path).read_text(encoding='utf8').splitlines() if s.strip()]


def independent_readback(folder,check=lambda:None):
    folder=Path(folder).resolve();receipt=read(folder/'receipt.json');manifest=read(folder/'artifact_manifest.json')
    require(receipt['profile']=='ROUND14_V1' and receipt['manifest_sha256']==sha(folder/'artifact_manifest.json',check),'SEAL_RECEIPT_BINDING')
    names=set()
    for row in manifest['files']:
        check()
        name=safe_name(row['path']);lexical=folder/name;p=lexical.resolve()
        require(name.casefold() not in names and p.is_relative_to(folder),'SEAL_UNSAFE_OR_DUPLICATE_PATH')
        require(not lexical.is_symlink() and all(not parent.is_symlink() for parent in lexical.parents if parent.is_relative_to(folder)), 'SEAL_LINK_MEMBER')
        names.add(name.casefold());require(p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes'] and sha(p,check)==row['sha256'],'SEAL_MEMBER_BYTES')
    expected={r['path'] for r in manifest['files']}|{'artifact_manifest.json','receipt.json'}
    require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}==expected,'SEAL_EXACT_MEMBER_SET')
    final=read(folder/'final_status.json')
    require(final['status']==receipt['status'] and final['exit_code']==receipt['exit_code']
            and {'PASS':0,'FAIL':1,'BLOCKED':2}[final['status']]==final['exit_code'],'SEAL_STATUS_CONSISTENCY')
    require(all(final.get(k)==v for k,v in FLAGS.items()),'SEAL_SCOPE_FLAGS')
    if final['status']=='PASS':
        require(all(final.get(k)=='PASS' for k in GATES),'SEAL_PASS_GATES')
        from .checker import terminal_verification
        reports,checks=lines(folder/'science/candidates.jsonl'),lines(folder/'science/checker.jsonl')
        terminal=terminal_verification(read(folder/'frozen/contract.json')['neighborhood'],reports,checks,
             read(folder/'science/independent_selection.json')['selected_identity'])
        require(terminal['status']=='PASS','SEAL_ENUMERATION_TERMINAL_CHECK')
        regression=read(folder/'legacy/job_result.json');tests=read(folder/'tests/job_result.json')
        require(regression['regression_tests']==202 and regression['binding_counterexamples']==26
                and tests['tests']>0 and tests['failures']==tests['errors']==tests['skipped']==0,'SEAL_TEST_COMPLETENESS')
        require(read(folder/'science/asset_context_verification.json')['asset_count']==60
                and read(folder/'science/baseline_checker.json')['status']=='PASS'
                and read(folder/'science/source_preservation.json')['status']=='PASS','SEAL_SCIENTIFIC_EVIDENCE')
        frozen=read(folder/'frozen/consumer_code.json')
        require(fingerprint(frozen)==read(folder/'frozen/contract.json')['source_manifest_identity'],'SEAL_FROZEN_SOURCE_IDENTITY')
        with zipfile.ZipFile(folder/'frozen/consumer_code.zip') as z:
            require(set(z.namelist())=={r['relative_path'] for r in frozen},'SEAL_SOURCE_SNAPSHOT_SET')
            for row in frozen:
                check()
                blob=z.read(row['relative_path'])
                require(len(blob)==row['bytes'] and __import__('hashlib').sha256(blob).hexdigest()==row['sha256'],'SEAL_SOURCE_SNAPSHOT_BYTES')
        bindings=read(folder/'consumer_version_binding.json')['selected']
        require(set(bindings)=={'science','tests','legacy','guards'},'SEAL_SELECTED_JOB_SET')
        for job,bound in bindings.items():
            check()
            attempt=folder/'attempt_history'/bound['attempt_id'];command=read(attempt/'command_result.json')
            require(read(attempt/'consumer_code.json')==command['code_manifest']==frozen,'SEAL_SELECTED_CONSUMER_VERSION')
            require(command['job']==job and command['attempt_id']==bound['attempt_id'] and command['timeout'] is False
                    and command['python_exit_code']==0,'SEAL_SELECTED_COMMAND_IDENTITY')
            require(fingerprint(command['output_artifacts'])==bound['output_artifacts_identity'],'SEAL_OUTPUT_SET_IDENTITY')
            from .binding import artifacts
            require(artifacts(folder/job)==command['output_artifacts'],'SEAL_EXECUTED_OUTPUT_READBACK')
    return dict(status=final['status'],exit_code=final['exit_code'],verified_members=len(manifest['files']),
                manifest_sha256=receipt['manifest_sha256'],delivery=str(folder),reexecuted=False)


def seal_early_prefix(work,status,error):
    """Even unavailable metadata gets an honest immutable preparation prefix."""
    out=Path(work)/('sealed_prefix_'+str(time.time_ns()));out.mkdir()
    for name in ['lifecycle.json','starting_tracked_manifest.json','starting_tracked_source.zip','initial_scope.json']:
        if (Path(work)/name).exists():shutil.copyfile(Path(work)/name,out/name)
    final=dict(status=status,exit_code=1 if status=='FAIL' else 2,**FLAGS,
        optimization_outcome='PARTIAL_NOT_CONCLUDED',evaluated_candidates=0,verified_candidates=0,
        reasons=[error],**{gate:'NOT_ACCEPTED' for gate in GATES})
    write(out/'final_status.json',final);write(out/'failure.json',error)
    (out/'report.md').write_text(report_text(final,None,{},{},{}),encoding='utf8')
    members=[dict(path=p.relative_to(out).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(out.rglob('*')) if p.is_file()]
    write(out/'artifact_manifest.json',dict(profile='ROUND14_V1',files=members))
    for row in members:require(sha(out/row['path'])==row['sha256'],'EARLY_PREFIX_READBACK')
    write(out/'receipt.json',dict(profile='ROUND14_V1',status=status,exit_code=final['exit_code'],
        manifest_sha256=sha(out/'artifact_manifest.json'),member_count=len(members),receipt_self_hashed=False))
    result=independent_readback(out);write(Path(work)/'latest_delivery.json',dict(path=str(out),manifest_sha256=result['manifest_sha256']))
    return result


def report_text(final, science, tests, legacy, timing):
    text=['# 第十四轮保存组件库离线研究', '',f'工程状态：{final["status"]}；退出码 {final["exit_code"]}。',
        f'优化结论：{final["optimization_outcome"]}。',
        '研究仅覆盖冻结 TEAM_COMPETITION_V3、同高度 28×32 单星替换邻域。未确认规则未转为我方协议；官方分数 null，后续科学运行门仍阻塞。',
        'K12 仍 BLOCKED/2、0 单元、成本 NOT_RUN；其他历史状态保留。未重跑的历史77/49和全包13315成员审计仅标 REUSED。','']
    if science and (science/'baseline.json').exists():
        baseline=read(science/'baseline.json'); selected=read(science/'selected.json') if (science/'selected.json').exists() else baseline
        text+=['| 指标 | 基线 | 选中结果 |','|---|---:|---:|']
        for label,get in [('mask覆盖',lambda r:f'{r["effective_grid"]["covered"]}/{r["effective_grid"]["points"]}'),
                          ('原域覆盖',lambda r:f'{r["full_grid"]["covered"]}/{r["full_grid"]["points"]}'),
                          ('T90 s',lambda r:r['effective_grid']['T90_s']),('T100 s',lambda r:r['effective_grid']['T100_s']),
                          ('Tavg s',lambda r:r['regional']['pooled_internal']['mean_s']),('Tmax s',lambda r:r['regional']['pooled_internal']['max_s'])]:
            text.append(f'| {label} | {get(baseline)} | {get(selected)} |')
        delta=baseline['regional']['pooled_internal']['max_s']-selected['regional']['pooled_internal']['max_s']
        text+=['',f'Tmax 减少 {delta!r} 秒；满足保守至少 1 秒改善门：{bool(selected.get("qualified_improvement"))}。',
            f'基线 identity：`{baseline["identity"]}`；选中 identity：`{selected["identity"]}`。',
            '新组合标记：保存组件库组合候选，未做新整星座 STK 验证。基线历史整星座验证来源另存，未转移给新组合。',
            '', '| 对象 | 基线最长内部 gap / 端点 s | 选中最长内部 gap / 端点 s | 基线首/尾 s | 选中首/尾 s |',
            '|---|---|---|---|---|']
        for target,b in baseline['regional']['targets'].items():
            s=selected['regional']['targets'][target]
            edge=lambda o:[p[1]-p[0] for p in o['boundary_segments']]
            text.append(f'| {target} | {b["internal"]["max_s"]} / {b["internal"]["longest_endpoints_s"]} | {s["internal"]["max_s"]} / {s["internal"]["longest_endpoints_s"]} | {edge(b)} | {edge(s)} |')
        text+=['','首尾空窗单列敏感性，不纳入主目标；内部改善不表示每个对象或首尾均改善。完整原始区间、合并区间、端点和首访见 science/baseline* 与 selected*。',
            f'实际完成候选 {final.get("evaluated_candidates",0)}，独立核对 {final.get("verified_candidates",0)}；基线另计 1。',
            '全部候选未筛选前实际计算43424首访和三对象区间；独立核对采用前后缀最小值、排序次序统计及累积前沿聚类；输入解析、坐标、mask和schema共享。',
            '绝对时间容差1e-6秒，rtol=0；新候选全量逐点比较后只保留摘要，基线与选中候选另保存逐点文件。',
            '若无合格改善，结论仅为声明邻域无合格改善，并不证明全局最优。']
    text+=['',f'旧测试：{legacy.get("regression_tests",0)}；历史绑定反例：{legacy.get("binding_counterexamples",0)}；新增测试：{tests.get("tests",0)}。',
        '两项R13活跃修复：封存重入拒绝新评价参数；封存绑定真实选中attempt/源码/命令/产物。历史K13按旧profile读回，未重写。',
        '完整冻结源码清单包括历史168文件和全部R14文件；隔离202项测试用168文件子集，历史绑定用冻结142文件子集。副本路径映射与运行前后摘要单独保存。',
        f'计时：{json.dumps(timing,ensure_ascii=False)}',
        '原生激活0，Git写操作0。EOP止2019而场景在2027、mask非官方、两轴半角0.81°和直接AreaTarget Access仍未获规则确认；本研究不证明连续几何完备性。',
        '封存清单形成于报告/状态/日志完成之后；receipt单向绑定manifest，receipt不自哈希。导出及Shell完成记录存于传输层。']
    if final.get('reasons'):text+=['',f'未完成/失败原因：{final["reasons"]}']
    return '\n'.join(text)+'\n'


def seal(work, selected, status, reasons, entry_start):
    life=Lifecycle(work/'lifecycle.json');life.check();rows=read(work/'frozen/consumer_code.json')
    verify_sources(rows,life.check)
    def checked_copy(source,destination):
        life.check()
        with Path(source).open('rb') as incoming,Path(destination).open('wb') as outgoing:
            while block:=incoming.read(1024*1024):
                life.check();outgoing.write(block)
        return str(destination)
    index=len(list(work.glob('sealed*')));out=work/('sealed' if index==0 else f'sealed_{index+1:02d}');out.mkdir()
    for name in ['frozen','frozen_history','starting_tracked_source.zip','starting_tracked_manifest.json','initial_scope.json','lifecycle.json']:
        src=work/name
        if src.is_dir():shutil.copytree(src,out/name,copy_function=checked_copy)
        elif src.exists():checked_copy(src,out/name)
    for src in work.glob('preflight*'):
        if src.is_dir():shutil.copytree(src,out/src.name,copy_function=checked_copy)
    for src in work.glob('starting_git_*'):shutil.copyfile(src,out/src.name)
    attempt_history=[];bindings={}
    for attempt in sorted((work/'attempts').iterdir()) if (work/'attempts').exists() else []:
        dest=out/'attempt_history'/attempt.name;dest.mkdir(parents=True)
        for name in ['consumer_code.json','consumer_code.zip','stdout.log','stderr.log','command_result.json','supervised_result.json']:
            if (attempt/name).exists():shutil.copyfile(attempt/name,dest/name)
        for name in ['job_result.json','error.log','guard.jsonl','parent_guard.jsonl','progress.json']:
            if (attempt/'output'/name).exists():shutil.copyfile(attempt/'output'/name,dest/name)
        attempt_history.append(dict(attempt_id=attempt.name,command=read(attempt/'command_result.json') if (attempt/'command_result.json').exists() else None))
        if attempt not in selected.values() and (attempt/'output').exists():
            shutil.copytree(attempt/'output',dest/'output',copy_function=checked_copy)
    for job,attempt in selected.items():
        if status=='PASS':bindings[job]=verify_attempt(attempt,rows,life.check)
        source=attempt/'output';dest=out/job
        if source.exists():shutil.copytree(source,dest,copy_function=checked_copy)
    write(out/'attempts.json',attempt_history);write(out/'consumer_version_binding.json',dict(status='PASS' if status=='PASS' else status,selected=bindings))
    science=out/'science' if (out/'science').exists() else None
    completion=read(science/'enumeration_completion.json') if science and (science/'enumeration_completion.json').exists() else {}
    tests=read(out/'tests/job_result.json') if (out/'tests/job_result.json').exists() else {}
    legacy=read(out/'legacy/job_result.json') if (out/'legacy/job_result.json').exists() else {}
    timing=dict(worker_wall_s={job:read(attempt/'output/job_result.json').get('worker_wall_s') for job,attempt in selected.items() if (attempt/'output/job_result.json').exists()},
        entry_end_to_end_s=time.perf_counter()-entry_start,lifecycle_elapsed_upper_bound_s=life.elapsed(),
        measurement_boundary='before final seal readback; completion boundary is recorded outside seal',wall_times_added=False)
    write(out/'timings.json',timing)
    final=dict(status=status,exit_code={'PASS':0,'FAIL':1,'BLOCKED':2}[status],**FLAGS,
        **{gate:'PASS' if status=='PASS' else 'NOT_ACCEPTED' for gate in GATES},
        optimization_outcome=completion.get('optimization_outcome','PARTIAL_NOT_CONCLUDED'),
        evaluated_candidates=completion.get('evaluated_candidates',0),verified_candidates=completion.get('independently_verified_candidates',0),
        reasons=reasons,consumer_binding_profile='ROUND14_V1',historical_K12=dict(status='BLOCKED',exit_code=2,units=0,cost='NOT_RUN'))
    if science and not completion and (science/'progress.json').exists():
        prefix=read(science/'progress.json');final.update(evaluated_candidates=prefix.get('evaluated',0),verified_candidates=prefix.get('verified',0))
    write(out/'final_status.json',final)
    (out/'report.md').write_text(report_text(final,science,tests,legacy,timing),encoding='utf8')
    verify_sources(rows,life.check)
    members=[dict(path=p.relative_to(out).as_posix(),bytes=p.stat().st_size,sha256=sha(p,life.check)) for p in sorted(out.rglob('*')) if p.is_file()]
    write(out/'artifact_manifest.json',dict(profile='ROUND14_V1',files=members))
    # A separate read of every file completes before the one-way receipt.
    for row in members:require(sha(out/row['path'],life.check)==row['sha256'],'SEAL_FINAL_READBACK')
    write(out/'receipt.json',dict(profile='ROUND14_V1',status=status,exit_code=final['exit_code'],
        manifest_sha256=sha(out/'artifact_manifest.json'),member_count=len(members),receipt_self_hashed=False))
    result=independent_readback(out,life.check);write(work/'latest_delivery.json',dict(path=str(out),manifest_sha256=result['manifest_sha256']))
    return result
