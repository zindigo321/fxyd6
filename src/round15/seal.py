"""Independent ROUND15 closure and one-way disk receipt."""
import hashlib
import sys
from pathlib import Path
import shutil
import time
import zipfile
from src.round13.archive import safe_name,safe_inventory
from src.round13.common import read,write,require,sha,fingerprint
from .binding import verify_sources,verify_attempt,artifacts
from .control import Lifecycle

FLAGS=dict(active_protocol_change_authorized=False,official_readiness='UNRESOLVED',official_score=None,
    next_scientific_run_gate='BLOCKED_PENDING_RULE_CONFIRMATION',native_activation_count=0,
    git_write_operations=0,new_native_validation_performed=False)
GATES=['input_identity','asset_context_verification','baseline_replay','neighborhood_definition',
       'gap_certificate_verification','enumeration_completion','independent_all_candidate_verification',
       'consumer_version_binding','regression','offline_research_acceptance']
COUNT_KEYS=['declared_candidates','fully_evaluated','fully_independently_verified','certificate_rejected',
            'certificate_independently_verified','unprocessed','unknown','qualified_count','retained_baseline']


def independent_readback(folder,check=lambda:None):
    from .worker import records
    folder=Path(folder).resolve();receipt=read(folder/'receipt.json');manifest=read(folder/'artifact_manifest.json')
    require(receipt['profile']=='ROUND15_V1' and receipt['manifest_sha256']==sha(folder/'artifact_manifest.json',check),'SEAL_RECEIPT_BINDING')
    names=set()
    for row in manifest['files']:
        check();name=safe_name(row['path']);lexical=folder/name;path=lexical.resolve()
        require(name.casefold() not in names and path.is_relative_to(folder) and not lexical.is_symlink()
                and all(not p.is_symlink() for p in lexical.parents if p.is_relative_to(folder)),'SEAL_MEMBER_SCOPE')
        names.add(name.casefold());require(path.is_file() and path.stat().st_size==row['bytes'] and sha(path,check)==row['sha256'],'SEAL_MEMBER_BYTES')
    require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
            =={r['path'] for r in manifest['files']}|{'artifact_manifest.json','receipt.json'},'SEAL_EXACT_MEMBER_SET')
    final=read(folder/'final_status.json')
    require(final['status']==receipt['status'] and final['exit_code']==receipt['exit_code']
            and {'PASS':0,'FAIL':1,'BLOCKED':2}[final['status']]==final['exit_code'],'SEAL_STATUS_EXIT')
    require(all(final.get(k)==v for k,v in FLAGS.items()),'SEAL_SCOPE_FLAGS')
    if final['status']=='PASS':
        require(all(final.get(g)=='PASS' for g in GATES),'SEAL_PASS_GATES')
        from .checker import terminal_verification
        contract=read(folder/'frozen/contract.json');meta=contract['metadata'];science=folder/'science'
        terminal=terminal_verification(meta['baseline_indices'],meta['donor_indices'],{int(i):s for i,s in meta['states'].items()},
            records(science/'ledger.jsonl'),records(science/'candidates.jsonl'),records(science/'checker.jsonl'),
            records(science/'certificates.jsonl'),records(science/'certificate_checker.jsonl'),
            read(science/'independent_selection.json')['selected_identity'],proof=read(science/'gap_proof.json'),check=check)
        require(terminal['status']=='PASS' and all(terminal[k]==final[k] for k in COUNT_KEYS),'SEAL_EXACT_SPACE_TERMINAL')
        require(read(science/'independent_terminal_verification.json')['baseline_checked'] is True
                and read(science/'baseline_checker.json')['status']=='PASS'
                and read(science/'independent_gap_proof.json')['status']=='PASS'
                and read(science/'source_preservation.json')['status']=='PASS','SEAL_INPUT_BASELINE_PROOF')
        tests=read(folder/'tests/job_result.json');legacy=read(folder/'legacy/job_result.json')
        require(tests['tests']>0 and tests['failures']==tests['errors']==tests['skipped']==0
                and legacy['regression_tests']==202 and legacy['round14_tests']==89 and legacy['binding_counterexamples']==26,'SEAL_TESTS')
        frozen=read(folder/'frozen/consumer_code.json')
        require(fingerprint(frozen)==contract['source_manifest_identity'],'SEAL_SOURCE_IDENTITY')
        with zipfile.ZipFile(folder/'frozen/consumer_code.zip') as z:
            safe_inventory(z.infolist());require(set(z.namelist())=={r['relative_path'] for r in frozen},'SEAL_SOURCE_SET')
            for row in frozen:
                check();blob=z.read(row['relative_path']);require(len(blob)==row['bytes'] and hashlib.sha256(blob).hexdigest()==row['sha256'],'SEAL_SOURCE_SNAPSHOT')
        bound=read(folder/'consumer_version_binding.json')['selected'];require(set(bound)=={'science','tests','legacy','guards'},'SEAL_JOB_SET')
        for job,b in bound.items():
            history=folder/'attempt_history'/b['attempt_id'];command=read(history/'command_result.json')
            require(read(history/'consumer_code.json')==command['code_manifest']==frozen,'SEAL_ATTEMPT_SOURCE')
            require(command['job']==job and command['attempt_id']==b['attempt_id'] and command['timeout'] is False
                    and command['python_exit_code']==0,'SEAL_ATTEMPT_COMMAND')
            source_out=Path(command['output']);source_work=source_out.parent.parent.parent
            require(command['command']==b['command']==[sys.executable,'-X','utf8','-B','-m','src.round15.worker',
                '--work',str(source_work),'--out',str(source_out),'--job',job],'SEAL_COMPLETE_COMMAND')
            result=read(folder/job/'job_result.json')
            require(read(history/'supervised_result.json')==result and command['supervised_result_exit_code']==0
                and result['attempt_id']==b['attempt_id'] and result['job']==job and result['consumer_identity']==fingerprint(frozen),
                'SEAL_SUPERVISED_WORKER_BINDING')
            require(sha(history/'consumer_code.zip',check)==b['code_snapshot_sha256'],'SEAL_ATTEMPT_ZIP')
            require(artifacts(folder/job,check)==command['output_artifacts']
                    and fingerprint(command['output_artifacts'])==b['output_artifacts_identity'],'SEAL_ATTEMPT_OUTPUTS')
    return dict(status=final['status'],exit_code=final['exit_code'],verified_members=len(manifest['files']),
        manifest_sha256=receipt['manifest_sha256'],delivery=str(folder),reexecuted=False)


def prefix_counts(science):
    """Recover durable work, including records after the last progress checkpoint."""
    from .worker import records
    science=Path(science);seen={};verified={};qualified=set()
    for name,kind in [('candidate_summary','full'),('certificates','cert')]:
        path=science/(name+'.jsonl')
        if path.exists():
            for row in records(path):
                seen[row['identity']]=kind
                if row.get('qualified_improvement'):qualified.add(row['identity'])
    for name,kind in [('checker','full'),('certificate_checker','cert')]:
        path=science/(name+'.jsonl')
        if path.exists():
            for row in records(path):
                if row.get('status')=='PASS':verified[row['identity']]=kind
    return dict(declared_candidates=187488,fully_evaluated=sum(k=='full' for k in seen.values()),
        fully_independently_verified=sum(k=='full' and seen.get(i)==k for i,k in verified.items()),
        certificate_rejected=sum(k=='cert' for k in seen.values()),
        certificate_independently_verified=sum(k=='cert' and seen.get(i)==k for i,k in verified.items()),
        unprocessed=187488-len(seen),unknown=len(set(seen)-set(verified)),
        qualified_count=len(qualified&set(verified)),retained_baseline=True)


def report_text(final,science,tests,legacy,timing):
    text=['# 第十五轮保存组件库完整双换研究','',f'工程状态 {final["status"]}，退出码 {final["exit_code"]}。',
        f'优化结论：{final["optimization_outcome"]}。','',
        f'声明 {final["declared_candidates"]}；精算 {final["fully_evaluated"]}，精算独立核对 {final["fully_independently_verified"]}；证书排除 {final["certificate_rejected"]}，证书独立核验 {final["certificate_independently_verified"]}；未处理 {final["unprocessed"]}，UNKNOWN {final["unknown"]}。',
        '证书排除只证明不可能通过至少1秒Tmax改善门；完整指标和可行性均为NOT_EVALUATED/null，未冒充精算。',
        'A加入1123；B删除911与1370且不加1123；其余C用原始空窗两侧保留访问的下界证明。B的465个例外完整保留。']
    if science and (science/'baseline.json').exists():
        baseline=read(science/'baseline.json');selected=read(science/'selected.json') if (science/'selected.json').exists() else baseline
        text+=['','| 指标 | 基线 | 选中 |','|---|---:|---:|']
        for name,get in [('mask覆盖',lambda r:f'{r["effective_grid"]["covered"]}/{r["effective_grid"]["points"]}'),
            ('原域覆盖',lambda r:f'{r["full_grid"]["covered"]}/{r["full_grid"]["points"]}'),
            ('mask T90 s',lambda r:r['effective_grid']['T90_s']),('mask T100 s',lambda r:r['effective_grid']['T100_s']),
            ('原域 T90 s',lambda r:r['full_grid']['T90_s']),('原域 T100 s',lambda r:r['full_grid']['T100_s']),
            ('池化内部Tavg s',lambda r:r['regional']['pooled_internal']['mean_s']),('内部Tmax s',lambda r:r['regional']['pooled_internal']['max_s'])]:
            text.append(f'| {name} | {get(baseline)} | {get(selected)} |')
        reduction=baseline['regional']['pooled_internal']['max_s']-selected['regional']['pooled_internal']['max_s']
        text+=['',f'合格改善数 {final["qualified_count"]}；保留基线 {final["retained_baseline"]}；Tmax减少 {reduction!r} 秒；保守至少1秒改善 {bool(selected["qualified_improvement"])}。',
            f'选中 identity `{selected["identity"]}`；删除 {selected.get("remove")}，新增 {selected.get("add")}，分区 {selected.get("partition","baseline")}。',
            '', '| 对象 | 基线最长内部gap/端点 s | 选中最长内部gap/端点 s | 基线首/尾 s | 选中首/尾 s |',
            '|---|---|---|---|---|']
        for target,b in baseline['regional']['targets'].items():
            s=selected['regional']['targets'][target];edge=lambda o:[p[1]-p[0] for p in o['boundary_segments']]
            text.append(f'| {target} | {b["internal"]["max_s"]}/{b["internal"]["longest_endpoints_s"]} | {s["internal"]["max_s"]}/{s["internal"]["longest_endpoints_s"]} | {edge(b)} | {edge(s)} |')
        text+=['',f'包含边界的池化敏感性：基线 {baseline["regional"]["pooled_boundary_inclusive"]}；选中 {selected["regional"]["pooled_boundary_inclusive"]}。',
            '首尾空窗未加入主目标或可行门；把内部空窗迁到首窗可能改善主指标，同时增加首窗代价，不表示整个任务窗全面改善。',
            '全部60资产并集与基线相同的354个原域缺失点ID及摘要另存；任何子集至少缺这些保存点，不推导物理不可达或官方mask有效。']
        if (science/'partition_B_best_qualified.json').exists():
            branch=read(science/'partition_B_best_qualified.json');obj=branch['regional']['targets']['YangtzeRiverDelta_Island_2']
            text+=['',f'分区B最优合格候选 `{branch["identity"]}`：Island_2首/尾区间 {obj["boundary_segments"]}，包含边界指标 {branch["regional"]["pooled_boundary_inclusive"]}；完整明细 science/partition_B_best_qualified.json。']
    text+=['',f'回归：旧202项 {legacy.get("regression_tests",0)}，R14项 {legacy.get("round14_tests",0)}；历史绑定反例 {legacy.get("binding_counterexamples",0)}；R15新增 {tests.get("tests",0)}。',
        '185旧消费文件均保持原字节；旧202/168文件、R14的89/185文件、绑定26/142文件独立子清单与隔离映射保留，未与顶层清单强行判等。',
        '独立checker共享冻结输入解析、坐标、mask及identity格式；最小值、次序统计、区间并集、证明、分区、可行门和选择算法独立。',
        f'计时边界：{timing}。完整入口和至导出累计在传输层单列，父子墙钟不相加。',
        '新组合：source=archived_component_composition，new_native_validation_performed=false，whole_constellation_STK_verified=false。基线历史整星座来源单列。',
        '两轴半角0.81°和直接AreaTarget Access未获用户规则确认；EOP止2019/场景2027、mask非官方、保存结果不证明连续几何完备性。官方评分null，后续科学运行门仍阻塞。',
        'K12仍BLOCKED/2、0单元、成本NOT_RUN；历史R14 PASS及0改善不改写。原生激活0，Git写0。',
        '本结论仅限固定N28同高度完整双换空间；不扩展搜索，不创建正式提交包或下一轮。']
    errors=[r for r in final.get('reasons',[]) if r.get('status')!='PASS']
    if errors:text+=['',f'未完成/失败证据：{errors}']
    return '\n'.join(text)+'\n'


def seal(work,selected,status,reasons,entry_start):
    work=Path(work);life=Lifecycle(work/'lifecycle.json');life.check();rows=read(work/'frozen/consumer_code.json');verify_sources(rows,life.check)
    out=work/('sealed' if not (work/'sealed').exists() else 'sealed_'+str(time.time_ns()));out.mkdir()
    def checked_copy(src,dst):
        with Path(src).open('rb') as source,Path(dst).open('wb') as target:
            while chunk:=source.read(1024*1024):life.check();target.write(chunk)
        return str(dst)
    for name in ['frozen','frozen_history','starting_code_manifest.json','starting_code_snapshot.zip','starting_scope.json','lifecycle.json']:
        p=work/name
        if p.is_dir():shutil.copytree(p,out/name,copy_function=checked_copy)
        elif p.is_file():checked_copy(p,out/name)
    for p in work.glob('preflight*'):
        if p.is_dir():shutil.copytree(p,out/p.name,copy_function=checked_copy)
    for p in work.glob('starting_git_*'):checked_copy(p,out/p.name)
    bindings={};history=[]
    for attempt in sorted((work/'attempts').iterdir()) if (work/'attempts').exists() else []:
        dest=out/'attempt_history'/attempt.name;dest.mkdir(parents=True)
        for p in attempt.iterdir():
            if p.is_file():checked_copy(p,dest/p.name)
        if attempt not in selected.values() and (attempt/'output').exists():shutil.copytree(attempt/'output',dest/'output',copy_function=checked_copy)
        history.append(dict(attempt_id=attempt.name,command=read(attempt/'command_result.json') if (attempt/'command_result.json').exists() else None))
    for job,attempt in selected.items():
        if status=='PASS':bindings[job]=verify_attempt(attempt,rows,life.check)
        if (attempt/'output').exists():shutil.copytree(attempt/'output',out/job,copy_function=checked_copy)
    write(out/'attempts.json',history);write(out/'consumer_version_binding.json',dict(status=status,profile='ROUND15_V1',selected=bindings))
    science=out/'science' if (out/'science').exists() else None
    complete=read(science/'enumeration_completion.json') if science and (science/'enumeration_completion.json').exists() else {}
    prefix=read(science/'progress.json') if science and (science/'progress.json').exists() else {}
    count={key:(complete or prefix).get(key,True if key=='retained_baseline' else 187488 if key in ['declared_candidates','unprocessed'] else 0) for key in COUNT_KEYS}
    if status!='PASS' and science:count=prefix_counts(science)
    tests=read(out/'tests/job_result.json') if (out/'tests/job_result.json').exists() else {};legacy=read(out/'legacy/job_result.json') if (out/'legacy/job_result.json').exists() else {}
    timing=dict(worker_wall_s={job:read(attempt/'output/job_result.json').get('worker_wall_s') for job,attempt in selected.items() if (attempt/'output/job_result.json').exists()},
        entry_to_pre_receipt_s=time.perf_counter()-entry_start,lifecycle_elapsed_upper_bound_s=life.elapsed(),
        boundary='Report/status before final member readback; actual entry/export completion outside seal',overlapping_walls_added=False)
    write(out/'timings.json',timing)
    final=dict(status=status,exit_code={'PASS':0,'FAIL':1,'BLOCKED':2}[status],**FLAGS,**count,
        **{g:'PASS' if status=='PASS' else 'NOT_ACCEPTED' for g in GATES},
        optimization_outcome=complete.get('optimization_outcome','PARTIAL_NOT_CONCLUDED') if status=='PASS' else 'PARTIAL_NOT_CONCLUDED',
        reasons=reasons,consumer_binding_profile='ROUND15_V1',historical_K12=dict(status='BLOCKED',exit_code=2,units=0,cost='NOT_RUN'))
    write(out/'final_status.json',final);(out/'report.md').write_text(report_text(final,science,tests,legacy,timing),encoding='utf8')
    verify_sources(rows,life.check)
    members=[dict(path=p.relative_to(out).as_posix(),bytes=p.stat().st_size,sha256=sha(p,life.check)) for p in sorted(out.rglob('*')) if p.is_file()]
    write(out/'artifact_manifest.json',dict(profile='ROUND15_V1',files=members))
    for row in members:require(sha(out/row['path'],life.check)==row['sha256'],'SEAL_FINAL_READBACK')
    write(out/'receipt.json',dict(profile='ROUND15_V1',status=status,exit_code=final['exit_code'],manifest_sha256=sha(out/'artifact_manifest.json'),member_count=len(members),receipt_self_hashed=False))
    result=independent_readback(out,life.check);write(work/'latest_delivery.json',dict(path=str(out),manifest_sha256=result['manifest_sha256']));return result


def seal_early_prefix(work,status,error):
    """Seal missing-input preparation honestly; never fabricate a completed space."""
    work=Path(work);out=work/('sealed_prefix_'+str(time.time_ns()));out.mkdir()
    for name in ['starting_code_manifest.json','starting_code_snapshot.zip','starting_scope.json','lifecycle.json']:
        if (work/name).exists():shutil.copyfile(work/name,out/name)
    count={key:True if key=='retained_baseline' else 187488 if key in ['declared_candidates','unprocessed'] else 0 for key in COUNT_KEYS}
    final=dict(status=status,exit_code=1 if status=='FAIL' else 2,**FLAGS,**count,optimization_outcome='PARTIAL_NOT_CONCLUDED',
        reasons=[dict(status=status,error=error)],**{g:'NOT_ACCEPTED' for g in GATES})
    write(out/'final_status.json',final);write(out/'failure.json',error);(out/'report.md').write_text(report_text(final,None,{},{},{}),encoding='utf8')
    members=[dict(path=p.relative_to(out).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(out.rglob('*')) if p.is_file()]
    write(out/'artifact_manifest.json',dict(profile='ROUND15_V1',files=members))
    for row in members:require(sha(out/row['path'])==row['sha256'],'PREFIX_READBACK')
    write(out/'receipt.json',dict(profile='ROUND15_V1',status=status,exit_code=final['exit_code'],manifest_sha256=sha(out/'artifact_manifest.json'),receipt_self_hashed=False))
    result=independent_readback(out);write(work/'latest_delivery.json',dict(path=str(out),manifest_sha256=result['manifest_sha256']));return result
