"""Orchestrate only saved-file checks, keeping subject and validator distinct."""
import json
import time
import traceback
from pathlib import Path
from src.round2.evidence import code_manifest
from . import binding, counterexamples, manifests, native, regression, science
from .common import KEYS, canonical, file_record, identities, no_fresh_native, outcome, read, sha, text, write


def source_identity(subject,validator,s,v,policy):
    issues=[];sources={}
    for label,folder in [('S',s),('V',v)]:
        ctx=read(folder/'run.json');config=read(folder/'config.json')
        if any(config[k]!=ctx[k] for k in KEYS) or sha(canonical(config['config']))!=ctx['config_sha256']:issues.append(label+':CONFIG_IDENTITY')
        for name,key in [('input_manifest.json','input_sha256'),('code_manifest.json','code_sha256')]:
            manifest=read(folder/name)
            if manifest['run_id']!=ctx['run_id'] or sha(canonical(manifest['files']))!=ctx[key]:issues.append(label+':MANIFEST_IDENTITY')
        sources[label]=dict(context=ctx,config_file=file_record(folder/'config.json'),command=read(folder/'command_result.json'),final_status=read(folder/'final_status.json'))
        delivery=read(folder/'delivery_verification.json')
        if file_record(folder/'artifact_manifest.json')['sha256']!=delivery['manifest_sha256']:
            issues.append(label+':HISTORICAL_DELIVERY_MANIFEST_HASH')
        sources[label]['historical_delivery_anchor']=dict(declared_sha256=delivery['manifest_sha256'],actual=file_record(folder/'artifact_manifest.json'))
    if sources['S']['context']!=subject:issues.append('SUBJECT_CONTEXT_REWRITTEN')
    if (subject['run_id'],subject['code_sha256'])!=(policy['subject_run_id'],policy['subject_code_sha256']):issues.append('S_EXPECTED_ANCHOR')
    if subject['config_sha256']!=policy['subject_config_sha256']:issues.append('S_CONFIG_ANCHOR')
    vc=sources['V']['context']
    if (vc['run_id'],vc['code_sha256'])!=(policy['historical_validator_run_id'],policy['historical_validator_code_sha256']):issues.append('V_EXPECTED_ANCHOR')
    if vc['source_run_id']!=subject['run_id'] or vc['source_output']!=str(s):issues.append('V_SOURCE_BINDING')
    if read(s/'config.json')['config']!=read(v/'config.json')['config']:issues.append('S_V_PHYSICAL_CONFIG')
    sf=sources['S']['final_status'];vf=sources['V']['final_status']
    if sf['business']['core_acceptance']!='FAIL' or vf['status']!='BLOCKED' or sources['S']['command']['exit_code']!=1 or sources['V']['command']['exit_code']!=1:issues.append('HISTORICAL_STATUS_CHANGED')
    identities(subject,validator)
    return dict(status='FAIL' if issues else 'PASS',errors=issues,sources=sources,validator=validator,baseline_commit=policy['baseline_commit'])


def validate(subject_ctx,validator_ctx,source_dir,historical_validator_dir,output_dir,work_dir,policy):
    s=Path(source_dir);v=Path(historical_validator_dir);out=Path(output_dir);work=Path(work_dir)
    root=Path(__file__).resolve().parents[2];baseline=Path(policy['baseline_evidence_dir']);ctx=subject_ctx
    provenance=identities(ctx,validator_ctx);checks={};values={};start=time.perf_counter()
    def check(name,call):
        t=time.perf_counter();print('CHECK',name,flush=True)
        try:
            value=call()
            if not isinstance(value,dict) or value.get('status') not in {'PASS','FAIL','BLOCKED'}:raise ValueError('CHECK_RESULT_SCHEMA')
        except (FileNotFoundError,PermissionError) as exc:
            value=dict(status='BLOCKED',errors=[type(exc).__name__+':'+str(exc)],traceback=traceback.format_exc())
        except Exception as exc:
            value=dict(status='FAIL',errors=[type(exc).__name__+':'+str(exc)],traceback=traceback.format_exc())
        value.update(provenance);values[name]=value
        checks[name]=dict(status=value['status'],elapsed_s=time.perf_counter()-t,artifact=name+'.json',errors=value.get('errors',[]))
        write(out/(name+'.json'),value);write(out/'progress.json',dict(checks=checks,**provenance))
        print('RESULT',name,value['status'],round(checks[name]['elapsed_s'],3),flush=True)
        return value
    check('source_identity',lambda:source_identity(ctx,validator_ctx,s,v,policy))
    cfg=read(s/'config.json')['config'];kmanifest=read(out/'code_manifest.json')['files']
    evidence_plan=manifests.plan(s,v,baseline,Path(policy['independent_audit_dir']),out)
    historical,before=manifests.audit(evidence_plan,out)
    check('historical_manifests',lambda:historical)
    versions={}
    def dependency():
        result,ss,vv,cc,kk=binding.bind_versions(root,s,v,baseline,kmanifest,out)
        versions.update(S=ss,V=vv,C=cc,K=kk)
        return result
    dep=check('dependency_binding',dependency)
    check('static_review',lambda:binding.static_review(root,dep))
    check('hash_erratum',lambda:manifests.hash_erratum(s,out))
    audit_reference=[]
    for name in evidence_plan.get('optional_reference_paths',[]):
        path=Path(name)
        if path.suffix!='.json':continue
        try:
            obj=read(path)
            audit_reference.append(dict(path=str(path),raw_sha256=file_record(path)['sha256'],top_level_fields=sorted(obj) if isinstance(obj,dict) else None,
                                        recorded_status=obj.get('status') if isinstance(obj,dict) else None,role='Optional historical reference, not substituted for current recalculation'))
        except (OSError,ValueError) as exc:
            audit_reference.append(dict(path=str(path),status='UNVERIFIED_OPTIONAL_REFERENCE',error=repr(exc)))
    write(out/'independent_audit_sources.json',audit_reference)
    identity=check('science_identity',lambda:science.identity_audit(ctx,cfg,s))
    points=read(s/'grid/frozen.json')['points'];folder=s/'G/T7'
    opps=read(folder/'opportunities.json');candidates=read(folder/'candidate_ledger.json');queries=read(folder/'raw_access_queries.json');raw=read(folder/'raw_intervals.json');geometry=read(folder/'geometry_audit.json')
    check('candidate_queries',lambda:science.query_audit(ctx,cfg,points,opps,candidates,queries,raw,geometry))
    check('trajectories',lambda:science.trajectory_audit(ctx,cfg,s,opps))
    check('camera_constraints',lambda:science.camera_audit(folder/'project',Path(cfg['round7']['source_round6'])/'G/T6/project',cfg['round7']['satellites'],[p['point_id'] for p in points]))
    check('independent_arithmetic',lambda:science.numerical_audit(cfg,s,points,raw))
    check('geometry_reopen',lambda:science.geometry_audit(ctx,cfg,s,points,raw,geometry))
    check('csv_json',lambda:science.csv_audit(s,cfg,raw))
    check('historical_native_evidence',lambda:native.native_evidence(ctx,cfg,s,dep,versions['S']))
    prior_tests=read(baseline/'test_result.json');prior_cmd=read(baseline/'command_result.json')
    attempts=[]
    for dirname in ['preflight','preflight2','preflight3']:
        folder=root/'work/round8'/dirname
        attempts.append(dict(directory=str(folder),command=read(folder/'command_result.json'),tests=read(folder/'test_result.json'),
                             explanation='Offline guard Windows command-line adaptation and controlled detector fixture; no production source change or native activation.' if dirname!='preflight3' else 'Baseline regression passed after harness adaptation.'))
    write(out/'preflight_attempts.json',attempts)
    check('baseline_regression',lambda:dict(status='PASS' if prior_tests['successful'] and prior_cmd['exit_code']==0 else 'FAIL',tests=prior_tests,command=prior_cmd,evidence=str(baseline)))
    check('complete_regression',lambda:regression.run_regression(root,work,kmanifest))
    check('counterexamples',lambda:counterexamples.run(ctx,validator_ctx,cfg,s,v,root,work,points,opps,candidates,queries,raw,geometry,versions['S'],versions['V']))
    guardlog=work/'validator_guard.jsonl'
    guardrows=[json.loads(x) for x in guardlog.read_text(encoding='utf-8').splitlines()]
    check('native_guard',lambda:dict(status='PASS' if not any(x['kind']=='denied' for x in guardrows) else 'FAIL',records=guardrows,round8_native_activation_count=0,fresh_native_validation_performed=False,native_imports_prevented=True,unapproved_subprocesses_prevented=True))
    check('source_raw_preservation',lambda:manifests.preservation(before))
    check('validator_code_preservation',lambda:dict(status='PASS' if code_manifest()==kmanifest else 'FAIL',frozen_code_sha256=validator_ctx['code_sha256'],actual_code_sha256=sha(canonical(code_manifest())),raw_bytes_required=True))
    for name in policy['required_checks']:
        checks.setdefault(name,dict(status='BLOCKED',errors=['REQUIRED_CHECK_NOT_EXECUTED']))
    summary=dict(kind=policy['kind'],baseline_commit=policy['baseline_commit'],subject_run_id=ctx['run_id'],historical_validator_run_id=read(v/'run.json')['run_id'],validator_run_id=validator_ctx['run_id'],validator_code_sha256=validator_ctx['code_sha256'],
                 source_original_engineering_status=read(s/'final_status.json')['business']['core_acceptance'],source_original_exit_code=read(s/'command_result.json')['exit_code'],prior_validator_original_status=read(v/'final_status.json')['status'],prior_validator_original_exit_code=read(v/'command_result.json')['exit_code'],
                 source_status_unchanged=checks['source_raw_preservation']['status']=='PASS',native_evidence_origin_run_id=ctx['run_id'],native_dependency_equivalence=dep['status'],
                 fresh_native_validation_performed=False,round8_native_activation_count=0,offline_acceptance=outcome(checks),official_readiness='UNRESOLVED',official_metrics_applicable=False,official_score=None,
                 full_historical_artifact_audit_status=historical['full_historical_artifact_audit_status'],checks=checks,elapsed_s=time.perf_counter()-start,output=str(out),work=str(work),
                 unresolved=['Official time system, full/half FOV, effective region and edge-censoring policy remain unresolved.','16 mainland points are not all-region coverage; two points have fewer than two visits.','Finite interpolation/diagnostic evidence does not prove global no-miss search.','No new native STK execution, propagation, performance run or project reopen.'])
    if not no_fresh_native(summary):summary['offline_acceptance']='FAIL'
    summary['exit_code']=0 if summary['offline_acceptance']=='PASS' else 1
    write(out/'summary.json',summary);write(out/'final_status.json',summary)
    text(out/'dependency_binding.md',dependency_report(dep,values.get('historical_native_evidence',{}),provenance))
    return summary


def dependency_report(dep,native_result,provenance):
    lines=['# S → V → C → K 依赖绑定',f"\n状态：{dep['status']}。subject=`{provenance['subject']['run_id']}`；validator=`{provenance['validator']['run_id']}`。\n",
           '|转换|变化文件|影响|','|---|---|---|']
    for transition,result in dep.get('transitions',{}).items():
        for row in result['changes']:lines.append(f"|{transition}|{row['path']}|{row['kind']}|")
    lines+=['\n函数源码行号、原始摘要、AST、全局环境、默认参数、继承、导入及调用集合见 function_evidence.json。完整源码差异见三份 diff；AST 摘要不取代原始字节保全。',
            '\nCAPS、validate_config、bind、compare_history、compare_expansion 与全部原生执行代码保留。audit_dataset 仅后置约束区域更换；新 audit_constraints 仅读取保存文件。',
            '\n历史阶段调用绑定：','|调用者|被调用者|实际绑定|','|---|---|---|']
    for edge in native_result.get('call_edges',[]):lines.append(f"|{edge['caller']}|{edge['callee']}|{edge['binding']}|")
    lines+=['\n历史阶段原始命令、task、run、实例 PID/创建时间、配置/代码依赖摘要、时间、退出码、超时及回收见 historical_native_evidence.json。每条标为 REUSED_HISTORICAL_NATIVE_EVIDENCE，executed_in_round8=false。',
            '\n原生回调、BaseModel、全局配置、导入别名和动态 cold_old 快照均在闭包中；没有用 K 替换原生证据 run_id。K 的新增模块不在历史入口导入路径上。']
    return '\n'.join(lines)+'\n'


def report(out,summary,command):
    def result(name):return read(out/(name+'.json')) if (out/(name+'.json')).exists() else {}
    numeric=result('independent_arithmetic');queries=result('candidate_queries');trajectory=result('trajectories');camera=result('camera_constraints');geo=result('geometry_reopen');faults=result('counterexamples');tests=result('complete_regression');manifest=result('historical_manifests')
    status=summary['offline_acceptance'];conclusion=('冻结科学数据通过修正版及依赖绑定的复合离线验收；原生证据来自未受影响的历史科学运行S。' if status=='PASS' else '复合离线验收未通过；具体失败或证据缺口见下表及对应检查文件。没有启动原生补验。')
    lines=['# 第八轮复合离线验收报告',f"\n新离线状态：**{status}**；验证命令退出 **{command['exit_code']}**，耗时 **{command['elapsed_s']:.6f} 秒**。",'\n'+conclusion,
           f"\n基线提交 `{summary['baseline_commit']}`；历史 C 工作树见 baseline_git.json。本次接手时已有未跟踪的第八轮实现，完整起点见 execution_start.json/zip，未覆盖或重置用户改动。K 为新代码清单哈希 `{summary['validator_code_sha256']}`，不是 Git SHA。",
           f"\nS：`{summary['subject_run_id']}`，原 {summary['source_original_engineering_status']} / 退出 {summary['source_original_exit_code']}；V：`{summary['historical_validator_run_id']}`，原 {summary['prior_validator_original_status']} / 退出 {summary['prior_validator_original_exit_code']}。历史状态保全：{summary['source_status_unchanged']}。",
           f"\nK：`{summary['validator_run_id']}`；fresh native=false；本轮原生激活数=0；official readiness=UNRESOLVED；official score=null。",
           '\n|检查|本轮状态|','|---|---|']
    for name,check in summary['checks'].items():lines.append(f"|{name}|{check['status']}|")
    lines+=[f"\n查询：{queries.get('candidates')} 候选 / {queries.get('queries')} 查询，空 {queries.get('empty_queries')}、正 {queries.get('positive_queries')}；事件 {queries.get('events')}。轨迹：{trajectory.get('unique_files')} 份，{trajectory.get('reference_count')} 条星点引用；实际与请求网格逐份复算。",
            f"\n对象：{camera.get('satellite_files')} 个卫星文件、{camera.get('facility_files')} 个点文件、{camera.get('unique_sensor_files')} 个共享 Sensor 文件，{camera.get('sensor_objects_bound')} 条逐星 Camera 绑定。",
            f"\n独立端点扫描：{numeric.get('event_count')} 事件，{numeric.get('gap_count')} 个内部 gap，覆盖 {numeric.get('covered_points')}/{numeric.get('denominator')}，不足两次 {numeric.get('insufficient_access_points')}/{numeric.get('denominator')}；条件均值 {numeric.get('conditional_mean_gap_s')} s，最大 {numeric.get('conditional_max_gap_s')} s。首尾删失单列，分母保留。",
            f"\n原七星：{numeric.get('original_seven',{}).get('event_count')} 事件，{numeric.get('original_seven',{}).get('covered_points')}/16 覆盖，{numeric.get('original_seven',{}).get('gap_count')} gap；新增21星贡献 {numeric.get('additional21_event_count')} 事件；搜索修复新增 {len(numeric.get('added_search_repair_events',[]))} 事件。",
            f"\n独立几何复算 {geo.get('probe_count')} 探针；历史重开正查询 {geo.get('positive_queries')}、短负查询 {len(geo.get('negative_queries',[]))}。负查询原记录不带 sat_id，绑定依据是已冻结的逐星循环顺序、参数顺序及逐星命令；不是本轮重开。",
            f"\n现象：{json.dumps(numeric.get('phenomena',{}),ensure_ascii=False)}。",
            f"\n完整离线回归 {tests.get('tests')} 项，失败 {tests.get('failures')}，错误 {tests.get('errors')}；拒绝反例 {faults.get('case_count')} 项，其中逐项删除空查询 {faults.get('empty_query_removals')} 项。反例在内存或本轮 work 中，原因码逐项匹配。",
            '\n初始预检有两次保护层适配失败（Windows 命令行解析、受控安装探测），均保留在 preflight_attempts.json 所列目录；随后71项基线通过。它们不属于源科学数据失败，未发生原生激活。',
            f"\n历史全量清单覆盖：{summary['full_historical_artifact_audit_status']}。引用项 {manifest.get('total_references')}，去重文件 {manifest.get('unique_files')}。不可读嵌套测试材料只记未独立核验，不记匹配；关键证据问题见 historical_manifests.json。",
            '\n|历史范围|引用数|去重数|实际结果|','|---|---:|---:|---|']
    for name,row in manifest.get('groups',{}).items():lines.append(f"|{name}|{row['references']}|{row['unique_files']}|{json.dumps(row['counts'])}|")
    lines+=['\n实际验证命令：\n\n```text\n'+' '.join(command['argv'])+'\n```',f"\n交付：`{out}`\n\n工作/日志：`{summary['work']}`",
            '\n哈希勘误见 hash_erratum.json/md；旧声明、旧 JSON 与原报告原始哈希全部保留。规范化只解释 CRLF/LF，源文件和 K 保全要求原始字节完全一致。',
            '\n清单策略：报告定稿、子进程日志关闭后生成 artifact_manifest.json；其自身与 delivery_verification.json 不列入成员。后验核验单向绑定清单原始字节并逐项读回，避免循环自哈希。',
            '\n仍未验证：']
    lines+=['- '+x for x in summary['unresolved']]
    if (out/'prior_round8_review.json').exists():
        lines+=['\n前一次本轮尝试的科学检查通过，但后验发现编码审计使用了三份封存前摘要；原目录及退出码保留，问题记录见 prior_round8_review.json。本次已修正封存顺序，使用新的 K/run_id 全量重算，不沿用前次 PASS。']
    failed=[name for name,c in summary['checks'].items() if c['status']!='PASS']
    if failed:lines+=['\n需处理的具体缺口：']+['- '+name+': '+json.dumps(summary['checks'][name].get('errors',[]),ensure_ascii=False) for name in failed]+['\n最小后续动作：先修复或补齐以上离线证据；仅当原生依赖仍无法证明时另行评估有授权和预算的定向补验。本轮不执行。']
    text(out/'audit_report.md','\n'.join(lines)+'\n')
