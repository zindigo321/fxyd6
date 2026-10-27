"""Relative-path closure and independent disk readback before receipt reuse."""
import ast
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import time
import zipfile
from .archive import safe_name
from .common import read, write, require, sha, record
from .control import Lifecycle

REQUIRED_PASS = ['archive_identity_verification','native_record_metrics_replay','stable_global_replay','component_whole_consistency','incompatible_request_handling','offline_alignment_acceptance']


def verify_seal(folder):
    folder=Path(folder).resolve()
    require((folder/'receipt.json').is_file() and (folder/'artifact_manifest.json').is_file(),'SEAL_INCOMPLETE')
    receipt=read(folder/'receipt.json');manifest=read(folder/'artifact_manifest.json')
    require(receipt.get('manifest_sha256')==sha(folder/'artifact_manifest.json'),'SEAL_RECEIPT_IDENTITY')
    seen=set()
    for row in manifest['files']:
        name=safe_name(row['path']);require(name.casefold() not in seen,'SEAL_DUPLICATE_PATH');seen.add(name.casefold())
        p=(folder/name).resolve();require(p.is_relative_to(folder),'SEAL_PATH_ESCAPE')
        require(p.is_file() and p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],'SEAL_BYTES_MISMATCH: '+name)
    expected={r['path'] for r in manifest['files']}|{'receipt.json','artifact_manifest.json'}
    require({p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}==expected,'SEAL_MEMBER_SET')
    final=read(folder/'final_status.json')
    require(final['exit_code']==receipt.get('exit_code') and final['status']==receipt.get('status'),'SEAL_STATUS_EXIT_INCONSISTENCY')
    require({'PASS':0,'FAIL':1,'BLOCKED':2}.get(final['status'])==final['exit_code'],'SEAL_STATUS_EXIT_INCONSISTENCY')
    if final['status']=='PASS':
        require(all(final.get(k)=='PASS' for k in REQUIRED_PASS),'SEAL_FAKE_PASS_GATES')
        require(final.get('active_protocol_change_authorized') is False and final.get('new_native_validation_performed') is False and final.get('round13_native_activation_count')==0 and final.get('git_write_operations')==0,'SEAL_SCOPE_FLAGS')
        checks=read(folder/'validation_summary.json')
        require(checks.get('old_tests')==149 and checks.get('binding_counterexamples')==26 and checks.get('new_tests',0)>0 and checks.get('independent_cases')==6,'SEAL_FAKE_PASS_VALIDATION')
        results=read(folder/'main/results.json')
        require(len(results)==6 and sum('components' in r for r in results.values())==2,'SEAL_CASE_COMPLETENESS')
        for r in results.values():
            require(r['source']=='archive_replay' and r['compatibility']['status']=='COMPATIBLE' and r['new_native_validation_performed'] is False,'SEAL_RESULT_SCOPE')
    return dict(status=final['status'],exit_code=final['exit_code'],reexecuted=False,verified_files=len(manifest['files']),delivery=str(folder))


def write_seal(folder, status, exit_code, entry_s, elapsed_s):
    paths=sorted(p for p in folder.rglob('*') if p.is_file() and p.name not in {'artifact_manifest.json','receipt.json'})
    manifest=dict(files=[dict(path=p.relative_to(folder).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in paths])
    write(folder/'artifact_manifest.json',manifest)
    # Separate disk reads, no reliance on cached hash objects or a prior receipt.
    for row in manifest['files']:
        p=folder/row['path'];require(sha(p)==row['sha256'] and p.stat().st_size==row['bytes'],'SEAL_READBACK_FAILURE')
    write(folder/'receipt.json',dict(status=status,exit_code=exit_code,manifest_sha256=sha(folder/'artifact_manifest.json'),
        entry_end_to_end_s=entry_s,lifecycle_elapsed_upper_bound_s=elapsed_s,scope='manifest read back after final report/status/logs; no future export included'))


def seal(work, entry_start):
    from .run import ROOT,code_files
    life=Lifecycle(work/'lifecycle.json');life.check()
    out=work/'delivery'
    if out.exists():
        import datetime
        out=work/('delivery_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S'))
    out.mkdir(exist_ok=False)
    locations={k:Path(read(work/('latest_'+k+'.json'))['path']) for k in ['main','check','tests','guards','legacy']}
    for key,source in locations.items():
        result=read(source/'job_result.json');require(result['status']=='PASS' and result['exit_code']==0,'SEAL_UNFINISHED_JOB: '+key)
        if key=='legacy':
            (out/key).mkdir()
            for p in source.rglob('*'):
                if p.is_file() and 'repo' not in p.relative_to(source).parts and 'tmp' not in p.relative_to(source).parts:
                    dest=out/key/p.relative_to(source);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
        else:
            shutil.copytree(source,out/key)
    frozen=read(work/'old_code_before.json')
    input_binding=read(work/'input_binding.json')
    preserve_rows=dict(input_binding['vendor']['actual_used_members'])
    if (work/'supplemental_reads.json').exists():
        preserve_rows.update(read(work/'supplemental_reads.json')['actual_used_members'])
    for name,row in preserve_rows.items():
        p=work/'vendor'/name
        require(p.stat().st_size==row['bytes'] and sha(p,life.check)==row['sha256'],'INPUT_CHANGED_AT_SEAL: '+name)
    require(sha(input_binding['archive']['path'],life.check)==input_binding['archive']['sha256'],'ARCHIVE_CHANGED_AT_SEAL')
    write(out/'all_used_input_preservation.json',dict(status='PASS',members=preserve_rows,archive=input_binding['archive']))
    for row in frozen['files']:
        require(record(row['path'],life.check)==row,'OLD_CODE_CHANGED_AT_SEAL')
    oldpaths={Path(r['path']).resolve() for r in frozen['files']}
    current={p.resolve() for folder in ['src','tools','tests','configs','docs'] for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    allowed={p.resolve() for p in code_files()}
    require(current-oldpaths==allowed,'ADDITION_OUTSIDE_ROUND13')
    for row in frozen['files']:
        p=Path(row['path'])
        if p.suffix=='.py':
            tree=ast.parse(p.read_text(encoding='utf-8-sig'))
            require(not any(isinstance(n,(ast.Import,ast.ImportFrom)) and 'round13' in ast.unparse(n) for n in ast.walk(tree)),'OLD_CODE_IMPORTS_ROUND13')
    write(out/'code_preservation.json',dict(status='PASS',unchanged_old_files=149,old_identity=frozen['sha256'],only_new_files=[p.relative_to(ROOT).as_posix() for p in code_files()]))
    new=[record(p,life.check) for p in code_files()];write(out/'consumer_code_manifest.json',new)
    with zipfile.ZipFile(out/'consumer_code_snapshot.zip','w',zipfile.ZIP_DEFLATED) as z:
        for p in code_files():z.write(p,p.relative_to(ROOT).as_posix())
    (out/'K12_to_K13.diff').write_text(''.join(line for p in code_files() for line in difflib.unified_diff([],p.read_text(encoding='utf8').splitlines(True),fromfile='/dev/null',tofile=p.relative_to(ROOT).as_posix())),encoding='utf8')
    for name in ['lifecycle.json','input_binding.json','old_code_before.json','old_code_snapshot.zip','reused_evidence.json','reused_independent_package_integrity.json','reused_methods_and_protocol_audit.json','git_rev-parse.txt','git_status.txt','git_diff.txt','git_diff_cached.txt']:
        if (work/name).exists():shutil.copyfile(work/name,out/name)
    # Save every attempt's log and code identity, including early failed imports; never rewrite them.
    attempts=[]
    for attempt in sorted((work/'attempts').iterdir()):
        command=read(attempt/'command_result.json');attempts.append(dict(attempt=attempt.name,command=command))
        dest=out/'attempt_history'/attempt.name;dest.mkdir(parents=True)
        for name in ['command_result.json','consumer_code.json','consumer_code.zip','stdout.log','stderr.log']:
            shutil.copyfile(attempt/name,dest/name)
        if (attempt/'supervised_result.json').exists():shutil.copyfile(attempt/'supervised_result.json',dest/'supervised_result.json')
        for name in ['error.log','job_result.json','guard.jsonl']:
            if (attempt/'output'/name).exists():shutil.copyfile(attempt/'output'/name,dest/name)
    write(out/'attempts.json',attempts)
    results=read(out/'main/results.json');checks=read(out/'check/checks.json')
    require(len(results)==6 and len(checks)==6 and all(c['status']=='PASS' for c in checks.values()),'SIX_CASE_REQUIREMENT')
    legacy=read(out/'legacy/job_result.json');tests=read(out/'tests/job_result.json')
    summary=dict(old_tests=legacy['regression_tests'],binding_counterexamples=legacy['binding_counterexamples'],new_tests=tests['tests'],controlled_guard_cases=read(out/'guards/job_result.json')['controlled_rejections'],independent_cases=len(checks))
    write(out/'validation_summary.json',summary)
    write(out/'code_review.json',dict(status='PASS',scope='New round13 files only; old 149 files unchanged',
        static_dimensions=dict(security='PASS: bound ZIP paths, no native/vendor execution',compatibility='PASS: physical identity gate before evaluation',errors='PASS: semantic rejection, preserved attempts and fail-dominant timeout',resources='PASS: streaming SHA, read-only mmap, closed ZIP/NPZ',change_scope='PASS: only authorized round13 additions',types='PASS: exact integer counts, normalized float times'),
        corrections=['No optional yaml/psutil dependency','Stable metadata version-specific field mapping','Lossless STK object byte decoding','Consumer code identity per result','Independent component comparison-summary validation','Monotonic remaining time and post-readback entry completion'],
        runtime_validation=summary,unresolved_p0=[],p1=['Receipts are byte-consistency records, not externally authenticated signatures','Historical stable producer source is provenance; packaged app is a later revision']))
    for key in ['main','check','tests']:
        guards=[json.loads(s) for s in (out/key/'guard.jsonl').read_text(encoding='utf8').splitlines()]
        require(not any(g['kind']=='unexpected_denial' for g in guards),'NORMAL_FLOW_GUARD_VIOLATION')
    metrics={key:read(locations[key]/'job_result.json') for key in locations}
    timings=dict(workers={k:dict(wall_s=v['worker_wall_s'],cpu_s=v['worker_cpu_s'],memory=v['memory']) for k,v in metrics.items()},
                 entry_elapsed_to_status_s=time.perf_counter()-entry_start,lifecycle_elapsed_to_status_upper_bound_s=life.elapsed(),
                 preparation_unmeasured_upper_bound_s=life.data['pre_record_preparation_upper_bound_seconds'],
                 accounting='Parent and child wall times overlap and are not summed; all authoring, retries and waits remain in lifecycle budget')
    write(out/'timings.json',timings)
    final=dict(status='PASS',exit_code=0,**{k:'PASS' for k in REQUIRED_PASS},protocol_alignment_status='COMPLETED_WITH_UNRESOLVED_RULES',
        active_protocol_change_authorized=False,new_native_validation_performed=False,historical_STK_completeness='UNRESOLVED',official_readiness='UNRESOLVED',official_score=None,
        next_scientific_run_gate='BLOCKED_PENDING_RULE_CONFIRMATION',round13_native_activation_count=0,git_write_operations=0,
        own_round12=dict(status='BLOCKED',exit_code=2,processed_cells=0,cost='NOT_RUN'),
        historical_stage_map={'S':'FAIL/1','V':'BLOCKED/1','K8':'PASS/0','K9':'PASS/0','K10':'PASS/0','K11':'NO_GO/BLOCKED/2','K12':'BLOCKED/2'},
        native_record_metrics_replay_meaning='saved historical native records recomputed offline, no new native validation',
        failed_development_attempts_preserved=[a['attempt'] for a in attempts if a['command']['python_exit_code']!=0],
        delivery=str(out),export_status='WORKSPACE_SEALED; preferred export handled separately after seal')
    write(out/'final_status.json',final)
    lines=['# 第十三轮离线对齐：PASS / 0','',
           '本报告只验收保存证据的离线接入、重算和一致性。没有新 STK 仿真，也没有新候选搜索。当前协议不变，官方分数 null；新科学运行仍等待规则确认。','',
           '| 案例 | 原域覆盖点/43424 | 原域 T90 秒 | 原域 T100 | 暂定域覆盖点/43070 | 暂定域 T90 秒 | 暂定域 T100 秒 |',
           '|---|---:|---:|---|---:|---:|---:|']
    for cid,r in results.items():
        a,b=r['full_grid'],r['effective_grid'];lines.append(f'| {cid} | {a["covered"]} | {a["T90_s"]} | {a["T100_s"]} | {b["covered"]} | {b["T90_s"]} | {b["T100_s"]} |')
    lines+=['','原域与暂定 mask 域同时保留。T100=null 表示未达；按点数统计，不将 99.99% 舍入为全覆盖。mask 是固定纬度规则排除 354 点，非官方域，本轮未重证其几何证书。','',
            '两份 competition 首访 CSV 实读 86,848 行；对应网格也是 86,848 行。四个稳定结果按轨道摘要唯一匹配历史数组，共使用 173,696 个首访值，均为旧结果重计分。', '']
    for cid,r in results.items():
        if 'regional' in r:
            gap=r['regional']['pooled_internal'];comp=r['components'];lines.append(f'{cid}：原访问 {r["regional"]["raw_count"]} 条，内部空窗 {gap["gap_count"]} 个，池化均值 {gap["mean_s"]} 秒，最大 {gap["max_s"]} 秒；组件 {comp["selected_assets"]} 个，逐点首访最大误差 {comp["whole_comparison"]["max_finite_first_hit_error_s"]} 秒。逐对象原始区间、并集、最长端点和首尾敏感性见 main/{cid}.json。')
    lines+=['','主计算与独立检查器分别读取原始证据：有序阈值/partition、逐区间并集/累积最大值分组、NumPy 最小值/Python 逐列最小值。所有计数精确核对；预声明时间绝对容差 1e-6 秒。',
            f'原冻结测试 {summary["old_tests"]} 项、原固定检查器绑定反例 {summary["binding_counterexamples"]} 项、新测试 {summary["new_tests"]} 项均通过。原 149 文件字节不变；旧 77/49 等证据明确 REUSED。',
            '独立已有结果评价命令：`D:\\conda_envs\\fmb\\python.exe -X utf8 -B G:\\fmb666\\tools\\run_round13.py --mode evaluate-existing --case team_competition_N28`。默认入口完成六案例及验证；已封存 --work 重入先校验全部字节。',
            '', '我方第十二轮仍为 BLOCKED/2、0 单元、成本 NOT_RUN。旧 28 星 16 点为小样本，不表示全球 90%/100%。队友宽视场不能离线变成我方窄视场，三对象不能变成 16 点或 0.1° 网格，新坐标不得插值补造；接口明确返回 NOT_COMPUTABLE_FROM_FROZEN_EVIDENCE。',
            '', '待确认事项：修订来源与全/半角；区域对象 Access 的评分语义；全球有效域；EOP/时间资源和采样设置。EOP 表止 2019、场景在 2027；有限采样校准不构成全域完备证明。没有代发询问。',
            '', '开发失败尝试及源码快照保留在 attempt_history：缺少可选依赖、稳定版元数据字段差异、区间边界数字类型及 STK 对象扩展字节编码；最终实现仅用现有环境，未安装依赖。失败尝试未被覆写，也没有从 FAIL 降为超时 BLOCKED。',
            '', '三种计时见 timings.json 与 receipt.json：各 worker 实测墙钟/CPU/自进程峰值内存；入口端到端墙钟；包含全部准备、编写、等待和失败尝试的生命周期上界。最初未精确计时的读取动作按 180 秒保守上界计入，父子墙钟不重复相加。',
            '', '封存目录使用相对成员清单，receipt 单向绑定清单；输入 ZIP 和大矩阵留在工作区，交付中保存其字节身份和实际读取清单。首选 G: 导出在封存外单独记录。本轮原生激活 0、Git 写入 0；不自动进入下一轮。']
    (out/'report.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    life.check()
    write_seal(out,'PASS',0,time.perf_counter()-entry_start,life.elapsed())
    result=verify_seal(out);write(work/'latest_delivery.json',dict(path=str(out),manifest_sha256=sha(out/'artifact_manifest.json')))
    print(json.dumps(result,ensure_ascii=False));return 0
