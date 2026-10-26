"""Orchestrate bound inputs, isolated candidate workers and post-seal checks."""
import ast
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
import unittest
from pathlib import Path
from src.round2.evidence import code_manifest
from src.round8.common import KEYS, canonical, file_record, outcome, read, sha, text, write
from src.round9.regression import run_regression
from . import binding, cases, evidence, official, prototype, retention
from .resources import usage


def configure_guard(work, out, log, entry, allowed_reads=None):
    tmp=work/'tmp';tmp.mkdir(parents=True,exist_ok=True)
    os.environ.update(ROUND10_WRITE_ROOTS=json.dumps([str(work),str(out)]),ROUND10_GUARD_LOG=str(log),ROUND10_VALIDATOR_ENTRY=str(entry),
                      PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8',TMP=str(tmp),TEMP=str(tmp),MPLCONFIGDIR=str(work/'mpl'))
    if allowed_reads:os.environ['ROUND10_READ_WHITELIST']=json.dumps(allowed_reads)
    else:os.environ.pop('ROUND10_READ_WHITELIST',None)
    from .guard import install
    install()


def static_review(root):
    errors=[];rows=[]
    forbidden={'Dispatch','DispatchEx','GetActiveObject','CreateObject','CoInitialize','supervise','ShellExecute','WinExec','eval','exec','Model','Propagate','ComputeAccess'}
    paths=list((root/'src/round10').glob('*.py'))+list((root/'tests').glob('test_round10*.py'))+[root/'tools/run_round10.py']
    for p in paths:
        tree=ast.parse(p.read_text(encoding='utf-8'),type_comments=True)
        bad=sorted({ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n,ast.Call) and ast.unparse(n.func).rsplit('.',1)[-1] in forbidden})
        if bad:errors.append(dict(path=str(p),calls=bad))
        rows.append(dict(file=file_record(p),forbidden_calls=bad))
    # Candidate generator has no dependency on verifier/event statistics modules.
    candidate_tree=ast.parse((root/'src/round10/prototype.py').read_text(encoding='utf-8'))
    imports=[ast.unparse(n) for n in ast.walk(candidate_tree) if isinstance(n,(ast.Import,ast.ImportFrom))]
    if any('retention' in s or 'science' in s or 'production' in s for s in imports):errors.append('CANDIDATE_DATAFLOW_IMPORT')
    return dict(status='FAIL' if errors else 'PASS',errors=errors,files=rows,candidate_imports=imports)


def child(argv, work, name, timeout, env=None):
    start=time.perf_counter();timed_out=False
    with (work/(name+'.stdout.log')).open('wb') as stdout,(work/(name+'.stderr.log')).open('wb') as stderr:
        try:proc=subprocess.run(argv,cwd=Path(__file__).resolve().parents[2],env=env,stdout=stdout,stderr=stderr,timeout=timeout);code=proc.returncode
        except subprocess.TimeoutExpired:code=124;timed_out=True
    return dict(argv=argv,exit_code=code,timeout=timed_out,timeout_limit_s=timeout,wall_s=time.perf_counter()-start,
                stdout=file_record(work/(name+'.stdout.log')),stderr=file_record(work/(name+'.stderr.log')))


def guard_probe(result_path):
    rows=[]
    events=[('native_import','import',('win32com',None,None,None,None),'ROUND10_NATIVE_IMPORT'),
            ('native_process','subprocess.Popen',('STK.exe',['STK.exe'],None,None),'ROUND10_UNAPPROVED_SUBPROCESS'),
            ('old_source_write','open',(str(Path(__file__).resolve().parents[2]/'configs/round7.json'),'w',os.O_WRONLY),'ROUND10_WRITE_OUTSIDE_ROUND10')]
    if os.environ.get('ROUND10_READ_WHITELIST'):
        events.append(('holdout_read','open',(str(Path(__file__).resolve().parents[2]/'work/round10/forbidden_events.json'),'r',0),'ROUND10_CANDIDATE_FORBIDDEN_READ'))
    for name,event,args,reason in events:
        try:sys.audit(event,*args);actual='NOT_REJECTED'
        except PermissionError as exc:actual=str(exc)
        rows.append(dict(case=name,expected=reason,actual=actual,status='PASS' if actual==reason else 'FAIL',simulated_audit_event_only=True))
    write(result_path,dict(status='PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL',cases=rows,native_activations=0))
    return 0 if all(r['status']=='PASS' for r in rows) else 1


def candidate_experiment(spec, screen, cfg, out, work, source, subject):
    projected=prototype.project_screening(screen);projection=work/'screening_projection.json';write(projection,projected)
    protocol_path=out/'experimental_protocol.json';protocol=read(protocol_path)
    inputs=[file_record(source/'config.json'),file_record(source/'grid/frozen.json'),file_record(projection),file_record(protocol_path)]
    trajectories={p['trajectory']['path']:p['trajectory'] for p in projected['pairs']}
    candidate_spec=dict(code_sha256=spec['validator']['code_sha256'],protocol=inputs[3],config=inputs[0],grid=inputs[1],screening=inputs[2],
                        source_identity={k:subject[k] for k in KEYS},output=str(out/'candidates'),allowed_reads=[r['path'] for r in inputs]+list(trajectories))
    resolved=dict(protocol=file_record(protocol_path),source_screening=file_record(source/'G/T7/opportunities_screened.json'),projected_fields='src.round10.prototype.project_screening',
                  candidate_input_whitelist=inputs+list(trajectories.values()),padding_s=cfg['round3']['search']['candidate_half_window_s'],merge_tolerance_s=0.,
                  coarse_cross_half_deg=2*cfg['camera']['cross_half_deg'],fine_cross_half_deg=cfg['camera']['cross_half_deg'],
                  point_identity=read(source/'grid/frozen.json')['point_set_sha256'],satellites=cfg['round7']['satellites'],
                  frozen_before_candidate_start_epoch=time.time(),events_allowed=False)
    write(out/'resolved_experimental_design.json',resolved)
    holdout=work/'isolation_external_holdout.json';write(holdout,dict(events=[]));holdout_before=file_record(holdout)
    commands=[];entry=Path(spec['root'])/'tools/run_round10.py'
    for attempt,destination in [('candidate',out/'candidates'),('isolation_replay',work/'isolation_replay')]:
        if attempt=='isolation_replay':write(holdout,dict(events=[dict(record_id='deliberate_changed_verification_table',start=-100.,stop=999999.)]))
        cs=dict(candidate_spec,output=str(destination));path=work/(attempt+'_spec.json');write(path,cs)
        candidate_work=work/(attempt+'_worker');candidate_work.mkdir();destination.mkdir()
        env=dict(os.environ,ROUND10_READ_WHITELIST=json.dumps(cs['allowed_reads']+[str(path)]),ROUND10_CANDIDATE_WORK=str(candidate_work))
        command=child([sys.executable,'-B',str(entry),'--candidate-worker','--run-spec',str(path)],work,attempt,600,env)
        commands.append(command)
        if command['exit_code']!=0:raise ValueError('CANDIDATE_WORKER_FAILED:'+str(command))
    comparisons=[]
    for name in ['candidate_decisions.jsonl','candidate_windows.json','coverage_ledger.json','selection.json','bound_provenance.json']:
        first=file_record(out/'candidates'/name);second=file_record(work/'isolation_replay'/name)
        comparisons.append(dict(file=name,first=first,second=second,identical=first['sha256']==second['sha256']))
    isolation=dict(status='PASS' if all(r['identical'] for r in comparisons) else 'FAIL',external_holdout_before=holdout_before,
                   external_holdout_after=file_record(holdout),changed_table_outside_candidate_whitelist=True,
                   comparisons=comparisons,full_candidate_pipeline_rerun=True,commands=commands)
    write(out/'holdout_isolation.json',isolation)
    if isolation['status']!='PASS':raise ValueError('EVENT_TABLE_CHANGED_CANDIDATES')
    return read(out/'candidates/prototype_result.json'),projected,commands


def regression(root,work,manifest):
    result=run_regression(root,work,manifest)
    def flatten(suite):
        for test in suite:
            if isinstance(test,unittest.TestSuite):yield from flatten(test)
            else:yield test.id()
    # Discovery imports tests only; it does not invoke tests or native code.
    ids=list(flatten(unittest.defaultTestLoader.discover(str(root/'tests'))))
    baseline=[i for i in ids if not i.startswith('test_round10')];added=[i for i in ids if i.startswith('test_round10')]
    result.update(original_test_count=len(baseline),new_test_count=len(added),executed_test_ids=ids,
                  legacy_fixture='Existing unchanged src.round9.guard installs its pre-existing mock missing-STK detector in isolated test copies only; no new monkeypatch or change to old assertions/modules.')
    if len(baseline)!=108 or result['tests']!=len(ids) or result.get('skipped')!=0:result['status']='FAIL'
    return result


def validate(spec):
    start=time.perf_counter();work=Path(spec['work']);out=Path(spec['output']);root=Path(spec['root']);policy=spec['policy'];k9=Path(policy['k9_dir'])
    checks={};values={};commands=[];state={}
    protocol=read(out/'experimental_protocol.json');deadline=protocol['freeze_epoch']+protocol['total_budget_s']-protocol['prefreeze_preparation_charged_upper_bound_s']
    def check(name,call):
        now=time.perf_counter();print('CHECK',name,flush=True)
        if time.time()>deadline:r=dict(status='BLOCKED',errors=['CUMULATIVE_BUDGET_EXHAUSTED'])
        else:
            try:r=call()
            except (FileNotFoundError,PermissionError,subprocess.TimeoutExpired) as exc:r=dict(status='BLOCKED',errors=[repr(exc)],traceback=traceback.format_exc())
            except Exception as exc:r=dict(status='FAIL',errors=[repr(exc)],traceback=traceback.format_exc())
        r['wall_s']=time.perf_counter()-now
        if time.time()>deadline and r['status']=='PASS':r.update(status='BLOCKED',errors=['CUMULATIVE_BUDGET_EXCEEDED'])
        checks[name]=dict(status=r['status'],errors=r.get('errors',[]),wall_s=r['wall_s']);values[name]=r;write(out/(name+'.json'),r)
        print('RESULT',name,r['status'],round(r['wall_s'],3),flush=True);return r
    check('static_review',lambda:static_review(root))
    def freeze():
        result,seen,screen,cfg=evidence.frozen_sources(policy,root,out);state.update(seen=seen,screen=screen,cfg=cfg)
        oldp=read(k9/'config.json')['policy'];state['source']=Path(oldp['source_dir']);state['subject']=read(state['source']/'run.json')
        return result
    check('k9_freeze',freeze)
    def bind():
        result,rerun=binding.bind(k9,root,read(out/'code_manifest.json')['files'],out,work);state['binding_cases']=rerun
        if rerun['status']!='PASS':result.update(status='FAIL',errors=['BINDING_COUNTEREXAMPLES'])
        return result
    check('dependency_binding',bind)
    check('official_contract_review',lambda:official.review(k9,out))
    def prototype_run():
        result,projected,child_commands=candidate_experiment(spec,state['screen'],state['cfg'],out,work,state['source'],state['subject'])
        state['projected']=projected;commands.extend(child_commands);return result
    check('prototype_behavior_acceptance',prototype_run)
    def compare():
        result,cost,stats=retention.verify_and_compare(out/'candidates',state['source'],state['cfg'],state['projected'],out,state['subject']);state.update(cost=cost,stats=stats)
        expected=read(k9/'engineering_statistics.json')
        pairs=[('internal_mean_s','conditional_mean_gap_s'),('internal_max_s','conditional_max_gap_s')]
        if any(abs(stats[a]-expected[b])>1e-8 for a,b in pairs):result.update(status='FAIL',errors=['HISTORICAL_STATISTICS_MISMATCH'])
        return result
    if checks['prototype_behavior_acceptance']['status']=='PASS':check('historical_53_retention',compare)
    else:check('historical_53_retention',lambda:dict(status='BLOCKED',errors=['CANDIDATES_NOT_SEALED_HOLDOUT_NOT_READ']))
    check('regression',lambda:regression(root,work,read(out/'code_manifest.json')['files']))
    check('prototype_counterexamples',lambda:cases.run(out/'constructed_cases'))
    def protection():
        result=work/'guard_probe_result.json';log=work/'guard_probe.jsonl';entry=root/'tools/run_round10.py'
        env=dict(os.environ,ROUND10_GUARD_LOG=str(log),ROUND10_READ_WHITELIST=json.dumps([str(out/'experimental_protocol.json')]))
        command=child([sys.executable,'-B',str(entry),'--guard-probe','--result',str(result)],work,'guard_probe',30,env);commands.append(command)
        probe=read(result);normal_logs=[work/'validator_guard.jsonl',work/'candidate_worker/guard.jsonl',work/'isolation_replay_worker/guard.jsonl']
        records=[]
        for p in normal_logs:
            records.extend(json.loads(x) for x in p.read_text(encoding='utf-8').splitlines())
        denied=[r for r in records if r['kind']=='denied']
        return dict(status='PASS' if command['exit_code']==0 and probe['status']=='PASS' and not denied else 'FAIL',errors=denied,probe=probe,command=command,
                    normal_guard_records=records,round10_native_activation_count=0,fresh_native_validation_performed=False,
                    mechanism='Import/process/write auditing in validator and both candidate children. Exact data read whitelist in candidate children; native audit tests simulate events only.')
    check('native_guard',protection)
    check('source_preservation',lambda:evidence.preserve(list(state['seen'].values())))
    def preserve_code():
        current=code_manifest();expected=read(out/'code_manifest.json')['files']
        return dict(status='PASS' if current==expected else 'FAIL',expected_sha256=spec['validator']['code_sha256'],actual_sha256=sha(canonical(current)),raw_bytes=True)
    check('code_preservation',preserve_code)
    for name in ['static_review','k9_freeze','dependency_binding','official_contract_review','prototype_behavior_acceptance','historical_53_retention','regression','prototype_counterexamples','native_guard','source_preservation','code_preservation']:
        checks.setdefault(name,dict(status='BLOCKED',errors=['NOT_EXECUTED']))
    result=dict(offline_engineering_acceptance=outcome(checks),official_contract_review=values.get('official_contract_review',{}).get('official_contract_review','NOT_COMPLETED'),
                official_readiness='UNRESOLVED',official_score=None,prototype_behavior_acceptance=checks['prototype_behavior_acceptance']['status'],
                real_continuous_bound_coverage='UNRESOLVED_NO_VERIFIED_REAL_CONTINUOUS_BOUND',historical_53_retention=checks['historical_53_retention']['status'],
                candidate_cost_status=state.get('cost',{}).get('status','BLOCKED'),search_completeness_certification='UNRESOLVED',
                historical_coverage=values.get('k9_freeze',{}).get('historical_coverage','UNVERIFIED'),next_scientific_run_gate='BLOCKED',
                historical_statuses=values.get('k9_freeze',{}).get('historical_statuses',{}),
                fresh_native_validation_performed=False,round10_native_activation_count=0,git_write_operations=0,
                validator=spec['validator'],subject={k:state.get('subject',{}).get(k) for k in KEYS},checks=checks,work=str(work),output=str(out),
                worker_inner_wall_s=time.perf_counter()-start,resources=usage())
    result['exit_code']=0 if result['offline_engineering_acceptance']=='PASS' else 1
    write(out/'subtask_commands.json',dict(commands=commands,regression=values.get('regression',{}).get('argv'),regression_exit_code=values.get('regression',{}).get('exit_code')))
    write(out/'summary.json',result);return result


def report(out, summary, command):
    def optional(name):return read(out/name) if (out/name).exists() else {}
    cost=optional('candidate_cost_comparison.json');ret=optional('historical_53_retention.json');tests=optional('regression.json');stats=optional('engineering_statistics.json');proto=optional('prototype_behavior_acceptance.json');fixture=optional('prototype_counterexamples.json')
    lines=['# 第十轮离线原型验收', '',f"工程：{summary['offline_engineering_acceptance']}，退出码 {summary['exit_code']}。K10：{summary['validator']['code_sha256']}。",'',
      f"固定28星、16点、[0,604800]秒；全部448对建立单元台账。实际处理 {proto.get('coverage',{}).get('processed_cells')} 单元，UNKNOWN {proto.get('coverage',{}).get('unknown_cells')} 单元。真实连续界缺失，认证式拒绝0；候选由实际拟合决定及 UNKNOWN 范围逐项生成。",'',
      f"完整历史区间严格保留 {ret.get('strictly_retained')}/{ret.get('events')}；原候选/新增回退/未知域新增/未保留分类：{ret.get('comparison_categories')}。原型保留的回退依赖比例 {ret.get('fallback_fraction')}；UNKNOWN/混合来源：{ret.get('prototype_origins')}。这不能证明筛除效率或真实全域零漏检。",'',
      f"候选成本：旧口径及统一口径见 candidate_cost_comparison.json；旧并集 {cost.get('historical_unified',{}).get('union_pair_seconds')} 星点对秒，原型 {cost.get('prototype',{}).get('union_pair_seconds')}，增量 {cost.get('increment_pair_seconds')}，比值 {cost.get('ratio')}。占全部域 {cost.get('prototype_retention_fraction')}。原型候选 {cost.get('prototype',{}).get('merged_window_count')} 个，均未执行 Access，event_count=null。",'',
      '成本按每一星点对分别裁剪、padding、求并集后求和。UNKNOWN 部分为保守工作量上界；分项 padding 后可能重叠，不能相加。星点对秒数不是 STK 墙钟时间。瓶颈是缺少可认证的连续轨迹、姿态、boresight、地平线及根误差界。', '',
      f"回归实际执行 {tests.get('tests')} 项：原 {tests.get('original_test_count')} + 新 {tests.get('new_test_count')}；失败 {tests.get('failures')}、错误 {tests.get('errors')}、跳过 {tests.get('skipped')}。新拒绝反例 {fixture.get('counterexample_count')}，数值/行为构造 {fixture.get('numerical_fixture_count')}。原26项绑定反例实际重跑；原77项拒绝场景及49项空查询删除证据按 REUSED 保存。",'',
      f"固定科学基线：{stats.get('event_count')}事件、{stats.get('internal_gap_count')}内部gap、{stats.get('covered_points')}/{stats.get('point_denominator')}覆盖、{stats.get('insufficient_points')}点不足两次；原七星{stats.get('original_seven_events')}、新增21星{stats.get('additional21_events')}、修复新增{stats.get('search_repair_new_events')}。",'',
      f"内部均值/最大值 {stats.get('internal_mean_s')}/{stats.get('internal_max_s')} 秒（分母 {stats.get('internal_gap_count')}）；含首尾 {stats.get('edge_inclusive_mean_s')}/{stats.get('edge_inclusive_max_s')} 秒（分母 {stats.get('edge_inclusive_denominator')}）。仅描述固定事件的敏感性，不是官方指标。",'',
      '正式确认项见 organizer_questions.md：时间系统、视场/幅宽/姿态、网格分母、首尾及不足访问处理、1秒要求与合并、最终工况和接口。物理参数变化为 NOT_COMPUTABLE_WITH_FROZEN_EVIDENCE。官方 UNRESOLVED、score=null；真实连续界及搜索完备性 UNRESOLVED；下一科学运行门 BLOCKED。', '',
      '历史 S FAIL/1、V BLOCKED/1、K8 PASS/0、K9 PASS/0 保留；旧第八轮封存缺陷不追改。当前关键直接输入实际复核，其余历史核验复用。K9进程4780 COMPLETE与独立审计4351匹配、429不可读分别保留。', '',
      f"worker 子进程时间 {command.get('worker_wall_s')} 秒；入口到封存及独立读回的端到端时间、含准备和失败尝试的累计时间见 delivery_verification.json 和 work/post_delivery_verification.json（最终读回之后测量，避免循环自哈希）。预算 {command.get('total_budget_s')} 秒；冻结前未计时只读准备保守计入900秒，不伪称精确测量。",'',
      '候选进程有输入白名单；用改变独立核对表后的完整候选重跑验证输出字节不变。轨迹逐星读取，未展开五千多万单元。原生激活0、fresh native=false、Git写操作0，旧生产链原字节不变。', '',
      '|状态项|结果|','|---|---|']
    for key in ['offline_engineering_acceptance','official_contract_review','official_readiness','prototype_behavior_acceptance','real_continuous_bound_coverage','historical_53_retention','candidate_cost_status','search_completeness_certification','historical_coverage','next_scientific_run_gate']:
        lines.append(f'|{key}|{summary[key]}|')
    lines += ['', '实际命令：', '', "```powershell\n& 'D:\\conda_envs\\fmb\\python.exe' -X utf8 -B 'G:\\fmb666\\tools\\run_round10.py'\n```",'',f'交付：{out}',f'工作与后验记录：{summary["work"]}','']
    for name,value in summary['checks'].items():
        if value['status']!='PASS':lines.append(name+': '+json.dumps(value,ensure_ascii=False))
    text(out/'audit_report.md','\n'.join(lines))
