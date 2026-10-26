"""Round9 checked routing, actual offline work, budgets and separated statuses."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from src.round2.evidence import code_manifest
from src.round8.common import KEYS,canonical,file_record,identities,outcome,read,sha,text,write
from src.round8.science import identity_audit,query_audit
from . import binding,evidence,header_cases,legacy_cases,official,regression,search

def static_review(root):
    rows=[];errors=[]
    forbidden={'Dispatch','DispatchEx','GetActiveObject','CreateObject','CoInitialize','supervise','ShellExecute','WinExec','eval','exec'}
    paths=list((root/'src/round9').glob('*.py'))+list((root/'tests').glob('test_round9*.py'))+[root/'tools/run_round9.py']
    for path in paths:
        tree=ast.parse(path.read_bytes().decode('utf-8'),type_comments=True)
        calls={ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n,ast.Call)}
        bad=sorted(n for n in calls if n.rsplit('.',1)[-1] in forbidden)
        if bad:errors.append(dict(path=str(path),calls=bad))
        rows.append(dict(file=file_record(path),forbidden_calls=bad,syntax_valid=True))
    return dict(status='FAIL' if errors else 'PASS',errors=errors,files=rows,review='Original rounds immutable; mutation text never compiled/imported/executed; shared reuse is pure saved-file parsing, mock-only old regression and statistical calculations.')

def guard_probe(result):
    """Audit-event simulation only; never attempts real import/process/file open."""
    cases=[]
    events=[('native_import','import',('win32com',None,None,None,None),'NATIVE_IMPORT'),
            ('native_subprocess','subprocess.Popen',('STK.exe',['STK.exe'],None,None),'UNAPPROVED_SUBPROCESS'),
            ('source_write','open',(str(Path(__file__).resolve().parents[2]/'configs/round7.json'),'w',os.O_WRONLY),'WRITE_OUTSIDE_ROUND9')]
    for name,event,args,reason in events:
        try:sys.audit(event,*args);actual='NOT_REJECTED'
        except PermissionError as exc:actual=str(exc)
        cases.append(dict(case=name,kind='SIMULATED_AUDIT_EVENT_NO_NATIVE_ACTION',expected=reason,actual=actual,status='PASS' if reason in actual else 'FAIL'))
    write(result,dict(status='PASS' if all(r['status']=='PASS' for r in cases) else 'FAIL',cases=cases,real_native_activations=0))
    return 0 if all(r['status']=='PASS' for r in cases) else 1

def validate(spec):
    p=spec['policy'];root=Path(spec['root']);out=Path(spec['output']);work=Path(spec['work']);subject=spec['subject'];validator=spec['validator']
    provenance=identities(subject,validator);start=time.perf_counter();checks={};spent={k:0. for k in p['budgets_s']};values={};state={}
    preliminary=read(out/'development_budget_ledger.json')
    for entry in preliminary['entries']:spent[entry['task']]+=entry['elapsed_s']
    preliminary_total=sum(spent.values())
    def check(name,category,call):
        now=time.perf_counter();print('CHECK',name,flush=True)
        if now-start+preliminary_total>p['total_budget_s'] or spent[category]>=p['budgets_s'][category]:r=dict(status='BLOCKED',errors=['BUDGET_EXHAUSTED_BEFORE_TASK'])
        else:
            try:r=call()
            except (FileNotFoundError,PermissionError,TimeoutError,subprocess.TimeoutExpired) as exc:r=dict(status='BLOCKED',errors=[type(exc).__name__+':'+str(exc)],traceback=traceback.format_exc())
            except Exception as exc:r=dict(status='FAIL',errors=[type(exc).__name__+':'+str(exc)],traceback=traceback.format_exc())
        elapsed=time.perf_counter()-now;spent[category]+=elapsed
        if spent[category]>p['budgets_s'][category] or time.perf_counter()-start+preliminary_total>p['total_budget_s']:
            r['status']='BLOCKED';r.setdefault('errors',[]).append('DECLARED_BUDGET_EXCEEDED')
        r.update(provenance);r['elapsed_s_round9']=elapsed
        if r.get('status') not in {'PASS','FAIL','BLOCKED'}:r['status']='FAIL';r['errors']=['CHECK_SCHEMA']
        values[name]=r;checks[name]=dict(status=r['status'],errors=r.get('errors',[]),elapsed_s=elapsed,artifact=name+'.json')
        write(out/(name+'.json'),r);write(out/'progress.json',dict(checks=checks,budget_spent_s=spent,**provenance));print('RESULT',name,r['status'],round(elapsed,3),flush=True)
        return r
    check('static_review','binding',lambda:static_review(root))
    check('k8_freeze','freeze',lambda:evidence.freeze_k8(p,root,out))
    def historical():
        r,before=evidence.historical(p,out);state['before']=before;return r
    coverage=check('historical_coverage','freeze',historical)
    def bind():
        result,checker,s,v=binding.bind(p,root,read(out/'code_manifest.json')['files'],out);state.update(checker=checker,s=s,v=v);return result
    check('dependency_binding','binding',bind)
    check('binding_counterexamples','counterexamples',lambda:header_cases.run(state['checker'],state['s'],state['v']))
    check('regression','regression',lambda:regression.run_regression(root,work,read(out/'code_manifest.json')['files']))
    cfg=read(Path(p['source_dir'])/'config.json')['config'];source=Path(p['source_dir']);folder=source/'G/T7'
    points=read(source/'grid/frozen.json')['points'];opps=read(folder/'opportunities.json');candidates=read(folder/'candidate_ledger.json');queries=read(folder/'raw_access_queries.json');raw=read(folder/'raw_intervals.json');geometry=read(folder/'geometry_audit.json')
    check('science_identity','statistics',lambda:identity_audit(subject,cfg,source))
    check('query_positive','statistics',lambda:query_audit(subject,cfg,points,opps,candidates,queries,raw,geometry))
    check('legacy_counterexamples','counterexamples',lambda:legacy_cases.run(subject,validator,cfg,source,Path(p['historical_validator_dir']),root,work,points,opps,candidates,queries,raw,geometry,state['s'],state['v'],state['checker']))
    check('official_contract_review','official',lambda:official.review(p,cfg,out))
    check('engineering_statistics','statistics',lambda:official.statistics(p,cfg,out))
    check('search_error_analysis','search',lambda:search.analyze(p,cfg,out,min(start+p['total_budget_s']-preliminary_total,time.perf_counter()+p['budgets_s']['search']-spent['search'])))
    def protection():
        result=work/'guard_probe_result.json';log=work/'guard_probe.jsonl'
        env=dict(os.environ,ROUND9_GUARD_LOG=str(log));argv=[sys.executable,'-B',str(root/'tools/run_round9.py'),'--guard-probe','--result',str(result)]
        probe_start=time.perf_counter();proc=subprocess.run(argv,cwd=root,env=env,capture_output=True,timeout=30)
        probe=read(result);events=[json.loads(line) for line in log.read_text(encoding='utf-8').splitlines()]
        parent=[json.loads(line) for line in (work/'validator_guard.jsonl').read_text(encoding='utf-8').splitlines()]
        denied=[r for r in parent if r['kind']=='denied']
        return dict(status='PASS' if proc.returncode==0 and probe['status']=='PASS' and not denied and len([r for r in events if r['kind']=='denied'])==3 else 'FAIL',errors=denied,probe=probe,probe_log=file_record(log),probe_command=dict(argv=argv,exit_code=proc.returncode,elapsed_s=time.perf_counter()-probe_start,stdout=proc.stdout.decode('utf-8'),stderr=proc.stderr.decode('utf-8')),validator_log_records=parent,round9_native_activation_count=0,fresh_native_validation_performed=False)
    check('native_guard','regression',protection)
    check('source_preservation','preservation',lambda:evidence.preserve(state['before']))
    frozen=read(out/'code_manifest.json')['files']
    check('code_preservation','preservation',lambda:dict(status='PASS' if frozen==code_manifest() else 'FAIL',expected_sha256=validator['code_sha256'],actual_sha256=sha(canonical(code_manifest())),raw_bytes_required=True))
    for name in p['required_checks']:
        if name!='delivery_verification':checks.setdefault(name,dict(status='BLOCKED',errors=['REQUIRED_TASK_NOT_EXECUTED']))
    historical_states=values.get('k8_freeze',{}).get('historical_identities',{})
    observed_history={label:dict(status=(r['status'].get('business',{}).get('core_acceptance') if label=='S' else r['status'].get('status') if label=='V' else r['status'].get('offline_acceptance')),exit_code=r['command']['exit_code'],run_id=r['context']['run_id'],code_sha256=r['context']['code_sha256']) for label,r in historical_states.items()}
    summary=dict(kind=p['kind'],validator_run_id=validator['run_id'],subject_run_id=subject['run_id'],validator_code_sha256=validator['code_sha256'],checks=checks,offline_engineering_acceptance=outcome(checks),
                 official_contract_review=values.get('official_contract_review',{}).get('official_contract_review','NOT_COMPLETED'),official_readiness='UNRESOLVED',official_score=None,
                 search_error_basis=values.get('search_error_analysis',{}).get('search_error_basis','UNRESOLVED'),search_completeness_certification='UNRESOLVED',next_scientific_run_gate='BLOCKED',historical_coverage=coverage.get('historical_coverage','UNVERIFIED'),
                 historical_statuses=observed_history,source_status_unchanged=checks['source_preservation']['status']=='PASS',fresh_native_validation_performed=False,round9_native_activation_count=0,output=str(out),work=str(work),budget_spent_s=spent,total_validation_s=time.perf_counter()-start)
    summary['exit_code']=0 if summary['offline_engineering_acceptance']=='PASS' else 1
    write(out/'budget_execution.json',dict(declared=p['budgets_s'],spent=spent,total_budget_s=p['total_budget_s'],elapsed_s=summary['total_validation_s'],preliminary_elapsed_s=preliminary_total,cumulative_offline_s=summary['total_validation_s']+preliminary_total,native_budget=0,adjusted_during_run=False))
    write(out/'summary.json',summary);write(out/'final_status.json',summary);return summary

def report(out,summary,command):
    def result(n):return read(out/(n+'.json')) if (out/(n+'.json')).exists() else {}
    tests=result('regression');headers=result('binding_counterexamples');legacy=result('legacy_counterexamples');stat=result('engineering_statistics');error=result('search_error_analysis');coverage=result('historical_coverage')
    lines=['# 第九轮离线工程验收报告',f"\n本轮工程状态：**{summary['offline_engineering_acceptance']}**；退出码 {summary['exit_code']}。实际验证耗时 {command['elapsed_s']:.6f} 秒。",
           f"\nK9 `{summary['validator_run_id']}`，代码清单 SHA-256 `{summary['validator_code_sha256']}`。subject=`{summary['subject_run_id']}`；来源身份保持独立。",
           '\nS 原 FAIL/退出1、V 原 BLOCKED/退出1、K8 原复合离线 PASS/退出0 均保留。前次第八轮摘要缺陷未追改；冻结证据见 k8_freeze.json 与 frozen_K8。',
           '\n修复：独立第九轮绑定器使用 type_comments=True 解析；仅正规化获准函数体区段后比较完整 AST，保留装饰器及顺序、名称、参数和默认值、注解、类型注释、节点种类及解释器支持字段。新辅助函数完整头部和函数体绑定到可信历史 V；同名定义在建字典前拒绝。K8 及更早文件原字节不变，未用猴补丁替换绑定器。',
           f"\n正式口径核对：{summary['official_contract_review']}；官方准备状态 {summary['official_readiness']}，官方评分 null。搜索误差依据 {summary['search_error_basis']}；搜索完备认证 UNRESOLVED；下一科学运行门 BLOCKED。",
           f"\n回归：{tests.get('tests')} 项，失败 {tests.get('failures')}、错误 {tests.get('errors')}、跳过 {tests.get('skipped')}；完整头部反例 {headers.get('case_count')} 项，旧拒绝场景实际重跑 {legacy.get('case_count')} 项，其中真实空查询逐项删除 {legacy.get('empty_query_removals')} 项。每个绑定场景显式调用 src.round9.binding，记录模块/函数摘要。",
           f"\n统计：{stat.get('event_count')} 事件，{stat.get('covered_points')}/{stat.get('point_denominator')} 覆盖，{stat.get('insufficient_points')} 点不足两次，{stat.get('gap_count')} 个内部 gap；条件均值 {stat.get('conditional_mean_gap_s')} s，最大值 {stat.get('conditional_max_gap_s')} s。原七星 {stat.get('original_seven_events')} 条，新增21星 {stat.get('additional21_events')} 条，搜索修复新增 {stat.get('search_repair_new_events')} 条。",
           f"\n误差实验：{json.dumps(error.get('empirical',{}),ensure_ascii=False)}。构造场景 {error.get('constructed_case_count')} 项；节点代理和事件附近 exact_states 的选择偏差见 search_error_method.md。固定余量未被升级为全窗严格上界。",
           f"\n本次历史核验主体为实际第九轮进程；历史引用 {coverage.get('reference_count')} 条、去重 {coverage.get('unique_reference_files')} 文件；K8 原保全并集 {coverage.get('original_k8_union_files')} 文件。本次加入直接锚点后的并集 {coverage.get('current_union_files')} 文件。当前读取状态 {summary['historical_coverage']}，实际计数 {coverage.get('current_union_counts')}。历史独立审计的 429 项不可读仍单独保存，不借用其匹配数或 K8 COMPLETE。",
           '\n本轮 fresh native=false，STK/COM 激活数为0；保护器模拟拒绝测试不执行真实导入、启动或源写入。无生产搜索修改、无新真实事件、无扩点扩星、无 Git 写操作。',
           '\n|检查|状态|','|---|---|']
    lines += [f"|{k}|{v['status']}|" for k,v in summary['checks'].items()]
    lines += ['\n实际命令：\n\n```powershell\n'+' '.join(command['invoked_entry'])+'\n```',f"\n交付 `{out}`；日志与临时文件 `{summary['work']}`。",'\n剩余条件：主办方确认时间系统、视场定义、区域/有效分母、边界删失、合并规则和最终工况/接口；取得可追溯的连续轨迹/姿态/地平线/数值求根误差界。上述条件未满足前不开放下一科学运行。',
              '\n封存：报告、状态与日志定稿后生成最终 raw manifest；后验文件单向绑定 manifest 并逐项读回，二者不递归自哈希。']
    for name,c in summary['checks'].items():
        if c['status']!='PASS':lines.append('\n缺口 '+name+': '+json.dumps(c.get('errors',[]),ensure_ascii=False))
    text(out/'audit_report.md','\n'.join(lines)+'\n')
