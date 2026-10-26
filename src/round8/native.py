"""Saved native stage evidence: read only, never import the supervisor."""
import datetime
import zipfile
from pathlib import Path
from .common import KEYS, canonical, file_record, owned, read, sha

STAGES = [
    ('lifecycle_normal','lifecycle/normal','normal'),
    ('lifecycle_exception','lifecycle/exception','exception'),
    ('lifecycle_timeout','lifecycle/timeout','timeout'),
    ('diagnostics','diagnostics','r7_diagnostics'),
    ('known_extra','reliability/known_extra','r7_known_extra'),
    ('cold_old','benchmarks/cold_old','r7_dataset_cold_old'),
    ('cold_new','benchmarks/cold_new','r7_dataset_cold_new'),
    ('B1','benchmarks/B1','r7_dataset_B1'),
    ('B2','benchmarks/B2','r7_dataset_B2'),
    ('main','G/T7','r7_dataset_T7'),
    ('reopen','reopen/instance','r7_reopen')]

# All files are bound by the conservative original-module closure. These edges
# document the actual dispatch/callback flow rather than implying AST equality
# alone makes a callback's binding safe.
CALL_EDGES = [
    ('tools/run_round7.py:run.task','src/round3/lifecycle.py:supervise','taskname, payload, exact S ctx/cfg; multiprocessing spawn _worker'),
    ('src/round3/lifecycle.py:_worker','src/round7/experiments.py:dispatch',"task.startswith('r7_'); local import; controlled lifecycle tasks bypass dispatch"),
    ('src/round7/experiments.py:dispatch','src/round6/experiments.py:diagnostics','explicit Model=round7.Model, search_batch=round7.search_batch, integrity=round7.integrity, ENTRY=round7.ENTRY; overrides all round6 defaults'),
    ('src/round7/experiments.py:dispatch','src/round7/experiments.py:known_and_extra','same round7 Model/search/integrity globals; frozen historical events define fixture windows only'),
    ('src/round7/experiments.py:dispatch','src/round7/experiments.py:dataset','r7_dataset_* dispatch; B1/B2 set effective duration 86400; main retains 604800'),
    ('src/round7/experiments.py:dataset','src/round7/production.py:Model/search_batch','new/main/B1/B2 fixed globals; no runtime plugin resolution'),
    ('src/round7/experiments.py:dataset','src/round7/experiments.py:old_implementation','cold_old only: spec_from_file_location to saved isolated round6/production.py; all eight declared dependencies checked against R6 ZIP and S'),
    ('src/round7/production.py:Model','src/round3/experiments.py:Model','BaseModel alias and inheritance, super calls, coordinate/attitude/access/readback methods'),
    ('src/round7/production.py:search_batch','src/round7/production.py:screen','models map keyed by sat; target/facility map keyed by frozen point; Model.access; audit_geometry after real events'),
    ('src/round7/production.py:screen','src/round7/candidates.py:cell_windows/normalize_sources','frozen camera/candidate_guard/horizon values; source/interval grouping'),
    ('src/round3/experiments.py:Model','src/round2/geometry.py','body_basis, angles, geodetic conversion, quaternion and intersection; frozen earth/camera config'),
    ('src/round7/experiments.py:dispatch','src/round4/experiments.py:reopen','r7_reopen; round4 imported Model is round3.Model; saved project loads once; ordered positive then per-star negative queries'),
    ('tools/run_round7.py:run','src/round7/audit.py:validate_config/bind/CAPS','unchanged pre-native functions/globals; same imports/defaults and old baseline reads'),
    ('tools/run_round7.py:run','src/round7/audit.py:audit_dataset','only after main and reopen return PASS; changed region has no native callees'),
    ('src/round7/audit.py:audit_dataset','src/round7/audit.py:audit_constraints','new read-only saved file parsing; no import/init effects, no writes, no COM, no process launch')]


def audit_stage(subject,folder,task):
    life=read(folder/'lifecycle.json');ownership=read(folder/'ownership.json');errors=[]
    if not owned([life],subject) or life['task']!=task:errors.append('NATIVE_STAGE_IDENTITY')
    if life['ownership']!=ownership:errors.append('OWNERSHIP_FILE_BINDING')
    if ownership['run_id']!=subject['run_id'] or not ownership['absent_from_before'] or not ownership['empty_scenario']:errors.append('INDEPENDENT_INSTANCE')
    for k in ('pid','executable','creation_time','creation_timestamp'):
        if ownership[k]!=ownership['supervisor_identity'][k]:errors.append('EXACT_HANDLE_IDENTITY:'+k)
    identity=(ownership['pid'],ownership['creation_time'])
    if any((x['pid'],x['creation_time'])==identity for x in life['before']+life['after']) or life['residual'] is not False:errors.append('CLEANUP_OR_PREEXISTING')
    timeout=task=='timeout'
    if life['status']!='PASS' or life['timed_out']!=timeout or life['forced_termination']!=timeout or (life['worker_exit_code']!=0 and not timeout) or timeout and life['worker_exit_code']==0:errors.append('NATIVE_COMMAND_OUTCOME')
    if not life['started_utc'] or not 0<life['elapsed_s']<life['timeout_s']+60:errors.append('NATIVE_TIMING')
    worker=None
    if not timeout:
        worker=read(folder/'worker.json')
        if worker['run_id']!=subject['run_id'] or worker['task']!=task or not worker['quit_requested'] or worker['com_interfaces_before_uninitialize']!=0:errors.append('WORKER_CLEANUP')
        if task=='exception':
            if not worker.get('expected_exception_observed'):errors.append('EXPECTED_EXCEPTION')
        elif task=='normal':
            if not worker.get('scenario_created'):errors.append('NORMAL_LIFECYCLE')
        elif worker.get('kind')!='REAL_STK' or worker.get('experiment',{}).get('status')!='PASS':errors.append('REAL_NATIVE_EXPERIMENT')
    logs=[file_record(life[k]) for k in ['stdout','stderr']]
    return dict(status='FAIL' if errors else 'PASS',errors=errors,task=task,original_status=life['status'],
                original_worker_exit_code=life['worker_exit_code'],started_utc=life['started_utc'],elapsed_s=life['elapsed_s'],
                timeout_s=life['timeout_s'],original_timed_out=life['timed_out'],controlled_timeout_fixture=timeout,
                ownership=ownership,cleanup=life['cleanup'],residual=life['residual'],logs=logs,
                original_native_run_id=life['run_id'],lifecycle_file=file_record(folder/'lifecycle.json'),worker=worker)


def native_evidence(subject,cfg,source,dependency,source_blobs):
    rows=[];errors=[];original=read(source/'command_result.json')
    for label,relative,task in STAGES:
        folder=source/relative
        try:row=audit_stage(subject,folder,task)
        except FileNotFoundError as exc:row=dict(status='BLOCKED',errors=['MISSING_NATIVE_STAGE'],missing=str(exc))
        row.update(stage=label,kind='REUSED_HISTORICAL_NATIVE_EVIDENCE',executed_in_round8=False,
                   original_outer_command=original,original_stage_invocation=dict(function='src.round3.lifecycle.supervise',task=task,folder=str(folder)),
                   source_context={k:subject[k] for k in KEYS},dependency_equivalence=dependency['status'],
                   dependency_digest=sha(canonical({n:sha(b) for n,b in source_blobs.items() if n.startswith(('src/','tools/','configs/'))})),
                   reuse_reason='Saved native stage plus raw-preserved dependencies; S→V post-native patch and V→C→K closure checked separately.',
                   limitation='No execution or instance activation in round8; original run and instance IDs retained.')
        if task.startswith('r7_dataset_'):
            effective=read(folder/'effective_config.json')
            row['original_effective_config']=effective
            if effective['parent_config_sha256']!=subject['config_sha256'] or sha(canonical(effective['config']))!=effective['sha256']:
                row['status']='FAIL';row.setdefault('errors',[]).append('EFFECTIVE_CONFIG_BINDING')
            expected=__import__('copy').deepcopy(cfg)
            if label in {'B1','B2'}:expected['duration_s']=86400.
            if expected!=effective['config']:
                row['status']='FAIL';row.setdefault('errors',[]).append('EFFECTIVE_CONFIG_UNEXPECTED_CHANGE')
        rows.append(row)
    index=read(source/'lifecycle_index.json')
    if {x['task'] for x in index}!={x[2] for x in STAGES} or len(index)!=len(STAGES):errors.append('LIFECYCLE_INVENTORY')
    for item in index:
        if {k:v for k,v in item.items() if k!='path'}!=read(item['path']):errors.append('LIFECYCLE_INDEX_CONTENT')
    gate=read(source/'main_launch_gate.json');state=read(source/'stage_progress.json')
    if not owned([gate],subject) or gate['status']!='PASS' or not gate['code_frozen'] or any(v['status']!='PASS' for v in gate['prerequisites'].values()):errors.append('MAIN_PREREQUISITES')
    if any(state[k]['status']!='PASS' for k in gate['prerequisites']):errors.append('STAGE_PREREQUISITES')
    when=datetime.datetime.fromisoformat(gate['at_utc']);main=next(x for x in rows if x['stage']=='main')
    if main.get('started_utc') and not when<datetime.datetime.fromisoformat(main['started_utc']):errors.append('MAIN_START_ORDER')
    for r in rows:
        if r['stage'] not in {'main','reopen'} and r.get('started_utc'):
            finish=datetime.datetime.fromisoformat(r['started_utc'])+datetime.timedelta(seconds=r['elapsed_s'])
            if finish>when:errors.append('PREREQUISITE_NOT_FINISHED:'+r['stage'])
    ref=read(source/'old_snapshot_reference.json');oldpath=Path(ref['source']);closure=[]
    if file_record(oldpath)['sha256']!=ref['sha256']:errors.append('OLD_DYNAMIC_SNAPSHOT_HASH')
    with zipfile.ZipFile(oldpath) as z:
        for item in read(source/'benchmarks/cold_old/experiment.json')['old_dependency_closure']:
            n=item['relative'];saved=file_record(item['isolated_path']);same=sha(z.read(n))==saved['sha256']==item['sha256']==sha(source_blobs[n])
            closure.append(dict(item,recomputed_match=same,actual_isolated_sha256=saved['sha256']))
            if not same:errors.append('DYNAMIC_OLD_DEPENDENCY:'+n)
    ledger=read(source/'cumulative_stk_budget.json');sums={}
    for item in ledger['entries']:
        life=read(item['evidence'])
        if any(item[k]!=life[k] for k in ['run_id','elapsed_s','status','started_utc']):errors.append('BUDGET_STAGE_BINDING')
        sums[item['category']]=sums.get(item['category'],0)+item['elapsed_s']
    total=sum(x['elapsed_s'] for x in ledger['entries'])
    if ledger['caps_s']!=cfg['round7']['budget_caps_s'] or total>ledger['caps_s']['cumulative'] or any(v>ledger['caps_s'][k] for k,v in sums.items()):errors.append('BUDGET_CAPS')
    status='FAIL' if errors or any(r['status']=='FAIL' for r in rows) else 'BLOCKED' if dependency['status']!='PASS' or any(r['status']!='PASS' for r in rows) else 'PASS'
    environment=read(source/'environment/environment.json')
    return dict(status=status,errors=errors,stages=rows,call_edges=[dict(caller=a,callee=b,binding=c) for a,b,c in CALL_EDGES],
                original_environment=dict(python=environment['python'],version=environment['version'],packages=environment['packages'],stk=environment['stk']),
                old_dynamic_import=closure,gate=gate,budget=dict(entries=len(ledger['entries']),total_s=total,by_category_s=sums,caps=ledger['caps_s'],modified=False),
                round8_native_activation_count=0,fresh_native_validation_performed=False)
