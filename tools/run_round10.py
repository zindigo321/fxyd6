"""Round10 offline-only entry; immutable code and one-way delivery sealing."""
import argparse
import datetime
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback
import uuid
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.round8.common import KEYS,canonical,file_record,outcome,read,sha,text,write


def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()


def freeze(policy,out,work,rid):
    from src.round2.evidence import code_manifest
    prep=Path(policy['preparation_dir']);protocol=prep/'experimental_protocol.json'
    if file_record(protocol)['sha256']!=policy['protocol_sha256']:raise ValueError('EXPERIMENTAL_PROTOCOL_CHANGED')
    manifest=code_manifest();k9=Path(policy['k9_dir']);inputs=[]
    for name in ['run.json','config.json','code_manifest.json','code_snapshot.zip','input_manifest.json','artifact_manifest.json','delivery_verification.json','final_status.json','source_read_plan.json','official_original_extract.json','official_contract.json']:
        inputs.append(file_record(k9/name))
    for name in ['execution_start.json','execution_start.zip','experimental_protocol.json','protocol_seal.json']:
        inputs.append(file_record(prep/name));shutil.copyfile(prep/name,out/name)
    development=out/'preparation_evidence';development.mkdir()
    for p in sorted(prep.rglob('*')):
        if p.is_file() and p.suffix in {'.json','.jsonl','.log','.py'} and not p.name.startswith('K9_'):
            target=development/p.relative_to(prep);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,target)
    audit=Path(policy['audit_dir'])/'audit_and_next_steps.md';inputs.append(file_record(audit))
    git={name:subprocess.check_output(['git','-c','safe.directory=G:/fmb666']+args,cwd=ROOT).decode('utf-8') for name,args in [('head',['show','-s','--format=%H','HEAD']),('status',['status','--porcelain=v1','--untracked-files=all']),('tracked_diff',['diff','--binary','HEAD'])]}
    write(out/'git_at_freeze.json',git)
    ctx=dict(run_id=rid,code_sha256=sha(canonical(manifest)),config_sha256=sha(canonical(policy)),input_sha256=sha(canonical(inputs)),output=str(out),work=str(work),created_utc=utc())
    write(out/'run.json',ctx);write(out/'config.json',dict(validator={k:ctx[k] for k in KEYS},policy=policy))
    write(out/'code_manifest.json',dict(code_sha256=ctx['code_sha256'],files=manifest));write(out/'input_manifest.json',dict(input_sha256=ctx['input_sha256'],files=inputs,scope='Direct anchors; transitive critical input bytes individually verified in source_bytes_before/source_preservation.'))
    with zipfile.ZipFile(out/'code_snapshot.zip','w',zipfile.ZIP_DEFLATED) as z:
        for row in manifest:
            p=Path(row['path']);blob=p.read_bytes()
            if sha(blob)!=row['sha256']:raise ValueError('CODE_CHANGED_DURING_FREEZE')
            z.writestr(p.relative_to(ROOT).as_posix(),blob)
    write(out/'environment.json',dict(executable=sys.executable,prefix=sys.prefix,version=sys.version,
        packages={n:importlib.metadata.version(n) for n in ['numpy','shapely','matplotlib','pywin32']},native_detection_performed=False))
    return ctx


def verify_delivery(out):
    errors=[];manifest=read(out/'artifact_manifest.json')
    wanted={Path(r['path']).resolve() for r in manifest['files']}
    # Nested historical manifests are members too; only the root pair is excluded.
    actual={p.resolve() for p in out.rglob('*') if p.is_file() and p not in {out/'artifact_manifest.json',out/'delivery_verification.json'}}
    if actual!=wanted:errors.append('ARTIFACT_INVENTORY')
    for row in manifest['files']:
        now=file_record(row['path'])
        if now['sha256']!=row['sha256'] or now['bytes']!=row['bytes']:errors.append('ARTIFACT_RAW_HASH:'+row['path'])
    summary=read(out/'summary.json');command=read(out/'command_result.json')
    if summary!=read(out/'final_status.json') or summary['exit_code']!=command['exit_code']:errors.append('FINAL_STATUS_COMMAND')
    code=read(out/'code_manifest.json')
    if sha(canonical(code['files']))!=read(out/'run.json')['code_sha256']:errors.append('CODE_MANIFEST_IDENTITY')
    with zipfile.ZipFile(out/'code_snapshot.zip') as z:
        expected={Path(r['path']).relative_to(ROOT).as_posix():r for r in code['files']}
        if set(z.namelist())!=set(expected) or len(z.namelist())!=len(expected):errors.append('CODE_ZIP_INVENTORY')
        for name,row in expected.items():
            if sha(z.read(name))!=row['sha256'] or file_record(row['path'])['sha256']!=row['sha256']:errors.append('CODE_ZIP_OR_CURRENT_BYTES:'+name)
    for p in out.rglob('*'):
        if p.is_file() and p.suffix in {'.json','.jsonl','.md','.log','.diff'}:
            try:
                value=p.read_bytes().decode('utf-8',errors='strict')
                if p.suffix=='.json':json.loads(value)
            except (ValueError,UnicodeError):errors.append('UTF8_OR_JSON:'+str(p))
    return dict(status='FAIL' if errors else 'PASS',errors=errors,artifact_files=len(manifest['files']),code_files=len(code['files']),
                manifest=file_record(out/'artifact_manifest.json'),verified_utc=utc(),raw_disk_readback=True)


def seal(out,work,summary,command,start_epoch,protocol):
    from src.round10.runtime import report
    def save():
        summary['offline_engineering_acceptance']=outcome(summary['checks']);summary['exit_code']=0 if summary['offline_engineering_acceptance']=='PASS' else 1
        command['exit_code']=summary['exit_code'];write(out/'summary.json',summary);write(out/'final_status.json',summary);write(out/'command_result.json',command)
        report(out,summary,command)
        write(out/'artifact_index.json',dict(artifacts=[str(p.relative_to(out)) for p in sorted(out.rglob('*')) if p.is_file() and p not in {out/'artifact_manifest.json',out/'delivery_verification.json'}],
              primary=['audit_report.md','summary.json','organizer_questions.md','candidates/coverage_ledger.json','candidates/candidate_decisions.jsonl','candidates/candidate_windows.json','historical_53_retention.json','candidate_cost_comparison.json']))
        rows=[file_record(p) for p in sorted(out.rglob('*')) if p.is_file() and p not in {out/'artifact_manifest.json',out/'delivery_verification.json'}]
        write(out/'artifact_manifest.json',dict(files=rows,exclusions=['root artifact_manifest.json','root delivery_verification.json'],algorithm='SHA-256 FINAL RAW BYTES'))
    cumulative=lambda:time.time()-protocol['freeze_epoch']+protocol['prefreeze_preparation_charged_upper_bound_s']
    summary['checks']['delivery_verification']=dict(status='PASS',note='Effective only if independent final disk readback succeeds.')
    summary['checks']['cumulative_budget']=dict(status='PASS' if cumulative()<=protocol['total_budget_s'] else 'BLOCKED')
    budget=dict(declared_total_s=protocol['total_budget_s'],freeze_epoch=protocol['freeze_epoch'],prefreeze_preparation_charged_upper_bound_s=protocol['prefreeze_preparation_charged_upper_bound_s'],
                cumulative_through_preseal_s=cumulative(),worker_wall_s=command['worker_wall_s'],end_to_end_through_preseal_s=time.time()-start_epoch,
                includes_authoring_preparation_failed_attempts_regression_all_children_preservation_and_seal=True,adjusted_during_run=False)
    write(out/'budget_and_resources.json',budget);save();result=verify_delivery(out)
    if result['status']!='PASS' or cumulative()>protocol['total_budget_s']:
        if result['status']!='PASS':summary['checks']['delivery_verification']=dict(status='FAIL',errors=result['errors'])
        if cumulative()>protocol['total_budget_s']:summary['checks']['cumulative_budget']=dict(status='BLOCKED',errors=['BUDGET_EXCEEDED'])
        save();result=verify_delivery(out)
    result.update(exit_code=summary['exit_code'] if result['status']=='PASS' else 1,
                  worker_wall_s=command['worker_wall_s'],end_to_end_wall_s=time.time()-start_epoch,cumulative_budget_charged_s=cumulative(),
                  budget_limit_s=protocol['total_budget_s'],timing_scope='End-to-end from entry start through final raw readback; cumulative from predeclared preparation freeze plus 900s conservative prefreeze charge. Receipt serialization itself excluded.',
                  output=str(out),work=str(work),one_way_binding=True)
    write(out/'delivery_verification.json',result);write(work/'post_delivery_verification.json',dict(result,delivery_receipt=file_record(out/'delivery_verification.json')))
    return result


def main():
    start=time.time()
    if Path(sys.executable).resolve()!=Path(r'D:\conda_envs\fmb\python.exe').resolve():raise ValueError('FMB_INTERPRETER_REQUIRED')
    policy=read(ROOT/'configs/round10.json')
    if policy['native_activation_budget']!=0:raise ValueError('NATIVE_BUDGET_MUST_BE_ZERO')
    rid=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'_offline_'+uuid.uuid4().hex[:10]
    work=ROOT/'work/round10'/rid;out=Path(policy['output_root'])/rid;work.mkdir(parents=True);out.mkdir(parents=True)
    print('ROUND10_OUTPUT',out,flush=True)
    freeze_start=time.perf_counter();ctx=freeze(policy,out,work,rid);freeze_wall=time.perf_counter()-freeze_start
    spec=dict(root=str(ROOT),output=str(out),work=str(work),policy=policy,validator={k:ctx[k] for k in KEYS})
    path=work/'run_spec.json';write(path,spec)
    from src.round10.runtime import configure_guard,child
    configure_guard(work,out,work/'launcher_guard.jsonl',Path(__file__).resolve())
    command=child([sys.executable,'-B',str(Path(__file__).resolve()),'--validate-worker','--run-spec',str(path)],work,'validator',policy['validator_timeout_s'])
    for p in work.glob('*.log'):shutil.copyfile(p,out/p.name)
    for p in work.glob('*.jsonl'):shutil.copyfile(p,out/p.name)
    for folder in ['candidate_worker','isolation_replay_worker']:
        if (work/folder/'guard.jsonl').exists():shutil.copyfile(work/folder/'guard.jsonl',out/(folder+'_guard.jsonl'))
    if (out/'summary.json').exists():summary=read(out/'summary.json')
    else:
        summary=dict(offline_engineering_acceptance='FAIL',official_contract_review='NOT_COMPLETED',official_readiness='UNRESOLVED',official_score=None,
            prototype_behavior_acceptance='BLOCKED',real_continuous_bound_coverage='UNRESOLVED',historical_53_retention='BLOCKED',candidate_cost_status='BLOCKED',
            search_completeness_certification='UNRESOLVED',historical_coverage='UNVERIFIED',next_scientific_run_gate='BLOCKED',validator=spec['validator'],checks={},
            fresh_native_validation_performed=False,round10_native_activation_count=0,git_write_operations=0,work=str(work),output=str(out),exit_code=1)
    summary['checks']['worker_exit']=dict(status='PASS' if command['exit_code']==0 else 'BLOCKED' if command['timeout'] else 'FAIL',exit_code=command['exit_code'])
    command.update(worker_wall_s=command.pop('wall_s'),invoked_entry=[sys.executable,'-X','utf8','-B',str(Path(__file__).resolve())],freeze_wall_s=freeze_wall,total_budget_s=policy['total_budget_s'])
    result=seal(out,work,summary,command,start,read(out/'experimental_protocol.json'))
    print(json.dumps(dict(output=str(out),status=summary['offline_engineering_acceptance'],**{k:result[k] for k in ['exit_code','worker_wall_s','end_to_end_wall_s','cumulative_budget_charged_s']}),ensure_ascii=False),flush=True)
    return result['exit_code']


def dispatch():
    parser=argparse.ArgumentParser();parser.add_argument('--validate-worker',action='store_true');parser.add_argument('--candidate-worker',action='store_true');parser.add_argument('--guard-probe',action='store_true');parser.add_argument('--run-spec');parser.add_argument('--result');args=parser.parse_args()
    if args.candidate_worker:
        spec=read(args.run_spec);work=Path(os.environ['ROUND10_CANDIDATE_WORK']);out=Path(spec['output'])
        from src.round10.runtime import configure_guard
        configure_guard(work,out,work/'guard.jsonl',Path(__file__).resolve(),spec['allowed_reads']+[args.run_spec])
        from src.round10.prototype import execute
        execute(spec);return 0
    if args.validate_worker:
        spec=read(args.run_spec);work=Path(spec['work']);out=Path(spec['output'])
        from src.round10.runtime import configure_guard,validate
        configure_guard(work,out,work/'validator_guard.jsonl',Path(__file__).resolve())
        try:return validate(spec)['exit_code']
        except Exception as exc:
            traceback.print_exc();write(out/'worker_error.json',dict(status='FAIL',error=repr(exc),traceback=traceback.format_exc()));return 1
    if args.guard_probe:
        work=Path(args.result).parent;roots=json.loads(os.environ['ROUND10_WRITE_ROOTS']);allowed=json.loads(os.environ.get('ROUND10_READ_WHITELIST','[]'))
        from src.round10.runtime import configure_guard,guard_probe
        configure_guard(work,Path(roots[1]),Path(os.environ['ROUND10_GUARD_LOG']),Path(__file__).resolve(),allowed)
        return guard_probe(args.result)
    return main()


if __name__=='__main__':raise SystemExit(dispatch())
