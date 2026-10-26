"""Freeze K9 and execute only guarded offline evidence checks."""
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
from src.round8.common import KEYS,canonical,file_record,outcome,read,sha,text,write,separate_paths

def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def configure_guard(work,out,log):
    os.environ.update(ROUND9_WRITE_ROOTS=json.dumps([str(work),str(out)]),ROUND9_GUARD_LOG=str(log),ROUND9_VALIDATOR_ENTRY=str(Path(__file__).resolve()),PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8',TEMP=str(work/'tmp'),TMP=str(work/'tmp'),MPLCONFIGDIR=str(work/'mpl'))
    (work/'tmp').mkdir(exist_ok=True)
    from src.round9.guard import install
    install()

def freeze(policy,out,work,rid):
    from src.round2.evidence import code_manifest
    if (ROOT/'configs/round9.json').read_bytes()!=(Path(policy['freeze_dir'])/'acceptance_policy.json').read_bytes():raise ValueError('PREDECLARED_POLICY_CHANGED')
    manifest=code_manifest();inputs=[]
    for key in ['source_dir','historical_validator_dir','k8_dir']:
        for name in ['run.json','config.json','code_manifest.json','code_snapshot.zip','input_manifest.json','final_status.json','command_result.json','artifact_manifest.json']:
            inputs.append(file_record(Path(policy[key])/name))
    for name in ['execution_start.json','execution_start.zip','acceptance_policy.json','k8_initial_verification.json','development_budget_ledger.json']:
        source=Path(policy['freeze_dir'])/name;inputs.append(file_record(source));shutil.copyfile(source,out/name)
    git={name:subprocess.check_output(['git','-c','safe.directory=G:/fmb666']+args,cwd=ROOT).decode('utf-8') for name,args in [('head',['show','-s','--format=%H','HEAD']),('tree',['show','-s','--format=%T','HEAD']),('status',['status','--porcelain=v1','--untracked-files=all']),('tracked_diff',['diff','--binary','HEAD'])]}
    write(out/'git_at_freeze.json',git)
    ctx=dict(run_id=rid,code_sha256=sha(canonical(manifest)),config_sha256=sha(canonical(policy)),input_sha256=sha(canonical(inputs)),output=str(out),work=str(work),created_utc=utc())
    write(out/'run.json',ctx);write(out/'config.json',dict(validator={k:ctx[k] for k in KEYS},policy=policy));write(out/'code_manifest.json',dict(run_id=rid,code_sha256=ctx['code_sha256'],files=manifest));write(out/'input_manifest.json',dict(run_id=rid,input_sha256=ctx['input_sha256'],files=inputs))
    with zipfile.ZipFile(out/'code_snapshot.zip','w',zipfile.ZIP_DEFLATED) as z:
        for row in manifest:
            p=Path(row['path']);b=p.read_bytes()
            if sha(b)!=row['sha256']:raise ValueError('K9_CHANGED_DURING_FREEZE')
            z.writestr(p.relative_to(ROOT).as_posix(),b)
    write(out/'environment.json',dict(executable=sys.executable,prefix=sys.prefix,version=sys.version,packages={name:importlib.metadata.version(name) for name in ['numpy','shapely','matplotlib','pywin32']},native_detection_performed=False))
    return ctx

def worker(spec_path):
    spec=read(spec_path);work=Path(spec['work']);out=Path(spec['output']);configure_guard(work,out,work/'validator_guard.jsonl')
    from src.round9.validate import validate
    try:return validate(spec)['exit_code']
    except Exception as exc:
        traceback.print_exc();write(out/'worker_error.json',dict(status='BLOCKED' if isinstance(exc,(FileNotFoundError,PermissionError)) else 'FAIL',error=repr(exc),traceback=traceback.format_exc()))
        return 1

def verify_delivery(out):
    manifest=read(out/'artifact_manifest.json');errors=[]
    wanted={Path(row['path']).resolve() for row in manifest['files']}
    actual={p.resolve() for p in out.rglob('*') if p.is_file() and p not in [out/'artifact_manifest.json',out/'delivery_verification.json']}
    if wanted!=actual:errors.append('ARTIFACT_INVENTORY')
    for row in manifest['files']:
        current=file_record(row['path'])
        if current['sha256']!=row['sha256'] or current['bytes']!=row['bytes']:errors.append('ARTIFACT_RAW_BYTES:'+row['path'])
    summary=read(out/'summary.json');final=read(out/'final_status.json');command=read(out/'command_result.json')
    if summary!=final or command['exit_code']!=summary['exit_code']:errors.append('STATUS_COMMAND_CONFLICT')
    for path in out.rglob('*'):
        if path.is_file() and path.suffix in {'.json','.md','.jsonl','.log'}:
            try:
                value=path.read_bytes().decode('utf-8',errors='strict')
                if path.suffix=='.json':json.loads(value)
            except (ValueError,UnicodeError):errors.append('ENCODING:'+str(path))
    return dict(status='FAIL' if errors else 'PASS',errors=errors,files_checked=len(manifest['files']),manifest=file_record(out/'artifact_manifest.json'),verified_utc=utc(),policy='Disk reread after all status/report/log writes; no recursive self-hash.')

def seal(out,summary,command):
    from src.round9.validate import report
    seal_started=time.perf_counter()
    def save():
        summary['offline_engineering_acceptance']=outcome(summary['checks']);summary['exit_code']=0 if summary['offline_engineering_acceptance']=='PASS' else 1
        command['exit_code']=summary['exit_code'];write(out/'summary.json',summary);write(out/'final_status.json',summary);write(out/'command_result.json',command);report(out,summary,command)
        rows=[file_record(p) for p in sorted(out.rglob('*')) if p.is_file() and p not in [out/'artifact_manifest.json',out/'delivery_verification.json']]
        write(out/'artifact_manifest.json',dict(files=rows,exclusions=['artifact_manifest.json','delivery_verification.json'],algorithm='SHA-256 final raw bytes'))
    summary['checks']['delivery_verification']=dict(status='PASS',errors=[],note='Tentative until verify_delivery reads every finalized member; failure reseals FAIL.')
    save();result=verify_delivery(out)
    if (out/'acceptance_policy.json').exists():
        policy=read(out/'acceptance_policy.json');elapsed=time.perf_counter()-seal_started
        if elapsed>policy['budgets_s']['delivery']:result=dict(result,status='BLOCKED',errors=['DELIVERY_BUDGET_EXCEEDED'])
        summary.setdefault('budget_spent_s',{})['delivery']=elapsed
        if (out/'budget_execution.json').exists():
            budget=read(out/'budget_execution.json');budget['spent']['delivery']=elapsed;budget['delivery_measured_through_first_readback_s']=elapsed
            budget['cumulative_offline_s']+=elapsed+command.get('freeze_elapsed_s',0)
            if budget['cumulative_offline_s']>policy['total_budget_s']:result=dict(result,status='BLOCKED',errors=['TOTAL_BUDGET_EXCEEDED'])
            write(out/'budget_execution.json',budget)
    if result['status']!='PASS':
        summary['checks']['delivery_verification']=dict(status=result['status'],errors=result['errors'])
    # Budget metadata and all final status changes precede the final manifest.
    save();result=verify_delivery(out)
    if result['status']!='PASS' and summary['checks']['delivery_verification']['status']=='PASS':
        summary['checks']['delivery_verification']=dict(status='FAIL',errors=result['errors']);save();result=verify_delivery(out)
    write(out/'delivery_verification.json',result)
    return summary['exit_code'] if result['status']=='PASS' else 1

def main():
    if Path(sys.executable).resolve()!=Path(r'D:\conda_envs\fmb\python.exe').resolve():raise ValueError('FMB_INTERPRETER_REQUIRED')
    policy=read(ROOT/'configs/round9.json')
    if policy['native_activation_budget']!=0:raise ValueError('ZERO_NATIVE_BUDGET_REQUIRED')
    stamp=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y%m%dT%H%M%S');rid=stamp+'_offline_'+uuid.uuid4().hex[:10]
    out=Path(policy['output_root'])/rid;work=ROOT/'work/round9'/rid
    separate_paths(policy['source_dir'],policy['historical_validator_dir'],out,work)
    if out.is_relative_to(Path(policy['k8_dir'])):raise ValueError('K8_OUTPUT_OVERLAP')
    out.mkdir(parents=True,exist_ok=False);work.mkdir(parents=True,exist_ok=False);print('OUTPUT',out,'WORK',work,flush=True)
    freeze_start=time.perf_counter();ctx=freeze(policy,out,work,rid);freeze_elapsed=time.perf_counter()-freeze_start
    spec=dict(policy=policy,root=str(ROOT),output=str(out),work=str(work),subject=read(Path(policy['source_dir'])/'run.json'),validator=ctx);write(work/'run_spec.json',spec)
    configure_guard(work,out,work/'launcher_guard.jsonl')
    argv=[sys.executable,'-B',str(Path(__file__).resolve()),'--validate-worker','--run-spec',str(work/'run_spec.json')]
    start=time.perf_counter();started=utc();timed_out=False
    with (work/'validator.stdout.log').open('wb') as stdout,(work/'validator.stderr.log').open('wb') as stderr:
        try:proc=subprocess.run(argv,cwd=ROOT,env=os.environ.copy(),stdout=stdout,stderr=stderr,timeout=policy['total_budget_s']);rc=proc.returncode
        except subprocess.TimeoutExpired:rc=124;timed_out=True
    command=dict(argv=argv,invoked_entry=[sys.executable,'-X','utf8','-B',str(Path(__file__).resolve())],started_utc=started,completed_utc=utc(),elapsed_s=time.perf_counter()-start,freeze_elapsed_s=freeze_elapsed,worker_exit_code=rc,exit_code=rc,timed_out=timed_out)
    for name in ['validator.stdout.log','validator.stderr.log','launcher_guard.jsonl','validator_guard.jsonl','guard_probe.jsonl','guard_probe_result.json']:
        if (work/name).exists():shutil.copyfile(work/name,out/name)
    if (out/'summary.json').exists():summary=read(out/'summary.json')
    else:
        error=read(out/'worker_error.json') if (out/'worker_error.json').exists() else dict(status='BLOCKED',error='WORKER_DID_NOT_COMPLETE')
        summary=dict(validator_run_id=rid,subject_run_id=spec['subject']['run_id'],validator_code_sha256=ctx['code_sha256'],checks={'worker_completion':dict(status=error['status'],errors=[error['error']])},official_contract_review='NOT_COMPLETED',official_readiness='UNRESOLVED',search_error_basis='UNRESOLVED',historical_coverage='UNVERIFIED',work=str(work),output=str(out),next_scientific_run_gate='BLOCKED',official_score=None,fresh_native_validation_performed=False,round9_native_activation_count=0)
    if rc!=0:summary['checks']['worker_exit']=dict(status='BLOCKED' if timed_out else 'FAIL',errors=['WORKER_NONZERO:'+str(rc)])
    from src.round2.evidence import code_manifest
    if code_manifest()!=read(out/'code_manifest.json')['files']:summary['checks']['launcher_code_preservation']=dict(status='FAIL',errors=['K9_CHANGED'])
    write(out/'artifact_index.json',dict(report='audit_report.md',status='final_status.json',command='command_result.json',freeze='k8_freeze.json',dependency='dependency_binding.json',header_cases='binding_counterexamples.json',legacy_cases='legacy_counterexamples.json',tests='regression.json',official='official_contract.md',statistics='engineering_statistics.json',error_method='search_error_method.md',error_data='search_error_analysis.json',history='historical_coverage.json',preservation='source_preservation.json',budget='budget_execution.json',guard='native_guard.json',work=str(work)))
    final=seal(out,summary,command);print('OFFLINE',summary['offline_engineering_acceptance'],'EXIT',final,'WORKER_SECONDS',command['elapsed_s'],'OUTPUT',out,flush=True);return final

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--validate-worker',action='store_true');parser.add_argument('--run-spec');parser.add_argument('--regression-worker',action='store_true');parser.add_argument('--guard-probe',action='store_true');parser.add_argument('--result');args=parser.parse_args()
    if args.regression_worker:
        from src.round9.regression import worker as regression_worker
        raise SystemExit(regression_worker(args.result))
    if args.guard_probe:
        from src.round9.guard import install
        install()
        from src.round9.validate import guard_probe
        raise SystemExit(guard_probe(Path(args.result)))
    if args.validate_worker:raise SystemExit(worker(args.run_spec))
    raise SystemExit(main())
