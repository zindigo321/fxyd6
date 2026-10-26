"""Freeze K, run a guarded offline validator, then finalize closed-log artifacts."""
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
from src.round8.common import KEYS, apply_final_checks, canonical, file_record, outcome, read, separate_paths, sha, text, write


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def configure_guard(work,out,log):
    os.environ.update(ROUND8_WRITE_ROOTS=json.dumps([str(work),str(out)]),ROUND8_GUARD_LOG=str(log),
                      ROUND8_VALIDATOR_ENTRY=str(Path(__file__).resolve()),PYTHONDONTWRITEBYTECODE='1',PYTHONIOENCODING='utf-8',
                      TEMP=str(work/'tmp'),TMP=str(work/'tmp'),MPLCONFIGDIR=str(work/'mpl'))
    (work/'tmp').mkdir(exist_ok=True)
    from src.round8.guard import install
    install()


def validator_worker(spec_path):
    spec=read(spec_path);work=Path(spec['work']);out=Path(spec['output'])
    configure_guard(work,out,work/'validator_guard.jsonl')
    from src.round8.validate import validate
    try:
        summary=validate(spec['subject'],spec['validator'],spec['policy']['source_dir'],spec['policy']['historical_validator_dir'],out,work,spec['policy'])
        return summary['exit_code']
    except Exception as exc:
        traceback.print_exc()
        write(out/'unhandled_validator_error.json',dict(status='FAIL',error=repr(exc),traceback=traceback.format_exc()))
        return 1


def freeze(out,work,rid,policy):
    from src.round2.evidence import code_manifest
    manifest=code_manifest();s=Path(policy['source_dir']);v=Path(policy['historical_validator_dir']);baseline=Path(policy['baseline_evidence_dir'])
    inputs=[file_record(folder/name) for folder in [s,v] for name in ['run.json','config.json','code_manifest.json','code_snapshot.zip','input_manifest.json','artifact_manifest.json','log_manifest.json','final_status.json','command_result.json']]
    inputs += [file_record(baseline/name) for name in ['baseline_git.json','C_worktree_manifest.json','C_worktree_snapshot.zip','C_git_manifest.json','C_git_snapshot.zip','test_result.json','command_result.json']]
    ctx=dict(run_id=rid,code_sha256=sha(canonical(manifest)),config_sha256=sha(canonical(policy)),input_sha256=sha(canonical(inputs)),created_utc=utc(),kind=policy['kind'],output=str(out),work=str(work))
    command=['git','-c','safe.directory=G:/fmb666']
    git={}
    for name,args in [('head',['show','-s','--format=%H','HEAD']),('tree',['show','-s','--format=%T','HEAD']),('status',['status','--porcelain=v1'])]:
        p=subprocess.run(command+args,cwd=ROOT,capture_output=True,check=True);git[name]=p.stdout.decode('utf-8').strip()
    if git['head']!=policy['baseline_commit'] or read(baseline/'baseline_git.json')['head']!=policy['baseline_commit']:
        raise ValueError('BASELINE_COMMIT_CHANGED')
    tree=subprocess.run(command+['ls-tree','-rz','--full-tree','HEAD'],cwd=ROOT,capture_output=True,check=True).stdout
    blobs={row.split(b'\t',1)[1].decode('utf-8'):row.split(b'\t',1)[0].split()[2].decode('ascii') for row in tree.split(b'\0') if row}
    if blobs!={r['path']:r['git_blob'] for r in read(baseline/'C_git_manifest.json')}:
        raise ValueError('BASELINE_GIT_TREE_BINDING')
    git['git_tree_blob_binding_verified']=True
    initial=Path(policy['execution_start_dir'])
    for name in ['execution_start.json','execution_start.zip']:
        inputs.append(file_record(initial/name))
        shutil.copyfile(initial/name,out/name)
    if policy.get('prior_round8_review'):
        inputs.append(file_record(policy['prior_round8_review']))
        shutil.copyfile(policy['prior_round8_review'],out/'prior_round8_review.json')
    ctx['input_sha256']=sha(canonical(inputs))
    write(out/'acceptance_policy.json',policy);write(out/'run.json',ctx);write(out/'config.json',dict(validator={k:ctx[k] for k in KEYS},policy=policy))
    write(out/'code_manifest.json',dict(run_id=rid,files=manifest,code_sha256=ctx['code_sha256'],algorithm='sha256(canonical manifest including absolute paths, file raw SHA-256 and sizes)'))
    write(out/'input_manifest.json',dict(run_id=rid,files=inputs,input_sha256=ctx['input_sha256'],scope='Direct anchor inputs, not a claim that every historical member was read; separate evidence_dependency_plan and historical_manifests audit each reference.'))
    write(out/'git_at_freeze.json',git)
    write(out/'environment.json',dict(executable=sys.executable,prefix=sys.prefix,version=sys.version,packages={x:importlib.metadata.version(x) for x in ['numpy','shapely','matplotlib','pywin32']},native_detection_performed=False))
    with zipfile.ZipFile(out/'code_snapshot.zip','w',zipfile.ZIP_DEFLATED) as z:
        for item in manifest:
            path=Path(item['path']);blob=path.read_bytes()
            if sha(blob)!=item['sha256']:raise ValueError('CODE_CHANGED_DURING_FREEZE')
            z.writestr(path.relative_to(ROOT).as_posix(),blob)
    for name in ['baseline_git.json','C_worktree_manifest.json','C_worktree_snapshot.zip','C_git_manifest.json','C_git_snapshot.zip']:
        shutil.copyfile(baseline/name,out/name)
    snapshot_index={}
    for label,folder in [('S',s),('V',v)]:
        target=out/'snapshots'/label;target.mkdir(parents=True)
        snapshot_index[label]=[]
        for name in ['run.json','config.json','code_manifest.json','code_snapshot.zip']:
            shutil.copyfile(folder/name,target/name);snapshot_index[label].append(file_record(target/name))
    target=out/'snapshots/C';target.mkdir(parents=True)
    with zipfile.ZipFile(baseline/'C_worktree_snapshot.zip') as z:(target/'config_round7.json').write_bytes(z.read('configs/round7.json'))
    snapshot_index['C']=dict(commit=policy['baseline_commit'],tree=read(baseline/'baseline_git.json')['tree'],git_snapshot='C_git_snapshot.zip',worktree_snapshot='C_worktree_snapshot.zip',config=file_record(target/'config_round7.json'))
    snapshot_index['K']=dict(context=ctx,code_snapshot='code_snapshot.zip',code_manifest='code_manifest.json',acceptance_config='config.json')
    write(out/'snapshots/index.json',snapshot_index)
    return ctx


def delivery(out):
    excluded={'artifact_manifest.json','delivery_verification.json'}
    rows=[file_record(p) for p in sorted(out.rglob('*')) if p.is_file() and p.name not in excluded]
    write(out/'artifact_manifest.json',dict(files=rows,exclusions=sorted(excluded),algorithm='SHA-256 of final raw bytes; verification hashes this manifest; no self-reference.'))
    checks=[]
    for item in rows:
        current=file_record(item['path']);checks.append(dict(path=item['path'],matches=current['sha256']==item['sha256'] and current['bytes']==item['bytes']))
    result=dict(status='PASS' if all(x['matches'] for x in checks) else 'FAIL',manifest=file_record(out/'artifact_manifest.json'),listed=len(rows),matched=sum(x['matches'] for x in checks),checked_utc=utc(),files=checks)
    write(out/'delivery_verification.json',result)
    return result


def encoding_audit(out,summary):
    rows=[];errors=[]
    for p in sorted(out.rglob('*')):
        if not p.is_file() or p.suffix not in {'.json','.md','.diff','.log','.jsonl'} or p.name in {'encoding_audit.json','artifact_manifest.json','delivery_verification.json'}:continue
        try:
            blob=p.read_bytes();decoded=blob.decode('utf-8',errors='strict')
            if p.suffix=='.json':json.loads(decoded)
            if '\ufffd' in decoded:errors.append('REPLACEMENT_CHARACTER:'+str(p))
            rows.append(dict(path=p.relative_to(out).as_posix(),utf8_valid=True,sha256=sha(blob)))
        except (OSError,ValueError) as exc:errors.append(str(p)+':'+repr(exc))
    known='原生证据来自未受影响的历史科学运行S' if summary['offline_acceptance']=='PASS' else '复合离线验收未通过'
    if known not in (out/'audit_report.md').read_bytes().decode('utf-8'):errors.append('CHINESE_READBACK')
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,known_chinese_readback=known,files=rows,
                scope='UTF-8 readback refreshed after final status seal; final raw bytes are also bound by artifact_manifest.')
    write(out/'encoding_audit.json',result)
    return result


def seal(out,summary,command):
    """Finalize status and logs before each one-direction delivery manifest."""
    from src.round8.validate import report
    def persist():
        command['exit_code']=summary['exit_code']
        command['validator_worker_exit_code']=command['worker_exit_code']
        write(out/'summary.json',summary);write(out/'final_status.json',summary)
        write(out/'command_result.json',command);report(out,summary,command)
    persist()
    encoding=encoding_audit(out,summary)
    apply_final_checks(summary,{'encoding_readback':dict(status=encoding['status'],errors=encoding['errors'],artifact='encoding_audit.json')})
    persist()
    result=delivery(out)
    apply_final_checks(summary,{'delivery_readback':dict(status=result['status'],errors=[] if result['status']=='PASS' else ['DELIVERY_RAW_BYTES_MISMATCH'],artifact='delivery_verification.json')})
    persist()
    # Status/report writes above invalidate their earlier encoding-audit hashes.
    # Refresh after sealing; this audit contains no self-hash or manifest hash.
    refreshed=encoding_audit(out,summary)
    if refreshed['status']!=summary['checks']['encoding_readback']['status']:
        apply_final_checks(summary,{'encoding_readback':dict(status='FAIL',errors=['ENCODING_CHANGED_DURING_SEAL'],artifact='encoding_audit.json')})
        persist();encoding_audit(out,summary)
    result=delivery(out)
    if result['status']!='PASS':
        apply_final_checks(summary,{'delivery_readback':dict(status='FAIL',errors=['FINAL_DELIVERY_RAW_BYTES_MISMATCH'])})
        persist();encoding_audit(out,summary);delivery(out)
    return summary['exit_code']


def main(output=None):
    if Path(sys.executable).resolve()!=Path(r'D:\conda_envs\fmb\python.exe').resolve():raise ValueError('FMB_INTERPRETER_REQUIRED')
    policy=read(ROOT/'configs/round8.json')
    if policy['native_activation_budget']!=0:raise ValueError('NATIVE_BUDGET_MUST_BE_ZERO')
    stamp=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y%m%dT%H%M%S')
    rid=stamp+'_offline_'+uuid.uuid4().hex[:10]
    out=Path(output).resolve() if output else Path(policy['output_root'])/rid
    work=ROOT/'work/round8'/rid
    separate_paths(policy['source_dir'],policy['historical_validator_dir'],out,work)
    out.mkdir(parents=True,exist_ok=False);work.mkdir(parents=True,exist_ok=False)
    print('OUTPUT',out,'WORK',work,flush=True)
    ctx=freeze(out,work,rid,policy)
    spec=dict(policy=policy,validator=ctx,subject=read(Path(policy['source_dir'])/'run.json'),output=str(out),work=str(work))
    write(work/'run_spec.json',spec)
    configure_guard(work,out,work/'launcher_guard.jsonl')
    argv=[sys.executable,'-B',str(Path(__file__).resolve()),'--validate-worker','--run-spec',str(work/'run_spec.json')]
    started=utc();t=time.perf_counter()
    with (work/'validator.stdout.log').open('wb') as stdout,(work/'validator.stderr.log').open('wb') as stderr:
        proc=subprocess.run(argv,cwd=ROOT,env=os.environ.copy(),stdout=stdout,stderr=stderr)
    command=dict(argv=argv,invoked_entry=[sys.executable,'-B',str(Path(__file__).resolve())]+(['--output',str(out)] if output else []),started_utc=started,completed_utc=utc(),elapsed_s=time.perf_counter()-t,exit_code=proc.returncode,worker_exit_code=proc.returncode,timed_out=False,started=True,completed=True)
    write(out/'command_result.json',command)
    for name in ['validator.stdout.log','validator.stderr.log','validator_guard.jsonl','launcher_guard.jsonl']:
        p=work/name
        if p.exists():shutil.copyfile(p,out/name)
    if not (out/'summary.json').exists():
        write(out/'final_status.json',dict(offline_acceptance='FAIL',exit_code=proc.returncode,reason='VALIDATOR_DID_NOT_COMPLETE',fresh_native_validation_performed=False,round8_native_activation_count=0))
        delivery(out);print('VALIDATOR_FAILED',out,flush=True);return 1
    summary=read(out/'summary.json')
    if proc.returncode!=summary['exit_code']:summary['offline_acceptance']='FAIL';summary['exit_code']=1;summary['checks']['process_exit']=dict(status='FAIL',errors=['COMMAND_RESULT_CONFLICT'])
    from src.round2.evidence import code_manifest
    if code_manifest()!=read(out/'code_manifest.json')['files']:summary['offline_acceptance']='FAIL';summary['exit_code']=1;summary['checks']['launcher_code_preservation']=dict(status='FAIL',errors=['K_CHANGED'])
    write(out/'artifact_index.json',dict(report='audit_report.md',status='final_status.json',command='command_result.json',policy='acceptance_policy.json',identity='source_identity.json',dependency='dependency_binding.json',functions='function_evidence.json',erratum='hash_erratum.json',science=['candidate_queries.json','trajectories.json','camera_constraints.json','independent_arithmetic.json','geometry_reopen.json'],tests=['complete_regression.json','counterexamples.json'],preservation='source_raw_preservation.json',coverage='historical_manifests.json',manifest='artifact_manifest.json',verification='delivery_verification.json',raw_work=str(work)))
    rc=seal(out,summary,command)
    print('OFFLINE',summary['offline_acceptance'],'COMMAND_EXIT',proc.returncode,'DELIVERY_EXIT',rc,'ELAPSED',command['elapsed_s'],'OUTPUT',out,flush=True)
    return rc


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output');parser.add_argument('--validate-worker',action='store_true');parser.add_argument('--run-spec');parser.add_argument('--regression-worker',action='store_true');parser.add_argument('--result')
    args=parser.parse_args()
    if args.regression_worker:
        from src.round8.regression import worker
        raise SystemExit(worker(args.result))
    if args.validate_worker:raise SystemExit(validator_worker(args.run_spec))
    raise SystemExit(main(args.output))
