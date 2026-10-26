"""Mutate actual frozen evidence in memory or small round8-only copies."""
import copy
import json
from pathlib import Path
import shutil
import zipfile
from .binding import require_checker, checker_identity, snapshot
import inspect

def actual_checker(name):
    if name.startswith('delete_empty_') or name in {'duplicate_query','orphan_query','failed_query','query_window','query_type','event_endpoint','event_reidentified_as_K','subject_validator_mixed','candidate_window'}: f=query_audit
    elif name.startswith('camera_') or name in {'shared_sensor_constraint','missing_satellite','missing_facility','extra_satellite','extra_sensor'}: f=camera_audit
    elif name in {'source_zip_member','manifest_run_replaced'}: f=snapshot
    elif name=='missing_native_stage':f=audit_stage
    elif name=='forged_fresh_native':f=no_fresh_native
    elif name=='wrong_algorithm_label':f=text_hashes
    elif name=='scientific_file_missing':f=file_record
    else:f=preserve
    return dict(module=f.__module__,function=f.__qualname__,module_raw_sha256=sha(Path(inspect.getsourcefile(f)).read_bytes()))

from src.round8.common import KEYS, NORMALIZATION, canonical, file_record, identities, no_fresh_native, preserve, read, sha, text_hashes, write
from src.round8.native import audit_stage
from src.round8.science import camera_audit, query_audit


def run(subject,validator,cfg,source,v,root,work,points,opps,candidates,queries,raw,geometry,s_blobs,v_blobs,checker):
    require_checker(checker)
    native_equivalence=checker.native_equivalence
    base=work/'counterexamples';base.mkdir();rows=[]
    def record(name,expected,actual,provenance,baseline_pass=True):
        codes=actual.get('errors',[]);accepted=baseline_pass and actual['status']!='PASS' and any(x.startswith(expected) for x in codes)
        rows.append(dict(case=name,kind='ROUND9_REEXECUTED_LEGACY_MUTATION',expected_reason_code=expected,
                         actual_reason_codes=codes,actual_status=actual['status'],status='PASS' if accepted else 'FAIL',baseline_pass=baseline_pass,
                         input_source=provenance,source_unchanged_by_design=True,actual_checker=checker_identity(checker.native_equivalence) if name in {'global_caps','import_alias','search_callback','dispatch','audit_patch_cannot_hide_global_change'} else actual_checker(name)))
    def qa(qq=queries,rr=raw,cc=candidates,oo=opps,ctx=subject):
        return query_audit(ctx,cfg,points,oo,cc,qq,rr,geometry)
    positive=qa();write(base/'query_positive_control.json',positive)
    for query in queries:
        if not query['intervals']:
            changed=[q for q in queries if q['query_id']!=query['query_id']]
            record('delete_empty_'+query['query_id'],'MISSING_CANDIDATE_QUERY:',qa(qq=changed),dict(path=str(source/'G/T7/raw_access_queries.json'),removed_query_id=query['query_id'],mutated_sha256=sha(canonical(changed))),positive['status']=='PASS')
    mutations=[]
    q=copy.deepcopy(queries);q.append(copy.deepcopy(q[0]));mutations.append(('duplicate_query','DUPLICATE_QUERY_ID',dict(qq=q)))
    q=copy.deepcopy(queries);q[0]['candidate_id']='ORPHAN';mutations.append(('orphan_query','ORPHAN_QUERY',dict(qq=q)))
    q=copy.deepcopy(queries);q[0]['query_status']='FAILED';mutations.append(('failed_query','QUERY_NOT_COMPLETE_OR_WRONG_KIND',dict(qq=q)))
    q=copy.deepcopy(queries);q[0]['window'][0]-=.01;mutations.append(('query_window','REVERSE_QUERY_BINDING',dict(qq=q)))
    q=copy.deepcopy(queries);q[0]['query_type']='MEDIUM_CONVERGENCE';mutations.append(('query_type','QUERY_NOT_COMPLETE_OR_WRONG_KIND',dict(qq=q)))
    r=copy.deepcopy(raw);r[0]['start_epsec']+=.0005;mutations.append(('event_endpoint','QUERY_EVENT_SET_MISMATCH',dict(rr=r)))
    r=copy.deepcopy(raw);r[0].update({k:validator[k] for k in KEYS});mutations.append(('event_reidentified_as_K','SOURCE_IDENTITY',dict(rr=r)))
    mutations.append(('subject_validator_mixed','SOURCE_IDENTITY',dict(ctx=validator)))
    c=copy.deepcopy(candidates);c[0]['local_query_window'][0]+=.0001;mutations.append(('candidate_window','CANDIDATE_SOURCE_WINDOW_MISMATCH',dict(cc=c)))
    for name,reason,kwargs in mutations:
        result=qa(**kwargs);record(name,reason,result,dict(path=str(source/'G/T7'),mutation_sha256=sha(canonical(kwargs))),positive['status']=='PASS')
    project=source/'G/T7/project';prior=Path(cfg['round7']['source_round6'])/'G/T6/project';ids=[p['point_id'] for p in points];sats=cfg['round7']['satellites']
    camera_positive=camera_audit(project,prior,sats,ids);write(base/'camera_positive_control.json',camera_positive)
    copydir=base/'camera';copydir.mkdir()
    for path in project.iterdir():
        if path.suffix in {'.sa','.sn','.f','.sc'}:shutil.copyfile(path,copydir/path.name)
    def camera_fault(name,reason,path,new):
        old=path.read_bytes() if path.exists() else None
        if new is None:path.unlink()
        else:path.write_bytes(new)
        try:
            result=camera_audit(copydir,prior,sats,ids)
            record(name,reason,result,dict(original_project=str(project),temporary_path=str(path),original_sha256=sha(old) if old else None,mutated_sha256=sha(new) if new else None),camera_positive['status']=='PASS')
        finally:
            if old is None:path.unlink()
            else:path.write_bytes(old)
    satpath=copydir/(sats[0]+'.sa');blob=satpath.read_bytes()
    camera_fault('camera_wrong_child','CAMERA_CHILD_BINDING',satpath,blob.replace(b'Camera',b'WrongCamera'))
    sensor=copydir/'Camera.sn';blob=sensor.read_bytes()
    camera_fault('shared_sensor_constraint','CONSTRAINT_BLOCK_CHANGED',sensor,blob.replace(b'BEGIN AccessConstraints',b'BEGIN AccessConstraints\n MutatedConstraint 1',1))
    camera_fault('missing_satellite','CAMERA_OBJECT_INVENTORY',satpath,None)
    camera_fault('missing_facility','CAMERA_OBJECT_INVENTORY',copydir/(ids[0]+'.f'),None)
    camera_fault('extra_satellite','CAMERA_OBJECT_INVENTORY',copydir/'Sat999.sa',satpath.read_bytes())
    camera_fault('extra_sensor','CAMERA_OBJECT_INVENTORY',copydir/'Unexpected.sn',sensor.read_bytes())
    # Native equivalence must include globals, import aliases, callbacks and
    # dispatch, even when individual production function bodies are unchanged.
    for name,path,old,new in [
        ('global_caps','src/round7/audit.py',b'B1=600',b'B1=601'),
        ('import_alias','src/round7/production.py',b'Model as BaseModel',b'OtherModel as BaseModel'),
        ('search_callback','src/round7/experiments.py',b'Model,search_batch,ENTRY',b'Model,screen as search_batch,ENTRY'),
        ('dispatch','src/round7/experiments.py',b"task=='r7_reopen'",b"task=='r7_other'")]:
        changed=dict(v_blobs);changed[path]=changed[path].replace(old,new,1)
        result=native_equivalence(v_blobs,changed)
        record(name,'UNPROVED_EXECUTABLE_OR_CONFIG_CHANGE',result,dict(path=path,old_sha256=sha(v_blobs[path]),mutated_sha256=sha(changed[path])),changed[path]!=v_blobs[path])
    changed=dict(v_blobs);path='src/round7/audit.py';changed[path]=changed[path].replace(b'B1=600',b'B1=601',1)
    record('audit_patch_cannot_hide_global_change','MODULE_GLOBAL_OR_IMPORT_CHANGED',
           native_equivalence(s_blobs,changed,allow_audit_patch=True),
           dict(path=path,original_sha256=sha(v_blobs[path]),mutated_sha256=sha(changed[path])),changed[path]!=v_blobs[path])
    # ZIP and manifests retain their original schema and S identity; only the
    # named member bytes or the explicit run field are changed.
    zipdir=base/'snapshot';zipdir.mkdir()
    for name in ['run.json','code_manifest.json']:shutil.copyfile(source/name,zipdir/name)
    with zipfile.ZipFile(zipdir/'code_snapshot.zip','w',zipfile.ZIP_DEFLATED) as z:
        for name,blob in s_blobs.items():z.writestr(name,blob+(b'\n# injected\n' if name=='src/round7/production.py' else b''))
    _,res=snapshot(zipdir,root);record('source_zip_member','SNAPSHOT_MEMBER:',res,dict(source_zip=str(source/'code_snapshot.zip'),member='src/round7/production.py'))
    shutil.copyfile(source/'code_snapshot.zip',zipdir/'code_snapshot.zip');manifest=read(zipdir/'code_manifest.json');manifest['run_id']=validator['run_id'];write(zipdir/'code_manifest.json',manifest)
    _,res=snapshot(zipdir,root);record('manifest_run_replaced','CODE_MANIFEST_IDENTITY',res,dict(source_manifest=str(source/'code_manifest.json'),changed_field='run_id'))
    empty=base/'missing_native_stage';empty.mkdir()
    try:audit_stage(subject,empty,'r7_dataset_T7');res=dict(status='PASS',errors=[])
    except FileNotFoundError:res=dict(status='BLOCKED',errors=['MISSING_NATIVE_STAGE'])
    record('missing_native_stage','MISSING_NATIVE_STAGE',res,dict(source=str(source/'G/T7/lifecycle.json'),temporary_missing_path=str(empty/'lifecycle.json')))
    oldpath=source/'baseline/round6_corrected_report.md';blob=oldpath.read_bytes();lf=blob.replace(b'\r\n',b'\n');path=base/'changed_report.md';path.write_bytes(lf)
    expected=file_record(oldpath);actual=file_record(path)
    result=dict(status='PASS' if preserve(expected,actual) else 'FAIL',errors=[] if preserve(expected,actual) else ['RAW_BYTES_CHANGED'])
    record('line_endings_only','RAW_BYTES_CHANGED',result,dict(source=str(oldpath),original=expected,mutated=actual,normalized_equal=text_hashes(blob)['normalized_text_sha256']==text_hashes(lf)['normalized_text_sha256']))
    try:text_hashes(blob,'UTF-8 strip then LF');result=dict(status='PASS',errors=[])
    except ValueError as exc:result=dict(status='FAIL',errors=[str(exc)])
    record('wrong_algorithm_label','HASH_ALGORITHM_LABEL',result,dict(source=str(oldpath),algorithm='UTF-8 strip then LF'))
    scientific=source/'G/T7/raw_intervals.json';path=base/'corrupt_scientific.json';path.write_bytes(b'{bad JSON')
    ok=preserve(file_record(scientific),file_record(path))
    record('scientific_file_corrupt','RAW_BYTES_CHANGED',dict(status='PASS' if ok else 'FAIL',errors=[] if ok else ['RAW_BYTES_CHANGED']),dict(source=str(scientific),temporary_path=str(path),exact_fault_bytes_hex=b'{bad JSON'.hex(),expected_sha256=file_record(scientific)['sha256'],actual_sha256=file_record(path)['sha256']))
    missing=base/'missing_scientific.json'
    try:file_record(missing);res=dict(status='PASS',errors=[])
    except FileNotFoundError:res=dict(status='BLOCKED',errors=['CRITICAL_FILE_MISSING'])
    record('scientific_file_missing','CRITICAL_FILE_MISSING',res,dict(source=str(scientific),temporary_missing_path=str(missing)))
    falseclaim=dict(subject_run_id=subject['run_id'],validator_run_id=validator['run_id'],native_evidence_origin_run_id=subject['run_id'],round8_native_activation_count=0,fresh_native_validation_performed=True)
    record('forged_fresh_native','FRESH_NATIVE_CLAIM',dict(status='FAIL' if not no_fresh_native(falseclaim) else 'PASS',errors=['FRESH_NATIVE_CLAIM'] if not no_fresh_native(falseclaim) else []),falseclaim)
    result=dict(status='PASS' if all(x['status']=='PASS' for x in rows) else 'FAIL',cases=rows,case_count=len(rows),
                empty_query_removals=sum(x['case'].startswith('delete_empty_') for x in rows),query_positive_status=positive['status'],camera_positive_status=camera_positive['status'],
                scope='All faults are in memory or this round8 work directory. A reason-specific rejection is required, not merely an exception or missing schema field.')
    write(base/'results.json',result)
    return result
