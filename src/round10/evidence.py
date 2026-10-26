"""Direct byte reads are distinguished from bound historical report reuse."""
import shutil
import zipfile
from pathlib import Path
from src.round8.common import KEYS, canonical, file_record, read, sha, write


def verify_record(row):
    actual=file_record(row['path'])
    if actual['sha256']!=row['sha256'] or 'bytes' in row and actual['bytes']!=row['bytes']:
        raise ValueError('HISTORICAL_RAW_HASH_MISMATCH:'+row['path'])
    return actual


def verify_manifest(folder, name):
    rows=read(folder/name)['files'];actual=[]
    for row in rows:
        p=Path(row['path']);p=p if p.is_absolute() else folder/p
        actual.append(verify_record(dict(row,path=str(p))))
    return actual


def frozen_sources(policy, root, out):
    k9=Path(policy['k9_dir']);prep=Path(policy['preparation_dir']);seen={}
    def track(path, expected=None):
        actual=verify_record(dict(expected,path=str(path))) if expected else file_record(path)
        seen[actual['path']]=actual;return actual
    ctx=read(k9/'run.json');cfg=read(k9/'config.json');code=read(k9/'code_manifest.json');inp=read(k9/'input_manifest.json')
    if ctx['code_sha256']!=policy['k9_code_sha256'] or sha(canonical(code['files']))!=ctx['code_sha256']:
        raise ValueError('K9_CODE_IDENTITY')
    if sha(canonical(cfg['policy']))!=ctx['config_sha256'] or sha(canonical(inp['files']))!=ctx['input_sha256']:
        raise ValueError('K9_CONFIG_INPUT_IDENTITY')
    if any(cfg['validator'][k]!=ctx[k] for k in KEYS):raise ValueError('K9_WRAPPER_IDENTITY')
    counts={}
    for name in ['code_manifest.json','artifact_manifest.json','input_manifest.json']:
        records=verify_manifest(k9,name);seen.update({r['path']:r for r in records});counts[name]=len(records)
    if counts!={'code_manifest.json':126,'artifact_manifest.json':90,'input_manifest.json':29}:
        raise ValueError('K9_INVENTORY_CHANGED')
    if track(k9/'artifact_manifest.json')['sha256']!=read(k9/'delivery_verification.json')['manifest']['sha256']:
        raise ValueError('K9_DELIVERY_ANCHOR')
    copy=out/'frozen_K9';copy.mkdir()
    names=['run.json','config.json','code_manifest.json','code_snapshot.zip','artifact_manifest.json','input_manifest.json','delivery_verification.json','final_status.json','command_result.json','binding_counterexamples.json','legacy_counterexamples.json','source_preservation.json','historical_coverage.json','k8_freeze.json','official_contract.json','official_original_extract.json']
    for name in names:
        track(k9/name)
        if (prep/('K9_'+name)).exists() and track(k9/name)['sha256']!=file_record(prep/('K9_'+name))['sha256']:
            raise ValueError('K9_CHANGED_AFTER_START')
        shutil.copyfile(k9/name,copy/name)
    post=Path(ctx['work'])/'post_delivery_verification.json';track(post);shutil.copyfile(post,copy/post.name)
    if read(post)['status']!='PASS':raise ValueError('K9_POST_DELIVERY_STATUS')
    with zipfile.ZipFile(k9/'code_snapshot.zip') as z:
        expected={Path(r['path']).relative_to(root).as_posix():r for r in code['files']}
        if len(z.namelist())!=len(expected) or set(z.namelist())!=set(expected):raise ValueError('K9_ZIP_INVENTORY')
        for n,r in expected.items():
            if sha(z.read(n))!=r['sha256']:raise ValueError('K9_ZIP_MEMBER')
    audit=Path(policy['audit_dir']);audit_copy=out/'independent_K9_audit';audit_copy.mkdir()
    for p in sorted(audit.iterdir()):
        if p.is_file():track(p);shutil.copyfile(p,audit_copy/p.name)
    old_policy=cfg['policy'];source=Path(old_policy['source_dir']);source_cfg=read(source/'config.json')['config']
    # round9.bind consumes these C and stage-map files directly. Binding the K8
    # manifest alone is insufficient: check the actual member bytes as well.
    k8=Path(old_policy['k8_dir']);k8_manifest=read(k8/'artifact_manifest.json')
    k8_members={str((Path(r['path']) if Path(r['path']).is_absolute() else k8/r['path']).resolve()):r for r in k8_manifest['files']}
    for name in ['C_worktree_snapshot.zip','C_worktree_manifest.json','C_git_snapshot.zip','C_git_manifest.json','historical_native_evidence.json']:
        path=k8/name;expected=k8_members.get(str(path.resolve()))
        if expected is None:raise ValueError('K8_DIRECT_MEMBER_NOT_ANCHORED:'+name)
        track(path,expected)
    for name in ['C_worktree_snapshot.zip','C_worktree_manifest.json','C_git_snapshot.zip','C_git_manifest.json','historical_native_evidence.json']:
        shutil.copyfile(k8/name,copy/('K8_'+name))
    historical_plan=read(k9/'source_read_plan.json')
    direct=[source/'config.json',source/'run.json',source/'grid/frozen.json',source/'selection.json',source/'G/T7/opportunities_screened.json',
            source/'G/T7/raw_intervals.json',source/'G/T7/raw_access_queries.json',source/'G/T7/candidate_ledger.json',
            Path(source_cfg['round7']['source_round6'])/'G/T6/raw_intervals.json',Path(source_cfg['round7']['source_round6'])/'grid/frozen.json']
    source_original=read(k9/'official_original_extract.json')['source'];direct.append(Path(source_original['path']))
    screen=read(source/'G/T7/opportunities_screened.json')
    direct.extend(Path(p['trajectory']['path']) for p in screen['pairs'])
    for p in sorted(set(direct)):
        expected=historical_plan.get(str(p),{}).get('expected')
        if expected is None:raise ValueError('DIRECT_SOURCE_NOT_BOUND_BY_K9:'+str(p))
        track(p,expected)
    states={}
    for label,folder in [('S',source),('V',Path(old_policy['historical_validator_dir'])),('K8',Path(old_policy['k8_dir'])),('K9',k9)]:
        for name in ['run.json','config.json','code_snapshot.zip','code_manifest.json','final_status.json','command_result.json']:
            track(folder/name)
        state=read(folder/'final_status.json');command=read(folder/'command_result.json')
        status=state['business']['core_acceptance'] if label=='S' else state['status'] if label=='V' else state['offline_acceptance'] if label=='K8' else state['offline_engineering_acceptance']
        states[label]=dict(status=status,exit_code=command['exit_code'],identity={k:read(folder/'run.json')[k] for k in KEYS})
    if [(states[n]['status'],states[n]['exit_code']) for n in ['S','V','K8','K9']] != [('FAIL',1),('BLOCKED',1),('PASS',0),('PASS',0)]:
        raise ValueError('HISTORICAL_STATUS_CHANGED')
    defect=read(k9/'k8_freeze.json')['previous_round8_defect']
    for r in defect['files']:track(Path(r['path']),r)
    reuse=read(k9/'legacy_counterexamples.json');headers=read(k9/'binding_counterexamples.json')
    if reuse['case_count']!=77 or reuse['empty_query_removals']!=49 or headers['case_count']!=26 or reuse['status']!='PASS' or headers['status']!='PASS':
        raise ValueError('K9_COUNTEREXAMPLE_EVIDENCE')
    result=dict(status='PASS',counts=counts,historical_statuses=states,k9_code_sha256=ctx['code_sha256'],
                previous_round8_defect=defect,k9_zip_verified=True,
                reused_records=dict(legacy_counterexamples=77,empty_query_deletions=49,old_binding_record=26,label='REUSED_RECORDS; fixed binding cases rerun separately; unchanged query/camera readers not rerun as mutation suite'),
                historical_coverage='DIRECT_INPUTS_VERIFIED_REMAINDER_REUSED',
                historical_actors=[dict(actor='K9 runtime reported',status='COMPLETE',matched=4780,unreadable=0,verification='REUSED'),
                                   dict(actor='K9 independent audit',matched=4351,unreadable=429,verification='REUSED; noncritical unreadable never counted MATCH')],
                current_direct_files=len(seen),current_direct_status='MATCH',critical_unreadable=0,
                scope='Direct critical bytes checked now; no new claim that all historical 4780/9171 references were reread.')
    write(out/'k9_freeze.json',result);write(out/'source_bytes_before.json',dict(files=list(seen.values())))
    return result,seen,screen,source_cfg


def preserve(records):
    errors=[];checked=[]
    for row in records:
        try:checked.append(verify_record(row))
        except OSError as e:errors.append(dict(path=row['path'],kind='UNREADABLE',error=repr(e)))
        except ValueError as e:errors.append(dict(path=row['path'],kind='MISMATCH',error=str(e)))
    return dict(status='FAIL' if any(e['kind']=='MISMATCH' for e in errors) else 'BLOCKED' if errors else 'PASS',
                checked=len(checked),errors=errors,raw_bytes=True)
