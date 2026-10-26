"""Recheck K8 and historical raw bytes under this process's actual permissions."""
from collections import Counter
from pathlib import Path
import zipfile
from src.round8.common import KEYS,canonical,file_record,read,sha,write
from src.round8.manifests import evidence_class

def freeze_k8(policy,root,out):
    k8=Path(policy['k8_dir']);errors=[];rows=[]
    for name in ['code_snapshot.zip','code_manifest.json','config.json','input_manifest.json','run.json','artifact_manifest.json','encoding_audit.json','delivery_verification.json','final_status.json','command_result.json','dependency_binding.json']:
        initial=Path(policy['freeze_dir'])/('K8_'+name)
        if file_record(initial)['sha256']!=file_record(k8/name)['sha256']:errors.append('K8_CHANGED_SINCE_INITIAL_FREEZE:'+name)
    for filename in ['code_manifest.json','artifact_manifest.json','input_manifest.json','encoding_audit.json']:
        obj=read(k8/filename)
        for row in obj['files']:
            p=Path(row['path']);p=p if p.is_absolute() else k8/p
            actual=file_record(p);ok=actual['sha256']==row['sha256'] and ('bytes' not in row or actual['bytes']==row['bytes'])
            rows.append(dict(manifest=filename,path=str(p),expected_sha256=row['sha256'],actual=actual,matches=ok))
            if not ok:errors.append('K8_MEMBER:'+str(p))
    ctx=read(k8/'run.json');code=read(k8/'code_manifest.json');cfg=read(k8/'config.json');inputs=read(k8/'input_manifest.json')
    if sha(canonical(code['files']))!=ctx['code_sha256'] or ctx['code_sha256']!=policy['k8_code_sha256']:errors.append('K8_CODE_IDENTITY')
    if sha(canonical(cfg['policy']))!=ctx['config_sha256'] or sha(canonical(inputs['files']))!=ctx['input_sha256']:errors.append('K8_CONFIG_INPUT_IDENTITY')
    if any(cfg['validator'][key]!=ctx[key] for key in KEYS):errors.append('K8_CONFIG_WRAPPER')
    if file_record(k8/'artifact_manifest.json')['sha256']!=read(k8/'delivery_verification.json')['manifest']['sha256']:errors.append('K8_DELIVERY_ANCHOR')
    with zipfile.ZipFile(k8/'code_snapshot.zip') as z:
        wanted={Path(r['path']).relative_to(root).as_posix():r for r in code['files']}
        if len(z.namelist())!=len(wanted) or set(z.namelist())!=set(wanted):errors.append('K8_ZIP_INVENTORY')
        for name,row in wanted.items():
            if sha(z.read(name))!=row['sha256']:errors.append('K8_ZIP_MEMBER:'+name)
    states={}
    for label,folder in [('S',Path(policy['source_dir'])),('V',Path(policy['historical_validator_dir'])),('K8',k8)]:
        state=read(folder/'final_status.json');command=read(folder/'command_result.json');run=read(folder/'run.json')
        states[label]=dict(context=run,status=state,command=command)
    if states['S']['status']['business']['core_acceptance']!='FAIL' or states['V']['status']['status']!='BLOCKED' or states['K8']['status']['offline_acceptance']!='PASS':errors.append('HISTORICAL_STATUS')
    if [states[k]['command']['exit_code'] for k in ['S','V','K8']]!=[1,1,0]:errors.append('HISTORICAL_EXIT')
    copies=out/'frozen_K8';copies.mkdir()
    for name in ['code_manifest.json','code_snapshot.zip','config.json','input_manifest.json','run.json','artifact_manifest.json','encoding_audit.json','delivery_verification.json','final_status.json','command_result.json','dependency_binding.json']:
        (copies/name).write_bytes((k8/name).read_bytes())
    post=Path(states['K8']['context']['work'])/'post_delivery_verification.json';(copies/'post_delivery_verification.json').write_bytes(post.read_bytes())
    prior=read(k8/'prior_round8_review.json');priorout=Path(prior['output'])
    defect=dict(review=prior,original_command=read(priorout/'command_result.json'),files=[file_record(priorout/n) for n in ['summary.json','final_status.json','command_result.json','encoding_audit.json']])
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,files=rows,counts=dict(Counter(r['manifest'] for r in rows)),historical_identities=states,previous_round8_defect=defect,initial_freeze=read(Path(policy['freeze_dir'])/'k8_initial_verification.json'))
    write(out/'k8_freeze.json',result);return result

def historical(policy,out):
    k8=Path(policy['k8_dir']);before=read(k8/'source_bytes_before.json')['files'];references=read(k8/'historical_manifests.json')['files']
    # Reclassify from immutable path policy BEFORE attempting any read.
    plan={r['path']:dict(expected=r,classification=evidence_class(r['path'])) for r in before}
    for folder in [Path(policy['source_dir']),Path(policy['historical_validator_dir']),k8]:
        for name in ['run.json','config.json','final_status.json','command_result.json','code_snapshot.zip','artifact_manifest.json']:
            p=str(folder/name)
            if p not in plan:plan[p]=dict(expected=file_record(p),classification='CRITICAL_SCIENCE_OR_DEPENDENCY')
    original=read(Path(policy['source_dir'])/'baseline/official_document_extract.json')
    if original['source'] not in plan:plan[original['source']]=dict(expected=dict(sha256=original['sha256']),classification='CRITICAL_SCIENCE_OR_DEPENDENCY')
    write(out/'source_read_plan.json',plan)
    observed={};bad=[]
    for index,(path,spec) in enumerate(sorted(plan.items())):
        try:
            actual=file_record(path);status='MATCH' if actual['sha256']==spec['expected']['sha256'] and ('bytes' not in spec['expected'] or actual['bytes']==spec['expected']['bytes']) else 'MISMATCH'
            row=dict(path=path,status=status,classification=spec['classification'],actual=actual)
        except OSError as exc:
            row=dict(path=path,status='MISSING' if isinstance(exc,FileNotFoundError) else 'UNREADABLE',classification=spec['classification'],error=repr(exc))
        observed[path]=row
        if row['status']=='MISMATCH' or row['status']=='MISSING' or row['classification']=='CRITICAL_SCIENCE_OR_DEPENDENCY' and row['status']!='MATCH':bad.append(row)
        if index%1000==0:print('HISTORY',index,'/',len(plan),flush=True)
    refrows=[]
    for r in references:
        row=observed[r['path']];status=row['status']
        if 'actual' in row and row['actual']['sha256']!=r['sha256']:status='MISMATCH'
        refrows.append(dict(owner=r['owner'],manifest=r['manifest'],path=r['path'],classification=evidence_class(r['path']),status=status))
    keys={r['path'] for r in references};legacy={r['path'] for r in before}
    groups={}
    for owner,name in sorted({(r['owner'],r['manifest']) for r in refrows}):
        subset=[r for r in refrows if (r['owner'],r['manifest'])==(owner,name)]
        groups[owner+'/'+name]=dict(reference_count=len(subset),unique_files=len({r['path'] for r in subset}),counts=dict(Counter(r['status'] for r in subset)))
    status='FAIL' if any(r['status'] in {'MISMATCH','MISSING'} for r in bad) or any(r['status']=='MISMATCH' for r in refrows) else 'BLOCKED' if bad else 'PASS'
    result=dict(status=status,errors=[r['path']+':'+r['status'] for r in bad],historical_coverage='COMPLETE' if all(r['status']=='MATCH' for r in observed.values()) else 'PARTIAL',
                actor='This round9 process and its current OS/sandbox permissions; no inherited COMPLETE',reference_count=len(refrows),unique_reference_files=len(keys),reference_counts=dict(Counter(r['status'] for r in refrows)),unique_reference_counts=dict(Counter(observed[p]['status'] for p in keys)),
                original_k8_union_files=len(legacy),original_k8_union_counts=dict(Counter(observed[p]['status'] for p in legacy)),current_union_files=len(observed),current_union_counts=dict(Counter(r['status'] for r in observed.values())),groups=groups,files=list(observed.values()),references=refrows,
                previous_audit_scope=dict(actor='Independent round8 audit, historical report only',union=4774,matched=4345,noncritical_unreadable=429,reference_unique_files=4736,not_used_as_current_matches=True))
    write(out/'historical_coverage.json',result);return result,observed

def preserve(observed):
    rows=[]
    for p,old in observed.items():
        if 'actual' not in old:continue
        try:
            current=file_record(p);ok=current['sha256']==old['actual']['sha256'] and current['bytes']==old['actual']['bytes']
        except OSError:ok=False
        rows.append(dict(path=p,status='PASS' if ok else 'FAIL',expected=old['actual']))
    return dict(status='PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL',checked=len(rows),files=rows,unreadable_before_not_claimed_preserved=sum('actual' not in r for r in observed.values()))
