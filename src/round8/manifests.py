"""Predeclare critical evidence; audit all historical references without promotion.

Only nested, explicitly named unittest fixtures are noncritical. All other
unreadable or altered members block acceptance; missing is never a match.
"""
from collections import Counter
from pathlib import Path
from .common import file_record, preserve, read, write, sha


def evidence_class(path):
    parts=Path(path).parts
    for i in range(len(parts)-2):
        if parts[i:i+2]==('tests','cases') and parts[i+2].startswith('test_'):
            return 'NONCRITICAL_HISTORICAL_UNITTEST_FIXTURE'
    return 'CRITICAL_SCIENCE_OR_DEPENDENCY'


def plan(s,v,baseline,audit_dir,output):
    references=[];direct=set()
    for label,folder in [('S',s),('V',v)]:
        for name in ['input_manifest.json','artifact_manifest.json','log_manifest.json']:
            path=folder/name;direct.add(path)
            value=read(path);rows=value['files'] if isinstance(value,dict) else value
            for row in rows:
                p=Path(row['path']);p=p if p.is_absolute() else folder/p
                references.append(dict(owner=label,manifest=name,classification=evidence_class(p),path=str(p.resolve()),sha256=row['sha256'],bytes=row['bytes']))
        for name in ['run.json','config.json','code_manifest.json','code_snapshot.zip','summary.json','final_status.json','command_result.json','delivery_verification.json']:
            direct.add(folder/name)
    direct.update(p for p in baseline.iterdir() if p.is_file())
    # The independent audit is explicitly optional; S/V evidence is authoritative.
    try:
        optional_paths=sorted(str(p.resolve()) for p in audit_dir.iterdir() if p.is_file())
        optional_error=None
    except OSError as exc:
        optional_paths=[];optional_error=repr(exc)
    for name in ['C_worktree_snapshot.zip','C_git_snapshot.zip','C_worktree_manifest.json','C_git_manifest.json','baseline_git.json','environment.json','command_result.json','test_result.json']:
        direct.add(baseline/name)
    for row in read(s/'benchmarks/cold_old/experiment.json')['old_dependency_closure']:
        direct.add(Path(row['isolated_path']))
    direct.add(Path(read(s/'old_snapshot_reference.json')['source']))
    direct.add(Path(r'G:\fmb666\work\round7\cumulative_stk_budget.json'))
    # The root manifests are single-direction anchors; their members are checked
    # separately. Exclude no missing critical member merely because a root hashes.
    result=dict(policy='Frozen before audit: all historical references critical except exact tests/cases/test_* descendants; unreadable fixtures remain unverified, never MATCH.',
                direct_paths=sorted(map(str,direct)),references=references,
                optional_reference_paths=optional_paths,optional_reference_error=optional_error,
                reference_count=len(references),unique_reference_files=len({x['path'] for x in references}))
    write(output/'evidence_dependency_plan.json',result)
    return result


def audit(plan,output):
    bypath={};rows=[]
    paths=sorted({x['path'] for x in plan['references']}|set(plan['direct_paths'])|set(plan.get('optional_reference_paths',[])))
    for index,path in enumerate(paths):
        try:record=file_record(path);record['read_status']='READABLE'
        except OSError as exc:record=dict(path=path,read_status='MISSING' if isinstance(exc,FileNotFoundError) else 'UNREADABLE',error=repr(exc))
        bypath[path]=record
        if index%500==0:print('HISTORICAL_HASH',index,'/',len(paths),flush=True)
    for ref in plan['references']:
        record=bypath[ref['path']]
        status=('MATCH' if preserve(ref,record) else 'MISMATCH') if record['read_status']=='READABLE' else record['read_status']
        rows.append(dict(ref,status=status,actual=record))
    critical=[r for r in rows if r['classification']=='CRITICAL_SCIENCE_OR_DEPENDENCY' and r['status']!='MATCH']
    direct_bad=[bypath[p] for p in plan['direct_paths'] if bypath[p]['read_status']!='READABLE']
    groups={}
    for key in sorted({(r['owner'],r['manifest']) for r in rows}):
        subset=[r for r in rows if (r['owner'],r['manifest'])==key]
        groups['/'.join(key)]=dict(references=len(subset),unique_files=len({r['path'] for r in subset}),counts=dict(Counter(r['status'] for r in subset)))
    altered=[r for r in rows if r['status']=='MISMATCH']
    missing_fixtures=[r for r in rows if r['classification']=='NONCRITICAL_HISTORICAL_UNITTEST_FIXTURE' and r['status']=='MISSING']
    status='FAIL' if altered or missing_fixtures else 'BLOCKED' if critical or direct_bad else 'PASS'
    result=dict(status=status,groups=groups,unique_files=len(paths),total_references=len(rows),
                classification_counts=dict(Counter(r['classification'] for r in rows)),critical_issues=critical,direct_unreadable=direct_bad,
                altered_references=altered,missing_fixtures=missing_fixtures,
                optional_references=[bypath[p] for p in plan.get('optional_reference_paths',[])],optional_reference_error=plan.get('optional_reference_error'),
                full_historical_artifact_audit_status='COMPLETE' if all(r['status']=='MATCH' for r in rows) and not direct_bad else 'PARTIAL',
                files=rows,duplicate_reference_explanation='V inputs reference prior S artifacts and their earlier inputs; each manifest occurrence is reported, raw bytes are read once per unique absolute path per preservation pass.')
    write(output/'historical_manifest_audit.json',result)
    write(output/'source_bytes_before.json',dict(files=list(bypath.values())))
    return result,bypath


def preservation(before):
    rows=[]
    for path,old in before.items():
        if old['read_status']!='READABLE':continue
        try:
            current=file_record(path);ok=preserve(old,current);error=None
        except OSError as exc:ok=False;error=repr(exc)
        rows.append(dict(path=path,status='PASS' if ok else 'FAIL',sha256=old['sha256'],bytes=old['bytes'],error=error))
    return dict(status='PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL',checked=len(rows),raw_bytes_only=True,files=rows)


def hash_erratum(s,output):
    oldpath=s/'baseline/round6_erratum.json';old=read(oldpath)
    corrected=Path(old['corrected_copy']);original=Path(old['source_path'])
    from .common import text_hashes,text
    detail=text_hashes(corrected.read_bytes());source=file_record(original)
    good=(old['corrected_sha256']!=detail['raw_file_sha256'] and old['corrected_sha256']==detail['normalized_text_sha256'] and source['sha256']==old['source_sha256'])
    result=dict(status='PASS' if good else 'FAIL',old_declaration=old,old_json=file_record(oldpath),original_report=source,
                corrected_report_path=str(corrected),**detail,
                old_claim_matches_raw=old['corrected_sha256']==detail['raw_file_sha256'],
                old_claim_matches_normalized=old['corrected_sha256']==detail['normalized_text_sha256'],
                reason='Historical producer hashed UTF-8 in-memory LF text before Windows text-mode CRLF serialization. New record distinguishes actual file preservation from normalized text equivalence.',history_rewritten=False)
    write(output/'hash_erratum.json',result)
    text(output/'hash_erratum.md','# 第八轮哈希勘误\n\n'
         f"状态：{result['status']}。旧 JSON 与报告原样保留。\n\n"
         f"原始文件：`{corrected}`\n\n原始字节 SHA-256：`{detail['raw_file_sha256']}`；{detail['raw_bytes']} 字节；CRLF={detail['crlf']}；BOM={detail['bom']}。\n\n"
         f"规范化文本 SHA-256：`{detail['normalized_text_sha256']}`。\n\n算法：{detail['normalization_algorithm']}。\n\n"
         '旧 corrected_sha256 匹配规范化文本，不匹配保存文件原始字节。规范化只解释差异，保全始终要求原始字节完全一致。\n')
    back=read(output/'hash_erratum.json')
    if back!=result or text_hashes(corrected.read_bytes())!=detail:raise ValueError('ERRATUM_READBACK')
    return result
