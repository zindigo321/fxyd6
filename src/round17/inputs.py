"""Read-only R17 adaptation of the frozen complete R16 input primitives."""
import hashlib
import json
from pathlib import Path
import zipfile

from src.round13.common import read,require,record,sha,fingerprint
from src.round16 import inputs as prior_inputs
from .science import neighborhood_summary

ROOT=Path(__file__).resolve().parents[2]
R16_MANIFEST='bfe09091812d995302d6a942062c6b212652ebc038a9630b00a1e3aeac9d4326'
R16_TRANSPORT='9e8a03f105af802aee6669c3c655863c1469cdfab880e24d8c2bb42d170c8bb6'
R16_ZIP='5afd73808ba955b2b8507150d957cc5ee564a103e30d0cbd636c40067d69c07d'


def prior_binding(cfg,check=lambda:None):
    base=Path(cfg['r16_delivery']);sealed=base/'sealed'
    require(sha(sealed/'artifact_manifest.json',check)==R16_MANIFEST,'R17_R16_MANIFEST_ANCHOR')
    require(sha(base/'transport_manifest.json',check)==R16_TRANSPORT,'R17_R16_TRANSPORT_ANCHOR')
    require(sha(sealed/'frozen/consumer_code.zip',check)==R16_ZIP,'R17_R16_SOURCE_ZIP_ANCHOR')
    members={r['path']:r for r in read(sealed/'artifact_manifest.json')['files']}
    used={}
    names=['report.md','final_status.json','frozen/contract.json','frozen/consumer_code.json',
        'consumer_version_binding.json','science/asset_context_verification.json','science/baseline.json',
        'science/candidate_summary.jsonl','science/candidates.jsonl','science/expanded_pool_raw_domain_diagnostic.json']
    for name in names:
        check();path=sealed/name;row=members[name]
        require(path.stat().st_size==row['bytes'] and sha(path,check)==row['sha256'],'R17_R16_USED_EVIDENCE:'+name)
        used[name]=dict(record(path,check),evidence_role='historical_only')
    rows=read(sealed/'frozen/consumer_code.json')
    require(len(rows)==len({r['relative_path'] for r in rows})==223,'R17_OLD223_COUNT')
    for row in rows:
        check();path=ROOT/row['relative_path']
        require(path.resolve().is_relative_to(ROOT) and not path.is_symlink() and path.is_file(),'R17_OLD_SOURCE_PATH')
        require(path.stat().st_size==row['bytes'] and sha(path,check)==row['sha256'],'R17_OLD_SOURCE_BYTES:'+row['relative_path'])
    require(read(sealed/'final_status.json')['status']=='PASS','R17_R16_NOT_PASS')
    transport_members={r['path']:r for r in read(base/'transport_manifest.json')['files']}
    transport={}
    for name in transport_members:
        if name.startswith('transport/') and (name.endswith('.json') or name.endswith('.md')):
            check();path=base/name;row=transport_members[name]
            require(path.stat().st_size==row['bytes'] and sha(path,check)==row['sha256'],'R17_R16_TRANSPORT_EVIDENCE:'+name)
            transport[name]=record(path,check)
    audit=Path(cfg['r16_audit'])
    audit_evidence={}
    for name in ['round16_audit_and_plan.md','evidence/science_audit.json','evidence/near_feasible_anchors.json','evidence/strategy_summary.json']:
        check();path=audit/name
        # These planning documents are read as evidence, never executed.
        blob=path.read_bytes();blob.decode('utf-8-sig')
        audit_evidence[name]=record(path,check)
    return dict(status='PASS',sealed_manifest_sha256=R16_MANIFEST,transport_manifest_sha256=R16_TRANSPORT,
        source_snapshot_sha256=R16_ZIP,old223_current_bytes_verified=True,old223_count=223,
        used_evidence=used,transport_evidence=transport,audit_evidence=audit_evidence,
        audit_is_new_candidate_evaluation=False,new_R17_candidates_evaluated=0)


def metadata_from(catalog,promotion,check=lambda:None):
    result=prior_inputs.metadata_from(catalog,promotion,check)
    states={int(i):s for i,s in result['states'].items()}
    result['space_summary']=neighborhood_summary(result['baseline_indices'],result['donor_indices'],states,check)
    result['scope']='Fixed R16 near-feasible anchor second replacement; no bridge restriction on second donor'
    result['fixed_remove']=1284;result['fixed_add']=705
    result['anchor_identity']='9258c0d332037e9e5f9cd658aca4c9bf9b61d5aca365aed49a2e05bc109040c8'
    return result


def metadata(cfg,work=None,check=lambda:None):
    prior=prior_binding(cfg,check)
    with zipfile.ZipFile(cfg['archive']) as z:
        prior_inputs.archived.safe_inventory(z.infolist())
        require(len(z.infolist())==cfg['archive_members'],'R17_ARCHIVE_MEMBER_COUNT')
        prefix=cfg['archive_root']+'/'
        cat=z.read(prefix+prior_inputs.CATALOG);pro=z.read(prefix+prior_inputs.PROMOTION)
        require(hashlib.sha256(cat).hexdigest()==prior_inputs.CATALOG_SHA,'R17_CATALOG_ANCHOR')
        require(hashlib.sha256(pro).hexdigest()==prior_inputs.PROMOTION_SHA,'R17_PROMOTION_ANCHOR')
    result=metadata_from(json.loads(cat),json.loads(pro),check)
    result['r16_prior_binding']=prior
    baseline=read(Path(cfg['r16_delivery'])/'sealed/science/baseline.json')
    result['original_reference_thresholds']=dict(tau100=baseline['effective_grid']['T100_s']+1e-6,
        tau90=baseline['effective_grid']['T90_s']+1e-6,k90=(9*baseline['effective_grid']['points']+9)//10,
        reference_identity=baseline['identity'])
    result['diagnostic_role']='Input identity and exact enumeration only; no new R17 evaluation'
    return result


def r16_anchor_records(cfg,check=lambda:None):
    result=[]
    path=Path(cfg['r16_delivery'])/'sealed/science/candidates.jsonl'
    with path.open(encoding='utf8') as stream:
        for n,line in enumerate(stream):
            if n%128==0:check()
            item=json.loads(line)
            if (item['feasibility']['rejection_reasons']==['T90_s_WORSE_THAN_BASELINE']
                    and item['improvement']['substantive_improvement']):
                result.append(item)
    require(len(result)==5,'R17_R16_NEAR_FEASIBLE_RECORD_COUNT')
    return result


def load(cfg,work,check=lambda:None):
    prior=prior_binding(cfg,check)
    lib=prior_inputs.load(cfg,work,check)
    try:
        lib.r16_baseline=read(Path(cfg['r16_delivery'])/'sealed/science/baseline.json')
        lib.r16_anchor_records=r16_anchor_records(cfg,check)
        lib.metadata['space_summary']=neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states,check)
        lib.metadata['scope']='Fixed705 anchor repair; 57834 second replacements'
        lib.evidence['r16_prior_binding']=prior
        lib.evidence['round17_adapter']='Fresh all2171 NPZ/matrix/context/own-altitude verification via immutable R16 primitives; R17 gates and science independent profile'
        return lib
    except BaseException:
        lib.close();raise


pool_diagnostic=prior_inputs.pool_diagnostic
