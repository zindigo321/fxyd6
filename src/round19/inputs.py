"""Fresh archive decoder adapter and immutable R18 evidence binding.

Only historical evidence is reused. All 2171 component rows, contexts, original
states and raw intervals are validated afresh by the unchanged R16 decoder.
"""
import hashlib
import json
from pathlib import Path
import zipfile

from src.round13.common import read, write, record, require, sha, fingerprint
from src.round13.archive import safe_name, safe_inventory
from src.round16 import inputs as decoder

ROOT = Path(__file__).resolve().parents[2]
B0 = 'c1fbd71e9dfca4e0a7d0d603d496fff8a71e2bc406d12eee113ab2bc4207b71d'
S = 'fa31ae444cd7afcf008b9d8d4d10a8ce6a8b8533c4d8f68c27bcf0003106d372'
ANCHORS = dict(sealed='5a59a9a3404d25f217b1c39840427ed8d2d8609bc1c4236e1c98bc4540efd0ee',
    transport='8b3c50043a8a3c1d78940243e79d1d7cc134b2f3cf0183952985a479c6c84de1',
    delivery='870f03f4fdf73a74b6514468a5e1c22e9f55772877f3b0b00bb1be20f46432c5',
    code='7192b30bd2e9c89e336740f571c02e1dcd84d3ea32cb50ab7c8c904f43ca7071')


def verify_layer(folder, manifest_name, receipt_name, digest, extras, check):
    folder = Path(folder).resolve()
    require(sha(folder/manifest_name, check) == digest, 'R19_PRIOR_MANIFEST:'+manifest_name)
    manifest, receipt = read(folder/manifest_name), read(folder/receipt_name)
    require(receipt['manifest_sha256'] == digest, 'R19_PRIOR_RECEIPT')
    names, folded = set(), set()
    for row in manifest['files']:
        check()
        name = safe_name(row['path']); p = folder/name
        require(name.casefold() not in folded and p.resolve().is_relative_to(folder)
            and not p.is_symlink() and not any(q.is_symlink() for q in p.parents if q.is_relative_to(folder)),
            'R19_PRIOR_PATH')
        names.add(name); folded.add(name.casefold())
        require(p.stat().st_size == row['bytes'] and sha(p, check) == row['sha256'], 'R19_PRIOR_BYTES:'+name)
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
    require(actual == names | {manifest_name, receipt_name} | set(extras), 'R19_PRIOR_EXACT_SET:'+manifest_name)
    return dict(status='PASS', files=len(names), manifest_sha256=digest, exact_set_verified=True)


def prior_binding(cfg, check=lambda: None):
    base = Path(cfg['r18_delivery']).resolve()
    layers = {}
    layers['sealed'] = verify_layer(base/'sealed', 'artifact_manifest.json', 'receipt.json', ANCHORS['sealed'], [], check)
    completion_extras = ['completion/export_command_result.json','completion/stdout.log','completion/stderr.log',
        'completion/export_shell_result.json','completion/cumulative_timing.json','delivery_manifest.json','delivery_receipt.json']
    layers['transport'] = verify_layer(base,'transport_manifest.json','transfer_receipt.json',ANCHORS['transport'],completion_extras,check)
    layers['delivery'] = verify_layer(base,'delivery_manifest.json','delivery_receipt.json',ANCHORS['delivery'],[],check)
    sealed = base/'sealed'
    require(sha(sealed/'frozen/consumer_code.zip',check) == ANCHORS['code'], 'R19_OLD268_ZIP')
    rows = read(sealed/'frozen/consumer_code.json')
    require(len(rows) == len({r['relative_path'] for r in rows}) == 268, 'R19_OLD268_COUNT')
    with zipfile.ZipFile(sealed/'frozen/consumer_code.zip') as z:
        safe_inventory(z.infolist())
        require(set(z.namelist()) == {r['relative_path'] for r in rows}, 'R19_OLD268_SNAPSHOT_SET')
        for row in rows:
            check(); name = safe_name(row['relative_path']); blob = z.read(name); p=ROOT/name
            require(len(blob) == row['bytes'] and hashlib.sha256(blob).hexdigest() == row['sha256'], 'R19_OLD268_ZIP_BYTES')
            require(p.resolve().is_relative_to(ROOT) and not p.is_symlink() and
                p.stat().st_size == row['bytes'] and sha(p,check) == row['sha256'], 'R19_OLD268_CHANGED:'+name)
    used={}
    for name in ['report.md','final_status.json','frozen/contract.json','frozen/consumer_code.json',
                 'consumer_version_binding.json','science/baseline.json','science/selected.json',
                 'science/selected_orbits.csv','science/candidates.jsonl','science/checker.jsonl',
                 'science/ledger.jsonl','science/enumeration_completion.json']:
        p=sealed/name; p.read_text(encoding='utf8'); used[name]=record(p,check)
    for name in ['transport/scientific_supplement.md','completion/export_command_result.json',
                 'completion/export_shell_result.json','completion/cumulative_timing.json']:
        p=base/name; p.read_text(encoding='utf8'); used[name]=record(p,check)
    require(used['science/selected_orbits.csv']['bytes'] == 5199 and used['science/selected_orbits.csv']['sha256'] ==
        '7b9480f8a1aef119b73cd2e1732ce45845b1634886492a8c5857636ad8654365', 'R19_R18_CSV_ANCHOR')
    final=read(sealed/'final_status.json'); require(final['status']=='PASS' and final['exit_code']==0,'R19_R18_NOT_PASS')
    child=read(base/'completion/export_command_result.json'); outer=read(base/'completion/export_shell_result.json')
    require(child['export_process_exit_code']==0 and child['export_shell_exit_code'] is None and
        outer['export_launcher_python_exit_code']==outer['export_shell_exit_code']==0,'R19_R18_EXIT_BINDING')
    source_work=Path(read(base/'transfer_receipt.json')['source_work'])
    for row in read(base/'transport_manifest.json')['files']:
        name=safe_name(row['source_path']); p=source_work/name
        require(p.resolve().is_relative_to(source_work) and not p.is_symlink() and
            p.stat().st_size==row['bytes'] and sha(p,check)==row['sha256'],'R19_R18_WORK_MAP')
    audit=Path(cfg['r18_audit']); audit_rows={}
    for name in ['round18_audit.md','source_manifest.json','evidence/science_audit.json',
                 'evidence/engineering_review_summary.json','evidence/export_guard_probe.json',
                 'evidence/artifact_audit.json','evidence/runtime_recheck_summary.json']:
        p=audit/name; p.read_text(encoding='utf-8-sig'); audit_rows[name]=record(p,check)
    return dict(status='PASS',disposition='HISTORICAL_EVIDENCE_BINDING_ONLY',layers=layers,
        old268_current_bytes_verified=True,old268_count=268,used_evidence=used,audit_evidence=audit_rows,
        candidate_REUSED=0,history_is_new_candidate_evaluation=False)


def metadata(cfg, work=None, check=lambda:None):
    prior=prior_binding(cfg,check)
    with zipfile.ZipFile(cfg['archive']) as z:
        safe_inventory(z.infolist()); require(len(z.infolist())==cfg['archive_members'],'R19_ARCHIVE_MEMBERS')
        prefix=cfg['archive_root']+'/'
        cat=z.read(prefix+decoder.CATALOG); pro=z.read(prefix+decoder.PROMOTION)
        require(hashlib.sha256(cat).hexdigest()==cfg['catalog_sha256'],'R19_CATALOG')
        require(hashlib.sha256(pro).hexdigest()==cfg['promotion_sha256'],'R19_PROMOTION')
    meta=decoder.metadata_from(json.loads(cat),json.loads(pro),check)
    center=sorted((set(meta['baseline_indices'])-{1217,1284})|{2021,2023})
    states={int(i):s for i,s in meta['states'].items()}
    require(fingerprint(sorted(states[i] for i in center))==S,'R19_CENTER_IDENTITY')
    require(read(Path(cfg['r18_delivery'])/'sealed/science/selected.json')['indices']==center,'R19_R18_SELECTED_INDICES')
    donors=sorted(set(meta['pool_indices'])-set(center))
    from .science import neighborhood_summary
    meta.update(center_indices=center,donor_indices19=donors,search_center_identity=S,
        original_constraint_reference=B0,search_center=S,improvement_reference=S,
        space_summary=neighborhood_summary(center,donors,states,check),r18_prior_binding=prior,
        scope='Complete fixed R18 center catalog single swap; 28 x 2143; candidate_REUSED=0')
    baseline=read(Path(cfg['r18_delivery'])/'sealed/science/baseline.json')
    meta['original_reference_thresholds']=dict(tau100=baseline['effective_grid']['T100_s']+1e-6,
        tau90=baseline['effective_grid']['T90_s']+1e-6,n=43070,k90=38763,reference_identity=B0)
    return meta


def load(cfg, work, check=lambda:None):
    lib=decoder.load(cfg,work,check)
    try:
        meta=read(Path(work)/'frozen/contract.json')['metadata']
        lib.center_indices=meta['center_indices']; lib.donor_indices19=meta['donor_indices19']
        lib.r18_baseline=read(Path(cfg['r18_delivery'])/'sealed/science/baseline.json')
        lib.r18_selected=read(Path(cfg['r18_delivery'])/'sealed/science/selected.json')
        lib.r18_delivery=Path(cfg['r18_delivery'])
        require(lib.baseline_indices==meta['baseline_indices'] and
            {str(i):s for i,s in lib.states.items()}==meta['states'],'R19_FROZEN_POOL_CHANGED')
        lib.evidence['round19_adapter']='Fresh validated entire catalog via immutable R16 decoder; source reading reused, candidates not reused'
        lib.evidence['r18_prior_binding']=meta['r18_prior_binding']
        lib.evidence['candidate_REUSED']=0
        return lib
    except BaseException:
        lib.close(); raise


pool_diagnostic=decoder.pool_diagnostic
