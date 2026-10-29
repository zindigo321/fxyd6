"""R15 adapter over the immutable R14 validated reader; no single-swap flow."""
import hashlib
import json
from pathlib import Path
import zipfile
import numpy as np
from src.round13.common import read,write,require,sha,record
from src.round14 import inputs as archived

ROOT=Path(__file__).resolve().parents[2]
R14_MANIFEST='07604d5753d83ef20ddad3c435254213e3b548167bef09be63c3fe6c33d1aa62'
R14_TRANSPORT='1e1502d2dc8defd247327282930c7d5424988e945f742d69e726def13478ac24'
R14_ZIP='f9090bd8e53509e1ab47514164e15a51f130e94be254b1631292ce37a7d54cf2'


def prior_binding(cfg,check=lambda:None):
    base=Path(cfg['r14_delivery']);sealed=base/'sealed'
    require(sha(sealed/'artifact_manifest.json',check)==R14_MANIFEST,'R14_MANIFEST_ANCHOR')
    require(sha(base/'transport_manifest.json',check)==R14_TRANSPORT,'R14_TRANSPORT_ANCHOR')
    require(sha(sealed/'frozen/consumer_code.zip',check)==R14_ZIP,'R14_SOURCE_SNAPSHOT_ANCHOR')
    members={r['path']:r for r in read(sealed/'artifact_manifest.json')['files']};bound={}
    for name in ['final_status.json','science/baseline.json','science/asset_context_verification.json',
                 'frozen/consumer_code.json','science/enumeration_completion.json','consumer_version_binding.json']:
        p=sealed/name;row=members[name]
        require(p.stat().st_size==row['bytes'] and sha(p,check)==row['sha256'],'R14_USED_EVIDENCE_BYTES')
        bound[name]=dict(record(p,check),status='REUSED')
    require(read(sealed/'final_status.json')['status']=='PASS','R14_NOT_PASS')
    receipt=read(base/'transfer_receipt.json')
    require(receipt['manifest_sha256']==R14_TRANSPORT and receipt['sealed_manifest_sha256']==R14_MANIFEST,'R14_TRANSFER_BINDING')
    return dict(status='REUSED',sealed_manifest_sha256=R14_MANIFEST,transport_manifest_sha256=R14_TRANSPORT,
        source_snapshot_sha256=R14_ZIP,used_evidence=bound,full_package_reaudit=False,
        previous_single_swap_result='PASS; zero feasible improvement; immutable')


def metadata(cfg,work=None,check=lambda:None):
    prior=prior_binding(cfg,check)
    meta=archived.metadata(cfg,work,check)
    with zipfile.ZipFile(cfg['archive']) as z:
        blob=z.read(cfg['archive_root']+'/'+archived.CATALOG)
    require(hashlib.sha256(blob).hexdigest()==archived.CATALOG_SHA,'CATALOG_METADATA_ANCHOR')
    assets=json.loads(blob)['assets']
    states={i:assets[i]['state'] for i in meta['pool_indices']}
    from .science import neighborhood_summary
    summary=neighborhood_summary(meta['baseline_indices'],meta['donor_indices'],states,check)
    return dict(baseline_indices=meta['baseline_indices'],donor_indices=meta['donor_indices'],
        pool_indices=meta['pool_indices'],states={str(i):s for i,s in states.items()},
        baseline_identity=meta['baseline_identity'],altitude_km=meta['altitude_km'],
        catalog_sha256=meta['catalog_sha256'],promotion_sha256=meta['promotion_sha256'],
        space_summary=summary,prior_binding=prior)


def load(cfg,work,check=lambda:None):
    prior=prior_binding(cfg,check)
    lib=archived.load(cfg,work,check)
    for row in lib.rows.values():row.flags.writeable=False
    lib.coords.flags.writeable=False;lib.keep.flags.writeable=False
    lib.r14_baseline=read(Path(cfg['r14_delivery'])/'sealed/science/baseline.json')
    lib.evidence['r14_prior_binding']=prior
    lib.evidence['round15_adapter']='Frozen R14 decoder only; new two-swap enumeration, proof, checker and seal'
    return lib


def pool_diagnostic(lib,baseline_hits):
    all_hits=np.minimum.reduce([lib.rows[i] for i in lib.pool_indices])
    pool_missing=np.flatnonzero(~np.isfinite(all_hits));base_missing=np.flatnonzero(~np.isfinite(baseline_hits))
    require(np.array_equal(pool_missing,base_missing) and len(pool_missing)==354,'POOL_MISSING_POINT_SET_CHANGED')
    ids=pool_missing.astype('<i8')
    return dict(status='PASS',raw_points=len(all_hits),pool_assets=len(lib.pool_indices),pool_covered=int(np.isfinite(all_hits).sum()),
        pool_uncovered=len(ids),baseline_uncovered=len(base_missing),missing_sets_equal=True,missing_point_ids=ids.tolist(),
        missing_point_ids_sha256=hashlib.sha256(ids.tobytes()).hexdigest(),
        scope='Saved exact-height 60-asset pool only; any subset cannot cover these stored missing points',
        physical_inaccessibility_claim=False,official_mask_validity_claim=False)
