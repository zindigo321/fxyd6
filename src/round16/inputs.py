"""Full frozen-catalog input gate for conditional mixed-altitude research.

Only schema, byte and physical-context validation is shared with the numerical
checker. Producer modules remain inert byte evidence. No origin path is opened.
"""
import hashlib
import json
from pathlib import Path
import zipfile

import numpy as np

from src.round13.common import require, read, sha, record, fingerprint, Unavailable
from src.round13.inputs import Inputs, state_key
from src.round13.metrics import normalized_coords, validate_hits
from src.round14 import inputs as archived


ROOT = Path(__file__).resolve().parents[2]
BASE = archived.BASE
CATALOG = archived.CATALOG
MATRIX = archived.MATRIX
WHOLE = archived.WHOLE
PROMOTION = archived.PROMOTION
CATALOG_SHA = archived.CATALOG_SHA
PROMOTION_SHA = archived.PROMOTION_SHA
BASELINE_IDENTITY = archived.BASELINE_IDENTITY
HEIGHT = archived.HEIGHT
ASSET_COUNT = 2171
R15_MANIFEST = '990be8e92123b1d69cbc5939b0c6df2dee5db902c306eabf2259223d61e94260'
R15_TRANSPORT = '6bdd93d02b68d9aae3459494199306dc80a63446368d2b0bf728108dc8c7f2a9'
R15_ZIP = '20ee1d55edb6163015a2234904faf80cb96de29e722f2c1a6cd388587f3c3ec0'
PROTOCOL_SHA = 'b176f9d3f1cc7627836b2c4b1ae72f9621564ebe8f57ca146c5db39bcda79ce2'


def validate_state(row):
    """Use the exact producer relation at this asset's preserved altitude."""
    return archived.validate_state(row, expected_height=float(row['altitude_km']))


def validate_npz_row(path, matrix_row, point_count, duration):
    """Read one NPZ at a time and compare every point, including no-hit class."""
    with np.load(path, allow_pickle=False) as source:
        require(set(source.files) == {'first_hits'}, 'COMPONENT_GLOBAL_SCHEMA')
        values = source['first_hits']
        require(values.shape == (point_count,) and values.dtype == np.dtype('float64'),
                'COMPONENT_HITS_SHAPE_DTYPE')
        validate_hits(values, duration)
        require(np.asarray(matrix_row).shape == values.shape and
                np.asarray(matrix_row).dtype == values.dtype,
                'COMPONENT_MATRIX_ROW_SHAPE_DTYPE')
        require(np.array_equal(values, matrix_row), 'COMPONENT_SOURCE_MATRIX_MISMATCH')
        return dict(points_verified=point_count,
            finite_hits=int(np.isfinite(values).sum()),
            no_hit_positive_infinity=int(np.isposinf(values).sum()),
            complete_row_sha256=hashlib.sha256(values.astype('<f8', copy=False).tobytes()).hexdigest())


def required_asset_members(assets):
    members = []
    for asset in assets:
        for kind, filename in [('global', 'hits.npz'), ('regional', 'intervals.json')]:
            folder = BASE+'runs/access_library/'+kind+'/'+asset[kind+'_key']
            members.extend([folder+'/entry.json', folder+'/'+filename])
    require(len(members) == len(set(members)), 'DUPLICATE_CATALOG_ASSET_MEMBERS')
    return members


def require_asset_inventory(assets, manifest):
    """Missing evidence blocks the complete catalog; it never deletes donors."""
    members = required_asset_members(assets)
    missing = sorted(set(members)-set(manifest['files']))
    if missing:
        raise Unavailable('UNAVAILABLE_FROM_FROZEN_LIBRARY: full catalog needs '+
                          str(len(missing))+' members; first='+missing[0])
    return dict(required_members=len(members), entry_members=len(members)//2,
                payload_members=len(members)//2, missing_members=0)


def prior_binding(cfg, check=lambda: None):
    """Bind the R15 continuation and compare every one of its 203 source files."""
    base = Path(cfg['r15_delivery'])
    sealed = base/'sealed'
    require(sha(sealed/'artifact_manifest.json', check) == R15_MANIFEST,
            'R15_MANIFEST_ANCHOR')
    require(sha(base/'transport_manifest.json', check) == R15_TRANSPORT,
            'R15_TRANSPORT_ANCHOR')
    require(sha(sealed/'frozen/consumer_code.zip', check) == R15_ZIP,
            'R15_SOURCE_SNAPSHOT_ANCHOR')
    members = {r['path']: r for r in read(sealed/'artifact_manifest.json')['files']}
    names = ['report.md', 'final_status.json', 'frozen/contract.json',
             'frozen/consumer_code.json', 'consumer_version_binding.json',
             'science/asset_context_verification.json', 'science/baseline.json',
             'science/gap_proof.json', 'science/enumeration_completion.json']
    used = {}
    for name in names:
        check()
        p = sealed/name
        expected = members[name]
        require(p.stat().st_size == expected['bytes'] and sha(p, check) == expected['sha256'],
                'R15_USED_EVIDENCE_BYTES: '+name)
        used[name] = dict(record(p, check), evidence_role='historical_only')
    require(read(sealed/'final_status.json')['status'] == 'PASS', 'R15_NOT_PASS')
    r14_prior = read(sealed/'science/asset_context_verification.json')['r14_prior_binding']
    r14_base = Path(cfg['r14_delivery'])/'sealed'
    require(sha(r14_base/'artifact_manifest.json', check) == r14_prior['sealed_manifest_sha256'],
            'R14_REPLAY_MANIFEST_BINDING')
    r14_baseline = r14_prior['used_evidence']['science/baseline.json']
    require((r14_base/'science/baseline.json').stat().st_size == r14_baseline['bytes'] and
            sha(r14_base/'science/baseline.json', check) == r14_baseline['sha256'],
            'R14_REPLAY_BASELINE_BYTES')
    source_records = read(sealed/'frozen/consumer_code.json')
    require(len(source_records) == 203 and
            len({r['relative_path'] for r in source_records}) == 203,
            'R15_SOURCE203_CARDINALITY')
    for row in source_records:
        check()
        archived.safe_name(row['relative_path'])
        current = ROOT/row['relative_path']
        require(current.is_file() and not current.is_symlink() and
                current.resolve().is_relative_to(ROOT), 'R15_SOURCE_PATH')
        require(current.stat().st_size == row['bytes'] and sha(current, check) == row['sha256'],
                'R15_CURRENT_SOURCE_BYTES_CHANGED: '+row['relative_path'])
    transport_members = {r['path']: r for r in read(base/'transport_manifest.json')['files']}
    transport = {}
    for name in sorted(n for n in transport_members if n.startswith('transport/') and
                       (n.endswith('.json') or 'partition_B' in n)):
        expected = transport_members[name]
        p = base/name
        require(p.stat().st_size == expected['bytes'] and sha(p, check) == expected['sha256'],
                'R15_TRANSPORT_EVIDENCE_BYTES: '+name)
        transport[name] = record(p, check)
    receipt = read(base/'transfer_receipt.json')
    require(receipt['manifest_sha256'] == R15_TRANSPORT and
            receipt['sealed_manifest_sha256'] == R15_MANIFEST,
            'R15_TRANSFER_BINDING')
    return dict(status='REUSED', sealed_manifest_sha256=R15_MANIFEST,
        transport_manifest_sha256=R15_TRANSPORT, source_snapshot_sha256=R15_ZIP,
        source203_current_bytes_verified=True, source203_count=len(source_records),
        used_evidence=used, transport_evidence=transport, full_package_reaudit=False,
        r14_replay_baseline_bound=record(r14_base/'science/baseline.json', check),
        previous_result='R15 PASS; zero feasible improvement in exact-height two-swap neighborhood',
        new_R16_candidates_evaluated=0)


def metadata_from(catalog, promotion, check=lambda: None):
    assets = catalog['assets']
    require(isinstance(assets, list) and len(assets) == ASSET_COUNT,
            'FULL_CATALOG_ASSET_COUNT')
    indices = promotion['choice']['indices']
    require(len(indices) == 28 and len(set(indices)) == 28 and indices == sorted(indices),
            'BASELINE_COMPONENT_COUNT_OR_ORDER')
    require(all(type(i) is int and 0 <= i < len(assets) for i in indices),
            'BASELINE_COMPONENT_INDEX')
    identity = fingerprint(sorted(assets[i]['state'] for i in indices))
    require(identity == promotion['choice']['identity'] == BASELINE_IDENTITY,
            'BASELINE_IDENTITY')
    normalized = set()
    for asset in assets:
        check()
        normalized.add(validate_state(asset['row']))
        require(state_key(asset['row']) == asset['state'], 'COMPONENT_STATE_IDENTITY')
    require(len({a['state'] for a in assets}) == len(assets), 'DUPLICATE_COMPONENT_STATE')
    require(len(normalized) == len(assets), 'DUPLICATE_NORMALIZED_COMPONENT_STATE')
    require(all(float(assets[i]['row']['altitude_km']).hex() == HEIGHT.hex()
                for i in indices), 'BASELINE_ALTITUDE_CHANGED')
    pool = list(range(len(assets)))
    donors = sorted(set(pool)-set(indices))
    require(len(donors) == 2143, 'FULL_CATALOG_DONOR_COUNT')
    states = {i: assets[i]['state'] for i in pool}
    from .science import neighborhood_summary
    summary = neighborhood_summary(indices, donors, states, check)
    same_height = [i for i in pool
                   if float(assets[i]['row']['altitude_km']).hex() == HEIGHT.hex()]
    require(len(same_height) == 60 and set(indices).issubset(same_height),
            'HISTORICAL_SAME_HEIGHT_POOL_CHANGED')
    return dict(baseline_indices=list(indices), donor_indices=donors, pool_indices=pool,
        states={str(i): states[i] for i in pool}, baseline_identity=identity,
        altitude_km=HEIGHT, altitude_float_hex=HEIGHT.hex(),
        catalog_altitude_range_km=[min(float(a['row']['altitude_km']) for a in assets),
                                   max(float(a['row']['altitude_km']) for a in assets)],
        historical_same_height_indices=same_height,
        historical_same_height_single_swaps=28*(len(same_height)-28),
        catalog_sha256=CATALOG_SHA, promotion_sha256=PROMOTION_SHA,
        space_summary=summary, scope='Complete fixed N28 full-catalog single replacement; conditional mixed-altitude offline research')


def metadata(cfg, work=None, check=lambda: None):
    cfg = archived._config(cfg)
    prior = prior_binding(cfg, check)
    with zipfile.ZipFile(cfg['archive']) as z:
        archived.safe_inventory(z.infolist())
        require(len(z.infolist()) == cfg['archive_members'], 'ARCHIVE_MEMBER_COUNT')
        prefix = cfg['archive_root']+'/'
        cat_blob, pro_blob = z.read(prefix+CATALOG), z.read(prefix+PROMOTION)
        require(hashlib.sha256(cat_blob).hexdigest() == CATALOG_SHA, 'CATALOG_ANCHOR')
        require(hashlib.sha256(pro_blob).hexdigest() == PROMOTION_SHA, 'PROMOTION_ANCHOR')
    result = metadata_from(json.loads(cat_blob), json.loads(pro_blob), check)
    result['prior_binding'] = prior
    result['diagnostic_role'] = 'Metadata and enumeration only; no new candidate evaluation'
    return result


def load(cfg, work, check=lambda: None):
    cfg = archived._config(cfg)
    prior = prior_binding(cfg, check)
    history = archived._historical_binding(cfg, check)
    arc = archived.FrozenArchive(cfg, work, check)
    lib = archived.Library(arc)
    try:
        require(sha(arc.path(CATALOG), check) == CATALOG_SHA, 'CATALOG_ANCHOR')
        require(sha(arc.path(PROMOTION), check) == PROMOTION_SHA, 'PROMOTION_ANCHOR')
        catalog, promotion = arc.json(CATALOG), arc.json(PROMOTION)
        meta = metadata_from(catalog, promotion, check)
        for key, value in meta.items():
            setattr(lib, key, value)
        lib.metadata = meta
        lib.assets = {i: catalog['assets'][i] for i in lib.pool_indices}
        lib.states = {i: a['state'] for i, a in lib.assets.items()}
        inventory = require_asset_inventory(catalog['assets'], arc.manifest)
        require(inventory['required_members'] == 8684 and inventory['entry_members'] == 4342,
                'FULL_CATALOG_REQUIRED_MEMBER_COUNT')
        old_inputs = Inputs(arc, cfg)
        lib.coords, lib.keep, lib.targets = old_inputs.coords, old_inputs.keep, old_inputs.targets
        require(lib.coords.dtype == np.dtype('float64'), 'CANONICAL_COORDINATE_DTYPE')
        normalized_coords(lib.coords)
        coord_path = arc.path(BASE+'research/canonical_global_coordinates.npy')
        domain = arc.json(BASE+'config/effective_global_domain.json')
        require(sha(coord_path, check) == domain['canonical_coordinate_sha256'] ==
                catalog['global_context']['canonical_point_sha256'], 'CANONICAL_COORDINATE_IDENTITY')
        whole = old_inputs.case('team_competition_N28')
        whole['intervals'] = archived.validate_intervals(whole['intervals'], lib.targets, cfg['duration_s'])
        lib.baseline_whole = whole
        lib.k13_baseline = history.pop('k13_baseline')
        protocol = archived._protocol(arc, cfg, catalog, whole['provenance'], lib.targets)
        require(protocol['producer_protocol_hash'] == PROTOCOL_SHA, 'R16_PROTOCOL_ANCHOR')
        matrix_path = arc.path(MATRIX)
        require(matrix_path.stat().st_size == cfg['matrix_bytes'] and
                arc.used[MATRIX]['sha256'] == catalog['matrix_sha256'] == cfg['matrix_sha256'],
                'COMPONENT_MATRIX_DIGEST')
        lib.matrix = np.load(matrix_path, mmap_mode='r', allow_pickle=False)
        require(lib.matrix.shape == (ASSET_COUNT, cfg['raw_point_count']) and
                lib.matrix.dtype == np.dtype('float64') and not lib.matrix.flags.writeable,
                'COMPONENT_MATRIX_SHAPE_DTYPE_OR_WRITEABLE')
        lib.rows, lib.intervals = {}, {}
        details = []
        for index in lib.pool_indices:
            check()
            asset = lib.assets[index]
            validate_state(asset['row'])
            require(state_key(asset['row']) == asset['state'], 'COMPONENT_STATE_IDENTITY')
            require(asset['origin']['native_protocol_hash'] == PROTOCOL_SHA,
                    'COMPONENT_ORIGIN_PROTOCOL')
            data_records = {}
            point_verification = None
            for kind, filename in [('global', 'hits.npz'), ('regional', 'intervals.json')]:
                context, key = catalog[kind+'_context'], asset[kind+'_key']
                folder = BASE+'runs/access_library/'+kind+'/'+key
                entry_name = folder+'/entry.json'
                entry = arc.json(entry_name)
                archived.validate_entry(asset, entry, context, key, PROTOCOL_SHA)
                data_name = folder+'/'+filename
                path = arc.path(data_name)
                require(arc.used[data_name]['sha256'] == entry['data_sha256'] ==
                        asset[kind+'_data_sha256'], 'COMPONENT_DATA_DIGEST')
                data_records[kind] = dict(path=str(path), bytes=path.stat().st_size,
                    sha256=arc.used[data_name]['sha256'], key=key,
                    entry=dict(member=entry_name, bytes=arc.used[entry_name]['bytes'],
                               sha256=arc.used[entry_name]['sha256']))
                if kind == 'global':
                    point_verification = validate_npz_row(path, lib.matrix[index],
                        cfg['raw_point_count'], cfg['duration_s'])
                    lib.rows[index] = lib.matrix[index]
                    lib.rows[index].flags.writeable = False
                else:
                    lib.intervals[index] = archived.validate_intervals(arc.json(data_name),
                        lib.targets, cfg['duration_s'])
                    data_records[kind]['interval_sha256'] = fingerprint(lib.intervals[index])
                    data_records[kind]['intervals_by_target'] = {
                        t: len(lib.intervals[index][t]) for t in lib.targets}
            details.append(dict(index=index, state=asset['state'], row=asset['row'],
                normalized_state=list(archived.normalized_state(asset['row'])),
                altitude_verified_at_own_saved_value=True, origin=asset['origin'],
                global_full_point_values_verified=cfg['raw_point_count'],
                point_verification=point_verification,
                coordinates='canonical NPY column order bound by context SHA; NPZ has no independent coordinates',
                data=data_records))
        require(set(lib.rows) == set(lib.intervals) == set(lib.pool_indices),
                'FULL_CATALOG_INCOMPLETE_INPUT_GATE')
        orbits = arc.csv(WHOLE+'/orbits.csv')
        require(len(orbits) == 28 and len({o['sat_id'] for o in orbits}) == 28,
                'BASELINE_ORBIT_COUNT')
        for i, orbit in zip(lib.baseline_indices, orbits):
            require(state_key(orbit) == lib.states[i], 'BASELINE_ORBIT_STATE_ORDER')
        require(sha(arc.path(WHOLE+'/orbits.csv'), check) ==
                promotion['orbit_csv_sha256'] == whole['provenance']['orbit_csv_sha256'],
                'BASELINE_ORBIT_CSV_DIGEST')
        lib.r14_baseline = read(Path(cfg['r14_delivery'])/'sealed/science/baseline.json')
        lib.r15_baseline = read(Path(cfg['r15_delivery'])/'sealed/science/baseline.json')
        lib.hits, lib.regions, lib.archive = lib.rows, lib.intervals, arc
        lib.historical = history
        lib.coords.flags.writeable = False
        lib.keep.flags.writeable = False
        lib.evidence = dict(status='PASS', metadata_status='PASS', regional_status='PASS',
            global_status='PASS', full_asset_gate_status='PASS', asset_count=len(details),
            baseline_count=len(lib.baseline_indices), donor_count=len(lib.donor_indices),
            entry_count=4342, global_NPZ_count=len(lib.rows), regional_payload_count=len(lib.intervals),
            required_member_inventory=inventory,
            source_point_values_verified=len(details)*cfg['raw_point_count'], assets=details,
            targets=lib.targets, matrix=dict(path=str(matrix_path), bytes=cfg['matrix_bytes'],
                sha256=cfg['matrix_sha256'], shape=list(lib.matrix.shape), dtype=str(lib.matrix.dtype),
                readonly_mmap=True), protocol=protocol, historical_evidence=history,
            r15_prior_binding=prior, schema_shared_with_checker=True,
            new_native_validation_performed=False, native_activation_count=0,
            source_origin_paths_accessed=False,
            round16_adapter='All original catalog assets at their own saved altitudes; new single-swap science/checker/profile')
        return lib
    except BaseException:
        lib.close()
        raise


def pool_diagnostic(lib, baseline_hits):
    """Recompute full-pool coverage without treating the old missing set as fixed."""
    all_hits = np.full(len(baseline_hits), np.inf, dtype=np.float64)
    old_hits = np.full(len(baseline_hits), np.inf, dtype=np.float64)
    same_height = set(lib.historical_same_height_indices)
    for index in lib.pool_indices:
        np.minimum(all_hits, lib.rows[index], out=all_hits)
        if index in same_height:
            np.minimum(old_hits, lib.rows[index], out=old_hits)
    pool_missing = np.flatnonzero(~np.isfinite(all_hits)).astype('<i8')
    old_missing = np.flatnonzero(~np.isfinite(old_hits)).astype('<i8')
    base_missing = np.flatnonzero(~np.isfinite(baseline_hits)).astype('<i8')
    require(len(old_missing) == 354 and np.array_equal(old_missing, base_missing),
            'HISTORICAL60_MISSING_POINT_SET_CHANGED')
    repaired = np.setdiff1d(old_missing, pool_missing).astype('<i8')
    def points(ids):
        return dict(count=len(ids), ids=ids.tolist(),
            sha256=hashlib.sha256(ids.tobytes()).hexdigest())
    return dict(status='PASS', raw_points=len(all_hits), pool_assets=len(lib.pool_indices),
        pool_covered=int(np.isfinite(all_hits).sum()), pool_uncovered=len(pool_missing),
        missing_point_ids=pool_missing.tolist(),
        missing_point_ids_sha256=hashlib.sha256(pool_missing.tobytes()).hexdigest(),
        historical_60_pool_missing=points(old_missing), baseline_missing=points(base_missing),
        expanded_pool_missing=points(pool_missing), repaired_old_missing_points=points(repaired),
        missing_sets_equal=bool(np.array_equal(pool_missing, old_missing)),
        mask_unchanged=True, mask_point_count=int(lib.keep.sum()),
        scope='All 2171 saved catalog assets; saved first-hit union only',
        physical_inaccessibility_claim=False, official_mask_validity_claim=False)
