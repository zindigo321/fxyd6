"""Strict frozen-library schemas; producer modules are byte evidence, never code.

The numerical checker shares this reader.  It does not share evaluation,
interval union, feasibility, or selection algorithms with the main path.
"""
import hashlib
import json
import math
from pathlib import Path
import re
import zipfile

import numpy as np

from src.round13.archive import Archive, safe_inventory, safe_name
from src.round13.common import require, read, sha, fingerprint, Unavailable
from src.round13.inputs import Inputs, state_key, ORBIT_FIELDS
from src.round13.metrics import coordinate_permutation, normalized_coords, validate_hits
from src.round13.protocol import protocol_scalars


BASE = 'competition_v1/'
CATALOG = BASE + 'runs/component_catalog_v1/catalog.json'
MATRIX = BASE + 'runs/component_catalog_v1/first_hits.npy'
WHOLE = BASE + 'runs/whole_reviews/N28_c1fbd71e9dfca4e0'
PROMOTION = WHOLE + '/promotion.json'
CATALOG_SHA = '1413efcfbaac3119541d0d2d1e9218bf6af260dabefb8707114f3e41749dfa3a'
PROMOTION_SHA = '3c68c3e0e242e47b284ca8868b02325a9199cb099379a347d2b82a37336c4d8c'
BASELINE_IDENTITY = 'c1fbd71e9dfca4e0a7d0d603d496fff8a71e2bc406d12eee113ab2bc4207b71d'
K13_MANIFEST_SHA = 'de6b21246d76f034eff2ba6df82671f33fd225bf56c0834975713d064256c87e'
HEIGHT = 692.8318965760104
DEFAULT_K13_WORK = 'G:/fmb666/work/round13/20261027T093702_offline'
DEFAULT_K13_SEAL = 'G:/gpt-file/Codex/outputs/bd-fmb/round13/20261027T093702_offline/sealed'


def _config(cfg):
    """R14 owns its final config; old defaults supply the pinned archive schema."""
    old = read(Path(__file__).resolve().parents[2] / 'configs/round13.json')
    old.update(cfg)
    old['cases'] = {'team_competition_N28': {'group': 'TEAM_COMPETITION_V3',
                     'N': 28, 'path': WHOLE, 'evidence_type': 'saved_whole_constellation'}}
    return old


def normalized_state(row):
    values = [float(row[k]) for k in ORBIT_FIELDS]
    require(all(math.isfinite(v) for v in values), 'NONFINITE_COMPONENT_STATE')
    # Modulo identities catch equivalent rotations while preserving original
    # hexadecimal state tokens separately for producer identity.
    values[2:] = [v % 360.0 for v in values[2:]]
    return tuple(v.hex() for v in values)


def validate_state(row, expected_height=HEIGHT):
    h, inc, raan, phase = [float(row[k]) for k in ORBIT_FIELDS]
    require(all(math.isfinite(v) for v in (h, inc, raan, phase)), 'NONFINITE_COMPONENT_STATE')
    require(h.hex() == float(expected_height).hex() and 500 <= h <= 700,
            'COMPONENT_HEIGHT_IDENTITY')
    require(0 <= raan < 360 and 0 <= phase < 360 and 0 < inc < 180,
            'ILLEGAL_COMPONENT_ORBIT')
    # Exact constants and relation from the frozen producer, without importing
    # its code or regenerating inclination using a different Earth model.
    a = 6371.0 + h
    cosine = -(2*math.pi/(365.2421897*86400)) / (
        1.5*(math.sqrt(5)*0.484165143790815e-3)*
        math.sqrt(398600.4415/a**3)*(6378.1363/a)**2)
    require(abs(inc - math.degrees(math.acos(cosine))) <= 1e-7,
            'COMPONENT_SSO_RELATION')
    return normalized_state(row)


def validate_intervals(saved, targets, duration):
    require(isinstance(saved, dict) and set(saved) == set(targets), 'COMPONENT_TARGET_SET')
    result = {}
    for name in targets:
        require(isinstance(saved[name], list), 'INVALID_ACCESS_LIST')
        result[name] = []
        for interval in saved[name]:
            require(isinstance(interval, (list, tuple)) and len(interval) == 2,
                    'INVALID_ACCESS_INTERVAL')
            require(all(type(v) in (int, float) for v in interval), 'INVALID_ACCESS_NUMBER')
            a, b = map(float, interval)
            require(math.isfinite(a) and math.isfinite(b) and 0 <= a <= b <= duration,
                    'ACCESS_OUTSIDE_WINDOW_OR_NONFINITE')
            result[name].append([a, b])
    return result


def validate_entry(asset, entry, context, key, protocol_hash):
    require(key == fingerprint(dict(state=asset['state'], context=context)),
            'COMPONENT_KEY_IDENTITY')
    require(entry['state'] == state_key(entry['original_row']) == asset['state'],
            'COMPONENT_ENTRY_STATE_IDENTITY')
    require(entry['original_row'] == asset['row'], 'COMPONENT_ORIGINAL_ROW_IDENTITY')
    require(entry['context'] == context, 'COMPONENT_PRODUCER_PROTOCOL')
    require(entry['origin'] == asset['origin'] and
            entry['origin']['native_protocol_hash'] == protocol_hash,
            'COMPONENT_ENTRY_ORIGIN_PROTOCOL')


def metadata_from(catalog, promotion):
    """Derive the exact Cartesian neighborhood without looking at payloads."""
    assets = catalog['assets']
    indices = promotion['choice']['indices']
    require(len(indices) == 28 and len(set(indices)) == 28, 'BASELINE_COMPONENT_COUNT')
    require(all(type(i) is int and 0 <= i < len(assets) for i in indices),
            'BASELINE_COMPONENT_INDEX')
    require(indices == sorted(indices), 'BASELINE_ORDER_IDENTITY')
    baseline_identity = fingerprint(sorted(assets[i]['state'] for i in indices))
    require(baseline_identity == promotion['choice']['identity'] == BASELINE_IDENTITY,
            'BASELINE_IDENTITY')
    pool = [i for i, a in enumerate(assets)
            if float(a['row']['altitude_km']).hex() == HEIGHT.hex()]
    require(len(pool) == 60 and set(indices).issubset(pool), 'EXACT_HEIGHT_POOL_COUNT')
    require(len({assets[i]['state'] for i in pool}) == 60, 'DUPLICATE_COMPONENT_STATE')
    require(len({normalized_state(assets[i]['row']) for i in pool}) == 60,
            'DUPLICATE_NORMALIZED_COMPONENT_STATE')
    donors = sorted(set(pool) - set(indices))
    require(len(donors) == 32, 'DONOR_COMPONENT_COUNT')
    neighborhood = []
    for remove in indices:
        for add in donors:
            selected = sorted((set(indices) - {remove}) | {add})
            neighborhood.append(dict(remove=remove, add=add, indices=selected,
                identity=fingerprint(sorted(assets[i]['state'] for i in selected))))
    require(len(neighborhood) == 896 and len({n['identity'] for n in neighborhood}) == 896,
            'NEIGHBORHOOD_IDENTITY_COLLISION')
    return dict(baseline_indices=list(indices), donor_indices=donors, pool_indices=pool,
        baseline_identity=baseline_identity, altitude_km=HEIGHT, altitude_float_hex=HEIGHT.hex(),
        neighborhood=neighborhood, traversal='baseline index ascending, donor index ascending',
        cardinality=896, catalog_sha256=CATALOG_SHA, promotion_sha256=PROMOTION_SHA,
        scope='Single replacement of frozen N28 baseline at exact frozen altitude')


def metadata(cfg, work=None, check=lambda: None):
    cfg = _config(cfg)
    check()
    with zipfile.ZipFile(cfg['archive']) as z:
        safe_inventory(z.infolist())
        require(len(z.infolist()) == cfg['archive_members'], 'ARCHIVE_MEMBER_COUNT')
        prefix = cfg['archive_root'] + '/'
        cat_blob, pro_blob = z.read(prefix + CATALOG), z.read(prefix + PROMOTION)
        require(hashlib.sha256(cat_blob).hexdigest() == CATALOG_SHA, 'CATALOG_ANCHOR')
        require(hashlib.sha256(pro_blob).hexdigest() == PROMOTION_SHA, 'PROMOTION_ANCHOR')
    return metadata_from(json.loads(cat_blob), json.loads(pro_blob))


class FrozenArchive(Archive):
    """Verify used K13 members in place; extract only missing members to R14."""
    def __init__(self, cfg, work, check):
        self.reused = (Path(cfg.get('k13_work', DEFAULT_K13_WORK)) / 'vendor').resolve()
        self.locations = {}
        super().__init__(cfg, Path(work) / 'materialized', check)

    def path(self, name):
        self.check()
        safe_name(name)
        if name in self.locations:
            return self.locations[name]
        if name not in self.manifest['files']:
            raise Unavailable('UNAVAILABLE_FROM_FROZEN_LIBRARY: ' + name)
        old_candidate = self.reused / name
        require(not old_candidate.is_symlink(), 'REUSED_LINK_OR_NONFILE')
        old = old_candidate.resolve()
        require(old.is_relative_to(self.reused), 'REUSED_MEMBER_PATH_ESCAPE')
        if old.exists():
            require(old.is_file() and not old.is_symlink(), 'REUSED_LINK_OR_NONFILE')
            for parent in old_candidate.parents:
                if parent == self.reused.parent:
                    break
                require(not parent.is_symlink(), 'REUSED_LINK_PARENT')
            expected = self.manifest['files'][name]
            digest = sha(old, self.check)
            require(old.stat().st_size == expected['bytes'] and digest == expected['sha256'],
                    'REUSED_MEMBER_BYTES_MISMATCH: ' + name)
            self.used[name] = dict(bytes=expected['bytes'], sha256=digest,
                source='REUSED_K13_VENDOR_FRESHLY_VERIFIED', path=str(old))
            self.locations[name] = old
            return old
        target_candidate = self.vendor / name
        require(not target_candidate.is_symlink(), 'MATERIALIZED_LINK_REJECTED')
        for parent in target_candidate.parents:
            if parent == self.vendor.parent:
                break
            require(not parent.is_symlink(), 'MATERIALIZED_LINK_PARENT')
        target = super().path(name)
        self.used[name]['path'] = str(target)
        self.used[name]['source'] = 'EXTRACTED_SAME_FROZEN_ZIP'
        self.locations[name] = target
        return target

    def preserve(self):
        for name, row in self.used.items():
            p = self.locations[name]
            require(p.stat().st_size == row['bytes'] and sha(p, self.check) == row['sha256'],
                    'MEMBER_CHANGED_AFTER_READ: ' + name)
        require(sha(self.zip_path, self.check) == self.cfg['archive_sha256'],
                'ARCHIVE_CHANGED_AFTER_READ')
        return dict(status='PASS', actual_used_members=self.used,
            archive_sha256=self.cfg['archive_sha256'],
            reused_members=sum(v['source'].startswith('REUSED') for v in self.used.values()),
            extracted_members=sum(v['source'].startswith('EXTRACTED') for v in self.used.values()))


def _historical_binding(cfg, check):
    manifest_path = Path(cfg.get('k13_manifest',
        str(Path(cfg.get('k13_sealed', DEFAULT_K13_SEAL)) / 'artifact_manifest.json')))
    folder = manifest_path.parent
    require(sha(manifest_path, check) == K13_MANIFEST_SHA, 'K13_MANIFEST_ANCHOR')
    members = {r['path']: r for r in read(manifest_path)['files']}
    bound = {}
    for name in ['input_binding.json', 'reused_independent_package_integrity.json',
                 'main/team_competition_N28.json']:
        p = folder / name
        expected = members[name]
        require(p.stat().st_size == expected['bytes'] and sha(p, check) == expected['sha256'],
                'K13_REUSED_EVIDENCE_CHANGED: ' + name)
        bound[name] = read(p)
    binding = bound['input_binding.json']
    require(binding['archive']['sha256'] == cfg['archive_sha256'] and
            binding['manifest_sha256'] == cfg['manifest_sha256'], 'K13_ARCHIVE_BINDING')
    prior = bound['reused_independent_package_integrity.json']
    require(prior['package']['sha256'] == cfg['archive_sha256'] and
            prior['manifest']['manifest_sha256'] == cfg['manifest_sha256'] and
            prior['manifest']['checked'] == 13315 and not prior['manifest']['mismatches'],
            'REUSED_FULL_PACKAGE_AUDIT_BINDING')
    return dict(status='REUSED', manifest_sha256=K13_MANIFEST_SHA,
        full_package_members_historically_verified=13315,
        full_package_reaudit_this_round=False, bound_member_records={n: members[n] for n in bound},
        k13_baseline=bound['main/team_competition_N28.json'])


def _protocol(arc, cfg, catalog, whole, targets):
    evaluation_name = BASE + 'config/evaluation_offline.yaml'
    evaluation = protocol_scalars(arc.text(evaluation_name))
    protocol_hash = sha(arc.path(evaluation_name), arc.check)
    require(protocol_hash == whole['native_protocol_hash'], 'WHOLE_PROTOCOL_BYTES')
    required = dict(epoch_utc='1 Jan 2027 00:00:00.000', stop_utc='8 Jan 2027 00:00:00.000',
        duration_s=604800.0, reference_frame='J2000', propagator='J2Perturbation',
        along_track_half_angle_deg=0.81, cross_track_half_angle_deg=0.81,
        merge_tolerance_s=1e-6, boundary_gaps_included=False, regional_grid_created=False)
    require(all(evaluation.get(k) == v for k, v in required.items()), 'FROZEN_PROTOCOL_SCALARS')
    for kind in ['global', 'regional']:
        ctx = catalog[kind + '_context']
        require(all(evaluation.get(k) == v for k, v in ctx['numerical_settings'].items()),
                'CATALOG_NUMERICAL_SETTINGS: ' + kind)
        for name, digest in ctx['physics_module_sha256'].items():
            require(sha(arc.path(BASE + 'src/famou/' + name), arc.check) == digest,
                    'CATALOG_PHYSICS_MODULE: ' + name)
    # Re-read the exact saved producer snapshot as evidence; never import it.
    snapshots = []
    for prefix in [BASE+'src/famou/', WHOLE+'/executed_source/'+whole['source_hash']+'/']:
        digest = hashlib.sha256()
        names = sorted(n for n in arc.manifest['files']
            if n.startswith(prefix) and n.endswith('.py') and '/' not in n[len(prefix):])
        require(bool(names), 'MISSING_PRODUCER_SOURCE_SNAPSHOT')
        for name in names:
            digest.update(name.rsplit('/', 1)[1].encode())
            digest.update(arc.path(name).read_bytes())
        require(digest.hexdigest() == whole['source_hash'], 'PRODUCER_EXECUTED_SOURCE_IDENTITY')
        snapshots.append(dict(prefix=prefix, files=len(names), sha256=digest.hexdigest()))
    resources = hashlib.sha256()
    resource_members = sorted(n for n in arc.manifest['files']
        if n.startswith(BASE+'config/earth/') and '/' not in n[len(BASE+'config/earth/'):])
    for name in resource_members:
        resources.update(name.rsplit('/', 1)[1].encode())
        resources.update(arc.path(name).read_bytes())
    require(resources.hexdigest() == whole['model_resources_hash'] ==
            catalog['global_context']['model_resources_hash'] ==
            catalog['regional_context']['model_resources_hash'], 'MODEL_RESOURCE_SET_IDENTITY')
    earth = arc.json(BASE + 'config/earth/manifest.json')
    require(sha(arc.path(BASE+'config/earth/EOP-v1.1.txt'), arc.check) ==
            earth['files']['EOP-v1.1.txt']['sha256'], 'EOP_BYTES_IDENTITY')
    target_manifest_name = BASE + evaluation['regional_targets']
    target_manifest = arc.json(target_manifest_name)
    require([t['name'] for t in target_manifest['targets']] == targets and len(targets) == 3,
            'FROZEN_TARGET_SET')
    target_hash = hashlib.sha256((sha(arc.path(target_manifest_name), arc.check) +
        json.dumps(target_manifest['targets'], sort_keys=True)).encode()).hexdigest()
    require(target_hash == catalog['regional_context']['target_hash'], 'TARGET_CONTEXT_HASH')
    for target in target_manifest['targets']:
        require(sha(arc.path(BASE + target['path']), arc.check) == target['sha256'],
                'FROZEN_TARGET_BYTES_IDENTITY')
        text = arc.path(WHOLE+'/native/'+target['name']+'.at').read_bytes().decode('latin1')
        values = [float(re.search(r'\b'+key+r'\s+(\S+)', text).group(1))
                  for key in ['EcfLatitude', 'EcfLongitude', 'EcfAltitude']]
        values[2] /= 1000.0
        require(all(abs(a-b) <= 1e-10 for a, b in
                    zip(values, target['frozen_centroid_planetodetic'])), 'TARGET_NATIVE_COORDINATES')
        require(re.search(r'AutoCentroid\s+Off', text) and re.search(r'UseTerrainInfo\s+Off', text),
                'TARGET_NATIVE_TERRAIN_SETTINGS')
    validation = arc.json(WHOLE+'/native/validation.json')
    require(validation['saved_and_reloaded'], 'HISTORICAL_SAVED_RELOADED')
    for phase in ['before', 'after']:
        v = validation[phase]
        require(v['satellite_count'] == 28 and len(v['satellites']) == 28,
                'HISTORICAL_VALIDATION_N')
        require(v['start_time'] == required['epoch_utc'] and v['stop_time'] == required['stop_utc'],
                'HISTORICAL_VALIDATION_TIME')
        require(v['model_resources_hash'] == whole['model_resources_hash'],
                'HISTORICAL_VALIDATION_RESOURCES')
        for sat in v['satellites']:
            require([sat['along_half_angle_deg'], sat['cross_half_angle_deg']] == [0.81, 0.81]
                    and sat['sensor_installation_quaternion'] == [0., 0., 0., 1.],
                    'HISTORICAL_VALIDATION_FOV_INSTALLATION')
    camera = arc.text(WHOLE+'/native/Camera.sn')
    require(all(float(re.search(r'\b'+key+r'\s+(\S+)', camera).group(1)) == 1.62
                for key in ['UpDownAngle', 'SideToSideAngle']), 'CAMERA_HALF_FULL_IDENTITY')
    return dict(status='PASS', group='TEAM_COMPETITION_V3', numerical_settings=evaluation,
        global_context=catalog['global_context'], regional_context=catalog['regional_context'],
        producer_protocol_hash=protocol_hash, earth=earth, targets=target_manifest,
        source_module_role='byte identity only; no producer code execution',
        producer_snapshots=snapshots,
        historical_validation=validation, active_protocol_change_authorized=False,
        limitations=['EOP covers through 2019, scenario in 2027', 'Provisional unofficial mask',
            'Unconfirmed FOV and regional object Access rules',
            'No new geometric or continuous completeness proof'])


class Library:
    def __init__(self, arc):
        self.arc = arc
        self.matrix = None
        self.rows = {}

    def close(self):
        if self.matrix is not None:
            self.rows.clear()
            self.matrix._mmap.close()
            self.matrix = None
        self.arc.close()

    def preserve(self):
        return self.arc.preserve()


def load(cfg, work, check=lambda: None):
    cfg = _config(cfg)
    history = _historical_binding(cfg, check)
    arc = FrozenArchive(cfg, work, check)
    lib = Library(arc)
    try:
        require(sha(arc.path(CATALOG), check) == CATALOG_SHA, 'CATALOG_ANCHOR')
        require(sha(arc.path(PROMOTION), check) == PROMOTION_SHA, 'PROMOTION_ANCHOR')
        catalog, promotion = arc.json(CATALOG), arc.json(PROMOTION)
        meta = metadata_from(catalog, promotion)
        for key, value in meta.items():
            setattr(lib, key, value)
        lib.metadata = meta
        lib.assets = {i: catalog['assets'][i] for i in meta['pool_indices']}
        lib.states = {i: a['state'] for i, a in lib.assets.items()}
        old_inputs = Inputs(arc, cfg)
        lib.coords, lib.keep, lib.targets = old_inputs.coords, old_inputs.keep, old_inputs.targets
        require(lib.coords.dtype == np.dtype('float64'), 'CANONICAL_COORDINATE_DTYPE')
        normalized_coords(lib.coords)
        coord_path = arc.path(BASE+'research/canonical_global_coordinates.npy')
        domain = arc.json(BASE+'config/effective_global_domain.json')
        require(sha(coord_path, check) == domain['canonical_coordinate_sha256'] ==
                catalog['global_context']['canonical_point_sha256'], 'CANONICAL_COORDINATE_IDENTITY')
        whole = old_inputs.case('team_competition_N28')
        whole['intervals'] = validate_intervals(whole['intervals'], lib.targets, cfg['duration_s'])
        lib.baseline_whole = whole
        lib.k13_baseline = history.pop('k13_baseline')
        protocol = _protocol(arc, cfg, catalog, whole['provenance'], lib.targets)
        matrix_path = arc.path(MATRIX)
        require(matrix_path.stat().st_size == cfg['matrix_bytes'] and
                arc.used[MATRIX]['sha256'] == catalog['matrix_sha256'] == cfg['matrix_sha256'],
                'COMPONENT_MATRIX_DIGEST')
        lib.matrix = np.load(matrix_path, mmap_mode='r', allow_pickle=False)
        require(lib.matrix.shape == (2171, cfg['raw_point_count']) and
                lib.matrix.dtype == np.dtype('float64') and not lib.matrix.flags.writeable,
                'COMPONENT_MATRIX_SHAPE_DTYPE_OR_WRITEABLE')
        lib.rows, lib.intervals = {}, {}
        details = []
        for index in lib.pool_indices:
            check()
            asset = lib.assets[index]
            validate_state(asset['row'])
            require(state_key(asset['row']) == asset['state'], 'COMPONENT_STATE_IDENTITY')
            require(asset['origin']['native_protocol_hash'] == protocol['producer_protocol_hash'],
                    'COMPONENT_ORIGIN_PROTOCOL')
            data_records = {}
            for kind, filename in [('global', 'hits.npz'), ('regional', 'intervals.json')]:
                context, key = catalog[kind+'_context'], asset[kind+'_key']
                folder = BASE+'runs/access_library/'+kind+'/'+key
                entry = arc.json(folder+'/entry.json')
                validate_entry(asset, entry, context, key, protocol['producer_protocol_hash'])
                data_name = folder+'/'+filename
                path = arc.path(data_name)
                require(arc.used[data_name]['sha256'] == entry['data_sha256'] ==
                        asset[kind+'_data_sha256'], 'COMPONENT_DATA_DIGEST')
                data_records[kind] = dict(path=str(path), bytes=path.stat().st_size,
                    sha256=arc.used[data_name]['sha256'], key=key)
                if kind == 'global':
                    with np.load(path, allow_pickle=False) as source:
                        require(set(source.files) == {'first_hits'}, 'COMPONENT_GLOBAL_SCHEMA')
                        values = source['first_hits']
                        require(values.shape == (cfg['raw_point_count'],) and
                                values.dtype == np.dtype('float64'), 'COMPONENT_HITS_SHAPE_DTYPE')
                        validate_hits(values, cfg['duration_s'])
                        require(np.array_equal(values, lib.matrix[index]),
                                'COMPONENT_SOURCE_MATRIX_MISMATCH')
                    lib.rows[index] = lib.matrix[index]
                else:
                    lib.intervals[index] = validate_intervals(arc.json(data_name), lib.targets,
                                                              cfg['duration_s'])
            details.append(dict(index=index, state=asset['state'], row=asset['row'],
                normalized_state=list(normalized_state(asset['row'])), origin=asset['origin'],
                global_full_point_values_verified=cfg['raw_point_count'],
                coordinates='canonical NPY column order bound by context SHA; NPZ has no independent coordinates',
                data=data_records))
        require(len({normalized_state(a['row']) for a in lib.assets.values()}) == 60,
                'DUPLICATE_NORMALIZED_COMPONENT_STATE')
        orbits = arc.csv(WHOLE+'/orbits.csv')
        require(len(orbits) == 28 and len({o['sat_id'] for o in orbits}) == 28,
                'BASELINE_ORBIT_COUNT')
        for i, orbit in zip(lib.baseline_indices, orbits):
            require(state_key(orbit) == lib.states[i], 'BASELINE_ORBIT_STATE_ORDER')
        require(sha(arc.path(WHOLE+'/orbits.csv'), check) ==
                promotion['orbit_csv_sha256'] == whole['provenance']['orbit_csv_sha256'],
                'BASELINE_ORBIT_CSV_DIGEST')
        lib.hits = lib.rows
        lib.evidence = dict(status='PASS', asset_count=60, baseline_count=28, donor_count=32,
            source_point_values_verified=60*cfg['raw_point_count'], assets=details,
            targets=lib.targets, matrix=dict(path=str(matrix_path), bytes=cfg['matrix_bytes'],
                sha256=cfg['matrix_sha256'], shape=list(lib.matrix.shape), dtype=str(lib.matrix.dtype),
                readonly_mmap=True), protocol=protocol, historical_evidence=history,
            schema_shared_with_checker=True, new_native_validation_performed=False,
            native_activation_count=0, source_origin_paths_accessed=False)
        return lib
    except BaseException:
        lib.close()
        raise
