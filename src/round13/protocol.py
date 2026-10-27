"""Evidence-derived protocol descriptors and fail-closed compatibility."""
import copy
import hashlib
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from .common import require, sha, read, fingerprint

PHYSICAL_FIELDS = ('time', 'frame', 'earth_eop', 'fov_half_deg', 'attitude_installation',
                   'coordinates', 'mask', 'regional', 'sampling', 'orbit_identity',
                   'producer_protocol_hash', 'coverage_scope')


def protocol_scalars(text):
    """Read the pinned producer format's top-level scalars, not arbitrary YAML.

    Nested gates and folded prose remain in the byte-bound source document and
    are never interpreted as execution instructions or numerical settings.
    """
    result = {}
    for line in text.splitlines():
        if not line or line[0].isspace() or line.startswith('#') or ':' not in line:
            continue
        key, value = line.split(':', 1); value = value.strip()
        if not value:
            continue
        if value in {'true','false','null'}:
            result[key] = {'true':True,'false':False,'null':None}[value]
        elif re.fullmatch(r'[-+]?\d+(\.\d*)?([eE][-+]?\d+)?', value):
            result[key] = float(value) if any(c in value for c in '.eE') else int(value)
        else:
            result[key] = value
    return result


def compatibility(stored, requested):
    missing = [k for k in PHYSICAL_FIELDS if k not in stored or k not in requested or stored.get(k) is None or requested.get(k) is None]
    differences = [k for k in PHYSICAL_FIELDS if k not in missing and stored[k] != requested[k]]
    okay = not missing and not differences
    return dict(status='COMPATIBLE' if okay else 'NOT_COMPUTABLE_FROM_FROZEN_EVIDENCE',
                missing_fields=missing, incompatible_fields=differences,
                missing_evidence=[] if okay else ['Raw first hits and/or target Access under requested ' + k for k in missing + differences],
                interpolation_permitted=False, new_native_validation_performed=False)


def build_protocols(arc, cfg, root):
    base = 'competition_v1/'
    evaluation = protocol_scalars(arc.text(base + 'config/evaluation_offline.yaml'))
    adaptive = protocol_scalars(arc.text(base + 'config/evaluation_adaptive.yaml'))
    earth = arc.json(base + 'config/earth/manifest.json')
    require(sha(arc.path(base + 'config/earth/EOP-v1.1.txt')) == earth['files']['EOP-v1.1.txt']['sha256'], 'EOP_BYTES_IDENTITY')
    targets = arc.json(base + evaluation['regional_targets'])
    for t in targets['targets']:
        require(sha(arc.path(base + t['path'])) == t['sha256'], 'TARGET_BYTES_IDENTITY')
    domain = arc.json(base + 'config/effective_global_domain.json')
    cat = arc.json(base + 'runs/component_catalog_v1/catalog.json')
    def source_identity(prefix):
        names=sorted(n for n in arc.manifest['files'] if n.startswith(prefix) and n.endswith('.py') and '/' not in n[len(prefix):])
        h=hashlib.sha256()
        for name in names:
            h.update(name.rsplit('/',1)[1].encode());h.update(arc.path(name).read_bytes())
        return dict(files=len(names),sha256=h.hexdigest(),prefix=prefix)
    producer_snapshot=source_identity(base+'src/famou/')
    stable_snapshot=source_identity('stable_app/src/famou/')
    resources=hashlib.sha256()
    for name in sorted(n for n in arc.manifest['files'] if n.startswith(base+'config/earth/') and '/' not in n[len(base+'config/earth/'):]):
        resources.update(name.rsplit('/',1)[1].encode());resources.update(arc.path(name).read_bytes())
    require(resources.hexdigest()==cat['global_context']['model_resources_hash'],'MODEL_RESOURCE_SET_IDENTITY')
    for name,digest in cat['global_context']['physics_module_sha256'].items():
        require(sha(arc.path(base+'src/famou/'+name))==digest,'CATALOG_PHYSICS_SOURCE_IDENTITY: '+name)
    for field, value in cat['global_context']['numerical_settings'].items():
        require(evaluation.get(field) == value, 'CATALOG_GLOBAL_PROTOCOL_MISMATCH: ' + field)
    require(cat['global_context']['canonical_point_sha256'] == domain['canonical_coordinate_sha256'], 'CATALOG_COORDINATE_IDENTITY')
    target_identity = hashlib.sha256((sha(arc.path(base + evaluation['regional_targets'])) + json.dumps(targets['targets'], sort_keys=True)).encode()).hexdigest()
    require(cat['regional_context']['target_hash'] == target_identity, 'CATALOG_TARGET_IDENTITY')
    descriptors, validations = {}, {}
    for case_id, case in cfg['cases'].items():
        if case['group'] == 'TEAM_COMPETITION_V3':
            folder = case['path']; meta = arc.json(folder + '/whole_review.json')
            executed=source_identity(folder+'/executed_source/'+meta['source_hash']+'/')
            require(executed['sha256']==meta['source_hash']==producer_snapshot['sha256'],'PRODUCER_EXECUTED_SOURCE_IDENTITY')
            validation = arc.json(folder + '/native/validation.json')
            require(validation['saved_and_reloaded'], 'SAVED_SCENE_VALIDATION_MISSING')
            camera = arc.text(folder + '/native/Camera.sn')
            full = [float(re.search(r'\b' + key + r'\s+(\S+)', camera).group(1)) for key in ['UpDownAngle', 'SideToSideAngle']]
            count = 0
            for phase in ['before', 'after']:
                snap = validation[phase]
                require(len(snap['satellites']) == case['N'] and snap['satellite_count'] == case['N'], 'VALIDATION_SATELLITE_COUNT')
                require(snap['start_time'] == evaluation['epoch_utc'] and snap['stop_time'] == evaluation['stop_utc'], 'VALIDATION_TIME')
                require(snap['model_resources_hash'] == meta['model_resources_hash'], 'VALIDATION_RESOURCES')
                for sat in snap['satellites']:
                    require([sat['along_half_angle_deg'], sat['cross_half_angle_deg']] == [evaluation['along_track_half_angle_deg'], evaluation['cross_track_half_angle_deg']], 'VALIDATION_FOV')
                    require(sat['sensor_installation_quaternion'] == [0., 0., 0., 1.], 'VALIDATION_INSTALLATION')
                    count += 1
            require(all(abs(a-2*b) < 1e-12 for a, b in zip(full, [evaluation['along_track_half_angle_deg'], evaluation['cross_track_half_angle_deg']])), 'CAMERA_FULL_HALF_MISMATCH')
            require(sha(arc.path(folder + '/orbits.csv')) == meta['orbit_csv_sha256'], 'WHOLE_ORBIT_IDENTITY')
            producer_protocol = meta['native_protocol_hash']; source = meta['source_hash']; orbit = meta['orbit_csv_sha256']; origin = meta['source_directory']
            require(producer_protocol == sha(arc.path(base + 'config/evaluation_offline.yaml')), 'WHOLE_PROTOCOL_BYTES')
            saved_targets={}
            for target in targets['targets']:
                # STK saved objects contain locale bytes in nonnumeric extensions.
                # Latin-1 preserves each byte; only ASCII numeric field names are interpreted.
                text=arc.path(folder+'/native/'+target['name']+'.at').read_bytes().decode('latin1')
                values=[float(re.search(r'\b'+k+r'\s+(\S+)',text).group(1)) for k in ['EcfLatitude','EcfLongitude','EcfAltitude']]
                expected=target['frozen_centroid_planetodetic'];values[2]/=1000.
                require(all(abs(a-b)<1e-10 for a,b in zip(values,expected)),'SAVED_TARGET_HEIGHT_OR_COORDINATE')
                require(re.search(r'AutoCentroid\s+Off',text) and re.search(r'UseTerrainInfo\s+Off',text),'SAVED_TARGET_TERRAIN_SETTINGS')
                saved_targets[target['name']]=dict(centroid_planetodetic=values,original_text=text,text_decoding='latin1 lossless byte mapping; numeric ASCII fields only')
            validations[case_id] = dict(satellite_readbacks=count, camera_full_deg=full, before_after=validation, camera_text=camera,targets=saved_targets,producer_executed_source=executed)
            numerical = evaluation
        else:
            meta = arc.json(f'stable_app/frontend/dist/assets/N{case["N"]}_metadata.json')
            orbit = meta['orbit_file_hash']; source = meta['source_hash']
            require(sha(arc.path(f'stable_app/frontend/dist/assets/N{case["N"]}_orbits.csv')) == orbit, 'STABLE_ORBIT_IDENTITY')
            # Historical raw arrays retain their original adaptive protocol, not the later frontend relabel.
            producer_protocol = meta.get('original_evaluation_protocol_hash', meta['evaluation_protocol_hash']); numerical = adaptive
            require(producer_protocol == sha(arc.path(base + 'config/evaluation_adaptive.yaml')), 'HISTORICAL_PROTOCOL_BYTES')
            origin = meta.get('source_legacy_run_id', meta['selection_source_legacy_run_id'])
        desc = dict(group=case['group'], evidence_type=case['evidence_type'],
                    time=[numerical['epoch_utc'], numerical['stop_utc'], numerical['duration_s']], frame=numerical['reference_frame'],
                    earth_eop=earth, fov_half_deg=[numerical['along_track_half_angle_deg'], numerical['cross_track_half_angle_deg']],
                    attitude_installation=dict(profile=numerical['attitude'], quaternion=[0., 0., 0., 1.]),
                    coordinates=dict(canonical_sha256=domain['canonical_coordinate_sha256'], raw_points=cfg['raw_point_count'], ordering='canonical array; explicit permutation stored per case', latitude='geodetic', longitude='modulo360'),
                    mask=dict(sha256=domain['mask_sha256'], rule=domain['rule'], official=False),
                    regional=dict(kind='AreaTarget', manifest=targets if case['group'] == 'TEAM_COMPETITION_V3' else 'historical regional geometry; raw regional replay out of scope', full_region_point_coverage=False),
                    sampling={k:v for k,v in numerical.items() if any(s in k for s in ['sampling', 'step', 'merge', 'boundary', 'precise']) and 'reason' not in k and 'note' not in k},
                    orbit_identity=orbit, producer_protocol_hash=producer_protocol, coverage_scope='complete_saved_global_point_set',
                    provenance=dict(source='stk', source_hash=source, protocol_hash=producer_protocol, origin=origin, producer_metadata=meta),
                    source='archive_replay', fov_full_deg=[2*numerical['along_track_half_angle_deg'], 2*numerical['cross_track_half_angle_deg']])
        descriptors[case_id] = desc
    own = read(root / 'configs/round7.json')
    descriptors['OUR_FROZEN'] = dict(group='OUR_FROZEN', time=[own['epoch_utcg'], own['duration_s']], frame=own['reference_frame'],
        earth_eop=dict(constants=own['earth'], EOP='See frozen historical evidence; not re-certified'),
        fov_half_deg=[own['camera']['along_half_deg'], own['camera']['cross_half_deg']],
        attitude_installation=own['camera'], coordinates=dict(diagnostic_points=16, spacing_deg=own['round3']['grid']['spacing_deg']),
        mask='No complete global result', regional=dict(kind='16 diagnostic points', altitude_km=own['diagnostic_surface']['altitude_km']),
        sampling=own['access_tiers'], orbit_identity=own['constellation'], producer_protocol_hash=sha(root/'configs/round7.json'),
        coverage_scope='diagnostic_sample_only', full_global='NOT_RUN', round12_processed_cells=0, round12_cost='NOT_RUN')
    revisions = []
    for name in arc.manifest['files']:
        if name.endswith('.docx'):
            with zipfile.ZipFile(arc.path(name)) as doc:
                tree = ET.fromstring(doc.read('word/document.xml'))
                texts = [''.join(p.itertext()) for p in tree.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p')]
            revisions.append(dict(path=name, matching_paragraphs=[s for s in texts if any(x in s for x in ['0.81', 'Access', '划网格'])], authority='historical_material_only'))
        elif '任务' in name and name.endswith(('.md', '.txt')):
            text = arc.text(name)
            revisions.append(dict(path=name, matching_lines=[s for s in text.splitlines() if any(x in s for x in ['0.81', 'Access', '划网格'])], authority='historical_material_only'))
    return dict(status='COMPLETED_WITH_UNRESOLVED_RULES', cases=descriptors, validation_readbacks=validations, revisions=revisions,
                producer_snapshots=dict(competition=producer_snapshot,stable_current_packaged=stable_snapshot,stable_note='Packaged stable application source is later than original historical source_hash. Historical producer identity is retained as provenance; do not relabel as executed current code.'),
                active_protocol_change_authorized=False,
                unresolved=['FOV revision authority and full/half-angle convention', 'Object Access versus all points in a region', 'Provisional global effective domain', 'EOP ends 2019; scenario is 2027', 'Adaptive small-sample calibration is not global completeness'],
                historical_stage_map={'S':'FAIL/1','V':'BLOCKED/1','K8':'PASS/0','K9':'PASS/0','K10':'PASS/0','K11':'NO_GO/BLOCKED/2','K12':'BLOCKED/2'})
