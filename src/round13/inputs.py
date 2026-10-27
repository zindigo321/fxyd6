"""Read-only schemas shared with the independent checker; no metrics here."""
import math
import numpy as np
from .common import require, Unavailable, sha, fingerprint
from .metrics import coordinate_permutation, validate_ids, fixed_mask, csv_hits, validate_hits

BASE = 'competition_v1/'
ORBIT_FIELDS = ['altitude_km', 'inclination_deg', 'raan_deg', 'arg_lat_deg']


def state_key(row):
    return fingerprint([float(row[k]).hex() for k in ORBIT_FIELDS])


def match_historical(records, meta):
    matches = [(i, r) for i, r in enumerate(records) if r['orbit_hash'] == meta['orbit_file_hash'] and r['N'] == meta['N']]
    require(bool(matches), 'HISTORICAL_ORBIT_UNMATCHED')
    require(len(matches) == 1, 'HISTORICAL_ORBIT_MULTIPLE_MATCHES')
    require(matches[0][1]['name'] == meta.get('source_legacy_run_id', meta.get('selection_source_legacy_run_id')), 'HISTORICAL_RECORD_ID_MISMATCH')
    return matches[0]


class Inputs:
    def __init__(self, archive, cfg):
        self.arc, self.cfg = archive, cfg
        self.coords = np.load(archive.path(BASE+'research/canonical_global_coordinates.npy'), allow_pickle=False)
        require(self.coords.shape == (cfg['raw_point_count'], 2), 'CANONICAL_GRID_SHAPE')
        domain = archive.json(BASE+'config/effective_global_domain.json')
        require(sha(archive.path(BASE+'config/effective_global_mask.csv')) == domain['mask_sha256'], 'MASK_SHA_MISMATCH')
        rows = archive.csv(BASE+'config/effective_global_mask.csv')
        validate_ids(rows, 'point_id', cfg['raw_point_count'])
        order = coordinate_permutation([[r['latitude_deg'], r['longitude_deg']] for r in rows], self.coords)
        require(all(r['include'] in {'True', 'False'} for r in rows), 'INVALID_MASK_ENCODING')
        self.keep = fixed_mask(self.coords, np.array([r['include'] == 'True' for r in rows])[order], cfg['mask_point_count'], cfg['mask_latitude_limit_deg'])
        self.targets = [r['name'] for r in archive.json(BASE+'config/targets/yangtze_frozen_objects.json')['targets']]

    def case(self, case_id):
        if case_id not in self.cfg['cases']:
            raise Unavailable('UNAVAILABLE_FROM_FROZEN_LIBRARY: unknown case ' + case_id)
        case = self.cfg['cases'][case_id]; arc = self.arc
        if case['group'] == 'TEAM_COMPETITION_V3':
            folder = case['path']
            rows = arc.csv(folder+'/native/global_first_hits.csv')
            grid = arc.csv(folder+'/native/global_grid.csv')
            ids = validate_ids(rows, 'point_id', self.cfg['raw_point_count'])
            gids = validate_ids(grid, 'Point Number', self.cfg['raw_point_count'])
            byid = {int(r['Point Number']):r for r in grid}
            coords = np.array([[r['latitude_deg'], r['longitude_deg']] for r in rows], dtype=float)
            gcoords = [[byid[i]['Latitude'], byid[i]['Longitude']] for i in ids]
            require(np.array_equal(coordinate_permutation(gcoords, coords), np.arange(len(rows))), 'POINT_ID_COORDINATE_MISMATCH')
            require(all(float(r['Altitude']) == 0 for r in grid), 'GRID_ALTITUDE_MISMATCH')
            order = coordinate_permutation(coords, self.coords)
            hits = csv_hits(rows, self.cfg['duration_s'])[order]
            raw = arc.csv(folder+'/native/access_raw.csv'); intervals = {t:[] for t in self.targets}
            for r in raw:
                require(r['target'] in intervals, 'UNKNOWN_REGIONAL_TARGET')
                intervals[r['target']].append([float(r['start_epsec']), float(r['stop_epsec'])])
            provenance = arc.json(folder+'/whole_review.json')
            details = dict(global_csv_rows=len(rows), grid_csv_rows=len(grid), raw_access_rows=len(raw), first_hit_encoding='CSV empty cell only means no hit; nonfinite literal prohibited')
        else:
            meta = arc.json(f'stable_app/frontend/dist/assets/N{case["N"]}_metadata.json')
            index = arc.json(BASE+'research/historical_dataset/dataset_index.json')
            i, rec = match_historical(index['records'], meta)
            with np.load(arc.path(BASE+'research/historical_dataset/dataset_arrays.npz'), allow_pickle=False) as arrays:
                require(arrays['hits'].shape == (len(index['records']), self.cfg['raw_point_count']), 'HISTORICAL_MATRIX_SHAPE')
                order = coordinate_permutation(arrays['coords'], self.coords)
                hits = validate_hits(arrays['hits'][i], self.cfg['duration_s'])[order]
            scope = arc.json(BASE+'research/historical_dataset/historical_protocol_scope.json')
            groups = [g for g in scope['groups'] if any(r['name'] == rec['name'] and r['N'] == rec['N'] for r in g['records'])]
            require(len(groups) == 1 and groups[0]['protocol_hash'] == meta.get('original_evaluation_protocol_hash', meta['evaluation_protocol_hash']), 'HISTORICAL_ORIGINAL_PROTOCOL_MISMATCH')
            intervals = None; provenance = dict(metadata=meta, historical_record=rec, original_protocol=groups[0]['protocol_hash'])
            details = dict(array_rows_used=1, point_values=len(hits), historical_index=i, historical_name=rec['name'], first_hit_encoding='positive infinity is producer NPY no-hit sentinel; NaN/negative/in-window violations rejected')
        return dict(case_id=case_id, spec=case, hits=hits, keep=self.keep, coords=self.coords, intervals=intervals,
                    coordinate_permutation=order, provenance=provenance, read_counts=details)

    def components(self, case_id):
        case = self.cfg['cases'][case_id]; arc = self.arc
        cat = arc.json(BASE+'runs/component_catalog_v1/catalog.json')
        promotion = arc.json(case['path']+'/promotion.json')
        indices = promotion['choice']['indices']
        require(len(indices) == case['N'], 'COMPONENT_COUNT_MISMATCH')
        require(len(set(indices)) == len(indices), 'DUPLICATE_COMPONENT_ASSET')
        require(all(type(i) is int and 0 <= i < len(cat['assets']) for i in indices), 'MISSING_COMPONENT_ASSET')
        matrix_path = arc.path(BASE+'runs/component_catalog_v1/first_hits.npy')
        require(matrix_path.stat().st_size == self.cfg['matrix_bytes'] and sha(matrix_path, arc.check) == cat['matrix_sha256'] == self.cfg['matrix_sha256'], 'COMPONENT_MATRIX_DIGEST')
        matrix = np.load(matrix_path, mmap_mode='r', allow_pickle=False)
        require(matrix.shape == (len(cat['assets']), self.cfg['raw_point_count']), 'COMPONENT_MATRIX_SHAPE')
        orbits = arc.csv(case['path']+'/orbits.csv')
        require(len(orbits) == case['N'] and len({r['sat_id'] for r in orbits}) == case['N'], 'COMPONENT_ORBIT_COUNT')
        selected, intervals, identities = [], {t:[] for t in self.targets}, []
        try:
            for position, index in enumerate(indices):
                arc.check()
                asset = cat['assets'][index]; row = asset['row']
                require(state_key(row) == asset['state'] == state_key(orbits[position]), 'COMPONENT_STATE_IDENTITY_MISMATCH')
                h, inc, raan, phase = [float(row[k]) for k in ORBIT_FIELDS]
                require(500 <= h <= 700 and all(math.isfinite(v) for v in (h, inc, raan, phase)) and 0 <= raan < 360 and 0 <= phase < 360, 'ILLEGAL_COMPONENT_ORBIT')
                # Frozen producer secular relation, checked offline; no propagation.
                a = 6371.0 + h
                cosine = -(2*math.pi/(365.2421897*86400)) / (1.5*(math.sqrt(5)*0.484165143790815e-3)*math.sqrt(398600.4415/a**3)*(6378.1363/a)**2)
                require(abs(inc-math.degrees(math.acos(cosine))) <= 1e-7, 'COMPONENT_SSO_RELATION')
                for kind, data in [('global','hits.npz'), ('regional','intervals.json')]:
                    key = asset[kind+'_key']; context = cat[kind+'_context']
                    require(key == fingerprint(dict(state=asset['state'], context=context)), 'COMPONENT_KEY_IDENTITY')
                    folder = BASE+'runs/access_library/'+kind+'/'+key
                    entry = arc.json(folder+'/entry.json')
                    require(entry['state'] == asset['state'] and state_key(entry['original_row']) == asset['state'], 'COMPONENT_ENTRY_IDENTITY')
                    require(entry['context'] == context, 'COMPONENT_PRODUCER_PROTOCOL')
                    require(entry['origin']['native_protocol_hash'] == promotion['choice'].get('native_protocol_hash', self.arc.json(case['path']+'/whole_review.json')['native_protocol_hash']), 'COMPONENT_ORIGIN_PROTOCOL')
                    path = arc.path(folder+'/'+data)
                    require(sha(path, arc.check) == entry['data_sha256'] == asset[kind+'_data_sha256'], 'COMPONENT_DATA_DIGEST')
                    if kind == 'global':
                        with np.load(path, allow_pickle=False) as d:
                            values = validate_hits(d['first_hits'], self.cfg['duration_s'])
                            require(np.array_equal(values, matrix[index]), 'COMPONENT_SOURCE_MATRIX_MISMATCH')
                        selected.append(np.asarray(matrix[index]).copy())
                    else:
                        saved = arc.json(folder+'/'+data)
                        require(set(saved) == set(self.targets), 'COMPONENT_TARGET_SET')
                        for t in self.targets:
                            intervals[t].extend(saved[t])
                identities.append(dict(index=index, state=asset['state'], row=row, origin=asset['origin']))
        finally:
            matrix._mmap.close()
        require(len({a['state'] for a in identities}) == len(identities), 'DUPLICATE_COMPONENT_STATE')
        require(fingerprint(sorted(a['state'] for a in identities)) == promotion['choice']['identity'], 'PROMOTION_IDENTITY')
        return dict(hits=selected, intervals=intervals, identities=identities, promotion=promotion, matrix_shape=[len(cat['assets']),self.cfg['raw_point_count']])
