"""Reusable evaluation of explicit archived cases after compatibility gating."""
import numpy as np
from .common import require, write
from .metrics import coverage, regional, compare_hits
from .protocol import compatibility


def evaluate_existing(inputs, case_id, protocol, requested=None, components=True):
    gate = compatibility(protocol, protocol if requested is None else requested)
    if gate['status'] != 'COMPATIBLE':
        return dict(case_id=case_id, source='archive_replay', compatibility=gate, metrics=None)
    raw = inputs.case(case_id)
    duration = inputs.cfg['duration_s']; tolerance = inputs.cfg['absolute_time_tolerance_s']
    result = dict(case_id=case_id, source='archive_replay', group=raw['spec']['group'], evidence_type=raw['spec']['evidence_type'],
                  compatibility=gate, provenance=raw['provenance'], read_counts=raw['read_counts'],
                  full_grid=coverage(raw['hits'], duration), effective_grid=coverage(raw['hits'][raw['keep']], duration),
                  mask_is_official=False, producer_code_identity=protocol['provenance']['source_hash'],
                  new_native_validation_performed=False)
    if raw['intervals'] is not None:
        result['regional'] = regional(raw['intervals'], duration, tolerance)
        if components:
            assets = inputs.components(case_id)
            combined = np.minimum.reduce(assets['hits'])
            comparison = compare_hits(combined, raw['hits'], tolerance)
            combined_regional = regional(assets['intervals'], duration, tolerance)
            regional_diff = {}
            for name in raw['intervals']:
                a = np.asarray(result['regional']['targets'][name]['merged_intervals'])
                b = np.asarray(combined_regional['targets'][name]['merged_intervals'])
                require(a.shape == b.shape, 'COMPONENT_REGIONAL_INTERVAL_COUNT')
                err = float(np.max(np.abs(a-b), initial=0))
                require(err <= tolerance, 'COMPONENT_REGIONAL_ENDPOINT_MISMATCH')
                regional_diff[name] = dict(merged_count=len(a), max_endpoint_error_s=err)
            result['components'] = dict(status='PASS', selected_assets=len(assets['identities']),
                source_point_values=sum(len(v) for v in assets['hits']), raw_regional_intervals=sum(map(len, assets['intervals'].values())),
                identities=assets['identities'], whole_comparison=comparison, regional_comparison=regional_diff,
                full_grid=coverage(combined, duration), effective_grid=coverage(combined[raw['keep']], duration),
                regional=combined_regional, scope='Only these saved N28/N30 selections; not all 2171 assets or candidates physically certified')
    result['coordinate_mapping'] = dict(length=len(raw['coordinate_permutation']), identity=bool(np.array_equal(raw['coordinate_permutation'], np.arange(len(raw['hits'])))))
    return result, raw['coordinate_permutation']
