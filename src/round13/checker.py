"""Independent numerical audit. No main coverage/union/gap/compatibility calls."""
import math
import numpy as np
from .common import EvidenceError, require


def independent_coverage(values):
    data = list(map(float, values)); count = len(data)
    finite = [v for v in data if math.isfinite(v)]
    threshold = math.ceil(count * 9 / 10)
    t90 = float(np.partition(finite, threshold-1)[threshold-1]) if count and len(finite) >= threshold else None
    t100 = max(finite) if count and len(finite) == count else None
    return dict(points=count, covered=len(finite), uncovered=count-len(finite),
                coverage_end_fraction=len(finite)/count if count else None, threshold_90_count=threshold,
                T90_s=t90, T100_s=t100, reached_90=t90 is not None, reached_100=t100 is not None,
                status='AVAILABLE' if count else 'EMPTY_DOMAIN')


def summary(gaps):
    durations = [v[1]-v[0] for v in gaps]
    # Ordinary summation is deliberately independent of the production fsum.
    return dict(gap_count=len(gaps), mean_s=sum(durations)/len(gaps) if gaps else None,
                max_s=max(durations) if gaps else None,
                longest_endpoints_s=gaps[durations.index(max(durations))] if gaps else None)


def independent_regions(regions, duration, tolerance):
    duration = float(duration)
    targets, pooled, boundary_pool = {}, [], []
    for target, raw in regions.items():
        spans = sorted([max(0., float(a)), min(duration, float(b))] for a,b in raw if b >= 0 and a <= duration)
        if spans:
            starts, stops = np.asarray(spans).T
            maximum = np.maximum.accumulate(stops)
            breaks = np.flatnonzero(starts[1:] > maximum[:-1] + tolerance) + 1
            firsts = [0] + breaks.tolist(); lasts = (breaks-1).tolist() + [len(spans)-1]
            merged = [[float(starts[i]), float(maximum[j])] for i,j in zip(firsts,lasts)]
        else:
            merged = []
        gaps = [[b[1], a[0]] for b,a in zip(merged, merged[1:])]
        edges = [[0., merged[0][0]], [merged[-1][1], duration]] if merged else [[0., duration]]
        all_uncovered = gaps + [v for v in edges if v[0] < v[1]]
        pooled += gaps; boundary_pool += all_uncovered
        targets[target] = dict(raw_count=len(raw), raw_intervals=raw, merged_count=len(merged), merged_intervals=merged,
            internal_gaps=gaps, internal=summary(gaps), boundary_segments=edges, boundary_inclusive=summary(all_uncovered), valid_revisit=len(merged)>1)
    return dict(targets=targets, raw_count=sum(map(len,regions.values())), pooled_internal=summary(pooled), pooled_boundary_inclusive=summary(boundary_pool),
                semantics='Pool individual internal gaps across objects; never average per-object means', boundary_gaps_included_in_primary=False)


def independent_compatibility(left, right):
    # Separate explicit list and algorithm: no calls to protocol.compatibility.
    keys = ['time','frame','earth_eop','fov_half_deg','attitude_installation','coordinates','mask','regional','sampling','orbit_identity','producer_protocol_hash','coverage_scope']
    absent, changed = [], []
    for key in keys:
        if left.get(key) is None or right.get(key) is None:
            absent.append(key)
        elif left[key] != right[key]:
            changed.append(key)
    return dict(status='NOT_COMPUTABLE_FROM_FROZEN_EVIDENCE' if absent or changed else 'COMPATIBLE', missing_fields=absent, incompatible_fields=changed)


def differences(expected, reported, tolerance=1e-6, path=''):
    result = []
    if isinstance(expected, dict):
        if not isinstance(reported, dict) or set(expected) != set(reported):
            return [dict(path=path, reason='SCHEMA_KEYS')]
        for key, value in expected.items():
            result.extend(differences(value, reported[key], tolerance, path+'/'+key))
    elif isinstance(expected, list):
        if not isinstance(reported, list) or len(expected) != len(reported):
            return [dict(path=path, reason='LIST_LENGTH')]
        for i, value in enumerate(expected):
            result.extend(differences(value, reported[i], tolerance, path+'/'+str(i)))
    elif isinstance(expected, float):
        if isinstance(reported, bool) or not isinstance(reported, (int, float)) or not math.isfinite(reported) or abs(expected-reported) > (1e-12 if 'fraction' in path else tolerance):
            result.append(dict(path=path, expected=expected, reported=reported, reason='NUMERIC_MISMATCH'))
    elif expected != reported or type(expected) is not type(reported):
        result.append(dict(path=path, expected=expected, reported=reported, reason='EXACT_MISMATCH'))
    return result


def verify_report(inputs, case_id, reported, protocol, requested=None):
    raw = inputs.case(case_id)
    tolerance = inputs.cfg['absolute_time_tolerance_s']; duration = inputs.cfg['duration_s']
    expected = dict(full_grid=independent_coverage(raw['hits']), effective_grid=independent_coverage(raw['hits'][raw['keep']]))
    diff = []
    if 'provenance' in raw:
        for key, value in [('source','archive_replay'),('group',raw['spec']['group']),('evidence_type',raw['spec']['evidence_type']),('provenance',raw['provenance']),('read_counts',raw['read_counts']),('producer_code_identity',protocol['provenance']['source_hash']),('new_native_validation_performed',False)]:
            diff.extend(differences(value,reported.get(key),tolerance,key))
    for key in expected:
        diff.extend(differences(expected[key], reported[key], tolerance, key))
    gate = independent_compatibility(protocol, protocol if requested is None else requested)
    for key in gate:
        diff.extend(differences(gate[key], reported['compatibility'][key], tolerance, 'compatibility/'+key))
    if raw['intervals'] is not None:
        expected['regional'] = independent_regions(raw['intervals'], duration, tolerance)
        diff.extend(differences(expected['regional'], reported['regional'], tolerance, 'regional'))
        assets = inputs.components(case_id)
        combined = np.array([min(column) for column in zip(*assets['hits'])])
        classifications_equal = all(math.isfinite(a) == math.isfinite(b) for a,b in zip(combined, raw['hits']))
        error = max([abs(a-b) for a,b in zip(combined,raw['hits']) if math.isfinite(a) and math.isfinite(b)] or [0.])
        component = dict(full_grid=independent_coverage(combined), effective_grid=independent_coverage(combined[raw['keep']]), regional=independent_regions(assets['intervals'],duration,tolerance))
        for key in component:
            diff.extend(differences(component[key], reported['components'][key], tolerance, 'components/'+key))
        if not classifications_equal or error > tolerance:
            diff.append(dict(path='components/whole', reason='RAW_COMPONENT_WHOLE_MISMATCH', max_finite_error_s=float(error)))
        comparison=dict(points=len(raw['hits']),finite_points=sum(math.isfinite(v) for v in raw['hits']),hit_classification_exact_match=classifications_equal,max_finite_first_hit_error_s=float(error),absolute_tolerance_s=tolerance)
        diff.extend(differences(comparison,reported['components']['whole_comparison'],tolerance,'components/whole_comparison'))
        for key,value in [('status','PASS'),('selected_assets',len(assets['identities'])),('source_point_values',sum(map(len,assets['hits']))),('raw_regional_intervals',sum(map(len,assets['intervals'].values()))),('identities',assets['identities'])]:
            diff.extend(differences(value,reported['components'][key],tolerance,'components/'+key))
        for target in raw['intervals']:
            diff.extend(differences(expected['regional']['targets'][target]['merged_intervals'], component['regional']['targets'][target]['merged_intervals'], tolerance, 'components/raw_union/'+target))
            a=expected['regional']['targets'][target]['merged_intervals'];b=component['regional']['targets'][target]['merged_intervals']
            endpoint_error=max([abs(x-y) for pair,other in zip(a,b) for x,y in zip(pair,other)] or [0.])
            diff.extend(differences(dict(merged_count=len(a),max_endpoint_error_s=float(endpoint_error)),reported['components']['regional_comparison'][target],tolerance,'components/regional_comparison/'+target))
        expected['components'] = dict(independently_reconstructed=component, hit_classification_exact_match=classifications_equal, max_finite_first_hit_error_s=float(error))
    return dict(case_id=case_id, status='FAIL' if diff else 'PASS', independently_computed=expected, differences=diff,
                method='partition order statistic; cumulative-maximum interval clusters; per-column Python minimum; separate compatibility decision')
