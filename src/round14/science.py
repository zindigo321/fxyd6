"""Declared finite-neighborhood composition of archived, validated components.

This module performs no native evaluation or data acquisition.  All timestamps
are seconds in the frozen scenario window; infinity is solely a no-hit marker.
"""
import hashlib
import math

import numpy as np

from src.round13.common import require, fingerprint


def hit_digest(values):
    """Canonical little-endian binary64 identity, including no-hit markers."""
    return hashlib.sha256(np.asarray(values, dtype='<f8').tobytes(order='C')).hexdigest()


def neighborhood(baseline, donors, states):
    """Freeze ascending remove x add order; each combination is visited once."""
    baseline, donors = list(baseline), list(donors)
    require(len(baseline) == len(set(baseline)), 'DUPLICATE_BASELINE_INDEX')
    require(len(donors) == len(set(donors)), 'DUPLICATE_DONOR_INDEX')
    require(not set(baseline) & set(donors), 'DONOR_IN_BASELINE')
    pool = baseline + donors
    require(all(type(i) is int and i in states for i in pool), 'MISSING_COMPONENT_ASSET')
    require(len({states[i] for i in pool}) == len(pool), 'DUPLICATE_COMPONENT_STATE')
    result = []
    for remove in sorted(baseline):
        for add in sorted(donors):
            indices = sorted((set(baseline) - {remove}) | {add})
            result.append(dict(remove=remove, add=add, indices=indices,
                               identity=fingerprint(sorted(states[i] for i in indices))))
    require(len({r['identity'] for r in result}) == len(result), 'DUPLICATE_CANDIDATE_IDENTITY')
    return result


def coverage(values, duration=604800):
    """The 90% threshold is an integer order statistic, never a rounded ratio."""
    a = np.asarray(values, dtype=np.float64)
    require(a.ndim == 1, 'FIRST_HITS_SHAPE')
    require(not np.isnan(a).any() and not np.isneginf(a).any(), 'INVALID_FIRST_HIT_SENTINEL')
    finite = a[np.isfinite(a)]
    require(not (finite < 0).any() and not (finite > duration).any(), 'FIRST_HIT_OUTSIDE_WINDOW')
    n, count = len(a), len(finite)
    threshold = (9*n + 9)//10
    t90 = float(np.partition(finite, threshold-1)[threshold-1]) if n and count >= threshold else None
    t100 = float(np.max(finite)) if n and count == n else None
    return dict(points=n, covered=count, uncovered=n-count,
                coverage_end_fraction=float(count/n) if n else None,
                threshold_90_count=threshold, T90_s=t90, T100_s=t100,
                reached_90=t90 is not None, reached_100=t100 is not None,
                status='AVAILABLE' if n else 'EMPTY_DOMAIN')


def union(raw, duration=604800, tolerance=1e-6):
    prepared = []
    for a, b in raw:
        a, b = float(a), float(b)
        require(math.isfinite(a) and math.isfinite(b) and 0 <= a <= b <= duration,
                'INVALID_ACCESS_INTERVAL')
        prepared.append([a, b])
    merged = []
    for a, b in sorted(prepared):
        if merged and a <= merged[-1][1] + tolerance:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def _gaps(spans):
    lengths = [b-a for a, b in spans]
    return dict(gap_count=len(spans), mean_s=math.fsum(lengths)/len(lengths) if lengths else None,
                max_s=max(lengths) if lengths else None,
                longest_endpoints_s=spans[lengths.index(max(lengths))] if lengths else None)


def regional(raw_by_target, targets, duration=604800, tolerance=1e-6):
    require(set(raw_by_target) == set(targets), 'REGIONAL_TARGET_SET')
    objects, pooled, boundaries = {}, [], []
    for target in targets:
        raw = raw_by_target[target]
        merged = union(raw, duration, tolerance)
        gaps = [[a[1], b[0]] for a, b in zip(merged, merged[1:])]
        edges = [[0., merged[0][0]], [merged[-1][1], float(duration)]] if merged else [[0., float(duration)]]
        with_edges = gaps + [pair for pair in edges if pair[1] > pair[0]]
        pooled.extend(gaps)
        boundaries.extend(with_edges)
        objects[target] = dict(raw_count=len(raw), raw_intervals=raw, merged_count=len(merged),
            merged_intervals=merged, internal_gaps=gaps, internal=_gaps(gaps),
            boundary_segments=edges, boundary_inclusive=_gaps(with_edges), valid_revisit=len(merged) >= 2)
    longest = None
    for target in targets:
        gap = objects[target]['internal']
        if gap['max_s'] is not None and (longest is None or gap['max_s'] > longest['duration_s']):
            longest = dict(target=target, duration_s=gap['max_s'], endpoints_s=gap['longest_endpoints_s'])
    return dict(targets=objects, raw_count=sum(len(v) for v in raw_by_target.values()),
                pooled_internal=_gaps(pooled), pooled_boundary_inclusive=_gaps(boundaries),
                longest_internal_gap=longest, boundary_gaps_included_in_primary=False,
                semantics='Individual internal gaps pooled across all declared objects')


def feasibility(report, baseline, required_count=28, duration=604800, tolerance=1e-6):
    reasons = []
    if len(report['indices']) != required_count or len(set(report['indices'])) != required_count or report['unique_state_count'] != required_count:
        reasons.append('NOT_EXACTLY_28_LEGAL_UNIQUE_STATES')
    if not report['effective_grid']['points'] or report['effective_grid']['uncovered']:
        reasons.append('MASK_NOT_EXACT_FULL_COVERAGE')
    for target, obj in report['regional']['targets'].items():
        if obj['merged_count'] < 2:
            reasons.append('INSUFFICIENT_MERGED_VISITS:'+target)
    mask = report['effective_grid']
    if mask['T100_s'] is None or mask['T100_s'] > duration:
        reasons.append('T100_INVALID_OR_OUTSIDE_WINDOW')
    if baseline is not None:
        for metric in ['T90_s', 'T100_s']:
            candidate, reference = mask[metric], baseline['effective_grid'][metric]
            if candidate is None or reference is None or candidate > reference+tolerance:
                reasons.append(metric+'_WORSE_THAN_BASELINE')
        candidate = report['regional']['pooled_internal']['mean_s']
        reference = baseline['regional']['pooled_internal']['mean_s']
        if candidate is None or reference is None or candidate > reference+tolerance:
            reasons.append('Tavg_s_WORSE_THAN_BASELINE')
    return dict(feasible=not reasons, rejection_reasons=reasons)


def evaluate(indices, rows, intervals, keep, targets, states, baseline=None,
             duration=604800, tolerance=1e-6, required_count=28):
    indices = list(indices)
    require(indices and len(indices) == len(set(indices)), 'DUPLICATE_OR_EMPTY_COMPONENT_INDICES')
    require(all(type(i) is int and i in rows and i in intervals and i in states for i in indices),
            'UNAVAILABLE_FROM_FROZEN_LIBRARY')
    require(len({states[i] for i in indices}) == len(indices), 'DUPLICATE_COMPONENT_STATE')
    arrays = [np.asarray(rows[i], dtype=np.float64) for i in indices]
    require(all(a.ndim == 1 and a.shape == arrays[0].shape for a in arrays), 'COMPONENT_ROW_SHAPE')
    keep = np.asarray(keep)
    require(keep.dtype == np.bool_ and keep.shape == arrays[0].shape, 'MASK_SHAPE_OR_DTYPE')
    # Directly reduce all 28 selected rows; no proxy ranking or pre-screening.
    hits = np.min(np.stack(arrays), axis=0)
    combined = {t: [] for t in targets}
    for i in indices:
        require(set(intervals[i]) == set(targets), 'REGIONAL_TARGET_SET')
        for target in targets:
            combined[target].extend(intervals[i][target])
    report = dict(indices=indices, identity=fingerprint(sorted(states[i] for i in indices)),
                  unique_state_count=len({states[i] for i in indices}),
                  full_grid=coverage(hits, duration), effective_grid=coverage(hits[keep], duration),
                  regional=regional(combined, targets, duration, tolerance), first_hits_sha256=hit_digest(hits),
                  input_state_identity=fingerprint([[i, states[i]] for i in sorted(indices)]),
                  source='archived_component_composition', new_native_validation_performed=False,
                  whole_constellation_STK_verified=False, native_verified=False)
    report['feasibility'] = feasibility(report, baseline, required_count, duration, tolerance)
    reference = baseline['regional']['pooled_internal']['max_s'] if baseline else None
    maximum = report['regional']['pooled_internal']['max_s']
    reduction = reference-maximum if reference is not None and maximum is not None else None
    # Guard a one-tolerance uncertainty band around the one-second boundary.
    substantive = reduction is not None and reduction-tolerance >= 1.
    report['improvement'] = dict(Tmax_reduction_s=reduction, minimum_required_s=1.,
        uncertainty_margin_s=tolerance, substantive_improvement=substantive,
        conservative_lower_bound_s=reduction-tolerance if reduction is not None else None)
    report['qualified_improvement'] = bool(report['feasibility']['feasible'] and substantive)
    report['selection_rejection_reasons'] = list(report['feasibility']['rejection_reasons'])
    if not substantive:
        report['selection_rejection_reasons'].append('Tmax_REDUCTION_BELOW_CONSERVATIVE_ONE_SECOND_GATE')
    return report, hits


def select(reports):
    qualified = [r for r in reports if r['qualified_improvement']]
    return min(qualified, key=lambda r: (r['regional']['pooled_internal']['max_s'],
        r['regional']['pooled_internal']['mean_s'], r['effective_grid']['T100_s'],
        r['effective_grid']['T90_s'], r['identity'])) if qualified else None


def summarize_completion(declared, reports, checks):
    expected_pairs = {(r['remove'], r['add']) for r in declared}
    removes = {r['remove'] for r in declared}
    adds = {r['add'] for r in declared}
    declared_by_pair = {(r['remove'], r['add']): r for r in declared}
    actual_pairs = [(r.get('remove'), r.get('add')) for r in reports]
    report_ids = [r['identity'] for r in reports]
    check_ids = [r['identity'] for r in checks]
    expected_ids = {r['identity'] for r in declared}
    full = (len(declared) == 896 and len(removes) == 28 and len(adds) == 32
            and not removes & adds and expected_pairs == {(r, a) for r in removes for a in adds}
            and len(expected_ids) == 896
            and all(r['indices'] == sorted((removes-{r['remove']}) | {r['add']}) for r in declared)
            and len(expected_pairs) == len(declared) and len(reports) == len(declared)
            and len(actual_pairs) == len(set(actual_pairs)) and set(actual_pairs) == expected_pairs
            and len(report_ids) == len(set(report_ids)) and set(report_ids) == expected_ids
            and all(r['identity'] == declared_by_pair[(r['remove'], r['add'])]['identity']
                    and r['indices'] == declared_by_pair[(r['remove'], r['add'])]['indices'] for r in reports)
            and len(check_ids) == len(set(check_ids)) and set(check_ids) == expected_ids
            and all(c['status'] == 'PASS' for c in checks)
            and all(len(r['indices']) == 28 and len(set(r['indices'])) == 28 for r in reports))
    return dict(completed=full, declared_candidates=len(declared), evaluated_candidates=len(reports),
                independently_verified_candidates=sum(c['status'] == 'PASS' for c in checks),
                optimization_outcome=('FEASIBLE_IMPROVEMENT_FOUND' if select(reports) else
                    'NO_FEASIBLE_IMPROVEMENT_IN_DECLARED_NEIGHBORHOOD') if full else 'PARTIAL_NOT_CONCLUDED')
