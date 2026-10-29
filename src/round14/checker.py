"""Independent numerical algorithms over the shared validated input schema.

No production coverage, interval union, feasibility or selection function is
imported.  Global hits use baseline prefix/suffix reductions; order statistics
use sorting; regional access uses cumulative-maximum interval clustering.
The input decoder and state fingerprint format are deliberately shared.
"""
import hashlib
import math

import numpy as np

from src.round13.common import require, fingerprint


def _digest(values):
    return hashlib.sha256(np.asarray(values, dtype='<f8').tobytes(order='C')).hexdigest()


def _coverage(values, duration):
    ordered = sorted(float(v) for v in values if math.isfinite(float(v)))
    n, count = len(values), len(ordered)
    threshold = math.ceil(9*n/10)
    t90 = ordered[threshold-1] if n and count >= threshold else None
    t100 = ordered[-1] if n and count == n else None
    return dict(points=n, covered=count, uncovered=n-count,
                coverage_end_fraction=count/n if n else None, threshold_90_count=threshold,
                T90_s=t90, T100_s=t100, reached_90=t90 is not None,
                reached_100=t100 is not None, status='AVAILABLE' if n else 'EMPTY_DOMAIN')


def _summary(spans):
    sizes = [pair[1]-pair[0] for pair in spans]
    return dict(gap_count=len(spans), mean_s=sum(sizes)/len(spans) if spans else None,
                max_s=max(sizes) if spans else None,
                longest_endpoints_s=spans[sizes.index(max(sizes))] if spans else None)


def _regional(raw, targets, duration, tolerance):
    require(set(raw) == set(targets), 'CHECKER_REGIONAL_TARGET_SET')
    objects, pooled, boundaries = {}, [], []
    longest = None
    for target in targets:
        spans = sorted([float(a), float(b)] for a, b in raw[target])
        require(all(math.isfinite(a) and math.isfinite(b) and 0 <= a <= b <= duration
                    for a, b in spans), 'CHECKER_INVALID_INTERVAL')
        # Cluster by gaps in the cumulative stopping frontier, independently
        # of the main implementation's incremental mutation of merged spans.
        if spans:
            starts, stops = np.asarray(spans, dtype=np.float64).T
            frontier = np.maximum.accumulate(stops)
            breaks = np.flatnonzero(starts[1:] > frontier[:-1]+tolerance)+1
            firsts = [0]+breaks.tolist()
            lasts = (breaks-1).tolist()+[len(spans)-1]
            merged = [[float(starts[a]), float(frontier[b])] for a, b in zip(firsts, lasts)]
        else:
            merged = []
        gaps = [[left[1], right[0]] for left, right in zip(merged, merged[1:])]
        edges = [[0., merged[0][0]], [merged[-1][1], float(duration)]] if merged else [[0., float(duration)]]
        with_edges = gaps + [pair for pair in edges if pair[0] < pair[1]]
        pooled += gaps
        boundaries += with_edges
        internal = _summary(gaps)
        objects[target] = dict(raw_count=len(raw[target]), raw_intervals=raw[target],
            merged_count=len(merged), merged_intervals=merged, internal_gaps=gaps,
            internal=internal, boundary_segments=edges, boundary_inclusive=_summary(with_edges),
            valid_revisit=len(merged) > 1)
        if internal['max_s'] is not None and (longest is None or internal['max_s'] > longest['duration_s']):
            longest = dict(target=target, duration_s=internal['max_s'], endpoints_s=internal['longest_endpoints_s'])
    return dict(targets=objects, raw_count=sum(map(len, raw.values())),
                pooled_internal=_summary(pooled), pooled_boundary_inclusive=_summary(boundaries),
                longest_internal_gap=longest, boundary_gaps_included_in_primary=False,
                semantics='Individual internal gaps pooled across all declared objects')


def _decision(report, baseline, required_count, duration, tolerance):
    reasons = []
    indices, mask = report['indices'], report['effective_grid']
    if len(indices) != required_count or len(set(indices)) != required_count or report['unique_state_count'] != required_count:
        reasons.append('NOT_EXACTLY_28_LEGAL_UNIQUE_STATES')
    if mask['points'] == 0 or mask['covered'] != mask['points']:
        reasons.append('MASK_NOT_EXACT_FULL_COVERAGE')
    for target, item in report['regional']['targets'].items():
        if not item['valid_revisit']:
            reasons.append('INSUFFICIENT_MERGED_VISITS:'+target)
    if mask['T100_s'] is None or mask['T100_s'] > duration:
        reasons.append('T100_INVALID_OR_OUTSIDE_WINDOW')
    if baseline is not None:
        for key in ('T90_s', 'T100_s'):
            a, b = mask[key], baseline['effective_grid'][key]
            if a is None or b is None or a > b+tolerance:
                reasons.append(key+'_WORSE_THAN_BASELINE')
        a = report['regional']['pooled_internal']['mean_s']
        b = baseline['regional']['pooled_internal']['mean_s']
        if a is None or b is None or a > b+tolerance:
            reasons.append('Tavg_s_WORSE_THAN_BASELINE')
    return dict(feasible=len(reasons) == 0, rejection_reasons=reasons)


def _differences(expected, reported, tolerance, path=''):
    differences = []
    if isinstance(expected, dict):
        if not isinstance(reported, dict) or set(expected) != set(reported):
            return [dict(path=path, reason='SCHEMA_KEYS')]
        for key in expected:
            differences += _differences(expected[key], reported[key], tolerance, path+'/'+key)
    elif isinstance(expected, list):
        if not isinstance(reported, list) or len(expected) != len(reported):
            return [dict(path=path, reason='LIST_LENGTH')]
        for i, (a, b) in enumerate(zip(expected, reported)):
            differences += _differences(a, b, tolerance, path+'/'+str(i))
    elif isinstance(expected, float):
        if isinstance(reported, bool) or not isinstance(reported, (float, int)) or not math.isfinite(reported) or abs(expected-reported) > tolerance:
            differences.append(dict(path=path, reason='ABSOLUTE_NUMERIC_MISMATCH', expected=expected, reported=reported))
    elif type(expected) is not type(reported) or expected != reported:
        differences.append(dict(path=path, reason='EXACT_MISMATCH', expected=expected, reported=reported))
    return differences


class IndependentChecker:
    def __init__(self, baseline_indices, rows, intervals, keep, targets, states,
                 duration=604800, tolerance=1e-6, required_count=28):
        self.baseline_indices = list(baseline_indices)
        self.rows, self.intervals, self.keep = rows, intervals, np.asarray(keep)
        self.targets, self.states = list(targets), states
        self.duration, self.tolerance, self.required_count = duration, tolerance, required_count
        require(self.baseline_indices and len(set(self.baseline_indices)) == len(self.baseline_indices), 'CHECKER_BASELINE_INDICES')
        shape = np.asarray(rows[self.baseline_indices[0]]).shape
        require(len(shape) == 1 and self.keep.dtype == np.bool_ and self.keep.shape == shape, 'CHECKER_ROW_MASK_SHAPE')
        self.row_digests = {}
        for index, row in rows.items():
            a = np.asarray(row)
            finite = a[np.isfinite(a)]
            require(a.shape == shape and not np.isnan(a).any() and not np.isneginf(a).any()
                    and not (finite < 0).any() and not (finite > duration).any(), 'CHECKER_INVALID_SOURCE_ROW')
            self.row_digests[index] = _digest(a)
        self.prefix = [np.full(shape, np.inf)]
        for index in self.baseline_indices:
            self.prefix.append(np.minimum(self.prefix[-1], rows[index]))
        self.suffix = [None]*(len(self.baseline_indices)+1)
        self.suffix[-1] = np.full(shape, np.inf)
        for position in range(len(self.baseline_indices)-1, -1, -1):
            self.suffix[position] = np.minimum(rows[self.baseline_indices[position]], self.suffix[position+1])
        self.expected = {}
        self.baseline_reference = self.recompute(self.baseline_indices)[0]

    def _hits(self, indices, remove=None, add=None):
        require(len(indices) == len(set(indices)), 'CHECKER_DUPLICATE_INDEX')
        original, selected = set(self.baseline_indices), set(indices)
        if original == selected:
            require(remove is None and add is None, 'CHECKER_BASELINE_WITH_SWAP_LABEL')
            return self.prefix[-1].copy()
        removed, added = original-selected, selected-original
        require(len(removed) == 1 and len(added) == 1, 'CHECKER_NOT_SINGLE_REPLACEMENT')
        actual_remove, actual_add = next(iter(removed)), next(iter(added))
        require((remove is None or remove == actual_remove) and (add is None or add == actual_add), 'CHECKER_SWAP_LABEL_MISMATCH')
        require(actual_add in self.rows and actual_add not in original, 'CHECKER_UNAVAILABLE_DONOR')
        position = self.baseline_indices.index(actual_remove)
        return np.minimum(np.minimum(self.prefix[position], self.suffix[position+1]), self.rows[actual_add])

    def recompute(self, indices, baseline_report=None, remove=None, add=None):
        indices = list(indices)
        if baseline_report is not None:
            # Gates use independently reconstructed baseline values, rather
            # than accepting a caller's mutable production baseline metrics.
            baseline_report = self.baseline_reference
        require(all(i in self.rows and i in self.intervals and i in self.states for i in indices), 'CHECKER_UNAVAILABLE_COMPONENT')
        require(len({self.states[i] for i in indices}) == len(indices), 'CHECKER_DUPLICATE_STATE')
        hits = self._hits(indices, remove, add)
        raw = {target: [] for target in self.targets}
        for index in indices:
            require(set(self.intervals[index]) == set(self.targets), 'CHECKER_REGIONAL_TARGET_SET')
            for target in self.targets:
                raw[target] += self.intervals[index][target]
        report = dict(indices=indices, identity=fingerprint(sorted(self.states[i] for i in indices)),
            unique_state_count=len({self.states[i] for i in indices}),
            full_grid=_coverage(hits, self.duration), effective_grid=_coverage(hits[self.keep], self.duration),
            regional=_regional(raw, self.targets, self.duration, self.tolerance),
            first_hits_sha256=_digest(hits),
            input_state_identity=fingerprint([[i, self.states[i]] for i in sorted(indices)]),
            source='archived_component_composition', new_native_validation_performed=False,
            whole_constellation_STK_verified=False, native_verified=False)
        report['feasibility'] = _decision(report, baseline_report, self.required_count, self.duration, self.tolerance)
        old = baseline_report['regional']['pooled_internal']['max_s'] if baseline_report else None
        new = report['regional']['pooled_internal']['max_s']
        change = old-new if old is not None and new is not None else None
        lower = change-self.tolerance if change is not None else None
        improvement = lower is not None and lower >= 1.
        report['improvement'] = dict(Tmax_reduction_s=change, minimum_required_s=1.,
            uncertainty_margin_s=self.tolerance, substantive_improvement=improvement, conservative_lower_bound_s=lower)
        report['qualified_improvement'] = bool(report['feasibility']['feasible'] and improvement)
        report['selection_rejection_reasons'] = list(report['feasibility']['rejection_reasons'])
        if not improvement:
            report['selection_rejection_reasons'].append('Tmax_REDUCTION_BELOW_CONSERVATIVE_ONE_SECOND_GATE')
        return report, hits

    def verify(self, indices, reported, reported_hits, baseline_report=None, remove=None, add=None):
        expected, hits = self.recompute(indices, baseline_report, remove, add)
        identity = expected['identity']
        # remove/add are traversal metadata, not scientific report fields.
        scientific = {key: value for key, value in reported.items() if key not in {'remove', 'add'}}
        differences = _differences(expected, scientific, self.tolerance)
        a = np.asarray(reported_hits)
        classification_count, maximum = None, None
        if a.shape != hits.shape:
            differences.append(dict(path='first_hits', reason='SHAPE_MISMATCH'))
        else:
            valid = np.isfinite(a)
            classification_count = int(np.count_nonzero(valid != np.isfinite(hits)))
            finite = valid & np.isfinite(hits)
            maximum = float(np.max(np.abs(a[finite]-hits[finite]), initial=0.))
            if classification_count or maximum > self.tolerance or np.isnan(a).any() or np.isneginf(a).any():
                differences.append(dict(path='first_hits', reason='POINTWISE_MISMATCH'))
            if _digest(a) != scientific.get('first_hits_sha256'):
                differences.append(dict(path='first_hits_sha256', reason='REPORTED_ARRAY_DIGEST_MISMATCH'))
        intervals = {}
        for target in self.targets:
            expected_spans = expected['regional']['targets'][target]['merged_intervals']
            claimed = reported.get('regional', {}).get('targets', {}).get(target, {}).get('merged_intervals')
            intervals[target] = dict(expected_merged_count=len(expected_spans),
                checker_intervals_sha256=fingerprint(expected_spans),
                main_intervals_sha256=fingerprint(claimed),
                differences=_differences(expected_spans, claimed, self.tolerance, target))
        if not differences:
            self.expected[identity] = expected
        return dict(identity=identity, status='FAIL' if differences else 'PASS',
            differences=differences, points_compared=len(hits), classification_difference_count=classification_count,
            max_absolute_first_hit_error_s=maximum, absolute_tolerance_s=self.tolerance,
            relative_tolerance=0, input_sha256=fingerprint([[i, self.states[i], self.row_digests[i]] for i in sorted(indices)]),
            main_first_hits_sha256=scientific.get('first_hits_sha256'), checker_first_hits_sha256=_digest(hits),
            main_output_sha256=fingerprint(scientific), checker_output_sha256=fingerprint(expected),
            interval_comparisons=intervals, shared_schema='Validated Library rows/coordinates/mask/target parser and state identity format',
            independent_methods='baseline prefix/suffix minima; sorted order statistic; cumulative-frontier clusters; separate gates and ranking')

    def selection(self, candidate_identities=None):
        allowed = set(candidate_identities) if candidate_identities is not None else set(self.expected)
        records = [self.expected[key] for key in allowed if key in self.expected and self.expected[key]['qualified_improvement']]
        records.sort(key=lambda r: (r['regional']['pooled_internal']['max_s'],
            r['regional']['pooled_internal']['mean_s'], r['effective_grid']['T100_s'],
            r['effective_grid']['T90_s'], r['identity']))
        return dict(selected_identity=records[0]['identity'] if records else None,
                    qualified_count=len(records), ranking=[r['identity'] for r in records])

    def verify_completion(self, donors, declared, reports, checks, reported_selected_identity=None):
        """Independently reconstruct all 28 x 32 swaps and the chosen identity."""
        differences = []
        baseline, donors = set(self.baseline_indices), list(donors)
        if len(baseline) != 28 or len(donors) != 32 or len(set(donors)) != 32 or baseline & set(donors):
            differences.append(dict(path='neighborhood', reason='NOT_28_BY_32_DISJOINT_POOL'))
        expected = {}
        for removed in sorted(baseline):
            for added in sorted(donors):
                indices = sorted([i for i in self.baseline_indices if i != removed]+[added])
                identity = fingerprint(sorted(self.states[i] for i in indices))
                expected[(removed, added)] = dict(indices=indices, identity=identity)
        expected_ids = {item['identity'] for item in expected.values()}
        if len(expected) != 896 or len(expected_ids) != 896:
            differences.append(dict(path='neighborhood', reason='NOT_896_UNIQUE_COMBINATIONS'))
        for name, records in [('declared', declared), ('main', reports)]:
            pairs = [(r.get('remove'), r.get('add')) for r in records]
            if len(records) != 896 or len(set(pairs)) != 896 or set(pairs) != set(expected):
                differences.append(dict(path=name, reason='CARTESIAN_PRODUCT_INCOMPLETE_OR_DUPLICATED'))
            for record in records:
                key = (record.get('remove'), record.get('add'))
                spec = expected.get(key)
                if spec is None or record.get('indices') != spec['indices'] or record.get('identity') != spec['identity']:
                    differences.append(dict(path=name, reason='PAIR_IDENTITY_OR_STATE_SET_MISMATCH', pair=key))
                if name == 'main' and spec is not None:
                    recomputed = self.expected.get(spec['identity'])
                    if recomputed is None:
                        differences.append(dict(path=name, reason='NO_INDEPENDENT_PASS', identity=spec['identity']))
                    else:
                        scientific = {k: v for k, v in record.items() if k not in {'remove', 'add'}}
                        differences += _differences(recomputed, scientific, self.tolerance, 'terminal/'+spec['identity'])
        check_ids = [r.get('identity') for r in checks]
        if len(checks) != 896 or len(set(check_ids)) != 896 or set(check_ids) != expected_ids or any(r.get('status') != 'PASS' for r in checks):
            differences.append(dict(path='checks', reason='INDEPENDENT_CANDIDATES_INCOMPLETE_OR_FAILED'))
        choice = self.selection(expected_ids)
        baseline_checked = any(set(r['indices']) == baseline for r in self.expected.values())
        if not baseline_checked:
            differences.append(dict(path='baseline', reason='NO_INDEPENDENT_BASELINE_PASS'))
        if reported_selected_identity != choice['selected_identity']:
            differences.append(dict(path='selection', reason='INDEPENDENT_SELECTION_MISMATCH',
                                    expected=choice['selected_identity'], reported=reported_selected_identity))
        return dict(status='FAIL' if differences else 'PASS', differences=differences,
                    expected_candidates=len(expected), unique_identities=len(expected_ids),
                    main_candidates=len(reports), checker_candidates=len(checks),
                    baseline_checked=baseline_checked,
                    independent_selection=choice,
                    method='Independent reconstruction of each remove/add state set and independent gate/ranking results')


def independently_select(reports):
    """Independent ranking for already independently recomputed reports."""
    ranked = [r for r in reports if r['qualified_improvement']]
    ranked.sort(key=lambda r: (r['regional']['pooled_internal']['max_s'],
        r['regional']['pooled_internal']['mean_s'], r['effective_grid']['T100_s'],
        r['effective_grid']['T90_s'], r['identity']))
    return ranked[0] if ranked else None


def terminal_verification(declared, reports, checks, reported_selected_identity,
                          point_count=43424, tolerance=1e-6):
    """Read-back proof of the sealed Cartesian enumeration and checked ranking.

    This deliberately uses only sealed records.  Full input-based numerical
    recomputation is performed by IndependentChecker before sealing; here its
    pointwise comparison record is bound to the exact corresponding main JSON.
    """
    differences = []
    removes = {r.get('remove') for r in declared}
    donors = {r.get('add') for r in declared}
    declared_pairs = [(r.get('remove'), r.get('add')) for r in declared]
    expected_pairs = {(removed, added) for removed in removes for added in donors}
    if (len(declared) != 896 or len(removes) != 28 or len(donors) != 32
            or removes & donors or len(set(declared_pairs)) != 896
            or set(declared_pairs) != expected_pairs):
        differences.append(dict(path='declared', reason='NOT_EXACT_28_BY_32_CARTESIAN_PRODUCT'))
    declarations = {pair: r for pair, r in zip(declared_pairs, declared)}
    declared_ids = [r.get('identity') for r in declared]
    if len(set(declared_ids)) != 896:
        differences.append(dict(path='declared', reason='NOT_896_UNIQUE_IDENTITIES'))
    for pair, record in declarations.items():
        removed, added = pair
        expected_indices = sorted((removes-{removed}) | {added})
        if record.get('indices') != expected_indices or len(expected_indices) != 28:
            differences.append(dict(path='declared', reason='SWAP_STATE_SET_MISMATCH', pair=pair))
    report_pairs = [(r.get('remove'), r.get('add')) for r in reports]
    report_ids = [r.get('identity') for r in reports]
    if (len(reports) != 896 or len(set(report_pairs)) != 896 or set(report_pairs) != expected_pairs
            or len(set(report_ids)) != 896 or set(report_ids) != set(declared_ids)):
        differences.append(dict(path='reports', reason='MISSING_DUPLICATE_OR_UNKNOWN_CANDIDATE'))
    check_ids = [r.get('identity') for r in checks]
    if len(checks) != 896 or len(set(check_ids)) != 896 or set(check_ids) != set(declared_ids):
        differences.append(dict(path='checks', reason='MISSING_DUPLICATE_OR_UNKNOWN_CHECKER'))
    by_identity = {r.get('identity'): r for r in checks}
    for report in reports:
        identity = report.get('identity')
        pair = (report.get('remove'), report.get('add'))
        declaration = declarations.get(pair)
        indices = report.get('indices', [])
        if (declaration is None or identity != declaration.get('identity')
                or indices != declaration.get('indices') or len(indices) != 28
                or len(set(indices)) != 28 or report.get('unique_state_count') != 28):
            differences.append(dict(path='reports', reason='PAIR_IDENTITY_OR_STATE_SET_MISMATCH', identity=identity))
        checked = by_identity.get(identity, {})
        maximum = checked.get('max_absolute_first_hit_error_s')
        valid_maximum = (not isinstance(maximum, bool) and isinstance(maximum, (int, float))
                         and math.isfinite(maximum) and 0 <= maximum <= tolerance)
        if (checked.get('status') != 'PASS' or checked.get('differences') != []
                or checked.get('points_compared') != point_count
                or checked.get('classification_difference_count') != 0 or not valid_maximum
                or checked.get('relative_tolerance') != 0 or checked.get('absolute_tolerance_s') != tolerance):
            differences.append(dict(path='checks', reason='POINTWISE_CHECK_NOT_COMPLETE_PASS', identity=identity))
        scientific = {key: value for key, value in report.items() if key not in {'remove', 'add'}}
        if checked.get('main_output_sha256') != fingerprint(scientific):
            differences.append(dict(path='checks', reason='MAIN_OUTPUT_DIGEST_MISMATCH', identity=identity))
        if (checked.get('main_first_hits_sha256') != report.get('first_hits_sha256')
                or checked.get('checker_first_hits_sha256') != report.get('first_hits_sha256')):
            differences.append(dict(path='checks', reason='POINT_OUTPUT_DIGEST_MISMATCH', identity=identity))
        region_names = set(report.get('regional', {}).get('targets', {}))
        comparisons = checked.get('interval_comparisons', {})
        if len(region_names) != 3 or set(comparisons) != region_names or any(item.get('differences') != [] for item in comparisons.values()):
            differences.append(dict(path='checks', reason='REGIONAL_CHECK_NOT_COMPLETE_PASS', identity=identity))
        if (report.get('source') != 'archived_component_composition'
                or report.get('new_native_validation_performed') is not False
                or report.get('whole_constellation_STK_verified') is not False
                or report.get('native_verified') is not False):
            differences.append(dict(path='reports', reason='COMPOSITION_NATIVE_SCOPE', identity=identity))
    qualified = [r for r in reports if r.get('qualified_improvement') is True]
    try:
        qualified.sort(key=lambda r: (r['regional']['pooled_internal']['max_s'],
            r['regional']['pooled_internal']['mean_s'], r['effective_grid']['T100_s'],
            r['effective_grid']['T90_s'], r['identity']))
        independently_selected = qualified[0]['identity'] if qualified else None
    except (KeyError, TypeError):
        independently_selected = None
        differences.append(dict(path='selection', reason='MALFORMED_RANKING_METRICS'))
    if independently_selected != reported_selected_identity:
        differences.append(dict(path='selection', reason='INDEPENDENT_RANKING_MISMATCH',
                                expected=independently_selected, reported=reported_selected_identity))
    return dict(status='FAIL' if differences else 'PASS', differences=differences,
                declared_candidates=len(declared), main_candidates=len(reports), checker_candidates=len(checks),
                unique_candidate_identities=len(set(report_ids)), points_per_candidate=point_count,
                selected_identity=independently_selected, qualified_count=len(qualified),
                independent_readback_scope='Sealed Cartesian identities, checked full-point records, exact output digest binding and separate ranking')


def verify_baseline_whole(report, hits, whole_hits, whole_intervals, targets,
                          duration=604800, tolerance=1e-6):
    """Compare reconstructed baseline to saved whole-constellation observations.

    Historical native provenance belongs to the saved observations only; this
    function does not confer native verification on composed candidates.
    """
    a, b = np.asarray(hits), np.asarray(whole_hits)
    differences, per_object = [], {}
    classification_count, maximum = None, None
    if a.shape != b.shape:
        differences.append(dict(path='first_hits', reason='WHOLE_POINT_SHAPE'))
    else:
        classification_count = int(np.count_nonzero(np.isfinite(a) != np.isfinite(b)))
        finite = np.isfinite(a) & np.isfinite(b)
        maximum = float(np.max(np.abs(a[finite]-b[finite]), initial=0.))
        if classification_count or maximum > tolerance or np.isnan(b).any() or np.isneginf(b).any():
            differences.append(dict(path='first_hits', reason='WHOLE_POINTWISE_MISMATCH'))
        differences += _differences(_coverage(b, duration), report['full_grid'], tolerance, 'whole/full_grid')
    historical = _regional(whole_intervals, targets, duration, tolerance)
    for target in targets:
        expected = historical['targets'][target]['merged_intervals']
        claimed = report['regional']['targets'][target]['merged_intervals']
        diff = _differences(expected, claimed, tolerance, 'whole/'+target)
        differences += diff
        error = max([abs(x-y) for pair, other in zip(expected, claimed) for x, y in zip(pair, other)] or [0.])
        per_object[target] = dict(whole_merged_count=len(expected), component_merged_count=len(claimed),
            max_absolute_endpoint_error_s=error,
            whole_intervals_sha256=fingerprint(expected), component_intervals_sha256=fingerprint(claimed),
            differences=diff)
    for key in ('pooled_internal', 'pooled_boundary_inclusive', 'longest_internal_gap'):
        differences += _differences(historical[key], report['regional'][key], tolerance, 'whole/'+key)
    return dict(status='FAIL' if differences else 'PASS', differences=differences,
                points_compared=len(b), classification_difference_count=classification_count,
                max_absolute_first_hit_error_s=maximum, relative_tolerance=0,
                absolute_tolerance_s=tolerance, whole_first_hits_sha256=_digest(b),
                component_first_hits_sha256=_digest(a), regional_comparisons=per_object,
                whole_native_provenance_scope='Historical saved whole constellation only')
