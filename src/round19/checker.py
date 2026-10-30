"""Independent R19 source-array numerics, certificates and exact stream audit.

Only the validated decoder, producer state-token format and the frozen R14
checker numerical primitives are shared.  This module never imports R19's
main science, bitset, interval merge, decision, ranking or selection code.
"""
import hashlib
import itertools
import math

import numpy as np

from src.round13.common import fingerprint, require
from src.round14.checker import (_coverage, _regional, _decision, _differences,
                                 _digest, verify_baseline_whole)

DECLARED = 60004
TARGET = 'YangtzeRiverDelta_Island_1'
PARTS = ('GAP', 'T100', 'T90', 'FULL')
META = {'ordinal', 'remove', 'add', 'partition', 'processing_state'}
ROUND19_FIELDS = {'improvement_vs_original_baseline', 'improvement_vs_R18_incumbent',
                  'qualified_for_round19', 'ranking_key',
                  'round19_selection_rejection_reasons'}


def _pool(center, donors, states):
    c, d = sorted(center), sorted(donors)
    require(len(c) == len(set(c)) == 28 and len(d) == len(set(d)) == 2143,
            'CHECKER_R19_POOL_CARDINALITY')
    require(not set(c) & set(d) and sorted(c+d) == list(range(2171)),
            'CHECKER_R19_EXACT_DONOR_SET')
    require(all(type(i) is int and i in states for i in c+d)
            and len({states[i] for i in c+d}) == 2171, 'CHECKER_R19_STATE_POOL')
    return c, d


def iter_candidates(center, donors, states, check=lambda: None):
    """Construct by replacing one position in a list, independently of sets."""
    c, d = _pool(center, donors, states)
    for ordinal in range(len(c)*len(d)):
        if ordinal % 512 == 0:
            check()
        position, donor_position = divmod(ordinal, len(d))
        indices = c.copy()
        indices[position] = d[donor_position]
        indices.sort()
        require(len(set(indices) ^ set(c)) == 2, 'CHECKER_R19_SYMMETRIC_DIFFERENCE')
        yield dict(ordinal=ordinal, remove=c[position], add=d[donor_position], indices=indices,
                   identity=fingerprint(sorted(states[i] for i in indices)))
    check()


def neighborhood_summary(center, donors, states, check=lambda: None):
    identities, operations = set(), set()
    order, pairs = hashlib.sha256(), hashlib.sha256()
    first = last = None
    for item in iter_candidates(center, donors, states, check):
        identity, operation = item['identity'], (item['remove'], item['add'])
        require(identity not in identities and operation not in operations,
                'CHECKER_R19_SPACE_DUPLICATE')
        identities.add(identity); operations.add(operation)
        order.update((identity+'\n').encode('ascii'))
        pairs.update((str(operation[0])+','+str(operation[1])+'\n').encode('ascii'))
        first = item if first is None else first
        last = item
    require(len(identities) == len(operations) == DECLARED, 'CHECKER_R19_SPACE_SIZE')
    return dict(declared_candidates=len(identities), unique_identities=len(identities),
        identity_order_sha256=order.hexdigest(), pair_order_sha256=pairs.hexdigest(),
        center_indices=sorted(center), baseline_indices=sorted(center), donor_indices=sorted(donors),
        first=first, last=last,
        method='Independent position replacement; exact operations/state identities and symmetric difference')


def classification_digest(values):
    return hashlib.sha256(np.asarray(values, dtype=np.uint8).tobytes(order='C')).hexdigest()


def boolean_on_time(rows, indices, keep, tau):
    keep = np.asarray(keep)
    require(keep.dtype == np.bool_ and keep.ndim == 1 and math.isfinite(float(tau)),
            'CHECKER_BOOLEAN_SCHEMA')
    result = np.zeros(int(keep.sum()), dtype=np.bool_)
    for index in indices:
        source = np.asarray(rows[index])
        finite = source[np.isfinite(source)]
        require(source.shape == keep.shape and not np.isnan(source).any()
                and not np.isneginf(source).any() and not (finite < 0).any()
                and not (finite > 604800).any(), 'CHECKER_BOOLEAN_SOURCE')
        result = np.logical_or(result, source[keep] <= tau)
    return result


def verify_t100_witness(rows, indices, point_id, tau, source_values=None, states=None):
    differences, expected = [], []
    if (type(point_id) is not int or point_id < 0 or not indices
            or any(point_id >= len(rows[i]) for i in indices)):
        return dict(status='FAIL', differences=[dict(path='point_id', reason='INVALID_POINT_ID')],
                    source_values=[])
    for index in indices:
        value = float(rows[index][point_id])
        if math.isnan(value) or value == -math.inf or value <= tau or (math.isfinite(value) and value > 604800):
            differences.append(dict(path='source_values/'+str(index), reason='SOURCE_NOT_VALID_LATE_VALUE'))
        row = dict(index=index, first_hit_s=value if math.isfinite(value) else None,
                   classification='FINITE_LATE' if math.isfinite(value) else 'NO_FIRST_HIT')
        if states is not None:
            row['state'] = states[index]
        expected.append(row)
    if source_values is not None:
        differences += _differences(expected, source_values, 0, 'source_values')
    return dict(status='FAIL' if differences else 'PASS', differences=differences,
                source_values=expected, point_id=point_id, tau100=tau)


def verify_t90_count(rows, indices, keep, tau, k90, c90, digest):
    values = boolean_on_time(rows, indices, keep, tau)
    count, actual_digest = int(np.count_nonzero(values)), classification_digest(values)
    differences = []
    if type(c90) is not int or count != c90:
        differences.append(dict(path='c90', reason='EXACT_COUNT_MISMATCH', expected=count, reported=c90))
    if actual_digest != digest:
        differences.append(dict(path='classification_sha256', reason='CLASSIFICATION_DIGEST_MISMATCH'))
    if count >= k90:
        differences.append(dict(path='c90', reason='NO_T90_VIOLATION'))
    return dict(status='FAIL' if differences else 'PASS', differences=differences,
                c90=count, k90=k90, classification_sha256=actual_digest)


def _scientific(report):
    return {key: value for key, value in report.items() if key not in META}


def _rank(report):
    return [report['regional']['pooled_internal']['max_s'],
            report['regional']['pooled_internal']['mean_s'],
            report['effective_grid']['T100_s'], report['effective_grid']['T90_s'], report['identity']]


def _annotate(report, center):
    old, new = center['regional']['pooled_internal']['max_s'], report['regional']['pooled_internal']['max_s']
    reduction = old-new if old is not None and new is not None else None
    lower = reduction-1e-6 if reduction is not None else None
    substantive = lower is not None and lower >= 1.
    report['improvement_vs_original_baseline'] = dict(report['improvement'])
    report['improvement_vs_R18_incumbent'] = dict(Tmax_reduction_s=reduction, minimum_required_s=1.,
        uncertainty_margin_s=1e-6, substantive_improvement=substantive, conservative_lower_bound_s=lower)
    report['qualified_for_round19'] = bool(report['feasibility']['feasible'] and substantive)
    report['ranking_key'] = _rank(report)
    reasons = list(report['feasibility']['rejection_reasons'])
    if not substantive:
        reasons.append('Tmax_REDUCTION_VS_R18_INCUMBENT_BELOW_CONSERVATIVE_ONE_SECOND_GATE')
    report['round19_selection_rejection_reasons'] = reasons
    return report


def compact_report(report):
    if report.get('_compact') is True:
        return report
    result = {key: report[key] for key in META | {'identity', 'indices', 'source',
        'new_native_validation_performed', 'whole_constellation_STK_verified', 'native_verified',
        'first_hits_sha256'} if key in report}
    result.update(_compact=True, qualified_for_round19=report['qualified_for_round19'],
                  rank=_rank(report), main_output_sha256=fingerprint(_scientific(report)))
    return result


class IndependentChecker:
    def __init__(self, lib, baseline_report=None, center_report=None, check=lambda: None,
                 duration=604800, tolerance=1e-6, required_count=28):
        self.lib, self.check = lib, check
        self.rows, self.intervals, self.states = lib.rows, lib.intervals, lib.states
        self.targets, self.keep = list(lib.targets), np.asarray(lib.keep)
        self.duration, self.tolerance, self.required_count = duration, tolerance, required_count
        self.original_indices = sorted(lib.baseline_indices)
        inferred = sorted((set(self.original_indices)-{1217, 1284}) | {2021, 2023})
        self.center_indices = sorted(center_report['indices'] if center_report is not None
                                     else getattr(lib, 'center_indices', inferred))
        self.donors = sorted(set(self.rows)-set(self.center_indices))
        _pool(self.center_indices, self.donors, self.states)
        shape = np.asarray(self.rows[self.original_indices[0]]).shape
        require(len(shape) == 1 and self.keep.dtype == np.bool_ and self.keep.shape == shape,
                'CHECKER_R19_ROW_MASK_SHAPE')
        require(set(self.rows) == set(self.intervals) == set(self.states), 'CHECKER_R19_SOURCE_POOL')
        self.row_digests = {}
        for index, source in self.rows.items():
            check()
            values = np.asarray(source); finite = values[np.isfinite(values)]
            require(values.shape == shape and not np.isnan(values).any() and not np.isneginf(values).any()
                    and not (finite < 0).any() and not (finite > duration).any(), 'CHECKER_INVALID_SOURCE_ROW')
            require(set(self.intervals[index]) == set(self.targets), 'CHECKER_REGIONAL_TARGET_SET')
            self.row_digests[index] = _digest(values)
        self.expected, self.certified, self.independent_partitions = {}, {}, {}
        self.boolean_cache, self.donor_boolean_cache, self.minimum_cache = {}, {}, {}
        self.cache_binding_cache = {}
        self.baseline_reference = None
        self.center_reference = None
        self.baseline_reference = self.recompute(self.original_indices)[0]
        self.center_reference = self.recompute(self.center_indices, self.baseline_reference)[0]
        self.mask_ids = np.flatnonzero(self.keep)
        self.tau100 = self.baseline_reference['effective_grid']['T100_s']+tolerance
        self.tau90 = self.baseline_reference['effective_grid']['T90_s']+tolerance
        self.k90 = math.ceil(9*len(self.mask_ids)/10)
        self.mask_sha256 = classification_digest(self.keep)
        self.coordinate_sha256 = hashlib.sha256(np.asarray(lib.coords, dtype='<f8').tobytes()).hexdigest()
        self.matrix_sha256 = getattr(lib, 'matrix_sha256', None)
        if self.matrix_sha256 is None:
            self.matrix_sha256 = getattr(lib, 'evidence', {}).get('matrix', {}).get('sha256')
        self.center_identity = self.center_reference['identity']
        self.gap_state = self._rebuild_gap()
        self.source_binding = fingerprint(dict(matrix_sha256=self.matrix_sha256,
            mask_sha256=self.mask_sha256, coordinate_sha256=self.coordinate_sha256,
            center_identity=self.center_identity, tau100=self.tau100, tau90=self.tau90,
            rows=[[i, self.states[i], self.row_digests[i], self.gap_state['payload'][i]] for i in sorted(self.rows)]))
        if baseline_report is not None or center_report is not None:
            self.set_references(baseline_report or self.baseline_reference,
                                center_report or self.center_reference)

    def set_references(self, baseline_report, center_report):
        for name, expected, reported in [('B0', self.baseline_reference, baseline_report),
                                         ('S', self.center_reference, center_report)]:
            for key in ('identity', 'indices', 'full_grid', 'effective_grid', 'regional', 'first_hits_sha256'):
                require(not _differences(expected[key], reported[key], self.tolerance),
                        'CHECKER_R19_REFERENCE_MISMATCH:'+name+'/'+key)
        return dict(status='PASS', original_constraint_reference=self.baseline_reference['identity'],
                    search_center=self.center_identity, improvement_reference=self.center_identity)

    def enumerate_space(self, check=lambda: None):
        return iter_candidates(self.center_indices, self.donors, self.states, check)

    def _hits(self, indices, remove_pair=None, add_pair=None):
        require(len(indices) == len(set(indices)), 'CHECKER_DUPLICATE_INDEX')
        selected, center = set(indices), set(self.center_indices)
        removed, added = sorted(center-selected), sorted(selected-center)
        if len(removed) == len(added) == 1:
            remove, add = removed[0], added[0]
            require((remove_pair is None or remove_pair == remove)
                    and (add_pair is None or add_pair == add), 'CHECKER_R19_SWAP_LABEL')
            key = (tuple(self.center_indices), remove,
                   tuple((i, self.row_digests[i]) for i in self.center_indices if i != remove))
            if key not in self.minimum_cache:
                # Independent pairwise reduction; main evaluator uses stack/min.
                vector = np.full(len(self.keep), np.inf)
                for index in self.center_indices:
                    if index != remove:
                        vector = np.minimum(vector, self.rows[index])
                self.minimum_cache[key] = vector
            return np.minimum(self.minimum_cache[key], self.rows[add])
        require(remove_pair is None and add_pair is None, 'CHECKER_REPLAY_WITH_SWAP_LABEL')
        require(selected in (set(self.original_indices), center), 'CHECKER_R19_OUT_OF_SCOPE_NUMERICS')
        vector = np.full(len(self.keep), np.inf)
        for index in indices:
            vector = np.minimum(vector, self.rows[index])
        return vector

    def recompute(self, indices, baseline_report=None, remove_pair=None, add_pair=None):
        indices = list(indices)
        require(all(type(i) is int and i in self.rows for i in indices), 'CHECKER_UNAVAILABLE_COMPONENT')
        require(len({self.states[i] for i in indices}) == len(indices), 'CHECKER_DUPLICATE_STATE')
        hits = self._hits(indices, remove_pair, add_pair)
        raw = {target: [] for target in self.targets}
        for index in indices:
            for target in self.targets:
                raw[target] += self.intervals[index][target]
        report = dict(indices=indices, identity=fingerprint(sorted(self.states[i] for i in indices)),
            unique_state_count=len({self.states[i] for i in indices}),
            full_grid=_coverage(hits, self.duration), effective_grid=_coverage(hits[self.keep], self.duration),
            regional=_regional(raw, self.targets, self.duration, self.tolerance), first_hits_sha256=_digest(hits),
            input_state_identity=fingerprint([[i, self.states[i]] for i in sorted(indices)]),
            source='archived_component_composition', new_native_validation_performed=False,
            whole_constellation_STK_verified=False, native_verified=False)
        reference = self.baseline_reference if baseline_report is not None else None
        report['feasibility'] = _decision(report, reference, self.required_count, self.duration, self.tolerance)
        old = reference['regional']['pooled_internal']['max_s'] if reference else None
        new = report['regional']['pooled_internal']['max_s']
        change = old-new if old is not None and new is not None else None
        lower = change-self.tolerance if change is not None else None
        substantive = lower is not None and lower >= 1.
        report['improvement'] = dict(Tmax_reduction_s=change, minimum_required_s=1.,
            uncertainty_margin_s=self.tolerance, substantive_improvement=substantive, conservative_lower_bound_s=lower)
        report['qualified_improvement'] = bool(report['feasibility']['feasible'] and substantive)
        report['selection_rejection_reasons'] = list(report['feasibility']['rejection_reasons'])
        if not substantive:
            report['selection_rejection_reasons'].append('Tmax_REDUCTION_BELOW_CONSERVATIVE_ONE_SECOND_GATE')
        return report, hits

    def verify(self, indices, reported, reported_hits, baseline_report=None, remove_pair=None, add_pair=None):
        expected, hits = self.recompute(indices, baseline_report, remove_pair, add_pair)
        if ROUND19_FIELDS & set(reported):
            _annotate(expected, self.center_reference)
        scientific = _scientific(reported)
        differences = _differences(expected, scientific, self.tolerance)
        actual = np.asarray(reported_hits)
        classification = maximum = None
        if actual.shape != hits.shape:
            differences.append(dict(path='first_hits', reason='SHAPE_MISMATCH'))
        else:
            classification = int(np.count_nonzero(np.isfinite(actual) != np.isfinite(hits)))
            finite = np.isfinite(actual) & np.isfinite(hits)
            maximum = float(np.max(np.abs(actual[finite]-hits[finite]), initial=0.))
            if classification or maximum > self.tolerance or np.isnan(actual).any() or np.isneginf(actual).any():
                differences.append(dict(path='first_hits', reason='POINTWISE_MISMATCH'))
            if _digest(actual) != scientific.get('first_hits_sha256'):
                differences.append(dict(path='first_hits_sha256', reason='REPORTED_ARRAY_DIGEST_MISMATCH'))
        comparisons = {}
        for target in self.targets:
            spans = expected['regional']['targets'][target]['merged_intervals']
            claimed = reported.get('regional', {}).get('targets', {}).get(target, {}).get('merged_intervals')
            comparisons[target] = dict(expected_merged_count=len(spans), checker_intervals_sha256=fingerprint(spans),
                main_intervals_sha256=fingerprint(claimed), differences=_differences(spans, claimed, self.tolerance, target))
        qualified = expected.get('qualified_for_round19', False)
        result = dict(identity=expected['identity'], status='FAIL' if differences else 'PASS', differences=differences,
            points_compared=len(hits), classification_difference_count=classification,
            max_absolute_first_hit_error_s=maximum, absolute_tolerance_s=self.tolerance, relative_tolerance=0,
            input_sha256=fingerprint([[i, self.states[i], self.row_digests[i]] for i in sorted(indices)]),
            main_first_hits_sha256=scientific.get('first_hits_sha256'), checker_first_hits_sha256=_digest(hits),
            main_output_sha256=fingerprint(scientific), checker_output_sha256=fingerprint(expected),
            interval_comparisons=comparisons, qualified_for_round19=qualified, rank=_rank(expected),
            shared_schema='Validated decoder/coordinates/mask/producer state-token format; frozen R14 checker primitives',
            independent_methods='Pairwise retained minima; sorted order statistic; cumulative-frontier intervals; B0 gates/S improvement')
        if not differences and ROUND19_FIELDS <= set(reported):
            self.expected[expected['identity']] = dict(identity=expected['identity'], indices=list(indices),
                qualified_for_round19=qualified, rank=_rank(expected), main_output_sha256=result['main_output_sha256'],
                checker_output_sha256=result['checker_output_sha256'])
        return result

    def _candidate(self, candidate):
        remove, add = candidate.get('remove'), candidate.get('add')
        require(type(remove) is int and remove in self.center_indices
                and type(add) is int and add in self.donors, 'CHECKER_R19_OPERATION_MEMBERSHIP')
        indices = [i for i in self.center_indices if i != remove]+[add]
        indices.sort()
        expected = dict(remove=remove, add=add, indices=indices,
            identity=fingerprint(sorted(self.states[i] for i in indices)),
            ordinal=self.center_indices.index(remove)*len(self.donors)+self.donors.index(add))
        require(all(candidate.get(k) == value for k, value in expected.items()),
                'CHECKER_R19_OPERATION_IDENTITY_OR_ORDER')
        return expected

    def _rebuild_gap(self):
        require(TARGET in self.targets, 'CHECKER_R19_GAP_TARGET_MISSING')
        raw, payload = {}, {}
        for index in sorted(self.rows):
            self.check()
            values = []
            for pair in self.intervals[index][TARGET]:
                require(isinstance(pair, (tuple, list)) and len(pair) == 2, 'CHECKER_GAP_INTERVAL_SCHEMA')
                a, b = map(float, pair)
                require(math.isfinite(a) and math.isfinite(b) and 0 <= a <= b <= self.duration,
                        'CHECKER_GAP_INTERVAL_WINDOW')
                values.append([a, b])
            raw[index] = values
            asset = getattr(self.lib, 'assets', {}).get(index, {})
            payload[index] = asset.get('regional_data_sha256', fingerprint(self.intervals[index]))
            if 'state' in asset:
                require(asset['state'] == self.states[index], 'CHECKER_GAP_ASSET_STATE')
        gaps = self.center_reference['regional']['targets'][TARGET]['internal_gaps']
        require(bool(gaps), 'CHECKER_R19_NO_INTERNAL_GAP')
        left, right = max(gaps, key=lambda pair: pair[1]-pair[0])
        require(abs((right-left)-self.center_reference['regional']['pooled_internal']['max_s']) <= self.tolerance,
                'CHECKER_R19_GAP_NOT_CENTER_TMAX')
        # Complement form includes interior zero-duration intervals; endpoint contact does not enter.
        inside = {i: [pair for pair in values if not (pair[1] <= left or pair[0] >= right)]
                  for i, values in raw.items()}
        require(not any(inside[i] for i in self.center_indices), 'CHECKER_CENTER_VISITS_INSIDE_OWN_GAP')
        before = {i: [pair for pair in raw[i] if pair[1] <= left] for i in self.center_indices}
        after = {i: [pair for pair in raw[i] if pair[0] >= right] for i in self.center_indices}
        return dict(target=TARGET, L=left, R=right, length=right-left, raw=raw, payload=payload,
                    inside=inside, before=before, after=after,
                    interval_sha256={i: fingerprint(raw[i]) for i in raw})

    def _gap_witnesses(self, candidate):
        gap, remove = self.gap_state, candidate['remove']
        left = [(i, span) for i in self.center_indices if i != remove for span in gap['before'][i]]
        right = [(i, span) for i in self.center_indices if i != remove for span in gap['after'][i]]
        return left, right

    def _retained_boolean(self, remove, tau):
        key = (remove, tau, self.source_binding, tuple(self.center_indices))
        if key not in self.boolean_cache:
            self.boolean_cache[key] = boolean_on_time(self.rows,
                [i for i in self.center_indices if i != remove], self.keep, tau)
        return self.boolean_cache[key]

    def _donor_boolean(self, donor, tau):
        key = (donor, tau, self.source_binding, self.row_digests[donor])
        if key not in self.donor_boolean_cache:
            self.donor_boolean_cache[key] = np.asarray(self.rows[donor])[self.keep] <= tau
        return self.donor_boolean_cache[key]

    def _boolean(self, candidate, tau):
        return np.logical_or(self._retained_boolean(candidate['remove'], tau),
                             self._donor_boolean(candidate['add'], tau))

    def partition(self, candidate):
        self._candidate(candidate)
        left, right = self._gap_witnesses(candidate)
        if not self.gap_state['inside'][candidate['add']] and left and right:
            part = 'GAP'
        elif not bool(np.all(self._boolean(candidate, self.tau100))):
            part = 'T100'
        elif int(np.count_nonzero(self._boolean(candidate, self.tau90))) < self.k90:
            part = 'T90'
        else:
            part = 'FULL'
        self.independent_partitions[candidate['identity']] = part
        return part

    def binding(self, candidate):
        return fingerprint(dict(source_binding=self.source_binding, center_identity=self.center_identity,
            original_constraint_reference_identity=self.baseline_reference['identity'],
            rows=[[i, self.states[i], self.row_digests[i], self.gap_state['payload'][i]] for i in candidate['indices']]))

    def _cache_binding(self, remove):
        cache_key = (remove, self.source_binding, tuple(self.center_indices))
        if cache_key in self.cache_binding_cache:
            return self.cache_binding_cache[cache_key]
        on_time100 = self._retained_boolean(remove, self.tau100)
        points = self.mask_ids[np.logical_not(on_time100)]
        boolean90 = self._retained_boolean(remove, self.tau90)
        # Packing is solely a cache-byte binding; scientific decisions above
        # use independently computed original-array Boolean OR/count.
        bit_integer = int.from_bytes(np.packbits(boolean90, bitorder='little').tobytes(), 'little')
        result = fingerprint(dict(source_binding=self.source_binding, center_identity=self.center_identity,
            remove=remove, tolerance_s=1e-6, failed_point_ids=points.tolist(),
            retained90_sha256=fingerprint(hex(bit_integer))))
        self.cache_binding_cache[cache_key] = result
        return result

    def verify_gate_evidence(self, evidence):
        gap, differences = self.gap_state, []
        assertions = dict(tau100=self.tau100, tau90=self.tau90, k90=self.k90,
            mask_sha256=self.mask_sha256, coordinate_sha256=self.coordinate_sha256,
            matrix_sha256=self.matrix_sha256, source_binding_sha256=self.source_binding,
            center_identity=self.center_identity, original_constraint_reference_identity=self.baseline_reference['identity'],
            center_indices=self.center_indices, donor_indices=self.donors,
            before_center_assets=[i for i in self.center_indices if gap['before'][i]],
            after_center_assets=[i for i in self.center_indices if gap['after'][i]],
            bridge_donors=[i for i in self.donors if gap['inside'][i]],
            nonbridge_donors=[i for i in self.donors if not gap['inside'][i]],
            cache_bindings={str(i): self._cache_binding(i) for i in self.center_indices},
            n=len(self.mask_ids), priority=list(PARTS),
            bitset_effective_bits=len(self.mask_ids), bitset_padding_bits=(-len(self.mask_ids)) % 8,
            bitset_padding_zero=True, feasibility_inferred_from_gap=False,
            candidate_REUSED=0, gap_is_internal_only_with_both_side_witnesses=True)
        for key, value in assertions.items():
            differences += _differences(value, evidence.get(key), 0, 'gate/'+key)
        # Evidence may group the gap data under "gap"; both schemas retain raw all-asset sources.
        context = evidence.get('gap', evidence)
        expected = dict(target=TARGET, L=gap['L'], R=gap['R'])
        for key, value in expected.items():
            differences += _differences(value, context.get(key), self.tolerance, 'gap/'+key)
        aliases = [('raw_asset_intervals', gap['raw']),
                   ('source_payload_sha256', gap['payload']),
                   ('asset_interval_sha256', gap['interval_sha256'])]
        for key, values in aliases:
            claimed = context.get(key, evidence.get(key))
            expected_values = {str(i): value for i, value in values.items()}
            differences += _differences(expected_values, claimed, 0, 'gap/'+key)
        proof_digest = fingerprint({k: v for k, v in evidence.items() if k != 'proof_sha256'})
        if evidence.get('proof_sha256') != proof_digest:
            differences.append(dict(path='proof_sha256', reason='GATE_PROOF_DIGEST'))
        self.gate_context = evidence
        self.gate_context_sha256 = fingerprint(evidence)
        return dict(status='FAIL' if differences else 'PASS', differences=differences,
            main_gate_sha256=fingerprint(evidence), all_raw_asset_intervals_rebuilt=len(gap['raw']),
            independently_entering_donors=[i for i in self.donors if gap['inside'][i]],
            before_owners=[i for i in self.center_indices if gap['before'][i]],
            after_owners=[i for i in self.center_indices if gap['after'][i]],
            method='All raw intervals; complementary open-gap predicate; independent source-array Boolean thresholds')

    def verify_certificate(self, candidate, record, gate_context=None):
        canonical = self._candidate(candidate)
        part = self.partition(candidate)
        require(part in PARTS[:-1], 'CHECKER_CANNOT_CERTIFY_FULL')
        differences = []
        for key, value in canonical.items():
            differences += _differences(value, record.get(key), 0, 'certificate/'+key)
        assertions = dict(partition=part, metrics_status='NOT_EVALUATED', full_grid=None,
            effective_grid=None, regional=None, feasibility='NOT_EVALUATED', first_hits_sha256=None,
            T90_s=None, T100_s=None, Tavg_s=None, Tmax_s=None, qualified_for_round19=False,
            known_infeasible=None if part == 'GAP' else True, input_binding_sha256=self.binding(candidate),
            center_identity=self.center_identity,
            original_constraint_reference_identity=self.baseline_reference['identity'],
            tau100=self.tau100, tau90=self.tau90, k90=self.k90,
            mask_sha256=self.mask_sha256, coordinate_sha256=self.coordinate_sha256,
            source='archived_component_composition', new_native_validation_performed=False,
            whole_constellation_STK_verified=False, native_verified=False,
            full_feasibility_evaluation_performed=False,
            status='PROVEN_NO_ROUND19_IMPROVEMENT' if part == 'GAP' else 'KNOWN_INFEASIBLE',
            processing_state=part+'_CERTIFICATE_REJECTED', cache_binding_sha256=self._cache_binding(candidate['remove']))
        for key, value in assertions.items():
            differences += _differences(value, record.get(key), 0, 'certificate/'+key)
        context = gate_context or getattr(self, 'gate_context', None)
        if context is not None and record.get('proof_sha256') != context.get('proof_sha256'):
            differences.append(dict(path='proof_sha256', reason='GATE_CONTEXT_BINDING'))
        proof_details = {}
        if part == 'GAP':
            gap, add = self.gap_state, candidate['add']
            left, right = self._gap_witnesses(candidate)
            assertions = dict(target=TARGET, L=gap['L'], R=gap['R'], Tmax_lower_bound_s=gap['length'],
                donor_raw_intervals=gap['raw'][add], donor_interval_sha256=gap['interval_sha256'][add],
                donor_source_payload_sha256=gap['payload'][add],
                retained_before_asset_count=len({i for i, span in left}),
                retained_after_asset_count=len({i for i, span in right}),
                minimum_required_improvement_s=1., uncertainty_margin_s=self.tolerance)
            for key, value in assertions.items():
                differences += _differences(value, record.get(key), 0, 'certificate/'+key)
            for side, witnesses in [('before', left), ('after', right)]:
                witness = record.get(side+'_witness')
                if not isinstance(witness, dict):
                    differences.append(dict(path=side+'_witness', reason='MISSING_WITNESS'))
                    continue
                index, interval = witness.get('index'), witness.get('interval')
                if not any(i == index and span == interval for i, span in witnesses):
                    differences.append(dict(path=side+'_witness', reason='NO_SURVIVING_RAW_WITNESS'))
                elif witness.get('state') != self.states[index] or witness.get('source_payload_sha256') != gap['payload'][index]:
                    differences.append(dict(path=side+'_witness', reason='RAW_WITNESS_BINDING'))
            if gap['inside'][add] or not left or not right:
                differences.append(dict(path='gap', reason='GAP_NOT_CERTIFIABLE'))
            proof_details = dict(target=TARGET, L=gap['L'], R=gap['R'],
                Tmax_lower_bound_s=gap['length'], proof_sha256=record.get('proof_sha256'),
                donor_raw_intervals_sha256=gap['interval_sha256'][add],
                surviving_left_witnesses=len(left), surviving_right_witnesses=len(right))
        elif part == 'T100':
            point = record.get('point_id')
            proof = verify_t100_witness(self.rows, candidate['indices'], point, self.tau100,
                                        record.get('source_values'), self.states)
            differences += proof['differences']
            if record.get('source_values_sha256') != fingerprint(proof['source_values']):
                differences.append(dict(path='source_values_sha256', reason='SOURCE_VALUE_DIGEST'))
            if type(point) is not int or not 0 <= point < len(self.keep) or not self.keep[point]:
                differences.append(dict(path='point_id', reason='WITNESS_NOT_IN_MASK'))
            else:
                differences += _differences(np.asarray(self.lib.coords[point]).tolist(),
                                              record.get('coordinates'), 0, 'coordinates')
            proof_details = dict(point_id=point, source_values=proof['source_values'],
                                 source_values_sha256=fingerprint(proof['source_values']))
        else:
            values = self._boolean(candidate, self.tau90)
            count, digest = int(np.count_nonzero(values)), classification_digest(values)
            for key, value in dict(c90=count, on_time_point_count=count, classification_sha256=digest).items():
                differences += _differences(value, record.get(key), 0, 'certificate/'+key)
            if count >= self.k90:
                differences.append(dict(path='c90', reason='NO_T90_VIOLATION'))
            proof_details = dict(c90=count, classification_sha256=digest, effective_bits=len(values), padding_zero=True)
        result = dict(identity=candidate['identity'], ordinal=candidate['ordinal'], partition=part,
            status='FAIL' if differences else 'PASS', differences=differences,
            main_certificate_sha256=fingerprint(record), input_binding_sha256=self.binding(candidate),
            full_feasibility_evaluation_performed=False, full_metrics_evaluated=False,
            independent_method='Raw gap/witness reconstruction or original source Boolean OR/count; exact 28 source T100 values',
            **proof_details)
        if not differences:
            self.certified[candidate['identity']] = result['main_certificate_sha256']
        return result

    def selection(self, candidate_identities=None):
        allowed = set(candidate_identities) if candidate_identities is not None else {
            identity for identity, part in self.independent_partitions.items() if part == 'FULL'}
        qualified = [row for identity, row in self.expected.items()
                     if identity in allowed and row['qualified_for_round19']]
        qualified.sort(key=lambda row: tuple(row['rank']))
        return dict(selected_identity=qualified[0]['identity'] if qualified else None,
                    qualified_count=len(qualified), qualified_for_round19=len(qualified),
                    ranked_identities=[row['identity'] for row in qualified],
                    retained_R18_incumbent=not qualified, improvement_reference=self.center_identity)

    def verify_completion(self, ledger, reports, checks, gapcerts, gapchecks, t100certs, t100checks,
                          t90certs, t90checks, reported_selected_identity, check=lambda: None, prefix=False):
        return terminal_verification(self.center_indices, self.donors, self.states, ledger, reports, checks,
            gapcerts, gapchecks, t100certs, t100checks, t90certs, t90checks,
            reported_selected_identity, check, prefix)


def terminal_verification(center, donors, states, ledger, reports, checks, gapcerts, gapchecks,
                          t100certs, t100checks, t90certs, t90checks, reported_selected_identity,
                          check=lambda: None, prefix=False):
    """Audit exact identity/operation/order sets and all report-check hash links.

    A final incomplete JSONL line must be rejected by the caller's decoder.
    Prefix mode commits only the contiguous, fully checked ledger prefix;
    interior holes and duplicates are substantive failures.
    """
    expected = list(iter_candidates(center, donors, states, check))
    by_id = {row['identity']: row for row in expected}
    require(len(by_id) == DECLARED, 'CHECKER_R19_EXPECTED_ID_COLLISION')
    differences, ledger_rows, ordered_ids = [], {}, []
    expected_order, actual_order = hashlib.sha256(), hashlib.sha256()
    for row in expected:
        expected_order.update((row['identity']+'\n').encode('ascii'))
    for ordinal, row in enumerate(ledger):
        if ordinal % 512 == 0:
            check()
        identity = row.get('identity')
        if ordinal >= len(expected) or any(row.get(k) != v for k, v in expected[ordinal].items()):
            differences.append(dict(path='ledger', reason='OPERATION_IDENTITY_OR_ORDER', ordinal=ordinal))
        if identity in ledger_rows:
            differences.append(dict(path='ledger', reason='DUPLICATE_IDENTITY', identity=identity))
        if row.get('partition') not in PARTS:
            differences.append(dict(path='ledger', reason='INVALID_PARTITION', identity=identity))
        ledger_rows[identity] = row; ordered_ids.append(identity)
        actual_order.update((str(identity)+'\n').encode('ascii'))
    all_ids = set(by_id)
    last_committed_ordinal = max((r.get('ordinal', -1) for r in ledger_rows.values()), default=-1)
    seen, verified = {part: set() for part in PARTS}, {part: set() for part in PARTS}
    qualified = []
    streams = [('FULL', reports, checks), ('GAP', gapcerts, gapchecks),
               ('T100', t100certs, t100checks), ('T90', t90certs, t90checks)]
    for part, rows, check_rows in streams:
        for position, pair in enumerate(itertools.zip_longest(rows, check_rows)):
            if position % 256 == 0:
                check()
            row, checked = pair
            if row is None or checked is None:
                if not prefix:
                    differences.append(dict(path=part, reason='REPORT_CHECK_LENGTH'))
                continue
            before = len(differences)
            identity = row.get('identity')
            canonical = by_id.get(identity)
            if canonical is None or any(row.get(k) != v for k, v in canonical.items()):
                differences.append(dict(path=part, reason='OPERATION_OR_IDENTITY', identity=identity))
            if identity in seen[part]:
                differences.append(dict(path=part, reason='DUPLICATE_RECORD', identity=identity))
            seen[part].add(identity)
            entry = ledger_rows.get(identity)
            if (prefix and entry is None and canonical is not None
                    and canonical['ordinal'] > last_committed_ordinal):
                # Independently flushed streams can contain a checked suffix
                # that the processing ledger has not committed yet.
                continue
            if entry is None or entry.get('partition') != part or row.get('partition') != part:
                differences.append(dict(path=part, reason='LEDGER_PARTITION_MISMATCH', identity=identity))
            if checked.get('identity') != identity or checked.get('status') != 'PASS' or checked.get('differences') != []:
                differences.append(dict(path=part, reason='NOT_INDEPENDENTLY_VERIFIED', identity=identity))
            if part == 'FULL':
                output_digest = row.get('main_output_sha256') if row.get('_compact') is True else fingerprint(_scientific(row))
                if (checked.get('main_output_sha256') != output_digest or entry is None
                        or entry.get('main_output_sha256') != output_digest
                        or entry.get('checker_output_sha256') != checked.get('checker_output_sha256')):
                    differences.append(dict(path=part, reason='FULL_HASH_BINDING', identity=identity))
                rank = row.get('rank') if row.get('_compact') is True else _rank(row)
                rank_differences = _differences(rank, checked.get('rank'), 1e-6, 'rank')
                qualification_differences = _differences(row.get('qualified_for_round19'),
                    checked.get('qualified_for_round19'), 0, 'qualified_for_round19')
                if rank_differences or qualification_differences:
                    differences.append(dict(path=part, reason='INDEPENDENT_RANK_OR_QUALIFICATION', identity=identity,
                        rank_differences=rank_differences, qualification_differences=qualification_differences))
                if checked.get('qualified_for_round19'):
                    qualified.append((checked.get('rank'), identity))
            else:
                digest = fingerprint(row)
                if (checked.get('main_certificate_sha256') != digest or checked.get('partition') != part
                        or entry is None or entry.get('certificate_sha256') != digest
                        or entry.get('checker_output_sha256') != fingerprint(checked)):
                    differences.append(dict(path=part, reason='CERTIFICATE_HASH_BINDING', identity=identity))
                if row.get('qualified_for_round19') is not False or any(row.get(k) is not None
                        for k in ('T90_s', 'T100_s', 'Tavg_s', 'Tmax_s', 'full_grid', 'effective_grid', 'regional', 'first_hits_sha256')):
                    differences.append(dict(path=part, reason='FABRICATED_UNCOMPUTED_METRICS', identity=identity))
                if row.get('feasibility') != 'NOT_EVALUATED' or row.get('known_infeasible') is not (None if part == 'GAP' else True):
                    differences.append(dict(path=part, reason='CERTIFICATE_SEMANTICS', identity=identity))
            if row.get('source') != 'archived_component_composition' or any(row.get(k) is not False for k in
                    ('new_native_validation_performed', 'whole_constellation_STK_verified', 'native_verified')):
                differences.append(dict(path=part, reason='NATIVE_SCOPE', identity=identity))
            if len(differences) == before:
                verified[part].add(identity)
    processed = set().union(*seen.values())
    if any(seen[a] & seen[b] for a, b in itertools.combinations(PARTS, 2)):
        differences.append(dict(path='partition', reason='OVERLAPPING_PARTITIONS'))
    for part in PARTS:
        ledger_part = {identity for identity, row in ledger_rows.items() if row.get('partition') == part}
        if not prefix and seen[part] != ledger_part:
            differences.append(dict(path=part, reason='EXACT_LEDGER_PARTITION_SET'))
        if prefix:
            last = max((by_id[i]['ordinal'] for i in seen[part] if i in by_id), default=-1)
            if any(i not in seen[part] and by_id[i]['ordinal'] < last for i in ledger_part if i in by_id):
                differences.append(dict(path=part, reason='MISSING_INTERIOR_RECORD'))
    if not prefix and (processed != all_ids or set(ledger_rows) != all_ids
                       or actual_order.hexdigest() != expected_order.hexdigest()):
        differences.append(dict(path='completion', reason='NOT_EXACT_DECLARED_SPACE'))
    pending = set()
    if prefix:
        committed = {part: set() for part in PARTS}
        for identity in ordered_ids:
            part = ledger_rows[identity].get('partition')
            if part not in PARTS or identity not in verified[part]:
                break
            committed[part].add(identity)
        pending = processed | set(ledger_rows)
        seen = committed
        verified = {part: set(values) for part, values in committed.items()}
        processed = set().union(*seen.values())
        pending -= processed
        qualified = [pair for pair in qualified if pair[1] in processed]
    qualified.sort(key=lambda pair: tuple(pair[0]))
    selected = qualified[0][1] if qualified else None
    if (not prefix or reported_selected_identity is not None) and selected != reported_selected_identity:
        differences.append(dict(path='selection', reason='INDEPENDENT_SELECTION_MISMATCH',
                                expected=selected, reported=reported_selected_identity))
    counts = dict(declared_candidates=DECLARED, fully_evaluated=len(seen['FULL'] & all_ids),
        fully_independently_verified=len(verified['FULL'] & all_ids),
        GAP_certificate_rejected=len(seen['GAP'] & all_ids), GAP_certificate_verified=len(verified['GAP'] & all_ids),
        T100_certificate_rejected=len(seen['T100'] & all_ids), T100_certificate_verified=len(verified['T100'] & all_ids),
        T90_certificate_rejected=len(seen['T90'] & all_ids), T90_certificate_verified=len(verified['T90'] & all_ids),
        unprocessed=len(all_ids-processed), unknown=len(processed-all_ids)+sum(len(seen[p]-verified[p]) for p in PARTS),
        qualified_count=len(qualified), qualified_for_round19=len(qualified), candidate_REUSED=0,
        retained_R18_incumbent=selected is None)
    counts.update(GAP_generated=counts['GAP_certificate_rejected'], GAP_verified=counts['GAP_certificate_verified'],
        T100_generated=counts['T100_certificate_rejected'], T100_verified=counts['T100_certificate_verified'],
        T90_generated=counts['T90_certificate_rejected'], T90_verified=counts['T90_certificate_verified'],
        FULL_evaluated=counts['fully_evaluated'], FULL_verified=counts['fully_independently_verified'],
        verified_candidates=sum(len(verified[p] & all_ids) for p in PARTS))
    incomplete = counts['unprocessed'] != 0 or counts['unknown'] != 0
    status = 'FAIL' if differences else 'BLOCKED' if incomplete else 'PASS'
    return dict(status=status, exit_code={'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[status], differences=differences,
        **counts, selected_identity=selected, identity_order_sha256=actual_order.hexdigest(),
        expected_identity_order_sha256=expected_order.hexdigest(), exact_disjoint_sets_checked=True,
        true_prefix=prefix, pending_uncommitted_count=len(pending),
        method='Independent full catalog S-centered generator; exact disjoint identity sets; report/check hashes; separate S rank')
