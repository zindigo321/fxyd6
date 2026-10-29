"""Independent numerical and exact-set checks for the remaining four-anchor repair study.

The validated archive decoder and state-token representation are shared.  Full
numerical algorithms are the frozen R14 checker algorithms, reached through
the R16 checker base.  Neither R18 main bitsets nor main decisions are used.
"""
import hashlib
import itertools
import math

import numpy as np

from src.round13.common import fingerprint, require
from src.round14.checker import _differences, _digest, verify_baseline_whole
from src.round16.checker import IndependentChecker as _NumericChecker

FIXED_REMOVE = 1284
EXCLUDED_DONOR = 705
ANCHOR_DONORS = {28, 218, 1801, 2021}
DECLARED = 231066
META = {'remove', 'add', 'ordinal', 'partition', 'processing_state',
        'fixed_remove', 'pivot', 'remove_pair', 'add_pair'}
PARTS = ('T100', 'T90', 'FULL')


def _pool(baseline, donors, states):
    b, d = sorted(baseline), sorted(donors)
    require(len(b) == len(set(b)) == 28 and len(d) == len(set(d)) == 2143,
            'CHECKER_REPAIR_POOL_CARDINALITY')
    require(not set(b) & set(d) and sorted(b+d) == list(range(2171)),
            'CHECKER_REPAIR_POOL_EXACT_INDEX_SET')
    require(FIXED_REMOVE in b and EXCLUDED_DONOR in d and ANCHOR_DONORS <= set(d) and
            all(type(i) is int and i in states for i in b+d) and
            len({states[i] for i in b+d}) == 2171, 'CHECKER_REPAIR_STATE_POOL')
    return b, d


def addition_pairs(donors):
    """Independent minimum-anchor pivot partitions, then numeric pair sorting."""
    eligible = [i for i in sorted(donors) if i != EXCLUDED_DONOR]
    parts = {}
    for pivot in sorted(ANCHOR_DONORS):
        parts[pivot] = [tuple(sorted((pivot, other))) for other in eligible
                        if other != pivot and (other not in ANCHOR_DONORS or other > pivot)]
    pairs = sorted(pair for partition in parts.values() for pair in partition)
    require(len(pairs) == len(set(pairs)) == 8558, 'CHECKER_ADDITION_PAIR_SET')
    return pairs


def iter_candidates(baseline, donors, states, check=lambda: None):
    """Pivot-partition reconstruction, independent of the main pair iterator."""
    b, d = _pool(baseline, donors, states)
    pairs = addition_pairs(d)
    ordinal = 0
    for position in range(len(b)):
        remove = b[position]
        if remove == FIXED_REMOVE:
            continue
        retained = [i for i in b if i != FIXED_REMOVE and i != remove]
        for first, second in pairs:
            if ordinal % 512 == 0:
                check()
            pivot = min(i for i in (first, second) if i in ANCHOR_DONORS)
            add = second if first == pivot else first
            indices = sorted(retained + [first, second])
            yield dict(ordinal=ordinal, fixed_remove=FIXED_REMOVE, remove=remove,
                add=add, pivot=pivot, remove_pair=sorted([FIXED_REMOVE, remove]),
                add_pair=[first, second], indices=indices,
                identity=fingerprint(sorted(states[i] for i in indices)))
            ordinal += 1
    check()


def neighborhood_summary(baseline, donors, states, check=lambda: None):
    identities, order, pairs = set(), hashlib.sha256(), hashlib.sha256()
    first = last = None
    count = 0
    pivot_counts = {str(i): 0 for i in sorted(ANCHOR_DONORS)}
    for candidate in iter_candidates(baseline, donors, states, check):
        require(candidate['identity'] not in identities, 'CHECKER_REPAIR_IDENTITY_COLLISION')
        identities.add(candidate['identity'])
        order.update((candidate['identity']+'\n').encode('ascii'))
        pairs.update((','.join(map(str, [candidate['remove']]+candidate['add_pair']))+'\n').encode('ascii'))
        pivot_counts[str(candidate['pivot'])] += 1
        first = candidate if first is None else first
        last = candidate
        count += 1
    require(count == DECLARED, 'CHECKER_REPAIR_CARDINALITY')
    require(pivot_counts == {'28':57807, '218':57780, '1801':57753, '2021':57726},
            'CHECKER_PIVOT_PARTITION_CARDINALITY')
    return dict(declared_candidates=count, unique_identities=len(identities),
        identity_order_sha256=order.hexdigest(), pair_order_sha256=pairs.hexdigest(),
        first=first, last=last, baseline_indices=sorted(baseline),
        donor_indices=sorted(donors), fixed_remove=FIXED_REMOVE,
        pivot_counts=pivot_counts, anchor_donors=sorted(ANCHOR_DONORS), excluded_donor=EXCLUDED_DONOR,
        method='Independent minimum-A4-pivot pair partitions and exact state-set identities')


def classification_digest(values):
    return hashlib.sha256(np.asarray(values, dtype=np.uint8).tobytes(order='C')).hexdigest()


def boolean_on_time(rows, indices, keep, tau):
    """Independent source Boolean OR in the frozen mask column order."""
    keep = np.asarray(keep)
    require(keep.dtype == np.bool_ and keep.ndim == 1, 'CHECKER_BOOLEAN_MASK')
    require(math.isfinite(float(tau)), 'CHECKER_BOOLEAN_DEADLINE')
    result = np.zeros(int(keep.sum()), dtype=np.bool_)
    for index in indices:
        source = np.asarray(rows[index])
        require(source.shape == keep.shape and not np.isnan(source).any() and
                not np.isneginf(source).any(), 'CHECKER_BOOLEAN_SOURCE')
        result |= source[keep] <= tau
    return result


def verify_t100_witness(rows, indices, point_id, tau, source_values=None):
    differences = []
    expected = []
    if type(point_id) is not int or point_id < 0 or not indices or any(point_id >= len(rows[i]) for i in indices):
        return dict(status='FAIL', differences=[dict(path='point_id', reason='INVALID_POINT_ID')], source_values=[])
    for index in indices:
        value = float(rows[index][point_id])
        if math.isnan(value) or value == -math.inf or value <= tau:
            differences.append(dict(path='source_values/'+str(index), reason='SOURCE_NOT_STRICTLY_AFTER_DEADLINE'))
        expected.append(dict(index=index, first_hit_s=value if math.isfinite(value) else None,
                             classification='FINITE_LATE' if math.isfinite(value) else 'NO_FIRST_HIT'))
    if source_values is not None:
        differences += _differences(expected, source_values, 0, 'source_values')
    return dict(status='FAIL' if differences else 'PASS', differences=differences,
                source_values=expected, point_id=point_id, tau100=tau)


def verify_t90_count(rows, indices, keep, tau, k90, c90, classification_sha256):
    values = boolean_on_time(rows, indices, keep, tau)
    actual = int(np.count_nonzero(values))
    digest = classification_digest(values)
    differences = []
    if type(c90) is not int or actual != c90:
        differences.append(dict(path='c90', reason='EXACT_COUNT_MISMATCH', expected=actual, reported=c90))
    if digest != classification_sha256:
        differences.append(dict(path='classification_sha256', reason='CLASSIFICATION_DIGEST_MISMATCH'))
    if actual >= k90:
        differences.append(dict(path='c90', reason='NOT_A_T90_CONSTRAINT_VIOLATION'))
    return dict(status='FAIL' if differences else 'PASS', differences=differences,
                c90=actual, k90=k90, classification_sha256=digest)


def _scientific(report):
    return {key: value for key, value in report.items() if key not in META}


def _rank(report):
    return [report['regional']['pooled_internal']['max_s'],
            report['regional']['pooled_internal']['mean_s'],
            report['effective_grid']['T100_s'], report['effective_grid']['T90_s'], report['identity']]


def compact_report(report):
    if report.get('_compact') is True:
        return report
    keys = list(META) + ['identity', 'indices', 'source', 'new_native_validation_performed',
                        'whole_constellation_STK_verified', 'native_verified', 'first_hits_sha256']
    result = {key: report[key] for key in keys if key in report}
    result.update(_compact=True, qualified_improvement=report['qualified_improvement'],
                  rank=_rank(report), main_output_sha256=fingerprint(_scientific(report)))
    return result


class IndependentChecker(_NumericChecker):
    """Independent 26-row retained minima, two donors and source-Boolean gates."""
    def __init__(self, lib, duration=604800, tolerance=1e-6, required_count=28):
        self.repair_minima = {}
        self.boolean_cache = {}
        self.independent_partitions = {}
        super().__init__(lib, duration, tolerance, required_count)
        _pool(self.baseline_indices, self.donors, self.states)
        self.mask_ids = np.flatnonzero(self.keep)
        self.tau100 = self.baseline_reference['effective_grid']['T100_s'] + tolerance
        self.tau90 = self.baseline_reference['effective_grid']['T90_s'] + tolerance
        self.k90 = math.ceil(9*len(self.mask_ids)/10)
        self.mask_sha256 = classification_digest(self.keep)
        self.coordinate_sha256 = hashlib.sha256(np.asarray(lib.coords, dtype='<f8').tobytes(order='C')).hexdigest()
        self.matrix_sha256 = getattr(lib, 'matrix_sha256', None)
        if self.matrix_sha256 is None:
            self.matrix_sha256 = getattr(lib, 'evidence', {}).get('matrix', {}).get('sha256')
        require(isinstance(self.matrix_sha256, str), 'CHECKER_MATRIX_BINDING_MISSING')
        self.certified = {}
        self.donor_boolean_cache = {}
        self.source_binding = fingerprint(dict(matrix_sha256=self.matrix_sha256,
            mask_sha256=self.mask_sha256, coordinate_sha256=self.coordinate_sha256,
            tau100=self.tau100, tau90=self.tau90, baseline_indices=self.baseline_indices,
            rows=[[i, self.states[i], self.row_digests[i]] for i in sorted(self.rows)]))
        self.exclusive_cache_bindings = {}
        self.exclusive_cache = {}

    def enumerate_space(self, check=lambda: None):
        return iter_candidates(self.baseline_indices, self.donors, self.states, check)

    def _hits(self, indices, remove_pair=None, add_pair=None):
        require(len(indices) == len(set(indices)), 'CHECKER_DUPLICATE_INDEX')
        selected, original = set(indices), set(self.baseline_indices)
        if selected == original:
            require(remove_pair is None and add_pair is None, 'CHECKER_BASELINE_WITH_SWAP_LABEL')
            return self.prefix[-1].copy()
        removed, added = sorted(original-selected), sorted(selected-original)
        # The five old single-swap near-feasible anchors may be independently
        # replayed before the fixed two-operation neighborhood is evaluated.
        if len(removed) == len(added) == 1:
            require(removed == [FIXED_REMOVE] and added[0] in self.donors, 'CHECKER_NOT_OLD_ANCHOR')
            require(remove_pair is None or remove_pair in (FIXED_REMOVE, removed), 'CHECKER_ANCHOR_REMOVE_LABEL')
            require(add_pair is None or add_pair in (added[0], added), 'CHECKER_ANCHOR_ADD_LABEL')
            position = self.baseline_indices.index(FIXED_REMOVE)
            return np.minimum(np.minimum(self.prefix[position], self.suffix[position+1]), self.rows[added[0]])
        require(len(removed) == len(added) == 2 and FIXED_REMOVE in removed and
                EXCLUDED_DONOR not in added and bool(set(added) & ANCHOR_DONORS),
                'CHECKER_NOT_REMAINING_FOUR_ANCHOR_REPAIR')
        second_remove = next(i for i in removed if i != FIXED_REMOVE)
        require(second_remove in self.baseline_indices and set(added) <= set(self.donors),
                'CHECKER_REPAIR_MEMBERSHIP')
        if remove_pair is not None:
            require(remove_pair == removed, 'CHECKER_REPAIR_REMOVE_LABEL')
        if add_pair is not None:
            require(add_pair == added, 'CHECKER_REPAIR_ADD_LABEL')
        if second_remove not in self.repair_minima:
            vector = np.full(len(self.keep), np.inf)
            for index in self.baseline_indices:
                if index not in removed:
                    vector = np.minimum(vector, self.rows[index])
            self.repair_minima[second_remove] = vector
        return np.minimum(np.minimum(self.repair_minima[second_remove], self.rows[added[0]]),
                          self.rows[added[1]])

    def verify(self, indices, reported, reported_hits, baseline_report=None, remove_pair=None, add_pair=None):
        expected, hits = self.recompute(indices, baseline_report, remove_pair, add_pair)
        scientific = _scientific(reported)
        differences = _differences(expected, scientific, self.tolerance)
        a = np.asarray(reported_hits)
        classification = maximum = None
        if a.shape != hits.shape:
            differences.append(dict(path='first_hits', reason='SHAPE_MISMATCH'))
        else:
            classification = int(np.count_nonzero(np.isfinite(a) != np.isfinite(hits)))
            finite = np.isfinite(a) & np.isfinite(hits)
            maximum = float(np.max(np.abs(a[finite]-hits[finite]), initial=0.))
            if classification or maximum > self.tolerance or np.isnan(a).any() or np.isneginf(a).any():
                differences.append(dict(path='first_hits', reason='POINTWISE_MISMATCH'))
            if _digest(a) != scientific.get('first_hits_sha256'):
                differences.append(dict(path='first_hits_sha256', reason='REPORTED_ARRAY_DIGEST_MISMATCH'))
        comparisons = {}
        for target in self.targets:
            spans = expected['regional']['targets'][target]['merged_intervals']
            claimed = reported.get('regional', {}).get('targets', {}).get(target, {}).get('merged_intervals')
            comparisons[target] = dict(expected_merged_count=len(spans), checker_intervals_sha256=fingerprint(spans),
                main_intervals_sha256=fingerprint(claimed), differences=_differences(spans, claimed, self.tolerance, target))
        result = dict(identity=expected['identity'], status='FAIL' if differences else 'PASS', differences=differences,
            points_compared=len(hits), classification_difference_count=classification,
            max_absolute_first_hit_error_s=maximum, absolute_tolerance_s=self.tolerance, relative_tolerance=0,
            input_sha256=fingerprint([[i, self.states[i], self.row_digests[i]] for i in sorted(indices)]),
            main_first_hits_sha256=scientific.get('first_hits_sha256'), checker_first_hits_sha256=_digest(hits),
            main_output_sha256=fingerprint(scientific), checker_output_sha256=fingerprint(expected),
            interval_comparisons=comparisons, qualified_improvement=expected['qualified_improvement'], rank=_rank(expected),
            shared_schema='Frozen validated archive decoder, coordinates, mask and producer state tokens',
            independent_methods='Retained 26-row minima plus two donors; sorted order statistics; cumulative-frontier regional merge; independent decisions and rank')
        if not differences:
            self.expected[expected['identity']] = dict(identity=expected['identity'], indices=list(indices),
                qualified_improvement=expected['qualified_improvement'], rank=_rank(expected),
                main_output_sha256=result['main_output_sha256'], checker_output_sha256=result['checker_output_sha256'])
        return result

    def _candidate(self, candidate):
        remove, pair = candidate.get('remove'), candidate.get('add_pair')
        require(type(remove) is int and remove in self.baseline_indices and remove != FIXED_REMOVE,
                'CHECKER_REPAIR_REMOVE')
        require(type(pair) is list and len(pair) == 2 and all(type(i) is int for i in pair)
                and pair == sorted(set(pair)) and set(pair) <= set(self.donors)
                and EXCLUDED_DONOR not in pair and bool(set(pair) & ANCHOR_DONORS),
                'CHECKER_REPAIR_ADDITION_PAIR')
        pivot = min(set(pair) & ANCHOR_DONORS)
        add = next(i for i in pair if i != pivot)
        indices = sorted([i for i in self.baseline_indices if i not in (FIXED_REMOVE, remove)] + pair)
        expected = dict(fixed_remove=FIXED_REMOVE, remove=remove, add=add, pivot=pivot,
            remove_pair=sorted([FIXED_REMOVE, remove]), add_pair=pair, indices=indices,
            identity=fingerprint(sorted(self.states[i] for i in indices)))
        require(all(candidate.get(k) == v for k, v in expected.items()), 'CHECKER_REPAIR_CANDIDATE_METADATA')
        return expected

    def _retained_boolean(self, remove, tau):
        key = (remove, tau, self.source_binding)
        if key not in self.boolean_cache:
            retained = [i for i in self.baseline_indices if i not in (FIXED_REMOVE, remove)]
            self.boolean_cache[key] = boolean_on_time(self.rows, retained, self.keep, tau)
        return self.boolean_cache[key]

    def _donor_boolean(self, donor, tau):
        key = (donor, tau, self.source_binding)
        if key not in self.donor_boolean_cache:
            self.donor_boolean_cache[key] = np.asarray(self.rows[donor])[self.keep] <= tau
        return self.donor_boolean_cache[key]

    def _boolean(self, candidate, tau):
        first, second = candidate['add_pair']
        return (self._retained_boolean(candidate['remove'], tau) |
                self._donor_boolean(first, tau) | self._donor_boolean(second, tau))

    def partition(self, candidate):
        self._candidate(candidate)
        if candidate['identity'] in self.independent_partitions:
            return self.independent_partitions[candidate['identity']]
        if not np.all(self._boolean(candidate, self.tau100)):
            part = 'T100'
        elif int(np.count_nonzero(self._boolean(candidate, self.tau90))) < self.k90:
            part = 'T90'
        else:
            part = 'FULL'
        self.independent_partitions[candidate['identity']] = part
        return part

    def binding(self, candidate):
        indices = candidate['indices']
        return fingerprint(dict(matrix_sha256=self.matrix_sha256, mask_sha256=self.mask_sha256,
            coordinate_sha256=self.coordinate_sha256,
            rows_sha256=[[i, self.states[i], self.row_digests[i]] for i in indices]))

    def _exclusive(self, pivot, remove):
        key = (pivot, remove, self.source_binding)
        if key in self.exclusive_cache:
            return self.exclusive_cache[key]
        retained = self._retained_boolean(remove, self.tau100)
        surviving = retained | self._donor_boolean(pivot, self.tau100)
        points = self.mask_ids[~surviving]
        digest = hashlib.sha256(np.asarray(points, dtype='<i8').tobytes()).hexdigest()
        binding = fingerprint(dict(source_binding=self.source_binding, pivot=pivot, remove=remove,
                                   point_ids_sha256=digest))
        self.exclusive_cache_bindings[pivot, remove] = binding
        result = dict(pivot=pivot, remove=remove, count=len(points), point_ids=points.tolist(),
                      point_ids_sha256=digest, cache_binding_sha256=binding)
        self.exclusive_cache[key] = result
        return result

    def verify_gate_evidence(self, evidence):
        """Rebuild each pivot/removal lost set directly from independent source OR."""
        differences, exclusive, anchors = [], {}, {}
        for pivot in sorted(ANCHOR_DONORS):
            anchor = [i for i in self.baseline_indices if i != FIXED_REMOVE] + [pivot]
            require(bool(np.all(boolean_on_time(self.rows, anchor, self.keep, self.tau100))),
                    'CHECKER_ANCHOR_NOT_FULL_AT_TAU100')
            anchors[str(pivot)] = fingerprint(sorted(self.states[i] for i in anchor))
            exclusive[str(pivot)] = {str(remove): self._exclusive(pivot, remove)
                for remove in self.baseline_indices if remove != FIXED_REMOVE}
        baseline_identity = fingerprint(sorted(self.states[i] for i in self.baseline_indices))
        assertions = dict(status='PASS', profile='ROUND18_EXACT_FIRST_HIT_GATES_V1',
            reference_identity=baseline_identity, anchor_donors=sorted(ANCHOR_DONORS),
            anchor_identities=anchors,
            tau100=self.tau100, tau90=self.tau90, k90=self.k90, mask_point_count=len(self.mask_ids),
            mask_sha256=self.mask_sha256, coordinate_sha256=self.coordinate_sha256,
            matrix_sha256=self.matrix_sha256, source_binding_sha256=self.source_binding,
            exclusive_points=exclusive,
            bitset_effective_bits=len(self.mask_ids), bitset_padding_bits=(-len(self.mask_ids)) % 8,
            bitset_padding_zero=True, priority=['T100_BASELINE_DEADLINE', 'T90_ON_TIME_COUNT', 'FULL'],
            full_metrics_from_necessary_gates=False, second_donor_bridge_required=False)
        for key, value in assertions.items():
            differences += _differences(value, evidence.get(key), 0, 'gate/'+key)
        return dict(status='FAIL' if differences else 'PASS', differences=differences,
            independently_derived_exclusive_points=exclusive, main_gate_sha256=fingerprint(evidence),
            source_binding_sha256=self.source_binding,
            method='Independent source Boolean OR of each retained 26 plus pivot; exact missing mask IDs')

    def verify_certificate(self, candidate, record, gate_context=None):
        canonical = self._candidate(candidate)
        part = self.partition(candidate)
        require(part in ('T100', 'T90'), 'CHECKER_CANNOT_CERTIFY_FULL_PARTITION')
        differences = []
        exclusive = self._exclusive(candidate['pivot'], candidate['remove'])
        for key, value in dict(canonical, ordinal=candidate['ordinal']).items():
            differences += _differences(value, record.get(key), 0, 'certificate/'+key)
        violation = 'T100_BASELINE_DEADLINE' if part == 'T100' else 'T90_ON_TIME_COUNT'
        assertions = dict(partition=part, status='KNOWN_INFEASIBLE', processing_state=part+'_CERTIFICATE_REJECTED',
            known_infeasible=True, verified_constraint_violation=violation,
            full_feasibility_evaluation_performed=False, metrics_status='NOT_EVALUATED',
            full_grid=None, effective_grid=None, regional=None, feasibility=None, first_hits_sha256=None,
            qualified_improvement=False, source='archived_component_composition',
            new_native_validation_performed=False, whole_constellation_STK_verified=False, native_verified=False,
            tau100=self.tau100, tau90=self.tau90, k90=self.k90,
            input_binding_sha256=self.binding(candidate), mask_sha256=self.mask_sha256,
            coordinate_sha256=self.coordinate_sha256, T90_s=None, T100_s=None, Tavg_s=None, Tmax_s=None,
            exclusive_cache_binding_sha256=exclusive['cache_binding_sha256'])
        for key, value in assertions.items():
            differences += _differences(value, record.get(key), 0, 'certificate/'+key)
        if part == 'T100':
            p = record.get('point_id')
            witness = verify_t100_witness(self.rows, candidate['indices'], p, self.tau100, record.get('source_values'))
            differences += witness['differences']
            if (not isinstance(record.get('source_values'), list) or
                    record.get('source_values_sha256') != fingerprint(witness['source_values'])):
                differences.append(dict(path='source_values', reason='SOURCE_VALUES_DIGEST_OR_SCHEMA'))
            if type(p) is not int or p < 0 or p >= len(self.keep) or not self.keep[p]:
                differences.append(dict(path='point_id', reason='WITNESS_NOT_IN_MASK'))
            else:
                differences += _differences(self.lib.coords[p].tolist(), record.get('coordinates'), 0, 'coordinates')
            proof_details = dict(point_id=p, source_values=witness['source_values'],
                source_values_sha256=fingerprint(witness['source_values']))
        else:
            values = self._boolean(candidate, self.tau90)
            c90 = int(np.count_nonzero(values))
            digest = classification_digest(values)
            for key, value in dict(c90=c90, on_time_point_count=c90, classification_sha256=digest).items():
                differences += _differences(value, record.get(key), 0, 'certificate/'+key)
            proof_details = dict(c90=c90, on_time_point_count=c90, classification_sha256=digest)
        result = dict(identity=candidate['identity'], ordinal=candidate['ordinal'], partition=part,
            status='FAIL' if differences else 'PASS', differences=differences,
            main_certificate_sha256=fingerprint(record), verified_constraint_violation=violation,
            input_binding_sha256=self.binding(candidate), tau100=self.tau100, tau90=self.tau90, k90=self.k90,
            full_feasibility_evaluation_performed=False, full_metrics_evaluated=False,
            independent_method='Original source Boolean OR/count; T100 witness individually checked against all 28 source values',
            **proof_details)
        if not differences:
            self.certified[candidate['identity']] = result['main_certificate_sha256']
        return result

    def selection(self, candidate_identities=None):
        if candidate_identities is None:
            allowed = {identity for identity, part in self.independent_partitions.items() if part == 'FULL'}
        else:
            allowed = set(candidate_identities)
        return super().selection(allowed)

    def verify_completion(self, ledger, reports, checks, t100certs, t100checks,
                          t90certs, t90checks, reported_selected_identity,
                          check=lambda: None, prefix=False):
        return terminal_verification(self.baseline_indices, self.donors, self.states,
            ledger, reports, checks, t100certs, t100checks, t90certs, t90checks,
            reported_selected_identity, check=check, numeric_expected=self.expected,
            certificate_expected=self.certified, partition_expected=self.independent_partitions,
            point_count=len(self.keep), tolerance=self.tolerance, prefix=prefix)


def _operation_key(row):
    pair = row.get('add_pair')
    if (type(row.get('remove')) is not int or type(pair) is not list or len(pair) != 2
            or not all(type(i) is int for i in pair)):
        return None
    return (row.get('remove'), pair[0], pair[1])


def terminal_verification(baseline, donors, states, ledger, reports, checks,
                          t100certs, t100checks, t90certs, t90checks,
                          reported_selected_identity, check=lambda: None,
                          numeric_expected=None, certificate_expected=None,
                          partition_expected=None, point_count=43424,
                          tolerance=1e-6, prefix=False):
    """Independent exact-set and on-disk record binding; supports true prefixes.

    Runtime maps, when supplied, bind these records to this checker instance's
    actual original-array computations.  A later sealed readback without arrays
    validates those saved source-bound check records and their output hashes.
    """
    expected, all_ids, expected_order = {}, set(), hashlib.sha256()
    for item in iter_candidates(baseline, donors, states, check):
        require(item['identity'] not in all_ids, 'CHECKER_TERMINAL_IDENTITY_COLLISION')
        expected[(item['remove'], *item['add_pair'])] = item
        all_ids.add(item['identity'])
        expected_order.update((item['identity']+'\n').encode('ascii'))
    differences, ledger_rows, ledger_ids = [], {}, set()
    actual_order = hashlib.sha256()
    ordered_ids = []
    def metadata_valid(row):
        canonical = expected.get(_operation_key(row))
        return canonical is not None and all(row.get(key) == value for key, value in canonical.items())
    for ordinal, row in enumerate(ledger):
        if ordinal % 1024 == 0:
            check()
        identity = row.get('identity')
        if not metadata_valid(row) or row.get('ordinal') != ordinal:
            differences.append(dict(path='ledger', reason='CANDIDATE_OR_PREFIX_ORDER', identity=identity))
        if identity in ledger_ids:
            differences.append(dict(path='ledger', reason='DUPLICATE_IDENTITY', identity=identity))
        if identity not in all_ids:
            differences.append(dict(path='ledger', reason='UNKNOWN_IDENTITY', identity=identity))
        part = row.get('partition')
        if part not in PARTS:
            differences.append(dict(path='ledger', reason='UNKNOWN_PARTITION', identity=identity))
        if partition_expected is not None and partition_expected.get(identity) != part:
            differences.append(dict(path='ledger', reason='INDEPENDENT_PARTITION_MISMATCH', identity=identity))
        expected_state = 'FULLY_EVALUATED_AND_INDEPENDENTLY_VERIFIED' if part == 'FULL' else str(part)+'_CERTIFICATE_REJECTED'
        if row.get('processing_state') != expected_state:
            differences.append(dict(path='ledger', reason='PROCESSING_STATE', identity=identity))
        ledger_ids.add(identity)
        ledger_rows[identity] = row
        ordered_ids.append(identity)
        actual_order.update((str(identity)+'\n').encode('ascii'))
    seen = {part: set() for part in PARTS}
    verified = {part: set() for part in PARTS}
    pending_ids = set()
    by_identity = {item['identity']: item for item in expected.values()}
    qualified = []
    previous_full_ordinal = -1
    for ordinal, pair in enumerate(itertools.zip_longest(reports, checks)):
        if ordinal % 128 == 0:
            check()
        report, checked = pair
        if report is None or checked is None:
            if not prefix:
                differences.append(dict(path='full', reason='REPORT_CHECK_LENGTH'))
            else:
                available = report if report is not None else checked
                identity = available.get('identity')
                if identity in seen['FULL'] or identity not in by_identity:
                    differences.append(dict(path='full', reason='DUPLICATE_OR_UNKNOWN_PENDING_IDENTITY', identity=identity))
                if report is not None and (not metadata_valid(report) or report.get('partition') != 'FULL'):
                    differences.append(dict(path='full', reason='PENDING_CANDIDATE_METADATA', identity=identity))
                if checked is not None and (checked.get('status') != 'PASS' or checked.get('differences') != []):
                    differences.append(dict(path='full', reason='PENDING_CHECK_FAILURE', identity=identity))
                pending_ordinal = by_identity.get(identity, {}).get('ordinal', -1)
                if pending_ordinal <= previous_full_ordinal:
                    differences.append(dict(path='full', reason='PENDING_TRAVERSAL_ORDER', identity=identity))
                previous_full_ordinal = pending_ordinal
                seen['FULL'].add(identity)
                pending_ids.add(identity)
            continue
        row = compact_report(report)
        identity = row.get('identity')
        previous = len(differences)
        ledger_row = ledger_rows.get(identity, {})
        if type(row.get('ordinal')) is not int or row['ordinal'] <= previous_full_ordinal:
            differences.append(dict(path='full', reason='FULL_TRAVERSAL_ORDER', identity=identity))
        else:
            previous_full_ordinal = row['ordinal']
        if (not metadata_valid(row) or row.get('partition') != 'FULL' or
                ((ledger_row or not prefix) and ledger_row.get('partition') != 'FULL')):
            differences.append(dict(path='full', reason='CANDIDATE_OR_PARTITION', identity=identity))
        if identity in seen['FULL']:
            differences.append(dict(path='full', reason='DUPLICATE_IDENTITY', identity=identity))
        seen['FULL'].add(identity)
        maximum = checked.get('max_absolute_first_hit_error_s')
        if (checked.get('identity') != identity or checked.get('status') != 'PASS' or checked.get('differences') != [] or
            type(checked.get('points_compared')) is not int or checked['points_compared'] != point_count or
            type(checked.get('classification_difference_count')) is not int or checked['classification_difference_count'] != 0 or
            not isinstance(maximum, (int, float)) or isinstance(maximum, bool) or not math.isfinite(maximum) or
            not 0 <= maximum <= tolerance or checked.get('absolute_tolerance_s') != tolerance or checked.get('relative_tolerance') != 0 or
            checked.get('main_output_sha256') != row.get('main_output_sha256') or
            checked.get('main_first_hits_sha256') != checked.get('checker_first_hits_sha256') or
            row.get('first_hits_sha256') != checked.get('main_first_hits_sha256')):
            differences.append(dict(path='full', reason='INCOMPLETE_OR_UNBOUND_POINT_CHECK', identity=identity))
        comparisons = checked.get('interval_comparisons', {})
        if len(comparisons) != 3 or any(value.get('differences') != [] for value in comparisons.values()):
            differences.append(dict(path='full', reason='INCOMPLETE_INTERVAL_CHECK', identity=identity))
        if (row.get('qualified_improvement') != checked.get('qualified_improvement') or
            _differences(row.get('rank'), checked.get('rank'), tolerance)):
            differences.append(dict(path='full', reason='DECISION_OR_RANK', identity=identity))
        for key in ('main_output_sha256', 'checker_output_sha256'):
            if ((ledger_row or not prefix) and ledger_row.get(key) != checked.get(key)) or checked.get(key) is None:
                differences.append(dict(path='full/'+key, reason='LEDGER_OUTPUT_BINDING', identity=identity))
        if numeric_expected is not None:
            runtime = numeric_expected.get(identity)
            if runtime is None or any(runtime.get(k) != checked.get(k) for k in ('main_output_sha256', 'checker_output_sha256', 'qualified_improvement', 'rank')):
                differences.append(dict(path='full', reason='RUNTIME_CHECK_RECORD_BINDING', identity=identity))
        if row.get('source') != 'archived_component_composition' or any(row.get(key) is not False for key in
                ('new_native_validation_performed', 'whole_constellation_STK_verified', 'native_verified')):
            differences.append(dict(path='full', reason='NATIVE_SCOPE', identity=identity))
        if len(differences) == previous:
            verified['FULL'].add(identity)
        if checked.get('qualified_improvement') is True:
            qualified.append((checked['rank'], identity))
    for part, certificate_stream, check_stream in [('T100', t100certs, t100checks), ('T90', t90certs, t90checks)]:
        previous_ordinal = -1
        for ordinal, pair in enumerate(itertools.zip_longest(certificate_stream, check_stream)):
            if ordinal % 512 == 0:
                check()
            report, checked = pair
            if report is None or checked is None:
                if not prefix:
                    differences.append(dict(path=part, reason='CERTIFICATE_CHECK_LENGTH'))
                else:
                    available = report if report is not None else checked
                    identity = available.get('identity')
                    if identity in seen[part] or identity not in by_identity:
                        differences.append(dict(path=part, reason='DUPLICATE_OR_UNKNOWN_PENDING_IDENTITY', identity=identity))
                    if report is not None and (not metadata_valid(report) or report.get('partition') != part):
                        differences.append(dict(path=part, reason='PENDING_CANDIDATE_METADATA', identity=identity))
                    if checked is not None and (checked.get('status') != 'PASS' or checked.get('differences') != []):
                        differences.append(dict(path=part, reason='PENDING_CHECK_FAILURE', identity=identity))
                    pending_ordinal = by_identity.get(identity, {}).get('ordinal', -1)
                    if pending_ordinal <= previous_ordinal:
                        differences.append(dict(path=part, reason='PENDING_TRAVERSAL_ORDER', identity=identity))
                    previous_ordinal = pending_ordinal
                    seen[part].add(identity)
                    pending_ids.add(identity)
                continue
            identity = report.get('identity')
            before = len(differences)
            ledger_row = ledger_rows.get(identity, {})
            if (not metadata_valid(report) or report.get('partition') != part or
                    ((ledger_row or not prefix) and ledger_row.get('partition') != part)):
                differences.append(dict(path=part, reason='CANDIDATE_OR_PARTITION', identity=identity))
            if type(report.get('ordinal')) is not int or report['ordinal'] <= previous_ordinal:
                differences.append(dict(path=part, reason='CERTIFICATE_TRAVERSAL_ORDER', identity=identity))
            else:
                previous_ordinal = report['ordinal']
            if identity in seen[part]:
                differences.append(dict(path=part, reason='DUPLICATE_IDENTITY', identity=identity))
            seen[part].add(identity)
            violation = 'T100_BASELINE_DEADLINE' if part == 'T100' else 'T90_ON_TIME_COUNT'
            digest = fingerprint(report)
            if (checked.get('identity') != identity or checked.get('status') != 'PASS' or checked.get('differences') != [] or
                checked.get('partition') != part or checked.get('main_certificate_sha256') != digest or
                checked.get('verified_constraint_violation') != violation or
                checked.get('full_feasibility_evaluation_performed') is not False or checked.get('full_metrics_evaluated') is not False or
                report.get('known_infeasible') is not True or report.get('verified_constraint_violation') != violation or
                report.get('full_feasibility_evaluation_performed') is not False or report.get('metrics_status') != 'NOT_EVALUATED' or
                report.get('status') != 'KNOWN_INFEASIBLE' or report.get('processing_state') != part+'_CERTIFICATE_REJECTED' or
                report.get('qualified_improvement') is not False or
                any(report.get(key) is not None for key in ('full_grid', 'effective_grid', 'regional', 'feasibility', 'first_hits_sha256', 'T90_s', 'T100_s', 'Tavg_s', 'Tmax_s')) or
                report.get('input_binding_sha256') != checked.get('input_binding_sha256') or
                report.get('input_binding_sha256') is None or
                ((ledger_row or not prefix) and (ledger_row.get('certificate_sha256') != digest or
                 ledger_row.get('checker_output_sha256') != fingerprint(checked)))):
                differences.append(dict(path=part, reason='INCOMPLETE_OR_UNBOUND_CERTIFICATE', identity=identity))
            for key in ('tau100', 'tau90', 'k90'):
                if report.get(key) != checked.get(key) or report.get(key) is None:
                    differences.append(dict(path=part+'/'+key, reason='THRESHOLD_BINDING', identity=identity))
            if part == 'T100':
                values = report.get('source_values')
                p = report.get('point_id')
                if (type(p) is not int or p < 0 or p >= point_count or p != checked.get('point_id') or
                    not isinstance(values, list) or len(values) != 28 or
                    [value.get('index') for value in values] != report.get('indices') or
                    fingerprint(values) != checked.get('source_values_sha256')):
                    differences.append(dict(path=part, reason='SOURCE_WITNESS_BINDING', identity=identity))
                elif any((value.get('classification') == 'FINITE_LATE' and
                          (type(value.get('first_hit_s')) not in (float, int) or not math.isfinite(value['first_hit_s']) or value['first_hit_s'] <= report['tau100'])) or
                         (value.get('classification') == 'NO_FIRST_HIT' and value.get('first_hit_s') is not None) or
                         value.get('classification') not in ('FINITE_LATE', 'NO_FIRST_HIT') for value in values):
                    differences.append(dict(path=part, reason='NOT_STRICTLY_LATE_28_SOURCE_VALUES', identity=identity))
            else:
                if (type(report.get('c90')) is not int or type(report.get('k90')) is not int or report['c90'] >= report['k90'] or
                    report['c90'] != checked.get('c90') or report.get('on_time_point_count') != report['c90'] or
                    report.get('classification_sha256') != checked.get('classification_sha256') or
                    not isinstance(report.get('classification_sha256'), str)):
                    differences.append(dict(path=part, reason='EXACT_COUNT_OR_CLASSIFICATION_BINDING', identity=identity))
            if certificate_expected is not None and certificate_expected.get(identity) != digest:
                differences.append(dict(path=part, reason='RUNTIME_CERTIFICATE_BINDING', identity=identity))
            if report.get('source') != 'archived_component_composition' or any(report.get(key) is not False for key in
                    ('new_native_validation_performed', 'whole_constellation_STK_verified', 'native_verified')):
                differences.append(dict(path=part, reason='NATIVE_SCOPE', identity=identity))
            if len(differences) == before:
                verified[part].add(identity)
    processed = seen['FULL'] | seen['T100'] | seen['T90']
    if any(seen[a] & seen[b] for a, b in itertools.combinations(PARTS, 2)) or (not prefix and processed != ledger_ids):
        differences.append(dict(path='partition', reason='NOT_EXACT_DISJOINT_LEDGER_UNION'))
    for part in PARTS:
        ledger_partition = {identity for identity, row in ledger_rows.items() if row.get('partition') == part}
        if not prefix and seen[part] != ledger_partition:
            differences.append(dict(path='partition/'+part, reason='EXACT_PARTITION_SET_MISMATCH'))
        if prefix:
            observed_ordinals = [by_identity[i]['ordinal'] for i in seen[part] if i in by_identity]
            last_observed = max(observed_ordinals, default=-1)
            # A missing interior record cannot be explained by an interrupted
            # final write. Independent per-stream buffering can leave only a
            # suffix, so a later same-part record makes such loss substantive.
            if any(i not in seen[part] and ledger_rows[i]['ordinal'] < last_observed for i in ledger_partition):
                differences.append(dict(path='partition/'+part, reason='MISSING_INTERIOR_RECORD'))
    if not prefix and (processed != all_ids or actual_order.hexdigest() != expected_order.hexdigest()):
        differences.append(dict(path='completion', reason='NOT_EXACT_COMPLETE_NEIGHBORHOOD'))
    if prefix:
        committed = {part: set() for part in PARTS}
        for identity in ordered_ids:
            part = ledger_rows[identity].get('partition')
            if part not in PARTS or identity not in verified[part]:
                break
            committed[part].add(identity)
        committed_ids = set().union(*committed.values())
        pending_ids |= (processed | ledger_ids)-committed_ids
        seen = committed
        verified = {part: set(committed[part]) for part in PARTS}
        processed = committed_ids
        qualified = [pair for pair in qualified if pair[1] in committed_ids]
    qualified.sort(key=lambda pair: tuple(pair[0]))
    selected = qualified[0][1] if qualified else None
    if (not prefix or reported_selected_identity is not None) and selected != reported_selected_identity:
        differences.append(dict(path='selection', reason='INDEPENDENT_SELECTION_MISMATCH', expected=selected,
                                reported=reported_selected_identity))
    counts = dict(declared_candidates=len(all_ids), fully_evaluated=len(seen['FULL'] & all_ids),
        fully_independently_verified=len(verified['FULL'] & all_ids),
        T100_certificate_rejected=len(seen['T100'] & all_ids), T100_certificate_verified=len(verified['T100'] & all_ids),
        T90_certificate_rejected=len(seen['T90'] & all_ids), T90_certificate_verified=len(verified['T90'] & all_ids),
        unprocessed=len(all_ids-processed), unknown=len(processed-all_ids) + sum(len(seen[p]-verified[p]) for p in PARTS),
        qualified_count=len(qualified), retained_original_baseline=True if prefix else selected is None)
    incomplete = counts['unprocessed'] != 0 or counts['unknown'] != 0
    status = 'FAIL' if differences else 'BLOCKED' if incomplete else 'PASS'
    return dict(status=status, exit_code={'PASS': 0, 'FAIL': 1, 'BLOCKED': 2}[status], differences=differences,
        **counts, selected_identity=selected, retained_baseline=True if prefix else selected is None,
        identity_order_sha256=actual_order.hexdigest(), expected_identity_order_sha256=expected_order.hexdigest(),
        exact_disjoint_sets_checked=True, true_prefix=prefix, pending_uncommitted_count=len(pending_ids),
        method='Independent minimum-pivot exact neighborhood; streamed report/check hash bindings; independent checked-result rank')


def verify_five_anchor_union(baseline, donors, states, r17_ledger, r18_ledger,
                             r17_binding, check=lambda: None):
    """Read-only REUSED R17 and new R18 exact identity/operation union audit.

    The caller first verifies R17's sealed, transport and delivery manifests.
    This function requires the fixed delivery/source identities and completed
    count record, then independently reconstructs all actual operation sets.
    """
    b, d = _pool(baseline, donors, states)
    require(r17_binding.get('status') == 'PASS' and
            r17_binding.get('delivery_manifest_sha256') ==
            'd95ed8d31fe285de7480f5b6ce7aa7c04876ae447595d5da249d1d987b03b13f' and
            r17_binding.get('source_zip_sha256') ==
            'caef7a821832e72bbadfd555261c6dc2058efee6c158d9a0e63c5e9ec23d12c8',
            'CHECKER_R17_REUSED_IDENTITY_BINDING')
    completion = r17_binding.get('completion', {})
    require(completion.get('completed') is True and completion.get('declared_candidates') == 57834
            and completion.get('unprocessed') == completion.get('unknown') == 0
            and completion.get('fully_evaluated') == completion.get('fully_independently_verified')
            and completion.get('T100_certificate_rejected') == completion.get('T100_certificate_verified')
            and completion.get('T90_certificate_rejected') == completion.get('T90_certificate_verified')
            and sum(completion.get(k, -1) for k in
                    ('fully_evaluated', 'T100_certificate_rejected', 'T90_certificate_rejected')) == 57834,
            'CHECKER_R17_REUSED_COMPLETENESS_BINDING')
    r17_operations, r17_ids = set(), set()
    r18_operations, r18_ids = set(), set()
    old_order, new_order = hashlib.sha256(), hashlib.sha256()
    removable = [i for i in b if i != FIXED_REMOVE]
    old_additions = [i for i in d if i != EXCLUDED_DONOR]
    differences = []
    for ordinal, row in enumerate(r17_ledger):
        if ordinal % 512 == 0:
            check()
        if ordinal >= 57834:
            differences.append(dict(path='R17', reason='EXCESS_LEDGER_RECORD'))
            continue
        remove = removable[ordinal // len(old_additions)]
        add = old_additions[ordinal % len(old_additions)]
        pair = sorted((EXCLUDED_DONOR, add))
        indices = sorted([i for i in b if i not in (FIXED_REMOVE, remove)] + pair)
        identity = fingerprint(sorted(states[i] for i in indices))
        operation = (remove, *pair)
        if (row.get('ordinal') != ordinal or row.get('remove') != remove or row.get('add') != add
                or row.get('remove_pair') != sorted((FIXED_REMOVE, remove))
                or row.get('add_pair') != pair or row.get('indices') != indices
                or row.get('identity') != identity):
            differences.append(dict(path='R17', reason='REUSED_OPERATION_OR_IDENTITY', ordinal=ordinal))
        if operation in r17_operations or identity in r17_ids:
            differences.append(dict(path='R17', reason='DUPLICATE_REUSED_ITEM', ordinal=ordinal))
        r17_operations.add(operation); r17_ids.add(identity)
        old_order.update((str(row.get('identity'))+'\n').encode('ascii'))
    for ordinal, pair in enumerate(itertools.zip_longest(
            iter_candidates(b, d, states, check), r18_ledger)):
        expected, row = pair
        if expected is None or row is None:
            differences.append(dict(path='R18', reason='NEW_EXACT_SET_LENGTH', ordinal=ordinal))
            continue
        operation = (expected['remove'], *expected['add_pair'])
        if any(row.get(key) != value for key, value in expected.items()):
            differences.append(dict(path='R18', reason='NEW_OPERATION_OR_IDENTITY', ordinal=ordinal))
        identity = row.get('identity')
        if operation in r18_operations or identity in r18_ids:
            differences.append(dict(path='R18', reason='DUPLICATE_NEW_ITEM', ordinal=ordinal))
        r18_operations.add(operation); r18_ids.add(identity)
        new_order.update((str(identity)+'\n').encode('ascii'))
    anchors = ANCHOR_DONORS | {EXCLUDED_DONOR}
    # A separately constructed five-anchor pivot set proves the union coverage.
    expected_pairs = set()
    for pivot in sorted(anchors):
        for other in d:
            if other != pivot and (other not in anchors or other > pivot):
                expected_pairs.add(tuple(sorted((pivot, other))))
    expected_union = {(remove, *pair) for remove in removable for pair in expected_pairs}
    overlap_operations = r17_operations & r18_operations
    overlap_identities = r17_ids & r18_ids
    actual_union = r17_operations | r18_operations
    if len(r17_operations) != 57834 or len(r17_ids) != 57834:
        differences.append(dict(path='R17', reason='INCOMPLETE_REUSED_EXACT_SET'))
    if len(r18_operations) != DECLARED or len(r18_ids) != DECLARED:
        differences.append(dict(path='R18', reason='INCOMPLETE_NEW_EXACT_SET'))
    if overlap_operations or overlap_identities or actual_union != expected_union:
        differences.append(dict(path='union', reason='NOT_EXACT_DISJOINT_FIVE_ANCHOR_UNION'))
    require(len(expected_union) == 288900, 'CHECKER_FIVE_ANCHOR_EXPECTED_CARDINALITY')
    digest = hashlib.sha256()
    for operation in sorted(actual_union):
        digest.update((','.join(map(str, operation))+'\n').encode('ascii'))
    return dict(status='FAIL' if differences else 'PASS', differences=differences,
        R17=dict(disposition='REUSED', candidates=len(r17_ids), new_evaluations=0,
                 identity_order_sha256=old_order.hexdigest(), binding_sha256=fingerprint(r17_binding)),
        R18=dict(disposition='PROCESSED_THIS_ROUND', candidates=len(r18_ids),
                 identity_order_sha256=new_order.hexdigest()),
        overlap_operations=len(overlap_operations), overlap_identities=len(overlap_identities),
        union_candidates=len(actual_union), expected_union_candidates=len(expected_union),
        exact_union_operations_sha256=digest.hexdigest(),
        full_catalog_double_swap_completed=False, third_swap_performed=False)
