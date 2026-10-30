"""Independent raw-source verification and exact R19 stream counterexamples."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np

from src.round13.common import EvidenceError, fingerprint
from src.round14.science import evaluate
from src.round19 import checker, science


def fixture():
    baseline = sorted(list(range(26))+[1217, 1284])
    center = sorted((set(baseline)-{1217, 1284}) | {2021, 2023})
    states = {i: 'checker-r19-state-'+str(i) for i in range(2171)}
    rows = {i: np.full(10, 30.) for i in states}
    rows[0] = np.array([10.]*8+[30., 20.])
    rows[1217] = np.array([10.]*9+[30.])
    rows[2021] = np.array([30.]*8+[10., 30.])
    rows[26] = np.array([30.]*9+[np.inf])
    rows[27] = np.array([30.]*8+[20., 30.])
    rows[28] = np.array([30.]*8+[10., 30.])
    targets = [checker.TARGET, 'second', 'third']
    intervals = {i: {t: [] for t in targets} for i in states}
    for index in set(baseline) | set(center):
        for target in targets[1:]:
            intervals[index][target] = [[0., 1.], [2., 3.]]
    intervals[0][checker.TARGET] = [[0., 2.]]
    intervals[1][checker.TARGET] = [[12., 14.]]
    intervals[2021][checker.TARGET] = [[10., 11.]]
    for index in (26, 27, 28):
        intervals[index][checker.TARGET] = [[5., 6.]]
    lib = SimpleNamespace(baseline_indices=baseline, center_indices=center,
        donor_indices=sorted(set(states)-set(baseline)), donor_indices19=sorted(set(states)-set(center)),
        rows=rows, intervals=intervals, targets=targets, states=states,
        keep=np.ones(10, dtype=np.bool_), coords=np.column_stack((np.arange(10, dtype=float), np.zeros(10))),
        evidence={'matrix': {'sha256': 'synthetic-checker-r19-matrix'}},
        assets={i: dict(state=states[i], regional_data_sha256=fingerprint(intervals[i])) for i in states})
    baseline_report, baseline_hits = evaluate(baseline, rows, intervals, lib.keep, targets, states)
    center_report, center_hits = evaluate(center, rows, intervals, lib.keep, targets, states, baseline_report)
    return lib, baseline_report, center_report, baseline_hits, center_hits


def candidate(lib, remove, add):
    indices = sorted([i for i in lib.center_indices if i != remove]+[add])
    return dict(ordinal=lib.center_indices.index(remove)*len(lib.donor_indices19)+lib.donor_indices19.index(add),
        remove=remove, add=add, indices=indices, identity=fingerprint(sorted(lib.states[i] for i in indices)))


def certificate(own, item):
    part = own.partition(item)
    result = dict(item, partition=part, status='PROVEN_NO_ROUND19_IMPROVEMENT' if part == 'GAP' else 'KNOWN_INFEASIBLE',
        processing_state=part+'_CERTIFICATE_REJECTED', metrics_status='NOT_EVALUATED', full_grid=None,
        effective_grid=None, regional=None, feasibility='NOT_EVALUATED', first_hits_sha256=None,
        T90_s=None, T100_s=None, Tavg_s=None, Tmax_s=None, qualified_for_round19=False,
        known_infeasible=None if part == 'GAP' else True, full_feasibility_evaluation_performed=False,
        source='archived_component_composition', new_native_validation_performed=False,
        whole_constellation_STK_verified=False, native_verified=False, center_identity=own.center_identity,
        original_constraint_reference_identity=own.baseline_reference['identity'], tau100=own.tau100,
        tau90=own.tau90, k90=own.k90, mask_sha256=own.mask_sha256, coordinate_sha256=own.coordinate_sha256,
        input_binding_sha256=own.binding(item), cache_binding_sha256=own._cache_binding(item['remove']), proof_sha256='synthetic-proof')
    if part == 'GAP':
        gap = own.gap_state
        left, right = own._gap_witnesses(item)
        def witness(pair):
            index, span = pair
            return dict(index=index, interval=span, state=own.states[index], source_payload_sha256=gap['payload'][index])
        result.update(target=checker.TARGET, L=gap['L'], R=gap['R'], Tmax_lower_bound_s=gap['length'],
            before_witness=witness(left[0]), after_witness=witness(right[0]),
            donor_raw_intervals=gap['raw'][item['add']], donor_interval_sha256=gap['interval_sha256'][item['add']],
            donor_source_payload_sha256=gap['payload'][item['add']], retained_before_asset_count=len({i for i, _ in left}),
            retained_after_asset_count=len({i for i, _ in right}), minimum_required_improvement_s=1., uncertainty_margin_s=1e-6)
    elif part == 'T100':
        point = int(own.mask_ids[np.flatnonzero(~own._boolean(item, own.tau100))[0]])
        values = checker.verify_t100_witness(own.rows, item['indices'], point, own.tau100, states=own.states)['source_values']
        result.update(point_id=point, coordinates=own.lib.coords[point].tolist(), in_mask=True,
                      source_values=values, source_values_sha256=fingerprint(values))
    elif part == 'T90':
        values = own._boolean(item, own.tau90)
        result.update(c90=int(np.count_nonzero(values)), on_time_point_count=int(np.count_nonzero(values)),
                      classification_sha256=checker.classification_digest(values), bitset_padding_zero=True)
    return result


class SourceAndReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib, cls.baseline, cls.center, cls.bhits, cls.chits = fixture()
        cls.own = checker.IndependentChecker(cls.lib, cls.baseline, cls.center)

    def test_both_references_are_reconstructed_pointwise_and_regionally(self):
        self.assertEqual(self.own.verify(self.lib.baseline_indices, self.baseline, self.bhits)['status'], 'PASS')
        self.assertEqual(self.own.verify(self.lib.center_indices, self.center, self.chits, self.baseline)['status'], 'PASS')
        changed = deepcopy(self.center); changed['regional']['pooled_internal']['max_s'] += 1.
        with self.assertRaisesRegex(EvidenceError, 'REFERENCE_MISMATCH'):
            self.own.set_references(self.baseline, changed)

    def test_raw_boolean_gate_priority_has_four_distinct_partitions(self):
        expected = [(2, 29, 'GAP'), (2021, 26, 'T100'), (2021, 27, 'T90'), (2021, 28, 'FULL')]
        for remove, add, part in expected:
            with self.subTest(part=part):
                self.assertEqual(self.own.partition(candidate(self.lib, remove, add)), part)

    def test_t100_rechecks_every_original_source_and_rejects_tampering(self):
        item = candidate(self.lib, 2021, 26)
        cert = certificate(self.own, item)
        self.assertEqual(self.own.verify_certificate(item, cert)['status'], 'PASS')
        changed = deepcopy(cert); changed['source_values'][-1]['first_hit_s'] = 0.
        changed['source_values_sha256'] = fingerprint(changed['source_values'])
        self.assertEqual(self.own.verify_certificate(item, changed)['status'], 'FAIL')

    def test_t90_rechecks_classification_and_count(self):
        item = candidate(self.lib, 2021, 27)
        cert = certificate(self.own, item)
        self.assertEqual(self.own.verify_certificate(item, cert)['status'], 'PASS')
        changed = deepcopy(cert); changed['classification_sha256'] = '0'*64
        self.assertEqual(self.own.verify_certificate(item, changed)['status'], 'FAIL')
        changed = deepcopy(cert); changed['c90'] += 1
        self.assertEqual(self.own.verify_certificate(item, changed)['status'], 'FAIL')

    def test_proof_context_digest_required_for_all_certificate_kinds(self):
        for remove, add, part in [(2, 29, 'GAP'), (2021, 26, 'T100'), (2021, 27, 'T90')]:
            with self.subTest(part=part):
                item = candidate(self.lib, remove, add)
                cert = certificate(self.own, item)
                context = dict(proof_sha256=cert['proof_sha256'])
                self.assertEqual(self.own.verify_certificate(item, cert, context)['status'], 'PASS')
                changed = deepcopy(cert); changed['proof_sha256'] = '0'*64
                self.assertEqual(self.own.verify_certificate(item, changed, context)['status'], 'FAIL')

    def test_deadline_equality_and_38762_38763_boundary(self):
        values = np.full(43070, 20.); values[:38762] = 10.
        keep = np.ones(43070, dtype=np.bool_)
        boolean = checker.boolean_on_time({0: values}, [0], keep, 10.)
        digest = checker.classification_digest(boolean)
        self.assertEqual(checker.verify_t90_count({0: values}, [0], keep, 10., 38763, 38762, digest)['status'], 'PASS')
        values[38762] = 10.
        boolean = checker.boolean_on_time({0: values}, [0], keep, 10.)
        result = checker.verify_t90_count({0: values}, [0], keep, 10., 38763, 38763, checker.classification_digest(boolean))
        self.assertEqual((result['status'], result['c90']), ('FAIL', 38763))
        self.assertEqual(len(boolean), 43070)

    def test_full_report_compares_all_points_and_regional_endpoints(self):
        item = candidate(self.lib, 2021, 28)
        report, hits = evaluate(item['indices'], self.lib.rows, self.lib.intervals, self.lib.keep,
                                self.lib.targets, self.lib.states, self.baseline)
        checker._annotate(report, self.center); report.update(item, partition='FULL')
        args = (item['indices'], report, hits, self.baseline, item['remove'], item['add'])
        self.assertEqual(self.own.verify(*args)['status'], 'PASS')
        changed = hits.copy(); changed[0] += .1
        self.assertEqual(self.own.verify(item['indices'], report, changed, self.baseline)['status'], 'FAIL')
        changed = deepcopy(report); changed['regional']['targets']['second']['merged_intervals'][0][1] += .1
        self.assertEqual(self.own.verify(item['indices'], changed, hits, self.baseline)['status'], 'FAIL')

    def test_r19_annotation_rejects_b0_improvement_that_is_worse_than_s(self):
        row = deepcopy(self.center)
        row['regional']['pooled_internal']['max_s'] = self.center['regional']['pooled_internal']['max_s']+.5
        row['qualified_improvement'] = True
        checker._annotate(row, self.center)
        self.assertFalse(row['qualified_for_round19'])

    def test_feasibility_is_bound_to_b0_not_mutable_caller_metrics(self):
        item = candidate(self.lib, 2021, 28)
        loose = deepcopy(self.baseline); loose['effective_grid']['T90_s'] = 604800.
        actual, _ = self.own.recompute(item['indices'], loose)
        expected, _ = self.own.recompute(item['indices'], self.baseline)
        self.assertEqual(actual['feasibility'], expected['feasibility'])


class GapWitnessTests(unittest.TestCase):
    def test_lost_left_witness_is_not_internal_gap_proof(self):
        lib, baseline, center, _, _ = fixture(); own = checker.IndependentChecker(lib, baseline, center)
        self.assertNotEqual(own.partition(candidate(lib, 0, 29)), 'GAP')

    def test_lost_right_witness_is_not_internal_gap_proof(self):
        lib, _, _, _, _ = fixture()
        lib.intervals[1][checker.TARGET] = []
        lib.intervals[1284][checker.TARGET] = [[12., 14.]]
        own = checker.IndependentChecker(lib)
        self.assertNotEqual(own.partition(candidate(lib, 2021, 29)), 'GAP')

    def test_zero_duration_interior_visit_enters_gap_endpoint_contact_does_not(self):
        lib, _, _, _, _ = fixture()
        lib.intervals[30][checker.TARGET] = [[5., 5.]]
        lib.intervals[31][checker.TARGET] = [[2., 2.], [10., 10.]]
        own = checker.IndependentChecker(lib)
        self.assertNotEqual(own.partition(candidate(lib, 2, 30)), 'GAP')
        self.assertEqual(own.partition(candidate(lib, 2, 31)), 'GAP')

    def test_gap_null_metrics_and_feasibility_semantics_are_enforced(self):
        lib, baseline, center, _, _ = fixture(); own = checker.IndependentChecker(lib, baseline, center)
        item = candidate(lib, 2, 29); cert = certificate(own, item)
        self.assertEqual(own.verify_certificate(item, cert)['status'], 'PASS')
        for key, value in [('Tmax_s', 8.), ('known_infeasible', True), ('feasibility', {'feasible': False})]:
            changed = deepcopy(cert); changed[key] = value
            self.assertEqual(own.verify_certificate(item, changed)['status'], 'FAIL')

    def test_wrong_or_removed_raw_witness_is_rejected(self):
        lib, baseline, center, _, _ = fixture(); own = checker.IndependentChecker(lib, baseline, center)
        item = candidate(lib, 2, 29); cert = certificate(own, item)
        cert['before_witness']['index'] = 2
        self.assertEqual(own.verify_certificate(item, cert)['status'], 'FAIL')


class ExactStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib, cls.baseline, cls.center, _, _ = fixture()
        cls.own = checker.IndependentChecker(cls.lib, cls.baseline, cls.center)
        cls.items = sorted([candidate(cls.lib, 2, 29), candidate(cls.lib, 2021, 26),
                            candidate(cls.lib, 2021, 27), candidate(cls.lib, 2021, 28)], key=lambda row: row['ordinal'])
        ledger, reports, checks = [], [], []
        certs, certchecks = {p: [] for p in ('GAP', 'T100', 'T90')}, {p: [] for p in ('GAP', 'T100', 'T90')}
        for item in cls.items:
            part = cls.own.partition(item)
            if part == 'FULL':
                report, hits = evaluate(item['indices'], cls.lib.rows, cls.lib.intervals, cls.lib.keep,
                    cls.lib.targets, cls.lib.states, cls.baseline)
                checker._annotate(report, cls.center); report.update(item, partition='FULL')
                checked = cls.own.verify(item['indices'], report, hits, cls.baseline)
                reports.append(checker.compact_report(report)); checks.append(checked)
                ledger.append(dict(item, partition=part, main_output_sha256=checked['main_output_sha256'],
                                   checker_output_sha256=checked['checker_output_sha256']))
            else:
                cert = certificate(cls.own, item); checked = cls.own.verify_certificate(item, cert)
                certs[part].append(cert); certchecks[part].append(checked)
                ledger.append(dict(item, partition=part, certificate_sha256=fingerprint(cert), checker_output_sha256=fingerprint(checked)))
        cls.streams = [ledger, reports, checks, certs['GAP'], certchecks['GAP'], certs['T100'], certchecks['T100'],
                       certs['T90'], certchecks['T90']]
        cls.selected = cls.own.selection()['selected_identity']

    def readback(self, streams, prefix=False):
        with patch.object(checker, 'DECLARED', len(self.items)), patch.object(checker, 'iter_candidates', return_value=iter(self.items)):
            return checker.terminal_verification(self.lib.center_indices, self.lib.donor_indices19, self.lib.states,
                                                 *streams, self.selected, prefix=prefix)

    def test_four_partitions_form_exact_disjoint_checked_union(self):
        result = self.readback(self.streams)
        self.assertEqual((result['status'], result['verified_candidates'], result['unprocessed']), ('PASS', 4, 0))
        self.assertEqual([result[p+'_verified'] for p in checker.PARTS], [1, 1, 1, 1])

    def test_duplicate_middle_missing_or_wrong_partition_is_failure(self):
        changed = deepcopy(self.streams); changed[0].insert(1, deepcopy(changed[0][0]))
        self.assertEqual(self.readback(changed)['status'], 'FAIL')
        changed = deepcopy(self.streams); changed[3].clear()
        self.assertEqual(self.readback(changed)['status'], 'FAIL')
        changed = deepcopy(self.streams); changed[0][0]['partition'] = 'T100'
        self.assertEqual(self.readback(changed)['status'], 'FAIL')

    def test_uncommitted_tail_is_blocked_prefix(self):
        changed = deepcopy(self.streams); changed[0].pop()
        # A valid selected identity can only describe the committed prefix.
        with patch.object(self, 'selected', None):
            result = self.readback(changed, prefix=True)
        self.assertEqual((result['status'], result['unprocessed'], result['pending_uncommitted_count']), ('BLOCKED', 1, 1))

    def test_report_checker_or_ledger_hash_substitution_is_failure(self):
        for stream, field in [(0, 'checker_output_sha256'), (4, 'main_certificate_sha256'), (1, 'main_output_sha256')]:
            changed = deepcopy(self.streams); changed[stream][0][field] = '0'*64
            self.assertEqual(self.readback(changed)['status'], 'FAIL')

    def test_terminal_rank_times_use_absolute_tolerance_without_relative_tolerance(self):
        for position in range(4):
            for delta, expected in [(1.8189894035458565e-12, 'PASS'), (5e-7, 'PASS'), (2e-6, 'FAIL')]:
                with self.subTest(position=position, delta=delta):
                    changed = deepcopy(self.streams)
                    changed[2][0]['rank'][position] += delta
                    self.assertEqual(self.readback(changed)['status'], expected)

    def test_terminal_rank_identity_and_qualification_remain_exact(self):
        changed = deepcopy(self.streams); changed[2][0]['rank'][4] = 'other-identity'
        self.assertEqual(self.readback(changed)['status'], 'FAIL')
        changed = deepcopy(self.streams); changed[2][0]['qualified_for_round19'] = not changed[2][0]['qualified_for_round19']
        self.assertEqual(self.readback(changed)['status'], 'FAIL')
        changed = deepcopy(self.streams); changed[2][0]['qualified_for_round19'] = int(changed[2][0]['qualified_for_round19'])
        self.assertEqual(self.readback(changed)['status'], 'FAIL')

    def test_false_partial_metrics_are_detected_even_when_hashes_rebound(self):
        changed = deepcopy(self.streams); row = changed[3][0]; row['Tmax_s'] = 8.
        changed[4][0]['main_certificate_sha256'] = fingerprint(row)
        changed[0][0]['certificate_sha256'] = fingerprint(row)
        changed[0][0]['checker_output_sha256'] = fingerprint(changed[4][0])
        self.assertEqual(self.readback(changed)['status'], 'FAIL')


class FullSpaceTests(unittest.TestCase):
    def test_all_60004_unique_operations_with_every_center_removal(self):
        lib, _, _, _, _ = fixture()
        items = list(checker.iter_candidates(lib.center_indices, lib.donor_indices19, lib.states))
        self.assertEqual(len(items), 60004)
        self.assertEqual(len({row['identity'] for row in items}), 60004)
        self.assertEqual({row['remove'] for row in items}, set(lib.center_indices))
        self.assertTrue({1217, 1284} <= {row['add'] for row in items})
        self.assertFalse({2021, 2023} & {row['add'] for row in items})
        self.assertEqual([(r['remove'], r['add']) for r in items],
                         sorted((r['remove'], r['add']) for r in items))

    def test_wrong_donor_members_even_when_count_equal_are_rejected(self):
        lib, _, _, _, _ = fixture()
        wrong = sorted((set(lib.donor_indices19)-{1217, 1284}) | {2021, 2023})
        with self.assertRaisesRegex(EvidenceError, 'EXACT_DONOR_SET'):
            next(checker.iter_candidates(lib.center_indices, wrong, lib.states))


class MainCheckerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        center = sorted(list(range(18))+[38, 263, 548, 676, 911, 974, 1412, 2021, 2023, 2049])
        baseline = sorted((set(center)-{2021, 2023}) | {1217, 1284})
        states = {i: 'integration-r19-state-'+str(i) for i in range(2171)}
        keep = np.arange(43424) < 43070
        shared = np.where(keep, 100., np.inf)
        targets = [checker.TARGET, 'second', 'third']
        intervals = {i: {t: [] for t in targets} for i in states}
        for i in set(center) | set(baseline):
            for target in targets[1:]:
                intervals[i][target] = [[0., 1.], [100., 101.]]
        left, right = 242031.721879453, 374083.009268146
        for i in [911, 974, 1412, 2021, 2049]:
            intervals[i][checker.TARGET].append([left-100., left])
        for i in [38, 263, 548, 676, 974, 1412, 2049]:
            intervals[i][checker.TARGET].append([right, right+100.])
        intervals[26][checker.TARGET] = [[left+100., right-100.]]
        cls.lib = SimpleNamespace(baseline_indices=baseline, center_indices=center,
            donor_indices=sorted(set(states)-set(baseline)), donor_indices19=sorted(set(states)-set(center)),
            rows={i: shared for i in states}, intervals=intervals, targets=targets, states=states, keep=keep,
            coords=np.column_stack((np.arange(43424, dtype=float), np.zeros(43424))),
            assets={i: dict(state=states[i], regional_data_sha256=fingerprint(intervals[i])) for i in states},
            evidence={'matrix': {'sha256': 'integration-r19-matrix'}})
        cls.baseline, cls.bhits = evaluate(baseline, cls.lib.rows, intervals, keep, targets, states)
        cls.center, cls.chits = evaluate(center, cls.lib.rows, intervals, keep, targets, states, cls.baseline)
        cls.own = checker.IndependentChecker(cls.lib, cls.baseline, cls.center)
        with patch.object(science, 'BASELINE_IDENTITY', cls.baseline['identity']), patch.object(science, 'CENTER_IDENTITY', cls.center['identity']):
            cls.gate = science.Gate(cls.lib, cls.baseline, cls.center)
            cls.evidence = cls.gate.evidence()
            cls.gap_item = candidate(cls.lib, 0, 27)
            cls.gap_part, cls.gap_cert = cls.gate.classify(cls.gap_item)
            cls.full_item = candidate(cls.lib, 0, 26)
            cls.full_part, _ = cls.gate.classify(cls.full_item)
            cls.report, cls.hits = evaluate(cls.full_item['indices'], cls.lib.rows, intervals, keep, targets, states, cls.baseline)
            science.annotate(cls.report, cls.center)
            cls.report.update(cls.full_item, partition='FULL')

    def test_actual_main_gate_raw_source_cache_and_proof_bindings_match(self):
        result = self.own.verify_gate_evidence(self.evidence)
        self.assertEqual(result['status'], 'PASS', result['differences'][:5])
        self.assertEqual((self.gap_part, self.full_part), ('GAP', 'FULL'))
        result = self.own.verify_certificate(self.gap_item, self.gap_cert)
        self.assertEqual(result['status'], 'PASS', result['differences'][:5])

    def test_gate_source_proof_and_cache_substitutions_fail(self):
        for key in ('source_binding_sha256', 'proof_sha256'):
            changed = deepcopy(self.evidence); changed[key] = '0'*64
            self.assertEqual(self.own.verify_gate_evidence(changed)['status'], 'FAIL')
        changed = deepcopy(self.evidence); changed['cache_bindings']['0'] = '0'*64
        self.assertEqual(self.own.verify_gate_evidence(changed)['status'], 'FAIL')
        self.own.verify_gate_evidence(self.evidence)

    def test_main_full_annotation_independently_matches_all_43424_points(self):
        result = self.own.verify(self.full_item['indices'], self.report, self.hits, self.baseline,
                                 self.full_item['remove'], self.full_item['add'])
        self.assertEqual(result['status'], 'PASS', result['differences'][:5])
        self.assertEqual(result['points_compared'], 43424)


if __name__ == '__main__':
    unittest.main()
