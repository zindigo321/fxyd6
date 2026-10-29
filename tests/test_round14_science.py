"""Synthetic-only validation of the frozen finite-neighborhood algorithms."""
import ast
import copy
from pathlib import Path
import unittest

import numpy as np

from src.round13.common import EvidenceError
from src.round14 import science
from src.round14.checker import IndependentChecker, verify_baseline_whole, terminal_verification


class ScientificTests(unittest.TestCase):
    def setUp(self):
        self.baseline = list(range(28))
        self.donors = list(range(28, 60))
        self.states = {i: 'state-'+str(i) for i in range(60)}
        self.rows = {i: np.array([2., 3., 4., np.inf]) for i in range(60)}
        self.targets = ['a', 'b', 'c']
        self.intervals = {i: {t: [[1., 2.], [5., 6.], [10., 11.]] for t in self.targets} for i in range(60)}
        self.keep = np.array([True, True, True, False])
        self.reference, self.reference_hits = self.run_main(self.baseline)

    def run_main(self, indices, baseline=None):
        return science.evaluate(indices, self.rows, self.intervals, self.keep, self.targets,
                                self.states, baseline, duration=20.)

    def checker(self):
        return IndependentChecker(self.baseline, self.rows, self.intervals, self.keep,
                                  self.targets, self.states, duration=20.)

    def candidate(self, donor=28, remove=0):
        return sorted((set(self.baseline)-{remove}) | {donor})

    def test_complete_cartesian_product(self):
        declared = science.neighborhood(self.baseline, self.donors, self.states)
        self.assertEqual(len(declared), 896)
        self.assertEqual({(r['remove'], r['add']) for r in declared},
                         {(a, b) for a in self.baseline for b in self.donors})
        self.assertEqual(len({r['identity'] for r in declared}), 896)
        self.assertTrue(all(len(r['indices']) == len(set(r['indices'])) == 28 for r in declared))

    def test_order_is_fixed_independent_of_input_order(self):
        left = science.neighborhood(self.baseline, self.donors, self.states)
        right = science.neighborhood(self.baseline[::-1], self.donors[::-1], self.states)
        self.assertEqual(left, right)

    def test_duplicate_state_or_donor_rejected(self):
        states = dict(self.states); states[28] = states[0]
        for baseline, donors, mapping in [(self.baseline, self.donors, states),
                (self.baseline, [28, 28], self.states),
                (self.baseline, [0, 28], self.states)]:
            with self.subTest(donors=donors), self.assertRaises(EvidenceError):
                science.neighborhood(baseline, donors, mapping)

    def test_strict_ninety_order_statistic(self):
        result = science.coverage(list(range(10))+[np.inf], duration=20)
        self.assertEqual(result['threshold_90_count'], 10)
        self.assertEqual(result['T90_s'], 9.)
        self.assertIsNone(result['T100_s'])
        self.assertEqual(result['covered'], 10)

    def test_no_hit_domain(self):
        result = science.coverage([np.inf]*11)
        self.assertIsNone(result['T90_s'])
        self.assertIsNone(result['T100_s'])
        self.assertEqual(result['uncovered'], 11)

    def test_invalid_first_hit_values(self):
        for value in (np.nan, -np.inf, -1., 21.):
            with self.subTest(value=value), self.assertRaises(EvidenceError):
                science.coverage([value], duration=20)

    def test_overlapping_and_touching_accesses(self):
        merged = science.union([[5, 6], [1, 3], [2, 4], [4+5e-7, 5]], duration=20)
        self.assertEqual(merged, [[1., 6.]])

    def test_gap_beyond_merge_tolerance_preserved(self):
        merged = science.union([[1, 2], [2+2e-6, 3]], duration=20)
        self.assertEqual(len(merged), 2)

    def test_invalid_interval_window_rejected(self):
        for interval in ([-1, 1], [1, 21], [2, 1], [np.nan, 2], [1, np.inf]):
            with self.subTest(interval=interval), self.assertRaises(EvidenceError):
                science.union([interval], duration=20)

    def test_pooled_internal_gaps_not_average_target_means(self):
        regions = {'a': [[0, 1], [3, 4]], 'b': [[0, 1], [5, 6], [12, 13]], 'c': []}
        report = science.regional(regions, self.targets, duration=20)
        self.assertEqual(report['pooled_internal']['gap_count'], 3)
        self.assertEqual(report['pooled_internal']['mean_s'], 4.)
        self.assertFalse(report['targets']['c']['valid_revisit'])
        self.assertEqual(report['targets']['c']['boundary_inclusive']['max_s'], 20.)

    def test_missing_target_rejected(self):
        self.intervals[28].pop('b')
        with self.assertRaisesRegex(EvidenceError, 'REGIONAL_TARGET_SET'):
            self.run_main(self.candidate(), self.reference)

    def test_insufficient_visit_remains_explicit_gate(self):
        report = copy.deepcopy(self.reference)
        report['regional']['targets']['c']['merged_count'] = 1
        report['regional']['targets']['c']['valid_revisit'] = False
        result = science.feasibility(report, self.reference, duration=20)
        self.assertIn('INSUFFICIENT_MERGED_VISITS:c', result['rejection_reasons'])

    def test_every_primary_gate(self):
        scenarios = [
            ('NOT_EXACTLY_28_LEGAL_UNIQUE_STATES', lambda r: r['indices'].pop()),
            ('MASK_NOT_EXACT_FULL_COVERAGE', lambda r: r['effective_grid'].update(uncovered=1)),
            ('T100_INVALID_OR_OUTSIDE_WINDOW', lambda r: r['effective_grid'].update(T100_s=None)),
            ('T90_s_WORSE_THAN_BASELINE', lambda r: r['effective_grid'].update(T90_s=5.)),
            ('T100_s_WORSE_THAN_BASELINE', lambda r: r['effective_grid'].update(T100_s=5.)),
            ('Tavg_s_WORSE_THAN_BASELINE', lambda r: r['regional']['pooled_internal'].update(mean_s=10.)),
        ]
        for reason, mutate in scenarios:
            with self.subTest(reason=reason):
                report = copy.deepcopy(self.reference); mutate(report)
                self.assertIn(reason, science.feasibility(report, self.reference, duration=20)['rejection_reasons'])

    def test_tolerance_gates_accept_exact_boundary(self):
        report = copy.deepcopy(self.reference)
        report['effective_grid']['T90_s'] += 1e-6
        report['effective_grid']['T100_s'] += 1e-6
        report['regional']['pooled_internal']['mean_s'] += 1e-6
        self.assertTrue(science.feasibility(report, self.reference, duration=20)['feasible'])

    def test_tolerance_gates_reject_above_boundary(self):
        report = copy.deepcopy(self.reference)
        report['effective_grid']['T90_s'] += 1.01e-6
        self.assertFalse(science.feasibility(report, self.reference, duration=20)['feasible'])

    def test_conservative_one_second_threshold(self):
        # The baseline's longest gap is four seconds.  A three-second gap
        # gives exactly one second reduction, inside the conservative band.
        for target in self.targets:
            self.intervals[28][target] = [[1, 2], [5, 6], [9, 11]]
        exact, _ = self.run_main(self.candidate(), self.reference)
        self.assertEqual(exact['improvement']['Tmax_reduction_s'], 1.)
        self.assertFalse(exact['qualified_improvement'])
        for target in self.targets:
            self.intervals[28][target] = [[1, 2], [5-2e-6, 6], [9-2e-6, 11]]
        above, _ = self.run_main(self.candidate(), self.reference)
        self.assertGreater(above['improvement']['Tmax_reduction_s'], 1+1e-6)
        self.assertTrue(above['qualified_improvement'])

    def test_strong_improvement_and_boundary_tradeoff(self):
        for target in self.targets:
            self.intervals[28][target] = [[3, 4], [7, 9]]
        report, _ = self.run_main(self.candidate(), self.reference)
        self.assertEqual(report['regional']['pooled_internal']['max_s'], 1.)
        self.assertTrue(report['qualified_improvement'])
        self.assertIn('boundary_segments', report['regional']['targets']['a'])

    def test_duplicate_minimum_survives_removal(self):
        self.rows[0] = np.array([0., 3., 4., np.inf])
        self.rows[1] = self.rows[0].copy()
        checker = self.checker()
        for remove in (0, 1):
            indices = self.candidate(remove=remove)
            report, hits = self.run_main(indices, self.reference)
            verification = checker.verify(indices, report, hits, self.reference, remove=remove, add=28)
            self.assertEqual(hits[0], 0.)
            self.assertEqual(verification['status'], 'PASS')

    def test_all_infinite_columns_classification(self):
        checker = self.checker()
        report, hits = self.run_main(self.candidate(), self.reference)
        result = checker.verify(self.candidate(), report, hits, self.reference)
        self.assertEqual(result['classification_difference_count'], 0)
        self.assertEqual(result['points_compared'], 4)
        self.assertEqual(result['max_absolute_first_hit_error_s'], 0.)

    def test_checker_rejects_forged_first_hit_array(self):
        report, hits = self.run_main(self.candidate(), self.reference)
        hits[0] += .1
        result = self.checker().verify(self.candidate(), report, hits, self.reference)
        self.assertEqual(result['status'], 'FAIL')

    def test_checker_rejects_forged_classification(self):
        report, hits = self.run_main(self.candidate(), self.reference)
        hits[-1] = 10
        result = self.checker().verify(self.candidate(), report, hits, self.reference)
        self.assertEqual(result['classification_difference_count'], 1)
        self.assertEqual(result['status'], 'FAIL')

    def test_checker_rejects_forged_interval_metric_digest_identity_native_flag(self):
        mutations = [lambda r: r['regional']['targets']['a']['merged_intervals'][0].__setitem__(0, .5),
            lambda r: r['effective_grid'].update(T90_s=2.),
            lambda r: r.update(first_hits_sha256='0'*64),
            lambda r: r.update(identity='forged'),
            lambda r: r.update(native_verified=True)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                report, hits = self.run_main(self.candidate(), self.reference); mutate(report)
                self.assertEqual(self.checker().verify(self.candidate(), report, hits, self.reference)['status'], 'FAIL')

    def test_checker_rejects_swap_label_mismatch(self):
        report, hits = self.run_main(self.candidate(), self.reference)
        with self.assertRaisesRegex(EvidenceError, 'SWAP_LABEL_MISMATCH'):
            self.checker().verify(self.candidate(), report, hits, self.reference, remove=1, add=28)

    def test_checker_does_not_trust_production_baseline_metrics(self):
        forged = copy.deepcopy(self.reference)
        forged['effective_grid']['T90_s'] = 0.
        report, hits = self.run_main(self.candidate(), forged)
        self.assertFalse(report['feasibility']['feasible'])
        self.assertEqual(self.checker().verify(self.candidate(), report, hits, forged)['status'], 'FAIL')

    def test_checker_rejects_double_swap(self):
        indices = sorted(set(self.baseline)-{0, 1}|{28, 29})
        report, hits = self.run_main(indices, self.reference)
        with self.assertRaisesRegex(EvidenceError, 'NOT_SINGLE_REPLACEMENT'):
            self.checker().verify(indices, report, hits, self.reference)

    def test_no_relative_tolerance_expansion(self):
        rows = {i: np.array([600000.]) for i in range(60)}
        checker = IndependentChecker(self.baseline, rows, self.intervals, np.array([True]),
                                     self.targets, self.states)
        report, hits = science.evaluate(self.baseline, rows, self.intervals, np.array([True]),
                                        self.targets, self.states)
        hits[0] += 1e-5
        self.assertEqual(checker.verify(self.baseline, report, hits)['status'], 'FAIL')

    def test_new_combination_never_inherits_native_verified(self):
        report, _ = self.run_main(self.candidate(), self.reference)
        self.assertEqual(report['source'], 'archived_component_composition')
        self.assertFalse(report['new_native_validation_performed'])
        self.assertFalse(report['whole_constellation_STK_verified'])
        self.assertFalse(report['native_verified'])

    def test_missing_library_is_error_no_fallback(self):
        self.rows.pop(28)
        with self.assertRaisesRegex(EvidenceError, 'UNAVAILABLE_FROM_FROZEN_LIBRARY'):
            self.run_main(self.candidate(), self.reference)

    def test_baseline_whole_readback(self):
        whole = {t: [[1., 2.], [5., 6.], [10., 11.]] for t in self.targets}
        result = verify_baseline_whole(self.reference, self.reference_hits, self.reference_hits, whole,
                                       self.targets, duration=20)
        self.assertEqual(result['status'], 'PASS')
        whole['c'][1][0] += 1.
        self.assertEqual(verify_baseline_whole(self.reference, self.reference_hits, self.reference_hits,
                                              whole, self.targets, duration=20)['status'], 'FAIL')

    def test_baseline_whole_point_forgery_rejected(self):
        whole = {t: [[1., 2.], [5., 6.], [10., 11.]] for t in self.targets}
        hits = self.reference_hits.copy(); hits[0] += 1e-4
        self.assertEqual(verify_baseline_whole(self.reference, self.reference_hits, hits, whole,
                                              self.targets, duration=20)['status'], 'FAIL')

    def test_incomplete_enumeration_cannot_complete(self):
        declared = science.neighborhood(self.baseline, self.donors, self.states)
        result = science.summarize_completion(declared, [], [])
        self.assertFalse(result['completed'])
        self.assertEqual(result['optimization_outcome'], 'PARTIAL_NOT_CONCLUDED')
        report, hits = self.run_main(declared[0]['indices'], self.reference)
        report.update(remove=declared[0]['remove'], add=declared[0]['add'])
        check = self.checker().verify(declared[0]['indices'], report, hits, self.reference)
        self.assertFalse(science.summarize_completion(declared[:1], [report], [check])['completed'])

    def test_full_no_improvement_is_complete_research(self):
        declared = science.neighborhood(self.baseline, self.donors, self.states)
        checker = self.checker(); reports, checks = [], []
        self.assertEqual(checker.verify(self.baseline, self.reference, self.reference_hits)['status'], 'PASS')
        for item in declared:
            report, hits = self.run_main(item['indices'], self.reference)
            report.update(remove=item['remove'], add=item['add'])
            reports.append(report)
            checks.append(checker.verify(item['indices'], report, hits, self.reference,
                                         remove=item['remove'], add=item['add']))
        result = science.summarize_completion(declared, reports, checks)
        self.assertTrue(result['completed'])
        self.assertEqual(result['optimization_outcome'], 'NO_FEASIBLE_IMPROVEMENT_IN_DECLARED_NEIGHBORHOOD')
        self.assertIsNone(science.select(reports))
        self.assertIsNone(checker.selection([r['identity'] for r in reports])['selected_identity'])
        terminal = checker.verify_completion(self.donors, declared, reports, checks)
        self.assertEqual(terminal['status'], 'PASS')
        self.assertEqual(terminal_verification(declared, reports, checks, None, point_count=4)['status'], 'PASS')
        self.assertEqual(terminal_verification(declared, reports, checks, None)['status'], 'FAIL')
        altered = copy.deepcopy(checks); altered[0]['main_output_sha256'] = 'forged'
        self.assertEqual(terminal_verification(declared, reports, altered, None, point_count=4)['status'], 'FAIL')
        altered = copy.deepcopy(reports); altered[0]['remove'], altered[1]['remove'] = altered[1]['remove'], altered[0]['remove']
        # Both first records share a remove; alter across two remove groups.
        altered[0]['remove'] = 1
        self.assertEqual(terminal_verification(declared, altered, checks, None, point_count=4)['status'], 'FAIL')
        altered = copy.deepcopy(checks); altered[0]['classification_difference_count'] = 1
        self.assertEqual(terminal_verification(declared, reports, altered, None, point_count=4)['status'], 'FAIL')
        self.assertEqual(checker.verify_completion(self.donors, declared[:-1], reports, checks)['status'], 'FAIL')
        self.assertEqual(checker.verify_completion(self.donors, declared, reports, checks,
                                                  reported_selected_identity='forged')['status'], 'FAIL')
        self.assertFalse(science.summarize_completion(declared, reports[:-1]+[reports[0]], checks)['completed'])

    def test_deterministic_unique_selection_matches_checker(self):
        for i in (28, 29):
            for target in self.targets:
                self.intervals[i][target] = [[3, 4], [7, 9]]
        checker = self.checker(); reports = []
        for donor in (28, 29):
            indices = self.candidate(donor)
            report, hits = self.run_main(indices, self.reference)
            self.assertEqual(checker.verify(indices, report, hits, self.reference)['status'], 'PASS')
            reports.append(report)
        self.assertEqual(science.select(reports)['identity'], min(r['identity'] for r in reports))
        self.assertEqual(science.select(reports)['identity'], checker.selection()['selected_identity'])

    def test_checker_has_no_main_algorithm_import(self):
        tree = ast.parse(Path(__file__).resolve().parents[1].joinpath('src/round14/checker.py').read_text(encoding='utf8'))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.assertNotIn('science', ast.unparse(node))


if __name__ == '__main__':
    unittest.main()
