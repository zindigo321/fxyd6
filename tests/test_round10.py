"""Pipeline boundaries with meaningful source corruption and cost counterexamples."""
import copy
import tempfile
import unittest
from pathlib import Path
import numpy as np
from src.round10 import cases
from src.round10.bounds import analytic_certificate, decide
from src.round10.ledger import union, measure, validate_coverage, windows_from_ranges, validate_windows
from src.round10.prototype import trajectory_arrays, process_cell, select, project_screening
from src.round10.retention import require_full_retention, statistics, independent_cost_review
from src.round10.binding import transition


class Round10Tests(unittest.TestCase):
    def test_targeted_counterexamples(self):
        with tempfile.TemporaryDirectory() as d:
            result=cases.run(Path(d))
        self.assertEqual(result['status'],'PASS',[(r['case'],r.get('actual_reason')) for r in result['counterexamples'] if r['status']!='PASS'])
        self.assertGreaterEqual(result['counterexample_count'],23)
        self.assertGreaterEqual(result['numerical_fixture_count'],11)

    def test_real_cell_pipeline_without_bound_retains(self):
        t,r,b=trajectory_arrays(cases.fixture_data(),3,5.)
        result=process_cell(t,r,b,np.array([1.,2.,600.]),1,.001622,1.62,.05,1e-9)
        self.assertEqual(result['decision'],'KEEP');self.assertTrue(result['missing_bound_terms'])
        self.assertFalse(result['old_horizon_gate_applied_after_fallback'])

    def test_shape_damage_propagates(self):
        d=cases.fixture_data();d['bases_screening']=[]
        with self.assertRaisesRegex(ValueError,'TRAJECTORY_SHAPE_UNRESOLVED'):trajectory_arrays(d,3,5.)

    def test_nonfinite_propagates(self):
        d=cases.fixture_data();d['positions_fixed_km'][0][0]=float('inf')
        with self.assertRaisesRegex(ValueError,'TRAJECTORY_NONFINITE_UNRESOLVED'):trajectory_arrays(d,3,5.)

    def test_duplicate_time_propagates(self):
        d=cases.fixture_data();d['times_epsec']=[0,5,5,15]
        with self.assertRaisesRegex(ValueError,'TRAJECTORY_TIME_UNRESOLVED'):trajectory_arrays(d,3,5.)

    def test_unordered_time_propagates(self):
        d=cases.fixture_data();d['times_epsec']=[0,10,5,15]
        with self.assertRaisesRegex(ValueError,'TRAJECTORY_TIME_UNRESOLVED'):trajectory_arrays(d,3,5.)

    def test_bad_basis_propagates(self):
        d=cases.fixture_data();d['bases_screening'][0][0][0]=4
        with self.assertRaisesRegex(ValueError,'TRAJECTORY_BASIS_UNRESOLVED'):trajectory_arrays(d,3,5.)

    def test_margin_does_not_cover_boresight(self):
        result=decide([[0.,0.,0.,0.]]*5,[0,1])
        self.assertEqual(result['padded_upper_km'],[.05,.05,.05,.05,0.])

    def test_analytic_certificate_does_not_certify_real(self):
        c=analytic_certificate()
        with self.assertRaisesRegex(ValueError,'FIXTURE_BOUND_USED_ON_REAL_DATA'):decide(c['polynomial'],[0,1],certificate=c)

    def test_horizon_fallback_survives_window_generation(self):
        c=analytic_certificate();d=decide(c['polynomial'],[0,1],certificate=c,real_data=False,boresight_known=True)
        p=dict(sat_id='s',point_id='p',ranges=[dict(first=0,stop=1,state='PROCESSED',decision=d['decision'],reason=d['reason'],decision_id='d')])
        self.assertEqual(windows_from_ranges(p,1,1,0,0)[0]['interval_s'],[0,1])

    def test_tangent_no_false_rejection(self):
        self.assertEqual(decide([[.25,-1,1,0]]*5,[0,1])['decision'],'KEEP')

    def test_near_double_root_no_false_rejection(self):
        self.assertEqual(decide([[.25-1e-14,-1,1,0]]*5,[0,1])['decision'],'KEEP')

    def test_endpoint_and_short_window(self):
        self.assertEqual(union([[0,1e-10],[1,1]],1),[[0,1e-10],[1,1]])

    def test_touch_merge(self):
        self.assertEqual(union([[0,1],[1,2],[.2,.5]],3),[[0,2]])

    def test_padding_clips(self):
        self.assertEqual(union([[0,.1],[9.9,10]],10,.2),[[0,.30000000000000004],[9.700000000000001,10]])

    def test_cost_counts_both_pairs(self):
        self.assertEqual(measure({('s','p'):[[0,10]],('t','p'):[[0,10]]},10)['union_pair_seconds'],20)

    def test_unknown_partition_complete(self):
        p=cases.fixture_pair();r=validate_coverage([p],[('s','p')],3,5)
        self.assertEqual((r['processed_cells'],r['unknown_cells']),(1,2))

    def test_missing_unknown_fails(self):
        p=cases.fixture_pair();p['ranges'].pop()
        with self.assertRaisesRegex(ValueError,'COVERAGE_GAP_OVERLAP_OR_RANGE'):validate_coverage([p],[('s','p')],3,5)

    def test_missing_pair_fails(self):
        with self.assertRaisesRegex(ValueError,'COVERAGE_PAIR_INVENTORY'):validate_coverage([], [('s','p')],3,5)

    def test_unqueried_count_null(self):
        p=cases.fixture_pair();w=windows_from_ranges(p,5,15,.05,0);w[0]['event_count']=0
        with self.assertRaisesRegex(ValueError,'UNQUERIED_EVENT_COUNT_NOT_NULL'):validate_windows(w,[p],5,15,.05,0)

    def test_full_interval_not_midpoint(self):
        e=[dict(record_id='e',sat_id='s',point_id='p',start_epsec=0,stop_epsec=1)]
        w=[dict(window_id='w',sat_id='s',point_id='p',interval_s=[.4,.6])]
        self.assertFalse(require_full_retention(e,w)[0]['strict_containment'])

    def test_tolerance_does_not_hide_strict_loss(self):
        e=[dict(record_id='e',sat_id='s',point_id='p',start_epsec=0,stop_epsec=1)]
        w=[dict(window_id='w',sat_id='s',point_id='p',interval_s=[1e-6,1])]
        row=require_full_retention(e,w)[0];self.assertFalse(row['strict_containment']);self.assertTrue(row['tolerance_containment'])

    def test_code_transition_does_not_normalize(self):
        self.assertEqual(transition({'x.json':b'{}\r\n'},{'x.json':b'{}\n'})['errors'],['K9_RAW_BYTES_CHANGED'])

    def test_statistics_zero_and_once_kept(self):
        raw=[dict(record_id='e',sat_id='s',point_id='p',start_epsec=2,stop_epsec=3)]
        s=statistics(raw,[dict(point_id='p'),dict(point_id='q')],dict(duration_s=10,round7=dict(original_seven=[])),[])
        self.assertEqual(s['insufficient_points'],2);self.assertEqual(s['point_denominator'],2)
        self.assertIsNone(s['internal_mean_s']);self.assertEqual(s['edge_inclusive_denominator'],3)

    def test_old_reasons_selection_not_events(self):
        pair=dict(candidates=[],cell_dispositions=dict(along_enclosure_rejected=120960))
        a=select(pair,120960,1e-9);pair['events']=[123456]
        self.assertEqual(a,select(pair,120960,1e-9))

    def test_invalid_polynomial_stops(self):
        with self.assertRaisesRegex(ValueError,'INVALID_POLYNOMIAL'):decide([[float('nan')]*4]*5,[0,1])

    def test_independent_cost_rejects_cross_pair_underestimate(self):
        groups={('s','p'):[[0,1],[.5,2]],('t','p'):[[0,2]]};expected=measure(groups,3)
        self.assertEqual(independent_cost_review(groups,3,0,expected)['union_pair_seconds'],4)
        expected['union_pair_seconds']=2
        with self.assertRaisesRegex(ValueError,'INDEPENDENT_COST_TOTAL_MISMATCH'):independent_cost_review(groups,3,0,expected)
