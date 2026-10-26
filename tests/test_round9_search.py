import unittest
import numpy as np
from src.round9.search import interpolate,synthetic,conservative_decision

class Round9SearchTests(unittest.TestCase):
    def test_independent_lagrange_nonuniform_exact_cubic(self):
        t=np.array([0.,.371,2.,5.]);v=np.column_stack([t**3,t*t,3*t]);q=np.array([.1,1.,3.,4.9])
        actual,_,_=interpolate(t,v,q);np.testing.assert_allclose(actual,np.column_stack([q**3,q*q,3*q]),rtol=0,atol=1e-10)

    def test_unknown_bound_never_discards(self):
        self.assertEqual(conservative_decision([-1]*5)['action'],'KEEP_CANDIDATE')

    def test_invalid_input_stops_certification(self):
        self.assertEqual(conservative_decision(None,valid=False)['action'],'UNRESOLVED')
        with self.assertRaisesRegex(ValueError,'UNRESOLVED'):interpolate([0,1,1,2],np.ones((4,3)),[.5])

    def test_proven_negative_margin_can_reject_conditionally(self):
        self.assertEqual(conservative_decision([-1]*5,[.1]*5)['action'],'REJECT_UNDER_BOUND_ASSUMPTIONS')

    def test_uncertain_root_or_horizon_kept(self):
        self.assertEqual(conservative_decision([-1]*5,[.1]*5,boundary_uncertain=True)['action'],'KEEP_CANDIDATE')

    def test_all_constructed_cases_keep_physics_and_proxy_claims_separate(self):
        result=synthetic();self.assertEqual(result['status'],'PASS',result)
        hidden=next(x for x in result['cases'] if x['case']=='unsampled_quartic_bump')
        self.assertEqual(hidden['classification'],'COUNTEREXAMPLE_FOUND')
        self.assertFalse(hidden['detail']['violates_existing_qualified_guarantee'])

    def test_no_extrapolation_outside_frozen_window(self):
        with self.assertRaisesRegex(ValueError,'UNRESOLVED_TARGET'):interpolate([0,1,2,3],np.ones((4,3)),[-1])
