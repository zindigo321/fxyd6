"""Finite two-swap/proof risks using synthetic inputs, never native execution."""
import copy
import hashlib
from types import SimpleNamespace
import unittest

import numpy as np

from src.round13.common import EvidenceError, fingerprint
from src.round15.science import (TARGET, L_EXPECTED, R_EXPECTED, INTERIOR_INTERVAL,
    iter_candidates, neighborhood_summary, prove_gap, classify, certificate_record,
    evaluate, raw_domain_diagnostic)


def fixture():
    baseline = sorted([911, 1370]+list(range(100, 126)))
    donors = sorted([1123]+list(range(200, 231)))
    states = {i: 'frozen-state-'+str(i) for i in baseline+donors}
    targets = ['main', 'island_1', TARGET]
    intervals = {i: {t: [[0., 10.], [20., 30.]] if t != TARGET else [] for t in targets}
                 for i in states}
    intervals[911][TARGET] = [[1000., L_EXPECTED]]
    intervals[1370][TARGET] = [[2000., L_EXPECTED-10.]]
    for offset, index in enumerate(range(100, 106)):
        intervals[index][TARGET] = [[R_EXPECTED+100.*offset, R_EXPECTED+100.*offset+10.]]
    intervals[1123][TARGET] = [INTERIOR_INTERVAL.copy()]
    rows = {i: np.array([0., 1., 2., 3.]) for i in states}
    assets = {i: dict(state=states[i], regional_data_sha256=fingerprint(intervals[i])) for i in states}
    lib = SimpleNamespace(baseline_indices=baseline, donor_indices=donors, states=states,
                          intervals=intervals, targets=targets, rows=rows, assets=assets,
                          keep=np.ones(4, dtype=bool))
    report, hits = evaluate(baseline, rows, intervals, lib.keep, targets, states)
    return lib, report, hits


class DoubleSwapEnumerationTests(unittest.TestCase):
    def test_exact_complete_cartesian_and_certificate_partition(self):
        lib, baseline, _ = fixture()
        proof = prove_gap(lib, baseline)
        identities, pairs, counts = set(), set(), {'A': 0, 'B': 0, 'C': 0}
        previous, count = None, 0
        for item in iter_candidates(lib.baseline_indices, lib.donor_indices, lib.states):
            key = (tuple(item['remove']), tuple(item['add']))
            self.assertTrue(previous is None or previous < key)
            self.assertEqual(item['ordinal'], count)
            self.assertEqual(len(item['indices']), 28)
            self.assertEqual(set(lib.baseline_indices)-set(item['indices']), set(item['remove']))
            self.assertEqual(set(item['indices'])-set(lib.baseline_indices), set(item['add']))
            identities.add(item['identity']);pairs.add(key);counts[classify(item, proof)] += 1
            count += 1;previous = key
        self.assertEqual(count, 187488)
        self.assertEqual(len(identities), count)
        self.assertEqual(len(pairs), count)
        self.assertEqual(counts, {'A': 11718, 'B': 465, 'C': 175305})

    def test_duplicate_or_baseline_donor_rejected(self):
        lib, _, _ = fixture()
        for donors in [lib.donor_indices[:-1]+[lib.donor_indices[0]],
                       lib.donor_indices[:-1]+[lib.baseline_indices[0]]]:
            with self.assertRaises(EvidenceError):
                next(iter_candidates(lib.baseline_indices, donors, lib.states))

    def test_equivalent_state_collision_rejected(self):
        lib, _, _ = fixture();lib.states[lib.donor_indices[0]] = lib.states[lib.baseline_indices[0]]
        with self.assertRaisesRegex(EvidenceError, 'DUPLICATE_STATE'):
            next(iter_candidates(lib.baseline_indices, lib.donor_indices, lib.states))

    def test_streaming_deadline_preserves_exact_prefix(self):
        lib, _, _ = fixture();calls = [0];prefix = []
        def check():
            calls[0] += 1
            if calls[0] > 1:raise TimeoutError('deadline')
        with self.assertRaises(TimeoutError):
            for item in iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states,check):prefix.append(item['ordinal'])
        self.assertEqual(prefix,list(range(1024)))


class GapProofTests(unittest.TestCase):
    def setUp(self):
        self.lib,self.baseline,self.hits=fixture()

    def proof(self):return prove_gap(self.lib,self.baseline)

    def candidate(self,remove,add):
        indices=sorted((set(self.lib.baseline_indices)-set(remove))|set(add))
        return dict(remove=sorted(remove),add=sorted(add),indices=indices,
                    identity=fingerprint(sorted(self.lib.states[i] for i in indices)),ordinal=0)

    def test_proof_reconstructs_endpoint_ownership_and_input_hashes(self):
        proof=self.proof()
        self.assertEqual(proof['interior_assets'],[1123])
        self.assertEqual(proof['before_baseline_assets'],[911,1370])
        self.assertEqual(proof['after_baseline_assets'],list(range(100,106)))
        self.assertEqual(proof['left_endpoint_owners'],[911])
        self.assertEqual(proof['right_endpoint_owners'],[100])
        self.assertEqual(len(proof['source_payload_sha256']),60)
        self.assertEqual(len(proof['asset_interval_sha256']),60)
        expected={k:v for k,v in proof.items() if k!='proof_sha256'}
        self.assertEqual(proof['proof_sha256'],fingerprint(expected))

    def test_missing_1123_is_missing_evidence_not_empty_access(self):
        del self.lib.intervals[1123]
        with self.assertRaisesRegex(EvidenceError,'MISSING_OR_EXTRA_ASSET'):self.proof()

    def test_1123_state_wrongly_bound_rejects_proof(self):
        self.lib.assets[1123]['state']='wrong-state'
        with self.assertRaisesRegex(EvidenceError,'ASSET_STATE_MISMATCH'):self.proof()

    def test_unknown_extra_gap_access_rejects_proof(self):
        self.lib.intervals[200][TARGET]=[[100000.,100001.]]
        with self.assertRaisesRegex(EvidenceError,'INTERIOR_ASSET_SET'):self.proof()

    def test_cross_gap_interval_rejects_proof(self):
        self.lib.intervals[200][TARGET]=[[L_EXPECTED-1,R_EXPECTED+1]]
        with self.assertRaisesRegex(EvidenceError,'INTERIOR_ASSET_SET'):self.proof()

    def test_zero_duration_internal_visit_rejects_proof(self):
        self.lib.intervals[200][TARGET]=[[L_EXPECTED+1,L_EXPECTED+1]]
        with self.assertRaisesRegex(EvidenceError,'INTERIOR_ASSET_SET'):self.proof()

    def test_endpoint_only_access_does_not_fill_open_gap(self):
        self.lib.intervals[200][TARGET]=[[L_EXPECTED,L_EXPECTED]]
        self.assertEqual(self.proof()['interior_assets'],[1123])

    def test_wrong_1123_interval_rejects_proof(self):
        self.lib.intervals[1123][TARGET][0][1] += 1e-3
        with self.assertRaisesRegex(EvidenceError,'INTERIOR_INTERVAL'):self.proof()

    def test_missing_or_unknown_target_rejects_proof(self):
        del self.lib.intervals[200]['main']
        with self.assertRaisesRegex(EvidenceError,'TARGET_SET'):self.proof()

    def test_candidate_certificate_never_invents_feasibility(self):
        proof=self.proof();item=self.candidate([100,101],[200,201]);row=certificate_record(item,proof)
        self.assertEqual(row['processing_state'],'PROVEN_NO_SUBSTANTIVE_TMAX_IMPROVEMENT')
        self.assertIsNone(row['feasibility'])
        self.assertIsNone(row['full_grid']);self.assertIsNone(row['effective_grid'])
        self.assertIsNone(row['regional']);self.assertIsNone(row['first_hits_sha256'])
        self.assertEqual(row['metrics_status'],'NOT_EVALUATED')
        self.assertEqual(row['Tmax_lower_bound_s'],R_EXPECTED-L_EXPECTED)
        self.assertFalse(row['whole_constellation_STK_verified'])

    def test_contains_1123_cannot_use_gap_certificate(self):
        proof=self.proof();item=self.candidate([100,101],[200,1123])
        self.assertEqual(classify(item,proof),'A')
        with self.assertRaisesRegex(EvidenceError,'EXCEPTION_PARTITION'):certificate_record(item,proof)

    def test_front_pair_exception_can_move_internal_gap_to_leading_window(self):
        proof=self.proof();item=self.candidate([911,1370],[200,201])
        self.assertEqual(classify(item,proof),'B')
        with self.assertRaisesRegex(EvidenceError,'EXCEPTION_PARTITION'):certificate_record(item,proof)
        report,_=evaluate(item['indices'],self.lib.rows,self.lib.intervals,self.lib.keep,
                          self.lib.targets,self.lib.states,self.baseline)
        self.assertLess(report['regional']['pooled_internal']['max_s'],100.)
        self.assertTrue(report['qualified_improvement'])
        self.assertEqual(report['regional']['targets'][TARGET]['boundary_segments'][0],[0.,R_EXPECTED])
        self.assertGreater(report['regional']['targets'][TARGET]['boundary_segments'][0][1],
                           self.baseline['regional']['targets'][TARGET]['boundary_segments'][0][1])
        self.assertEqual(report['regional']['pooled_boundary_inclusive']['max_s'],
                         self.baseline['regional']['pooled_boundary_inclusive']['max_s'])

    def test_forged_candidate_indices_cannot_get_certificate(self):
        item=self.candidate([100,101],[200,201]);item['indices'][0]=999999
        with self.assertRaisesRegex(EvidenceError,'STATE_SET_MISMATCH'):certificate_record(item,self.proof())

    def test_raw_pool_missing_354_ids_are_not_physical_claim(self):
        shape=np.r_[np.zeros(46),np.full(354,np.inf)]
        self.lib.rows={i:shape.copy() for i in self.lib.states}
        result=raw_domain_diagnostic(self.lib,shape)
        self.assertTrue(result['expected_354_set_confirmed'])
        self.assertEqual(result['uncovered_ids_zero_based'],list(range(46,400)))
        self.assertFalse(result['physical_unreachability_claim']);self.assertFalse(result['official_mask_proof'])


if __name__=='__main__':unittest.main()
