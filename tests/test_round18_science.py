"""Synthetic tests for the remaining-four-anchor scope and exact gates."""
import copy
import itertools
from types import SimpleNamespace
import unittest

import numpy as np

from src.round13.common import EvidenceError, fingerprint
from src.round14.science import feasibility, regional
from src.round18 import science


def fixture():
    baseline = list(range(27))+[1284]
    donors = sorted(set(range(2171))-set(baseline))
    states = {i:'synthetic-r18-state-'+str(i) for i in range(2171)}
    late = np.full(10,30.,dtype=np.float64)
    rows = {i:late for i in range(2171)}
    rows[0] = np.array([10.]*8+[30.,20.])
    rows[1284] = np.array([10.]*9+[30.])
    for pivot in science.ANCHOR_DONORS:
        rows[pivot] = np.array([10.]*8+[20.,30.])
    rows[218] = np.array([10.]*8+[20.,20.])
    rows[27] = np.array([30.]*9+[np.inf])
    rows[29] = np.array([30.]*9+[20.])
    rows[30] = np.array([30.]*8+[10.,20.])
    targets = ['A','B','C']
    intervals = {i:{t:[] for t in targets} for i in range(2171)}
    for i in baseline:
        intervals[i] = {t:[[0.,1.],[2.,3.]] for t in targets}
    lib = SimpleNamespace(baseline_indices=baseline, donor_indices=donors, states=states,
        rows=rows, intervals=intervals, targets=targets, keep=np.ones(10,dtype=np.bool_),
        coords=np.column_stack([np.arange(10,dtype=float),np.zeros(10)]),
        evidence={'matrix':{'sha256':'synthetic-r18-matrix'}})
    reference,hits = science.evaluate(baseline,rows,intervals,lib.keep,targets,states)
    return lib,reference,hits


def candidate(lib, remove, a, b):
    pair = sorted([a,b])
    pivot = min(set(pair) & science.ANCHOR_DONORS)
    indices = sorted((set(lib.baseline_indices)-{1284,remove})|set(pair))
    return dict(ordinal=0,fixed_remove=1284,remove=remove,pivot=pivot,
        add=next(i for i in pair if i != pivot),remove_pair=sorted([1284,remove]),
        add_pair=pair,indices=indices,identity=fingerprint(sorted(lib.states[i] for i in indices)))


class SpaceTests(unittest.TestCase):
    def test_unordered_pairs_are_lexicographic_and_two_anchor_pairs_unique(self):
        lib,_,_=fixture()
        actual = list(science.iter_add_pairs(lib.donor_indices))
        independent = sorted({tuple(sorted([p,d])) for p in science.ANCHOR_DONORS
            for d in lib.donor_indices if d not in {705,p}})
        self.assertEqual(actual,independent)
        self.assertEqual(len(actual),8558)
        self.assertEqual(sum(a in science.ANCHOR_DONORS and b in science.ANCHOR_DONORS for a,b in actual),6)
        self.assertTrue(all(705 not in pair for pair in actual))

    def test_full_synthetic_space_has_expected_pivots_and_no_r17_intersection(self):
        lib,_,_=fixture()
        counts = {p:0 for p in science.ANCHOR_DONORS}
        operations,ids = set(),set()
        prior = None
        for item in science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states):
            operation = (item['remove'],*item['add_pair'])
            self.assertTrue(prior is None or prior < operation)
            prior = operation
            operations.add(operation);ids.add(item['identity']);counts[item['pivot']]+=1
        self.assertEqual((len(operations),len(ids)),(231066,231066))
        self.assertEqual(counts,{28:57807,218:57780,1801:57753,2021:57726})
        old_operations = {(r,*sorted([705,d])) for r in lib.baseline_indices if r != 1284
            for d in lib.donor_indices if d != 705}
        self.assertFalse(operations & old_operations)
        self.assertEqual(len(operations | old_operations),288900)

    def test_missing_pool_member_and_duplicate_state_raise_instead_of_shrinking(self):
        lib,_,_=fixture()
        with self.assertRaisesRegex(EvidenceError,'R18_DONOR_POOL'):
            next(science.iter_candidates(lib.baseline_indices,lib.donor_indices[:-1],lib.states))
        lib.states[27]=lib.states[28]
        with self.assertRaisesRegex(EvidenceError,'R18_DUPLICATE_STATE'):
            next(science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states))

    def test_shared_deadline_stops_at_verified_enumeration_chunk_boundary(self):
        lib,_,_=fixture();calls=[];seen=[]
        def check():
            calls.append(1)
            if len(calls)==2:
                raise TimeoutError('synthetic shared deadline')
        with self.assertRaises(TimeoutError):
            for item in science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states,check):
                seen.append(item)
        self.assertEqual([r['ordinal'] for r in seen],list(range(512)))


class ThresholdTests(unittest.TestCase):
    def test_priority_and_null_full_metrics_for_both_negative_certificates(self):
        lib,reference,_=fixture();gate=science.ThresholdGate(lib,reference)
        results=[gate.classify(candidate(lib,0,28,d)) for d in [27,29,30]]
        self.assertEqual([p for p,_ in results],['T100','T90','FULL'])
        for _,cert in results[:2]:
            self.assertFalse(cert['full_feasibility_evaluation_performed'])
            self.assertTrue(cert['known_infeasible'])
            self.assertEqual(cert['metrics_status'],'NOT_EVALUATED')
            self.assertTrue(all(cert[k] is None for k in ['full_grid','effective_grid','regional','feasibility',
                'T90_s','T100_s','Tavg_s','Tmax_s']))
        cert=results[0][1]
        self.assertEqual((cert['point_id'],len(cert['source_values'])),(9,28))
        self.assertEqual({v['classification'] for v in cert['source_values']},{'FINITE_LATE','NO_FIRST_HIT'})
        self.assertIsNone(next(v for v in cert['source_values'] if v['classification']=='NO_FIRST_HIT')['first_hit_s'])
        self.assertIsNone(results[2][1])

    def test_pivot_cache_swap_and_input_binding_change_are_detected(self):
        lib,reference,_=fixture();gate=science.ThresholdGate(lib,reference)
        item=candidate(lib,0,28,27)
        self.assertEqual(gate.exclusive[28,0].tolist(),[9])
        self.assertEqual(gate.exclusive[218,0].tolist(),[])
        gate.exclusive[28,0]=gate.exclusive[218,0]
        with self.assertRaisesRegex(EvidenceError,'R18_EXCLUSIVE_CACHE_BINDING'):
            gate.classify(item)
        other=science.ThresholdGate(lib,reference)
        before=other.binding(item)
        other.row_digests[27]='changed'
        self.assertNotEqual(before,other.binding(item))

    def test_noncanonical_pivot_and_excluded_705_cannot_enter_gate(self):
        lib,reference,_=fixture();gate=science.ThresholdGate(lib,reference)
        item=candidate(lib,0,28,218);self.assertEqual(item['pivot'],28)
        item['pivot'],item['add']=218,28
        with self.assertRaisesRegex(EvidenceError,'R18_GATE_CANONICAL_PIVOT'):
            gate.classify(item)
        with self.assertRaisesRegex(EvidenceError,'R18_GATE_OPERATION_SCOPE'):
            gate.classify(candidate(lib,0,28,705))

    def test_original_reference_is_required_and_deadline_is_inclusive(self):
        lib,reference,_=fixture()
        changed=copy.deepcopy(reference);changed['identity']='anchor-cannot-be-reference'
        with self.assertRaisesRegex(EvidenceError,'R18_ORIGINAL_BASELINE_REFERENCE_REQUIRED'):
            science.ThresholdGate(lib,changed)
        self.assertEqual(science.count_on_time_bits(science.pack_on_time(np.array([10.,10.+1e-8,np.inf]),10.),0,3),1)
        values=np.full(43070,20.);values[:38762]=10.
        self.assertEqual(science.pack_on_time(values,10.).bit_count(),38762)
        values[38762]=10.
        self.assertEqual(science.pack_on_time(values,10.).bit_count(),38763)

    def test_padding_and_invalid_first_hits_fail(self):
        with self.assertRaisesRegex(EvidenceError,'R18_NONZERO_PADDING'):
            science.count_on_time_bits(1<<43070,0,43070)
        for value in [np.nan,-np.inf,-1.,604801.]:
            with self.assertRaises(EvidenceError):
                science.pack_on_time(np.array([value]),10.)

    def test_gate_evidence_binds_all_four_pivots_and_both_deadlines(self):
        lib,reference,_=fixture();gate=science.ThresholdGate(lib,reference);data=gate.evidence()
        self.assertEqual(set(data['exclusive_points']),{'28','218','1801','2021'})
        self.assertTrue(all(len(v)==27 for v in data['exclusive_points'].values()))
        self.assertEqual(data['priority'],['T100_BASELINE_DEADLINE','T90_ON_TIME_COUNT','FULL'])
        self.assertEqual(data['bitset_effective_bits'],10)
        self.assertEqual(data['bitset_padding_bits'],6)
        self.assertFalse(data['second_donor_bridge_required'])


class ActualGapMeanTests(unittest.TestCase):
    def test_actual_gap_denominator_changes_when_an_additional_visit_splits_gap(self):
        targets=['A','B','C']
        original=regional({t:[[0.,10.],[30.,40.],[80.,90.]] for t in targets},targets)
        split=regional({t:[[0.,10.],[30.,40.],[50.,60.],[80.,90.]] for t in targets},targets)
        self.assertEqual(original['pooled_internal']['gap_count'],6)
        self.assertEqual(split['pooled_internal']['gap_count'],9)
        self.assertAlmostEqual(split['pooled_internal']['mean_s'],150./9)

    def test_real_r17_mean_excess_is_rejected_despite_substantial_tmax_improvement(self):
        lib,reference,_=fixture()
        report=copy.deepcopy(reference)
        reference['regional']['pooled_internal']['mean_s']=9413.983168107334
        report['regional']['pooled_internal']['mean_s']=9414.080072585104
        report['regional']['pooled_internal']['max_s']=132051.28738869302
        decision=feasibility(report,reference)
        self.assertFalse(decision['feasible'])
        self.assertIn('Tavg_s_WORSE_THAN_BASELINE',decision['rejection_reasons'])


if __name__ == '__main__':
    unittest.main()
