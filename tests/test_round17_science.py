"""Synthetic R17 exact-space, necessary-gate and independent-checker cases."""
import copy
import hashlib
import itertools
from types import SimpleNamespace
import unittest

import numpy as np

from src.round13.common import EvidenceError, fingerprint
from src.round17 import science, checker


def fixture():
    baseline = list(range(27))+[1284]
    donors = sorted(set(range(2171))-set(baseline))
    states = {i:'synthetic-state-'+str(i) for i in range(2171)}
    late = np.full(10,30.,dtype=np.float64)
    rows = {i:late for i in range(2171)}
    rows[0] = np.array([10.]*8+[30.,20.])
    rows[1284] = np.array([10.]*9+[30.])
    rows[705] = np.array([10.]*8+[20.,30.])
    rows[27] = np.array([30.]*9+[np.inf])
    rows[28] = np.array([30.]*9+[20.])
    rows[29] = np.array([30.]*8+[10.,20.])
    targets = ['A','B','C']
    intervals = {i:{target:[] for target in targets} for i in range(2171)}
    for i in baseline:
        intervals[i] = {target:[[0.,1.],[2.,3.]] for target in targets}
    lib = SimpleNamespace(baseline_indices=baseline,donor_indices=donors,states=states,
        rows=rows,intervals=intervals,targets=targets,keep=np.ones(10,dtype=np.bool_),
        coords=np.column_stack([np.arange(10,dtype=float),np.zeros(10)]),
        evidence={'matrix':{'sha256':'synthetic-matrix-sha'}})
    baseline_report,hits = science.evaluate(baseline,rows,intervals,lib.keep,targets,states)
    items = list(itertools.islice(science.iter_candidates(baseline,donors,states),3))
    return lib, baseline_report, hits, items


class SpaceTests(unittest.TestCase):
    def test_exact_57834_space_and_two_operations_match_independent_order(self):
        lib,_,_,_=fixture()
        main=science.neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states)
        independent=checker.neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states)
        for key in ['declared_candidates','unique_identities','identity_order_sha256','pair_order_sha256']:
            self.assertEqual(main[key],independent[key])
        self.assertEqual(main['declared_candidates'],57834)
        for item in [main['first'],main['last']]:
            self.assertEqual(len(item['indices']),28)
            self.assertIn(705,item['indices']); self.assertNotIn(1284,item['indices'])
            self.assertNotEqual(item['remove'],705); self.assertNotIn(item['add'],lib.baseline_indices)
            self.assertEqual(set(item['remove_pair']),{1284,item['remove']})
            self.assertEqual(set(item['add_pair']),{705,item['add']})

    def test_missing_donor_and_duplicate_state_do_not_shrink_search(self):
        lib,_,_,_=fixture()
        with self.assertRaisesRegex(EvidenceError,'R17_DONOR_POOL'):
            next(science.iter_candidates(lib.baseline_indices,lib.donor_indices[:-1],lib.states))
        lib.states[27]=lib.states[28]
        with self.assertRaisesRegex(EvidenceError,'R17_DUPLICATE_STATE'):
            next(science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states))

    def test_shared_deadline_preserves_a_real_enumeration_prefix(self):
        lib,_,_,_=fixture(); calls=[]; seen=[]
        def check():
            calls.append(1)
            if len(calls)==2:raise TimeoutError('shared synthetic cutoff')
        with self.assertRaises(TimeoutError):
            for item in science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states,check):seen.append(item)
        self.assertEqual([item['ordinal'] for item in seen],list(range(512)))


class AnchorAndThresholdTests(unittest.TestCase):
    def test_63_point_shortfall_uses_original_baseline_deadline_count(self):
        baseline={'identity':'original','effective_grid':{'points':43070,'T90_s':100.,'T100_s':200.}}
        shortfalls={705:63,28:78,1801:82,2021:91,218:98}
        replays=[dict(add=add,identity=str(add),on_time_count=38763-loss,T90_s=101.+add/10000.) for add,loss in shortfalls.items()]
        result=science.select_anchor(replays,baseline)
        self.assertEqual((result['selected_add'],result['k90']),(705,38763))
        self.assertEqual([row['shortfall_points'] for row in result['ranked']],[63,78,82,91,98])
        self.assertFalse(result['anchor_is_admissible_reference'])

    def test_anchor_t90_does_not_replace_original_reference(self):
        lib,baseline,_,items=fixture();gate=science.ThresholdGate(lib,baseline)
        anchor=sorted((set(lib.baseline_indices)-{1284})|{705})
        anchor_report,_=science.evaluate(anchor,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
        self.assertFalse(anchor_report['feasibility']['feasible'])
        self.assertEqual(gate.tau90,baseline['effective_grid']['T90_s']+1e-6)
        self.assertLess(gate.tau90,anchor_report['effective_grid']['T90_s'])
        self.assertEqual(gate.classify(items[1])[0],'T90')

    def test_t100_exclusive_point_accounts_for_second_removal_loss(self):
        lib,baseline,_,items=fixture();gate=science.ThresholdGate(lib,baseline)
        self.assertEqual(gate.exclusive[0].tolist(),[9])
        part,certificate=gate.classify(items[0])
        self.assertEqual((part,certificate['point_id']),('T100',9))
        self.assertEqual(len(certificate['source_values']),28)
        classes={value['classification'] for value in certificate['source_values']}
        self.assertEqual(classes,{'FINITE_LATE','NO_FIRST_HIT'})
        nohit=next(value for value in certificate['source_values'] if value['classification']=='NO_FIRST_HIT')
        self.assertIsNone(nohit['first_hit_s'])
        own=checker.IndependentChecker(lib)
        self.assertEqual(own.verify_certificate(items[0],certificate)['status'],'PASS')
        changed=copy.deepcopy(certificate);changed['source_values'][0]['first_hit_s']=0.
        self.assertEqual(own.verify_certificate(items[0],changed)['status'],'FAIL')

    def test_priority_and_partial_certificate_semantics(self):
        lib,baseline,_,items=fixture();gate=science.ThresholdGate(lib,baseline)
        parts=[gate.classify(item) for item in items]
        self.assertEqual([part for part,_ in parts],['T100','T90','FULL'])
        for _,certificate in parts[:2]:
            self.assertFalse(certificate['full_feasibility_evaluation_performed'])
            self.assertEqual(certificate['metrics_status'],'NOT_EVALUATED')
            self.assertTrue(all(certificate[key] is None for key in
                ['full_grid','effective_grid','regional','feasibility','T90_s','T100_s','Tavg_s','Tmax_s']))
        self.assertIsNone(parts[2][1])

    def test_38762_38763_boundary_and_exact_deadline_inclusion(self):
        keep=np.ones(43070,dtype=np.bool_); values=np.full(43070,20.)
        values[:38762]=10.; rows={0:values}
        classification=checker.boolean_on_time(rows,[0],keep,10.)
        result=checker.verify_t90_count(rows,[0],keep,10.,38763,38762,checker.classification_digest(classification))
        self.assertEqual(result['status'],'PASS')
        values[38762]=10.
        classification=checker.boolean_on_time(rows,[0],keep,10.)
        result=checker.verify_t90_count(rows,[0],keep,10.,38763,38763,checker.classification_digest(classification))
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(science.count_on_time_bits(science.pack_on_time(np.array([10.,10.+1e-8,np.inf]),10.),0,3),1)

    def test_nonzero_bitset_padding_and_invalid_hits_are_errors(self):
        with self.assertRaisesRegex(EvidenceError,'R17_NONZERO_PADDING'):
            science.count_on_time_bits(1<<10,0,10)
        for value in [np.nan,-np.inf,-1.,604801.]:
            with self.assertRaises(EvidenceError):science.pack_on_time(np.array([value]),10.)

    def test_independent_boolean_rejects_wrong_main_count_or_digest(self):
        lib,baseline,_,items=fixture();gate=science.ThresholdGate(lib,baseline);own=checker.IndependentChecker(lib)
        _,certificate=gate.classify(items[1]);self.assertEqual(own.verify_certificate(items[1],certificate)['status'],'PASS')
        changed=copy.deepcopy(certificate);changed['c90']+=1
        self.assertEqual(own.verify_certificate(items[1],changed)['status'],'FAIL')
        changed=copy.deepcopy(certificate);changed['classification_sha256']='0'*64
        self.assertEqual(own.verify_certificate(items[1],changed)['status'],'FAIL')
        gate.bits90[items[2]['add']]=0
        self.assertEqual(gate.classify(items[2])[0],'T90')
        self.assertEqual(own.partition(items[2]),'FULL')

    def test_nonbridge_second_donor_can_pass_both_necessary_gates(self):
        lib,baseline,_,items=fixture()
        self.assertTrue(all(not spans for spans in lib.intervals[items[2]['add']].values()))
        gate=science.ThresholdGate(lib,baseline)
        self.assertEqual(gate.classify(items[2]),('FULL',None))
        self.assertFalse(gate.evidence()['second_donor_bridge_required'])


class CompleteNumericalTests(unittest.TestCase):
    def test_full_numeric_checker_compares_all_points_and_interval_endpoints(self):
        lib,baseline,_,items=fixture();item=items[2];own=checker.IndependentChecker(lib)
        report,values=science.evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
        report.update({key:item[key] for key in item if key!='identity' and key!='indices'});report['partition']='FULL'
        checked=own.verify(item['indices'],report,values,baseline,item['remove'],item['add'])
        self.assertEqual((checked['status'],checked['points_compared']),('PASS',10))
        changed=values.copy();changed[-1]+=1
        self.assertEqual(own.verify(item['indices'],report,changed,baseline,item['remove'],item['add'])['status'],'FAIL')
        changed_report=copy.deepcopy(report);changed_report['regional']['targets']['A']['merged_intervals'][0][1]+=.1
        self.assertEqual(own.verify(item['indices'],changed_report,values,baseline,item['remove'],item['add'])['status'],'FAIL')


if __name__ == '__main__':unittest.main()
