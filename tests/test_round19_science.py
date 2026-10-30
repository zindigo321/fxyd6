"""R19 reference, exact-space and certificate-boundary counterexamples."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from src.round13.common import fingerprint
from src.round14.science import regional
from src.round19 import science


class ReferencePolicyTests(unittest.TestCase):
    def setUp(self):
        self.center=dict(identity=science.CENTER_IDENTITY,regional=dict(pooled_internal=dict(max_s=100.)))

    def candidate(self, maximum, feasible=True, mean=10., identity='b'):
        return dict(identity=identity,regional=dict(pooled_internal=dict(max_s=maximum,mean_s=mean)),
            effective_grid=dict(T100_s=500.,T90_s=300.),
            feasibility=dict(feasible=feasible,rejection_reasons=[] if feasible else ['T90_s_WORSE_THAN_BASELINE']),
            improvement=dict(Tmax_reduction_s=200.-maximum,substantive_improvement=True),qualified_improvement=True)

    def test_original_baseline_improvement_is_insufficient(self):
        row=science.annotate(self.candidate(150.),self.center)
        self.assertTrue(row['qualified_improvement'])
        self.assertFalse(row['qualified_for_round19'])
        self.assertIsNone(science.select([row]))
        self.assertEqual(row['improvement_vs_original_baseline']['Tmax_reduction_s'],50.)

    def test_feasibility_stays_with_original_baseline(self):
        row=self.candidate(98.)
        row['effective_grid']['T90_s']=301.
        annotated=science.annotate(row,self.center)
        self.assertTrue(annotated['qualified_for_round19'])
        self.assertEqual(annotated['effective_grid']['T90_s'],301.)

    def test_failure_of_original_constraints_cannot_qualify(self):
        self.assertFalse(science.annotate(self.candidate(90.,feasible=False),self.center)['qualified_for_round19'])

    def test_one_second_and_uncertainty_band(self):
        for delta,expected in [(1.,False),(1.0000005,False),(1.000002,True)]:
            with self.subTest(delta=delta):
                self.assertEqual(science.annotate(self.candidate(100.-delta),self.center)['qualified_for_round19'],expected)

    def test_fixed_center_is_not_updated(self):
        before=deepcopy(self.center)
        first=science.annotate(self.candidate(95.),self.center)
        second=science.annotate(self.candidate(96.),self.center)
        self.assertEqual(self.center,before)
        self.assertTrue(second['qualified_for_round19'])
        self.assertIs(science.select([second,first]),first)

    def test_selection_uses_lexicographic_ties(self):
        rows=[science.annotate(self.candidate(95.,mean=9.,identity='z'),self.center),
              science.annotate(self.candidate(95.,mean=9.,identity='a'),self.center),
              science.annotate(self.candidate(95.,mean=10.,identity='0'),self.center)]
        self.assertEqual(science.select(rows)['identity'],'a')

    def test_wrong_improvement_reference_rejected(self):
        with self.assertRaises(ValueError):
            science.annotate(self.candidate(90.),dict(self.center,identity=science.BASELINE_IDENTITY))

    def test_actual_gap_denominator_is_candidate_specific(self):
        targets=['a','b','c']
        one={t:[[0.,1.],[5.,6.]] for t in targets}
        two=deepcopy(one);two['a'].append([10.,11.])
        r1,r2=regional(one,targets),regional(two,targets)
        self.assertEqual(r1['pooled_internal']['gap_count'],3)
        self.assertEqual(r2['pooled_internal']['gap_count'],4)
        self.assertEqual(r2['pooled_internal']['mean_s'],4.)


class SpaceTests(unittest.TestCase):
    def setUp(self):
        self.states={i:'state-'+str(i) for i in range(2171)}
        self.center=sorted(list(range(26))+[2021,2023])
        self.donors=sorted(set(self.states)-set(self.center))
        self.center_patch=patch.object(science,'CENTER_IDENTITY',fingerprint(sorted(self.states[i] for i in self.center)))
        self.center_patch.start()
        self.addCleanup(self.center_patch.stop)

    def test_full_unique_space_all_deletions_and_symmetric_difference(self):
        summary=science.neighborhood_summary(self.center,self.donors,self.states)
        self.assertEqual(summary['declared_candidates'],60004)
        self.assertEqual(summary['unique_identities'],60004)
        self.assertEqual(summary['last']['remove'],2023)
        self.assertEqual(summary['first']['remove'],0)
        self.assertEqual(summary['candidate_REUSED'],0)
        self.assertEqual(summary['first']['indices'],sorted((set(self.center)-{0})|{26}))
        self.assertEqual(summary['last']['indices'],sorted((set(self.center)-{2023})|{2170}))

    def test_same_size_wrong_donor_members_rejected(self):
        old_baseline=sorted((set(self.center)-{2021,2023})|{1217,1284})
        old_donors=sorted(set(self.states)-set(old_baseline))
        self.assertEqual(len(old_donors),2143)
        with self.assertRaises(ValueError):
            next(science.iter_candidates(self.center,old_donors,self.states))

    def test_missing_removal_or_locked_new_star_rejected(self):
        with self.assertRaises(ValueError):
            next(science.iter_candidates([i for i in self.center if i!=2021],self.donors,self.states))

    def test_changed_center_same_count_rejected(self):
        changed=sorted((set(self.center)-{2021})|{1217})
        donors=sorted(set(self.states)-set(changed))
        with self.assertRaises(ValueError):
            next(science.iter_candidates(changed,donors,self.states))


class GapAndThresholdTests(unittest.TestCase):
    def test_endpoint_contacts_do_not_enter(self):
        self.assertFalse(science.intersects_open_gap([1.,10.],10.,20.))
        self.assertFalse(science.intersects_open_gap([20.,25.],10.,20.))

    def test_interior_zero_duration_does_enter(self):
        self.assertTrue(science.intersects_open_gap([15.,15.],10.,20.))
        self.assertFalse(science.intersects_open_gap([10.,10.],10.,20.))

    def test_deleting_either_side_invalidates_internal_gap_proof(self):
        raw={1:[[1.,10.]],2:[[20.,25.]],3:[]}
        before,after=science.side_witnesses(raw,[1,2],10.,20.)
        self.assertTrue(before and after)
        before,after=science.side_witnesses(raw,[2,3],10.,20.)
        self.assertFalse(before);self.assertTrue(after)
        before,after=science.side_witnesses(raw,[1,3],10.,20.)
        self.assertTrue(before);self.assertFalse(after)

    def test_boundary_window_does_not_create_two_sided_witness(self):
        before,after=science.side_witnesses({1:[[20.,25.]]},[1],0.,20.)
        self.assertFalse(before);self.assertTrue(after)

    def test_deadline_equality_is_included(self):
        bits=science.pack_on_time(np.array([0.,10.,10.00000001,np.inf]),10.)
        self.assertEqual(bits,3)

    def test_90_percent_threshold_and_padding(self):
        for count in [38762,38763]:
            self.assertEqual(science.count_on_time_bits((1<<count)-1,0,43070),count)
        with self.assertRaises(ValueError):
            science.count_on_time_bits(1<<43070,0,43070)

    def test_illegal_first_visit_values_rejected(self):
        for value in [np.nan,-np.inf,-1.,604801.]:
            with self.subTest(value=value),self.assertRaises(ValueError):
                science.pack_on_time(np.array([value]),10.)
        self.assertEqual(science.pack_on_time(np.array([np.inf]),10.),0)


class DurableFullReportTests(unittest.TestCase):
    def setUp(self):
        root=Path(os.environ.get('ROUND19_TEST_ROOT',science.ROOT/'work/round19/science_preflight'))
        root.mkdir(parents=True,exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.tmp.cleanup)
        self.out=Path(self.tmp.name)
        self.targets=['a','b','c']
        self.report=dict(identity='full-test-identity',indices=[1,2],ordinal=3,remove=0,add=2,partition='FULL',
            regional=regional({t:[[0.,1.],[5.,6.]] for t in self.targets},self.targets),
            feasibility=dict(feasible=True,rejection_reasons=[]),round19_selection_rejection_reasons=[])

    def write_rows(self,report=None,summary_count=1):
        report=deepcopy(report or self.report)
        meta={'ordinal','remove','add','partition','processing_state'}
        digest=fingerprint({k:v for k,v in report.items() if k not in meta})
        summary={k:report[k] for k in ['identity','indices','ordinal','remove','add','partition']}
        summary.update(_compact=True,main_output_sha256=digest)
        checked=dict(identity=report['identity'],main_output_sha256=digest,status='PASS',differences=[])
        for name,rows in [('candidates',[report]),('candidate_summary',[summary]*summary_count),('checker',[checked])]:
            (self.out/(name+'.jsonl')).write_text(''.join(json.dumps(row)+'\n' for row in rows),encoding='utf8')

    def test_all_durable_full_details_match_original_independent_check(self):
        self.write_rows()
        result=science.verify_full_report_readback(self.out,1,self.targets)
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['full_reports_read_back'],1)

    def test_raw_payload_mutation_or_summary_length_substitution_rejected(self):
        self.write_rows()
        mutated=deepcopy(self.report)
        mutated['regional']['targets']['a']['raw_intervals'][0][0]=0.5
        (self.out/'candidates.jsonl').write_text(json.dumps(mutated)+'\n',encoding='utf8')
        with self.assertRaises(ValueError):
            science.verify_full_report_readback(self.out,1,self.targets)
        self.write_rows(summary_count=2)
        with self.assertRaises(ValueError):
            science.verify_full_report_readback(self.out,1,self.targets)

    def test_rebound_hashes_do_not_allow_missing_full_regional_details(self):
        missing=deepcopy(self.report)
        del missing['regional']['targets']['a']['raw_intervals']
        self.write_rows(missing)
        with self.assertRaises(ValueError):
            science.verify_full_report_readback(self.out,1,self.targets)


if __name__=='__main__':
    unittest.main()
