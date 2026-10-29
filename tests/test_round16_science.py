"""New mixed-height single-swap risks, with synthetic saved observations only."""
import copy
from types import SimpleNamespace
import unittest

import numpy as np

from src.round13.common import EvidenceError, fingerprint
from src.round16 import science, checker


def fixture():
    required={38,548,911,974,1370,1412,1931,2049}
    baseline=sorted(required | set(i for i in range(20)))
    donors=sorted(set(range(2171))-set(baseline))
    states={i:'synthetic-'+str(i) for i in range(2171)}
    targets=[science.TARGET,'Synthetic_A','Synthetic_B']
    intervals={i:{target:[] for target in targets} for i in range(2171)}
    for i in baseline:
        for target in targets[1:]:intervals[i][target]=[[0.,1.],[2.,3.]]
    left,right=science.L_EXPECTED,science.R_EXPECTED
    for i in [911,1370]:intervals[i][science.TARGET]=[[left-1.,left]]
    for i in [38,548,974,1412,1931,2049]:intervals[i][science.TARGET]=[[right,right+1.]]
    # Construct exactly223, with1123 the only original-height donor.
    bridges=sorted([1123]+[i for i in donors if i!=1123][:222])
    assets={i:dict(state=states[i],regional_data_sha256=fingerprint(intervals[i]),
        row=dict(altitude_km=692.8318965760104 if i in baseline or i==1123 else 600.)) for i in range(2171)}
    for i in bridges:
        intervals[i][science.TARGET]=[[left+1.,left+2.]]
        assets[i]['regional_data_sha256']=fingerprint(intervals[i])
    rows={i:np.array([0.,5.,np.inf,8.],dtype=np.float64) for i in range(2171)}
    lib=SimpleNamespace(baseline_indices=baseline,donor_indices=donors,states=states,targets=targets,
        intervals=intervals,assets=assets,rows=rows,keep=np.array([True,True,False,True]))
    report,hits=science.evaluate(baseline,rows,intervals,lib.keep,targets,states)
    return lib,report,hits,bridges


class Round16SpaceTests(unittest.TestCase):
    def test_exact_space_and_independent_order_include_historical_896(self):
        lib,_,_,_=fixture()
        main=science.neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states)
        independent=checker.neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states)
        for key in ['declared_candidates','unique_identities','identity_order_sha256','pair_order_sha256']:
            self.assertEqual(main[key],independent[key])
        self.assertEqual(main['declared_candidates'],60004)
        same=lib.donor_indices[:32]
        historical={(remove,add) for remove in lib.baseline_indices for add in same}
        actual={(row['remove'],row['add']) for row in science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states)
                if row['add'] in same}
        self.assertEqual(actual,historical)
        self.assertEqual(len(actual),896)

    def test_missing_asset_does_not_shrink_declared_space(self):
        lib,_,_,_=fixture()
        with self.assertRaisesRegex(EvidenceError,'FULL_CATALOG_DONOR_COUNT'):
            next(science.iter_candidates(lib.baseline_indices,lib.donor_indices[:-1],lib.states))

    def test_duplicate_state_rejected(self):
        lib,_,_,_=fixture();lib.states[1]=lib.states[0]
        with self.assertRaisesRegex(EvidenceError,'DUPLICATE_STATE'):
            next(science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states))

    def test_deadline_preserves_actual_order_prefix(self):
        lib,_,_,_=fixture();seen=[];calls=[]
        def check():
            calls.append(1)
            if len(calls)==2:raise TimeoutError('synthetic deadline')
        with self.assertRaises(TimeoutError):
            for row in science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states,check):seen.append(row)
        self.assertEqual(len(seen),512)
        self.assertEqual([row['ordinal'] for row in seen],list(range(512)))


class Round16ProofTests(unittest.TestCase):
    def setUp(self):
        self.lib,self.baseline,self.hits,self.bridges=fixture()
        self.proof=science.prove_gap(self.lib,self.baseline)

    def test_mixed_altitude_bridges_rebuilt_and_independently_derived(self):
        self.assertEqual(self.proof['same_height_bridge_donors'],[1123])
        self.assertEqual(self.proof['different_height_bridge_donor_count'],222)
        own=checker.IndependentChecker(self.lib)
        self.assertEqual(own.verify_gap_proof(self.proof,self.baseline)['status'],'PASS')
        self.assertEqual(own.proof_state['bridge_donors'],self.bridges)

    def test_open_endpoints_and_interior_zero_duration(self):
        left,right=self.proof['L'],self.proof['R']
        self.assertFalse(science.intersects_open_gap([left-1,left],left,right))
        self.assertFalse(science.intersects_open_gap([right,right+1],left,right))
        self.assertTrue(science.intersects_open_gap([left+1,left+1],left,right))
        extra=next(i for i in self.lib.donor_indices if i not in self.bridges)
        self.lib.intervals[extra][science.TARGET]=[[left+1,left+1]]
        with self.assertRaisesRegex(EvidenceError,'BRIDGE_DONOR_COUNT'):
            science.prove_gap(self.lib,self.baseline)

    def test_single_deletion_has_no_double_swap_boundary_exception(self):
        self.assertEqual(self.proof['boundary_exception_candidates'],0)
        add=self.proof['nonbridge_donors'][0]
        for remove in [911,1370]:
            item=dict(remove=remove,add=add,ordinal=0,
                indices=sorted((set(self.lib.baseline_indices)-{remove})|{add}))
            item['identity']=fingerprint(sorted(self.lib.states[i] for i in item['indices']))
            self.assertEqual(science.classify(item,self.proof),'C')
            record=science.certificate_record(item,self.proof)
            self.assertEqual(record['retained_before_asset_count'],1)
            self.assertGreaterEqual(record['retained_after_asset_count'],5)

    def test_certificate_null_metrics_and_actual_witness_binding(self):
        own=checker.IndependentChecker(self.lib);own.verify_gap_proof(self.proof,self.baseline)
        item=next(row for row in science.iter_candidates(self.lib.baseline_indices,self.lib.donor_indices,self.lib.states)
                  if row['add'] in self.proof['nonbridge_donors'])
        certificate=science.certificate_record(item,self.proof)
        self.assertIsNone(certificate['feasibility'])
        self.assertIsNone(certificate['effective_grid'])
        self.assertEqual(own.verify_certificate(item,certificate,self.proof)['status'],'PASS')
        certificate['before_witness']=item['remove']
        self.assertEqual(own.verify_certificate(item,certificate,self.proof)['status'],'FAIL')

    def test_changed_source_proof_or_identity_rejected(self):
        own=checker.IndependentChecker(self.lib)
        changed=copy.deepcopy(self.proof);changed['source_payload_sha256']['0']='0'*64
        changed['proof_sha256']=fingerprint({key:value for key,value in changed.items() if key!='proof_sha256'})
        self.assertEqual(own.verify_gap_proof(changed,self.baseline)['status'],'FAIL')
        self.assertIsNone(own.proof_state)

    def test_bridge_donor_never_gets_certificate(self):
        item=next(row for row in science.iter_candidates(self.lib.baseline_indices,self.lib.donor_indices,self.lib.states)
                  if row['add'] in self.bridges)
        with self.assertRaisesRegex(EvidenceError,'CANNOT_CERTIFY_BRIDGE_DONOR'):
            science.certificate_record(item,self.proof)


class Round16NumericalTests(unittest.TestCase):
    def test_processing_ledger_cannot_reference_other_checked_outputs(self):
        lib,baseline,hits,_=fixture();own=checker.IndependentChecker(lib)
        proof=science.prove_gap(lib,baseline);own.verify_gap_proof(proof,baseline)
        item=next(science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states))
        report,values=science.evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
        report.update(remove=item['remove'],add=item['add'],ordinal=item['ordinal'],partition='A')
        checked=own.verify(item['indices'],report,values,baseline,item['remove'],item['add'])
        ledger=dict(main_output_sha256=checked['main_output_sha256'],checker_output_sha256=checked['checker_output_sha256'])
        self.assertEqual(checker._ledger_binding(ledger,report,checked),[])
        ledger['checker_output_sha256']='0'*64
        self.assertTrue(checker._ledger_binding(ledger,report,checked))
        cert_item=next(row for row in science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states)
                       if row['add'] in proof['nonbridge_donors'])
        cert=science.certificate_record(cert_item,proof);cert_check=own.verify_certificate(cert_item,cert,proof)
        cert_ledger=dict(certificate_sha256=fingerprint(cert),proof_sha256=proof['proof_sha256'])
        self.assertEqual(checker._ledger_binding(cert_ledger,cert,cert_check,certificate=True),[])
        cert_ledger['certificate_sha256']='0'*64
        self.assertTrue(checker._ledger_binding(cert_ledger,cert,cert_check,certificate=True))

    def test_full_point_vector_and_regions_checked_before_discard(self):
        lib,baseline,hits,_=fixture();own=checker.IndependentChecker(lib)
        self.assertEqual(own.verify(lib.baseline_indices,baseline,hits)['status'],'PASS')
        item=next(science.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states))
        report,values=science.evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
        report.update(remove=item['remove'],add=item['add'],ordinal=item['ordinal'],partition='A')
        self.assertEqual(own.verify(item['indices'],report,values,baseline,item['remove'],item['add'])['status'],'PASS')
        changed=values.copy();changed[-1]+=1
        result=own.verify(item['indices'],report,changed,baseline,item['remove'],item['add'])
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(result['points_compared'],4)

    def test_t100_null_and_exact_threshold_order_statistic(self):
        values=np.array([float(i) for i in range(9)]+[np.inf])
        from src.round14.science import coverage
        result=coverage(values)
        self.assertIsNone(result['T100_s'])
        self.assertEqual(result['T90_s'],8.)
        self.assertEqual(checker._coverage(values,604800),result)

    def test_one_second_reduction_requires_uncertainty_margin(self):
        lib,baseline,_,_=fixture()
        report,values=science.evaluate(lib.baseline_indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states)
        for reduction,expected in [(1.,False),(1.000002,True)]:
            reference=copy.deepcopy(baseline)
            reference['regional']['pooled_internal']['max_s']=report['regional']['pooled_internal']['max_s']+reduction
            result,_=science.evaluate(lib.baseline_indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,reference)
            self.assertEqual(result['improvement']['substantive_improvement'],expected)


if __name__=='__main__':unittest.main()
