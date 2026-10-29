"""Adversarial checks against the actual independent two-swap paths."""
import ast
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest

import numpy as np

from src.round13.common import EvidenceError,fingerprint
from src.round14.science import evaluate
from src.round15 import science
from src.round15 import checker as independent


def fixture():
    baseline=sorted(list(range(100,126))+[911,1370]);donors=sorted(list(range(200,231))+[1123])
    states={i:'synthetic-state-'+str(i) for i in baseline+donors}
    targets=['main','island1',independent.TARGET]
    intervals={i:{t:([[0.,10.],[20.,30.]] if t!=independent.TARGET else []) for t in targets} for i in states}
    left,right=69292.439694662,242022.755780764
    intervals[911][independent.TARGET]=[[1000.,left]]
    intervals[1370][independent.TARGET]=[[2000.,left-10.]]
    for position,index in enumerate(range(100,106)):
        intervals[index][independent.TARGET]=[[right+100*position,right+100*position+10]]
    intervals[1123][independent.TARGET]=[[155654.373767399,155659.896226983]]
    rows={i:np.array([1.,2.,3.,np.inf]) for i in states}
    assets={i:dict(state=states[i],regional_data_sha256=fingerprint(intervals[i])) for i in states}
    return SimpleNamespace(baseline_indices=baseline,donor_indices=donors,states=states,
        rows=rows,intervals=intervals,targets=targets,keep=np.array([True,True,True,False]),assets=assets)


def main(lib,indices,baseline=None):
    return evaluate(indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)


def candidate(lib,removed=(100,101),added=(200,201),ordinal=0):
    indices=sorted((set(lib.baseline_indices)-set(removed))|set(added))
    return dict(remove=list(removed),add=list(added),indices=indices,ordinal=ordinal,
                identity=fingerprint(sorted(lib.states[i] for i in indices)))


class CheckerNumericalTests(unittest.TestCase):
    def setUp(self):
        self.lib=fixture();self.base,self.hits=main(self.lib,self.lib.baseline_indices)
        self.checker=independent.IndependentChecker(self.lib)

    def test_baseline_and_full_two_swap_are_pointwise_checked(self):
        checked=self.checker.verify(self.lib.baseline_indices,self.base,self.hits)
        self.assertEqual(checked['status'],'PASS')
        item=candidate(self.lib);report,hits=main(self.lib,item['indices'],self.base)
        report.update(item,partition='C')
        checked=self.checker.verify(item['indices'],report,hits,self.base,item['remove'],item['add'])
        self.assertEqual(checked['status'],'PASS');self.assertEqual(checked['points_compared'],4)
        self.assertEqual(checked['classification_difference_count'],0)
        self.assertEqual(checked['max_absolute_first_hit_error_s'],0.)
        self.assertEqual(len(self.checker.retained_min),1)

    def test_single_swap_is_not_accepted_as_two_swap(self):
        indices=sorted((set(self.lib.baseline_indices)-{100})|{200})
        with self.assertRaisesRegex(EvidenceError,'NOT_TWO_REPLACEMENTS'):self.checker.recompute(indices,self.base)

    def test_wrong_pair_label_is_rejected(self):
        item=candidate(self.lib)
        with self.assertRaisesRegex(EvidenceError,'LABEL_MISMATCH'):
            self.checker.recompute(item['indices'],self.base,[100,102],item['add'])

    def test_forged_point_classification_is_rejected(self):
        item=candidate(self.lib);report,hits=main(self.lib,item['indices'],self.base)
        hits[-1]=4.
        checked=self.checker.verify(item['indices'],report,hits,self.base)
        self.assertEqual(checked['status'],'FAIL');self.assertEqual(checked['classification_difference_count'],1)

    def test_finite_time_uses_absolute_not_relative_tolerance(self):
        item=candidate(self.lib);report,hits=main(self.lib,item['indices'],self.base);hits[0]+=2e-6
        checked=self.checker.verify(item['indices'],report,hits,self.base)
        self.assertEqual(checked['status'],'FAIL');self.assertGreater(checked['max_absolute_first_hit_error_s'],1e-6)
        self.assertEqual(independent._differences(500000.,500000.+0.5e-6,1e-6),[])
        self.assertTrue(independent._differences(500000.,500000.+2e-6,1e-6))

    def test_nan_or_negative_infinity_cannot_hide_as_no_hit(self):
        item=candidate(self.lib);report,hits=main(self.lib,item['indices'],self.base)
        for value in [np.nan,-np.inf]:
            altered=hits.copy();altered[-1]=value
            self.assertEqual(self.checker.verify(item['indices'],report,altered,self.base)['status'],'FAIL')

    def test_extra_unknown_report_field_is_rejected(self):
        item=candidate(self.lib);report,hits=main(self.lib,item['indices'],self.base);report['unknown']=0
        self.assertEqual(self.checker.verify(item['indices'],report,hits,self.base)['status'],'FAIL')

    def test_missing_regional_target_is_rejected(self):
        self.lib.intervals[200].pop('main')
        with self.assertRaisesRegex(EvidenceError,'TARGET_SET'):independent.IndependentChecker(self.lib)

    def test_t100_null_and_native_scope_preserved(self):
        self.lib.keep[:]=True
        checker=independent.IndependentChecker(self.lib);item=candidate(self.lib)
        report,hits=main(self.lib,item['indices'],self.base)
        checked=checker.verify(item['indices'],report,hits,self.base)
        self.assertEqual(checked['status'],'PASS');self.assertIsNone(report['effective_grid']['T100_s'])
        report['native_verified']=True
        self.assertEqual(checker.verify(item['indices'],report,hits,self.base)['status'],'FAIL')

    def test_forged_production_baseline_cannot_relax_gates(self):
        item=candidate(self.lib);badbase=copy.deepcopy(self.base)
        badbase['effective_grid']['T90_s']=604800.
        a=self.checker.recompute(item['indices'],self.base)[0]
        b=self.checker.recompute(item['indices'],badbase)[0]
        self.assertEqual(a['feasibility'],b['feasibility']);self.assertEqual(a['improvement'],b['improvement'])

    def test_one_second_uncertainty_boundary_is_conservative(self):
        item=candidate(self.lib)
        candidate_max=self.checker.recompute(item['indices'],self.base)[0]['regional']['pooled_internal']['max_s']
        self.checker.baseline_reference['regional']['pooled_internal']['max_s']=candidate_max+1.
        below=self.checker.recompute(item['indices'],self.base)[0]
        self.assertFalse(below['improvement']['substantive_improvement'])
        self.checker.baseline_reference['regional']['pooled_internal']['max_s']+=2e-6
        above=self.checker.recompute(item['indices'],self.base)[0]
        self.assertTrue(above['improvement']['substantive_improvement'])


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.lib=fixture();self.base,self.hits=main(self.lib,self.lib.baseline_indices)
        self.proof=science.prove_gap(self.lib,self.base)
        self.checker=independent.IndependentChecker(self.lib)

    def test_all_raw_payloads_and_endpoints_independently_verified(self):
        result=self.checker.verify_gap_proof(self.proof,self.base)
        self.assertEqual(result['status'],'PASS')
        derived=result['independently_derived']
        self.assertEqual(derived['before_baseline_assets'],[911,1370])
        self.assertEqual(len(derived['after_baseline_assets']),6)
        self.assertEqual(len(derived['source_payload_sha256']),60)

    def test_certificate_is_objective_bound_not_infeasibility(self):
        self.checker.verify_gap_proof(self.proof,self.base);item=candidate(self.lib)
        record=science.certificate_record(item,self.proof)
        result=self.checker.verify_certificate(item,record,self.proof)
        self.assertEqual(result['status'],'PASS');self.assertIsNone(record['feasibility'])
        self.assertFalse(result['full_metrics_evaluated']);self.assertFalse(result['feasibility_evaluated'])
        self.assertEqual(result['Tmax_lower_bound_s'],self.base['regional']['pooled_internal']['max_s'])

    def test_both_exception_partitions_cannot_receive_certificate(self):
        self.checker.verify_gap_proof(self.proof,self.base)
        for item in [candidate(self.lib,added=(200,1123)),candidate(self.lib,removed=(911,1370))]:
            with self.assertRaisesRegex(EvidenceError,'CANNOT_CERTIFY_EXCEPTION'):
                self.checker.verify_certificate(item,{})

    def test_removing_front_owners_can_move_gap_to_leading_boundary(self):
        item=candidate(self.lib,removed=(911,1370));report,_=main(self.lib,item['indices'],self.base)
        region=report['regional']['targets'][independent.TARGET]
        self.assertEqual(region['boundary_segments'][0],[0.,242022.755780764])
        self.assertLess(region['internal']['max_s'],self.base['regional']['pooled_internal']['max_s'])
        self.assertGreater(region['boundary_segments'][0][1],self.base['regional']['targets'][independent.TARGET]['boundary_segments'][0][1])
        self.assertGreater(region['boundary_inclusive']['max_s'],region['internal']['max_s'])

    def test_missing_1123_raw_asset_rejects_proof(self):
        del self.lib.intervals[1123]
        with self.assertRaisesRegex(EvidenceError,'ASSET_POOL'):self.checker.verify_gap_proof(self.proof)

    def test_wrong_1123_source_identity_rejects_proof(self):
        self.lib.assets[1123]['state']='forged'
        with self.assertRaisesRegex(EvidenceError,'SOURCE_STATE'):self.checker.verify_gap_proof(self.proof)

    def test_unknown_gap_visit_and_zero_duration_visit_reject_proof(self):
        for interval in [[100000.,100001.],[100000.,100000.]]:
            self.lib.intervals[200][independent.TARGET]=[interval]
            with self.assertRaisesRegex(EvidenceError,'INTERIOR_ASSETS'):self.checker.verify_gap_proof(self.proof)

    def test_forged_proof_or_payload_digest_is_rejected(self):
        forged=copy.deepcopy(self.proof);forged['source_payload_sha256']['1123']='0'*64
        forged['proof_sha256']=fingerprint({k:v for k,v in forged.items() if k!='proof_sha256'})
        self.assertEqual(self.checker.verify_gap_proof(forged)['status'],'FAIL')
        forged=copy.deepcopy(self.proof);forged['L']+=1
        self.assertEqual(self.checker.verify_gap_proof(forged)['status'],'FAIL')

    def test_forged_certificate_witness_metrics_or_state_rejected(self):
        self.checker.verify_gap_proof(self.proof);item=candidate(self.lib);record=science.certificate_record(item,self.proof)
        for key,value in [('before_witness',200),('feasibility',False),('Tmax_lower_bound_s',0.),('identity','0'*64),('full_grid',{})]:
            forged=dict(record);forged[key]=value
            self.assertEqual(self.checker.verify_certificate(item,forged)['status'],'FAIL')

    def test_proof_must_be_verified_before_any_certificate(self):
        item=candidate(self.lib);record=science.certificate_record(item,self.proof)
        with self.assertRaisesRegex(EvidenceError,'NOT_VALIDATED'):self.checker.verify_certificate(item,record)


class EnumerationAndTerminalTests(unittest.TestCase):
    def test_independent_exact_space_order_and_partitions(self):
        lib=fixture();base,_=main(lib,lib.baseline_indices);proof=science.prove_gap(lib,base)
        checker=independent.IndependentChecker(lib);checker.verify_gap_proof(proof)
        main_summary=science.neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states)
        seen=set();order=hashlib.sha256();counts={'A':0,'B':0,'C':0}
        for n,item in enumerate(checker.enumerate_space()):
            self.assertEqual(item['ordinal'],n);self.assertNotIn(item['identity'],seen);seen.add(item['identity'])
            order.update((item['identity']+'\n').encode());counts[checker.partition(item)]+=1
        self.assertEqual(len(seen),187488);self.assertEqual(order.hexdigest(),main_summary['identity_order_sha256'])
        self.assertEqual(counts,{'A':11718,'B':465,'C':175305})

    def test_partial_stream_cannot_be_completed(self):
        lib=fixture();base,_=main(lib,lib.baseline_indices);proof=science.prove_gap(lib,base)
        result=independent.terminal_verification(lib.baseline_indices,lib.donor_indices,lib.states,
            iter([]),iter([]),iter([]),iter([]),iter([]),None,point_count=4,proof=proof)
        self.assertEqual(result['status'],'FAIL');self.assertEqual(result['unprocessed'],187488)

    def test_shuffled_ledger_cannot_match_frozen_traversal(self):
        lib=fixture();base,_=main(lib,lib.baseline_indices);proof=science.prove_gap(lib,base)
        iterator=independent.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states)
        first,second=next(iterator),next(iterator)
        for item in [first,second]:
            item.update(partition='C',processing_state=independent.CERT_STATUS)
        result=independent.terminal_verification(lib.baseline_indices,lib.donor_indices,lib.states,
            [second,first],[],[],[],[],None,point_count=4,proof=proof)
        self.assertEqual(result['status'],'FAIL')
        self.assertTrue(any(row['reason']=='PAIR_IDENTITY_STATE_OR_ORDER' for row in result['differences']))
        self.assertNotEqual(result['identity_order_sha256'],result['expected_identity_order_sha256'])

    def test_checker_source_never_imports_production_science(self):
        tree=ast.parse(Path(independent.__file__).read_text(encoding='utf8'))
        imports=[ast.unparse(node) for node in ast.walk(tree) if isinstance(node,(ast.Import,ast.ImportFrom))]
        self.assertFalse(any('science' in line for line in imports))


if __name__=='__main__':unittest.main()
