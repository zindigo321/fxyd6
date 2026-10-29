"""Independent source, numerical, stream-binding and reused-space checks."""
import copy
import itertools
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np

from src.round13.common import EvidenceError, fingerprint
from src.round14.science import evaluate
from src.round18 import checker, science


def fixture():
    baseline = sorted(list(range(27))+[1284])
    donors = [i for i in range(2171) if i not in baseline]
    rows = {i:np.full(10,30.) for i in range(2171)}
    rows[0] = np.array([10.]*8+[30.,20.])
    rows[1284] = np.array([10.]*9+[30.])
    for pivot in (28,218,1801,2021):
        rows[pivot] = np.array([10.]*8+[20.,30.])
    rows[27] = np.array([30.]*9+[np.inf])
    rows[29] = np.array([30.]*9+[20.])
    rows[30] = np.array([30.]*8+[10.,20.])
    targets = ['A','B','C']
    intervals = {i:{target:[] for target in targets} for i in rows}
    for index in baseline:
        intervals[index] = {target:[[0.,1.],[2.,3.]] for target in targets}
    lib = SimpleNamespace(baseline_indices=baseline, donor_indices=donors,
        states={i:'independent-r18-state-'+str(i) for i in rows}, rows=rows,
        intervals=intervals, targets=targets, keep=np.ones(10,dtype=np.bool_),
        coords=np.column_stack((np.arange(10,dtype=float),np.zeros(10))),
        evidence={'matrix':{'sha256':'synthetic-independent-matrix'}})
    report,hits = evaluate(baseline,rows,intervals,lib.keep,targets,lib.states)
    return lib,report,hits


def checked_prefix():
    lib,reference,hits = fixture()
    own = checker.IndependentChecker(lib)
    assert own.verify(lib.baseline_indices,reference,hits)['status'] == 'PASS'
    gate = science.ThresholdGate(lib,reference)
    assert own.verify_gate_evidence(gate.evidence())['status'] == 'PASS'
    ledger,reports,checks = [],[],[]
    certificates,certificate_checks = {'T100':[],'T90':[]},{'T100':[],'T90':[]}
    items = list(itertools.islice(own.enumerate_space(),6))
    for item in items:
        part,certificate = gate.classify(item)
        assert own.partition(item) == part
        if certificate:
            checked = own.verify_certificate(item,certificate)
            assert checked['status'] == 'PASS'
            certificates[part].append(certificate);certificate_checks[part].append(checked)
            ledger.append(dict(item,partition=part,processing_state=part+'_CERTIFICATE_REJECTED',
                certificate_sha256=fingerprint(certificate),checker_output_sha256=fingerprint(checked)))
        else:
            report,vector = evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,reference)
            report.update(item,partition='FULL')
            checked = own.verify(item['indices'],report,vector,reference,item['remove_pair'],item['add_pair'])
            assert checked['status'] == 'PASS'
            reports.append(checker.compact_report(report));checks.append(checked)
            ledger.append(dict(item,partition=part,processing_state='FULLY_EVALUATED_AND_INDEPENDENTLY_VERIFIED',
                main_output_sha256=checked['main_output_sha256'],checker_output_sha256=checked['checker_output_sha256']))
    return lib,own,items,[ledger,reports,checks,certificates['T100'],certificate_checks['T100'],
                          certificates['T90'],certificate_checks['T90']]


class IndependentSourceTests(unittest.TestCase):
    def test_t100_checker_rechecks_all_28_sources_and_rejects_tampered_value(self):
        lib,reference,_ = fixture();own=checker.IndependentChecker(lib)
        item = next(own.enumerate_space());gate=science.ThresholdGate(lib,reference)
        part,certificate=gate.classify(item)
        self.assertEqual(part,'T100')
        self.assertEqual(own.verify_certificate(item,certificate)['status'],'PASS')
        changed=copy.deepcopy(certificate);changed['source_values'][-1]['first_hit_s']=0.
        changed['source_values_sha256']=fingerprint(changed['source_values'])
        result=own.verify_certificate(item,changed)
        self.assertEqual(result['status'],'FAIL')
        self.assertTrue(any('source_values' in d['path'] for d in result['differences']))

    def test_t90_source_boolean_count_and_classification_reject_main_bitset_corruption(self):
        lib,reference,_=fixture();own=checker.IndependentChecker(lib);gate=science.ThresholdGate(lib,reference)
        item=next(i for i in itertools.islice(own.enumerate_space(),6) if i['add_pair']==[28,30])
        self.assertEqual(own.partition(item),'FULL')
        gate.bits90[30]=0
        part,certificate=gate.classify(item)
        self.assertEqual(part,'T90')
        with self.assertRaisesRegex(EvidenceError,'CHECKER_CANNOT_CERTIFY_FULL_PARTITION'):
            own.verify_certificate(item,certificate)

    def test_threshold_count_boundary_is_independently_inclusive(self):
        source=np.full(43070,20.);source[:38762]=10.
        rows={0:source};keep=np.ones(43070,dtype=np.bool_)
        digest=checker.classification_digest(checker.boolean_on_time(rows,[0],keep,10.))
        self.assertEqual(checker.verify_t90_count(rows,[0],keep,10.,38763,38762,digest)['status'],'PASS')
        source[38762]=10.
        digest=checker.classification_digest(checker.boolean_on_time(rows,[0],keep,10.))
        result=checker.verify_t90_count(rows,[0],keep,10.,38763,38763,digest)
        self.assertEqual((result['status'],result['c90']),('FAIL',38763))

    def test_pivot_or_input_cache_misbinding_is_detected_from_independent_sources(self):
        lib,reference,_=fixture();own=checker.IndependentChecker(lib);gate=science.ThresholdGate(lib,reference)
        evidence=gate.evidence()
        self.assertEqual(own.verify_gate_evidence(evidence)['status'],'PASS')
        evidence['exclusive_points']['28']['0']['cache_binding_sha256']=evidence['exclusive_points']['218']['0']['cache_binding_sha256']
        self.assertEqual(own.verify_gate_evidence(evidence)['status'],'FAIL')
        evidence=gate.evidence();evidence['source_binding_sha256']='other-matrix'
        self.assertEqual(own.verify_gate_evidence(evidence)['status'],'FAIL')

    def test_full_comparison_checks_every_point_and_regional_endpoint(self):
        lib,reference,_=fixture();own=checker.IndependentChecker(lib)
        item=next(i for i in itertools.islice(own.enumerate_space(),6) if i['add_pair']==[28,30])
        report,hits=evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,reference)
        report.update(item,partition='FULL')
        args=(item['indices'],report,hits,reference,item['remove_pair'],item['add_pair'])
        self.assertEqual(own.verify(*args)['status'],'PASS')
        changed=hits.copy();changed[8]+=1.
        self.assertEqual(own.verify(item['indices'],report,changed,reference,item['remove_pair'],item['add_pair'])['status'],'FAIL')
        changed=copy.deepcopy(report);changed['regional']['targets']['B']['merged_intervals'][0][1]+=.01
        self.assertEqual(own.verify(item['indices'],changed,hits,reference,item['remove_pair'],item['add_pair'])['status'],'FAIL')


class ExactStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib,cls.own,cls.items,cls.streams=checked_prefix()

    def readback(self,streams):
        # The finite synthetic universe isolates stream failure handling. The
        # full 231066 cardinality/order is separately tested below and at run.
        with patch.object(checker,'iter_candidates',return_value=iter(self.items)):
            return checker.terminal_verification(self.lib.baseline_indices,self.lib.donor_indices,
                self.lib.states,*streams,None,prefix=True,point_count=10)

    def test_three_independently_checked_partitions_form_exact_disjoint_union(self):
        result=self.readback(self.streams)
        self.assertEqual((result['status'],result['unprocessed'],result['unknown']),('PASS',0,0))
        self.assertEqual([result[k] for k in ['fully_independently_verified','T100_certificate_verified',
                                           'T90_certificate_verified']],[1,4,1])
        self.assertEqual(result['differences'],[])

    def test_tail_uncommitted_checked_record_is_pending(self):
        streams=copy.deepcopy(self.streams);streams[0].pop()
        result=self.readback(streams)
        self.assertEqual((result['status'],result['unprocessed'],result['pending_uncommitted_count']),('BLOCKED',1,1))
        self.assertEqual(result['differences'],[])

    def test_false_partial_metrics_and_source_binding_fail_before_cutoff(self):
        streams=copy.deepcopy(self.streams)
        streams[3][0]['T90_s']=123.
        streams[4][0]['main_certificate_sha256']=fingerprint(streams[3][0])
        result=self.readback(streams)
        self.assertEqual((result['status'],result['exit_code']),('FAIL',1))
        self.assertTrue(any(d['reason']=='INCOMPLETE_OR_UNBOUND_CERTIFICATE' for d in result['differences']))

    def test_duplicate_identity_or_missing_interior_stream_record_is_failure(self):
        streams=copy.deepcopy(self.streams);streams[0].append(copy.deepcopy(streams[0][-1]))
        self.assertEqual(self.readback(streams)['status'],'FAIL')
        streams=copy.deepcopy(self.streams);del streams[3][0];del streams[4][0]
        result=self.readback(streams)
        self.assertEqual(result['status'],'FAIL')
        self.assertTrue(any(d['reason']=='MISSING_INTERIOR_RECORD' for d in result['differences']))

    def test_operation_pair_swap_cannot_reuse_another_candidate_identity(self):
        streams=copy.deepcopy(self.streams);streams[0][0]['add_pair']=[28,29]
        result=self.readback(streams)
        self.assertEqual(result['status'],'FAIL')
        self.assertTrue(any(d['reason']=='CANDIDATE_OR_PREFIX_ORDER' for d in result['differences']))


class IndependentUniverseTests(unittest.TestCase):
    def test_full_independent_pivot_universe_matches_main_exact_identities_and_order(self):
        lib,_,_=fixture()
        main=science.neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states)
        other=checker.neighborhood_summary(lib.baseline_indices,lib.donor_indices,lib.states)
        self.assertEqual({k:main[k] for k in ['declared_candidates','unique_identities','identity_order_sha256','pair_order_sha256','pivot_counts']},
                         {k:other[k] for k in ['declared_candidates','unique_identities','identity_order_sha256','pair_order_sha256','pivot_counts']})
        self.assertEqual(other['declared_candidates'],231066)

    def test_positive_reused_and_new_exact_union_is_bound_and_not_counted_as_new(self):
        lib,_,_=fixture()
        completion=dict(completed=True,declared_candidates=57834,unprocessed=0,unknown=0,
            fully_evaluated=1,fully_independently_verified=1,T100_certificate_rejected=57822,
            T100_certificate_verified=57822,T90_certificate_rejected=11,T90_certificate_verified=11)
        binding=dict(status='PASS',delivery_manifest_sha256=
            'd95ed8d31fe285de7480f5b6ce7aa7c04876ae447595d5da249d1d987b03b13f',source_zip_sha256=
            'caef7a821832e72bbadfd555261c6dc2058efee6c158d9a0e63c5e9ec23d12c8',completion=completion)
        def old_ledger():
            ordinal=0
            for remove in lib.baseline_indices:
                if remove==1284:
                    continue
                for add in lib.donor_indices:
                    if add==705:
                        continue
                    pair=sorted([705,add])
                    indices=sorted([i for i in lib.baseline_indices if i not in (1284,remove)]+pair)
                    yield dict(ordinal=ordinal,remove=remove,add=add,remove_pair=sorted([1284,remove]),
                        add_pair=pair,indices=indices,identity=fingerprint(sorted(lib.states[i] for i in indices)))
                    ordinal+=1
        result=checker.verify_five_anchor_union(lib.baseline_indices,lib.donor_indices,lib.states,
            old_ledger(),checker.iter_candidates(lib.baseline_indices,lib.donor_indices,lib.states),binding)
        self.assertEqual((result['status'],result['union_candidates'],result['overlap_identities']),('PASS',288900,0))
        self.assertEqual(result['R17']['disposition'],'REUSED')
        self.assertEqual((result['R17']['new_evaluations'],result['R18']['candidates']),(0,231066))
        self.assertFalse(result['full_catalog_double_swap_completed'])

    def test_reused_binding_must_identify_exact_r17_delivery_before_union(self):
        lib,_,_=fixture()
        with self.assertRaisesRegex(EvidenceError,'CHECKER_R17_REUSED_IDENTITY_BINDING'):
            checker.verify_five_anchor_union(lib.baseline_indices,lib.donor_indices,lib.states,[],[],{'status':'PASS'})


if __name__=='__main__':
    unittest.main()
