"""Committed-prefix closure, pending writes and independent failure priority."""
import copy
import itertools
from types import SimpleNamespace
import unittest

import numpy as np

from src.round13.common import fingerprint
from src.round14.science import evaluate
from src.round17.checker import IndependentChecker, compact_report, terminal_verification
from src.round17.science import ThresholdGate


def checked_prefix():
    baseline = sorted(list(range(27))+[1284])
    donors = [i for i in range(2171) if i not in baseline]
    rows = {i: np.full(10, np.inf) for i in range(2171)}
    for i in range(10):
        rows[i][i] = 10. if i < 9 else 100.
    rows[27][0] = 20.
    rows[29][0] = 10.
    targets = ['A', 'B', 'C']
    intervals = {i: {t: [[0., 1.], [20., 21.]] for t in targets} for i in rows}
    lib = SimpleNamespace(baseline_indices=baseline, donor_indices=donors,
        states={i: 'prefix-state-'+str(i) for i in rows}, rows=rows,
        intervals=intervals, targets=targets, keep=np.ones(10, dtype=np.bool_),
        coords=np.zeros((10, 2)), evidence={'matrix': {'sha256': 'synthetic-matrix'}})
    reference, hits = evaluate(baseline, rows, intervals, lib.keep, targets, lib.states)
    checker = IndependentChecker(lib)
    assert checker.verify(baseline, reference, hits)['status'] == 'PASS'
    gate = ThresholdGate(lib, reference)
    ledger, reports, checks = [], [], []
    certs, checked_certs = {'T100': [], 'T90': []}, {'T100': [], 'T90': []}
    for item in itertools.islice(checker.enumerate_space(), 4):
        part, certificate = gate.classify(item)
        assert checker.partition(item) == part
        if certificate:
            checked = checker.verify_certificate(item, certificate)
            assert checked['status'] == 'PASS'
            certs[part].append(certificate)
            checked_certs[part].append(checked)
            ledger.append(dict(item, partition=part, processing_state=part+'_CERTIFICATE_REJECTED',
                certificate_sha256=fingerprint(certificate), checker_output_sha256=fingerprint(checked)))
        else:
            report, hits = evaluate(item['indices'], rows, intervals, lib.keep, targets, lib.states, reference)
            report.update(item, partition='FULL')
            checked = checker.verify(item['indices'], report, hits, reference, item['remove_pair'], item['add_pair'])
            assert checked['status'] == 'PASS'
            reports.append(compact_report(report))
            checks.append(checked)
            ledger.append(dict(item, partition=part, processing_state='FULLY_EVALUATED_AND_INDEPENDENTLY_VERIFIED',
                main_output_sha256=checked['main_output_sha256'], checker_output_sha256=checked['checker_output_sha256']))
    streams = [ledger, reports, checks, certs['T100'], checked_certs['T100'], certs['T90'], checked_certs['T90']]
    return lib, checker, streams


class PrefixClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib, cls.checker, cls.original = checked_prefix()

    def readback(self, streams):
        return terminal_verification(self.lib.baseline_indices, self.lib.donor_indices,
            self.lib.states, *streams, None, prefix=True, point_count=10)

    def test_three_processing_partitions_form_verified_committed_prefix(self):
        result = self.checker.verify_completion(*self.original, None, prefix=True)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual([result[k] for k in ['fully_independently_verified', 'T100_certificate_verified',
                                           'T90_certificate_verified']], [1, 2, 1])
        self.assertEqual((result['unprocessed'], result['unknown']), (57830, 0))
        self.assertEqual(result['differences'], [])
        self.assertTrue(result['retained_baseline'])

    def test_complete_checked_record_after_ledger_tail_remains_pending(self):
        streams = copy.deepcopy(self.original)
        streams[0].pop()
        result = self.readback(streams)
        self.assertEqual((result['status'], result['unprocessed'], result['pending_uncommitted_count']),
                         ('BLOCKED', 57831, 1))
        self.assertEqual(result['T100_certificate_verified'], 1)
        self.assertEqual(result['differences'], [])

    def test_last_main_certificate_without_checker_is_pending(self):
        streams = copy.deepcopy(self.original)
        streams[0].pop()
        streams[4].pop()
        result = self.readback(streams)
        self.assertEqual((result['status'], result['unprocessed'], result['pending_uncommitted_count']),
                         ('BLOCKED', 57831, 1))
        self.assertEqual(result['differences'], [])

    def test_tampered_certificate_binding_dominates_cutoff(self):
        streams = copy.deepcopy(self.original)
        streams[6][0]['main_certificate_sha256'] = 'tampered'
        result = self.readback(streams)
        self.assertEqual((result['status'], result['exit_code']), ('FAIL', 1))
        self.assertTrue(any('UNBOUND_CERTIFICATE' in d['reason'] for d in result['differences']))

    def test_missing_interior_record_cannot_be_treated_as_tail_interruption(self):
        streams = copy.deepcopy(self.original)
        del streams[3][0]
        del streams[4][0]
        result = self.readback(streams)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(any(d['reason'] == 'MISSING_INTERIOR_RECORD' for d in result['differences']))

    def test_duplicate_ledger_identity_remains_failure_in_prefix_mode(self):
        streams = copy.deepcopy(self.original)
        streams[0].append(copy.deepcopy(streams[0][-1]))
        result = self.readback(streams)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(any(d['reason'] == 'DUPLICATE_IDENTITY' for d in result['differences']))


if __name__ == '__main__':
    unittest.main()
