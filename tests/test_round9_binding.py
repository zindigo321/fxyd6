import ast
import unittest
from pathlib import Path
from src.round8.common import read
from src.round9.binding import AUDIT,Checker,load_references,parse,header,functions,require_checker
from src.round9.header_cases import run

class Round9BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=Path(__file__).resolve().parents[1]
        cls.policy=read(cls.root/'configs/round9.json')
        # Snapshot manifests record the original project root, not test-copy paths.
        cls.checker,cls.s,cls.v=load_references(cls.policy,Path('G:/fmb666'))

    def test_actual_s_v_full_node_positive(self):
        r=self.checker.audit_patch(self.s[AUDIT],self.v[AUDIT]);self.assertEqual(r['status'],'PASS',r)
        self.assertTrue(r['actual_headers_equal'])

    def test_all_real_input_header_mutations_target_specific_reason(self):
        r=run(self.checker,self.s,self.v)
        self.assertEqual(r['status'],'PASS',[x for x in r['cases'] if x['status']!='PASS'])
        self.assertGreaterEqual(r['case_count'],26)

    def test_reference_cannot_be_derived_from_candidate(self):
        with self.assertRaisesRegex(ValueError,'UNTRUSTED_REFERENCE'):Checker(self.s[AUDIT],self.v[AUDIT]+b'\n')

    def test_type_comment_retained(self):
        tree=parse(b'def f(x): # type: (int) -> str\n return x\n')
        self.assertEqual(functions(tree)['f'].type_comment,'(int) -> str')

    def test_parse_error_is_not_successful_semantic_rejection(self):
        r=self.checker.audit_patch(self.s[AUDIT],b'def invalid(')
        self.assertFalse(r['parsed']);self.assertTrue(r['errors'][0].startswith('PARSE_ERROR'))

    def test_duplicate_definition_rejected_before_dictionary(self):
        with self.assertRaisesRegex(ValueError,'DUPLICATE_TOP_LEVEL_DEFINITION'):parse(b'def f(): pass\ndef f(): pass\n')

    def test_simultaneously_changed_headers_not_trusted(self):
        a=self.s[AUDIT].replace(b'def audit_dataset(ctx,cfg):',b'def audit_dataset(ctx,cfg)->int:')
        b=self.v[AUDIT].replace(b'def audit_dataset(ctx,cfg):',b'def audit_dataset(ctx,cfg)->int:')
        r=self.checker.audit_patch(a,b);self.assertIn('SOURCE_AST_NOT_TRUSTED_S',r['errors'])

    def test_old_checker_route_rejected(self):
        from src.round8.binding import audit_patch
        with self.assertRaisesRegex(ValueError,'CHECKER_ROUTE_NOT_ROUND9'):require_checker(audit_patch)

    def test_old_boundary_reproduced_but_not_used_as_new_acceptance(self):
        from src.round8.binding import audit_patch
        v=self.v[AUDIT].replace(b'def audit_dataset(',b'@native_side_effect_marker()\ndef audit_dataset(',1)
        self.assertEqual(audit_patch(self.s[AUDIT],v)['status'],'PASS')
        self.assertIn('FUNCTION_HEADER_CHANGED:audit_dataset',self.checker.audit_patch(self.s[AUDIT],v)['errors'])

    def test_helper_type_comment_is_bound_to_reference(self):
        v=self.v[AUDIT].replace(b'def audit_constraints(project,prior,satellites,point_ids):',b'def audit_constraints(project,prior,satellites,point_ids): # type: (object, object, object, object) -> object')
        self.assertIn('HELPER_HEADER_CHANGED',self.checker.audit_patch(self.s[AUDIT],v)['errors'])
