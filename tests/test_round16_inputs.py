"""Full-catalog gate risks, using only small synthetic payloads."""
import math
import os
from pathlib import Path
import tempfile
import unittest

import numpy as np

from src.round13.common import EvidenceError, Unavailable, fingerprint
from src.round13.inputs import state_key
from src.round16 import inputs


class Round16InputTests(unittest.TestCase):
    def test_preserved_altitude_controls_sso_validation(self):
        high = dict(altitude_km=700.0, inclination_deg=98.15893063155772,
                    raan_deg=183.1345202161212, arg_lat_deg=340.6300058018238)
        low = dict(high, altitude_km=inputs.HEIGHT, inclination_deg=98.12982292389323)
        self.assertEqual(inputs.validate_state(high), inputs.archived.normalized_state(high))
        self.assertEqual(inputs.validate_state(low), inputs.archived.normalized_state(low))
        with self.assertRaisesRegex(EvidenceError, 'COMPONENT_SSO_RELATION'):
            inputs.validate_state(dict(high, inclination_deg=low['inclination_deg']))
        for altitude in [499.999, 700.001, math.nan, math.inf]:
            with self.subTest(altitude=altitude), self.assertRaises(EvidenceError):
                inputs.validate_state(dict(high, altitude_km=altitude))

    def test_float_hex_state_is_not_rounded(self):
        a = dict(altitude_km=700.0, inclination_deg=98.15893063155772,
                 raan_deg=183.1345202161212, arg_lat_deg=340.6300058018238)
        b = dict(a, raan_deg=float(np.nextafter(a['raan_deg'], math.inf)))
        inputs.validate_state(a)
        inputs.validate_state(b)
        self.assertNotEqual(state_key(a), state_key(b))

    def test_complete_npz_row_and_no_hit_classification(self):
        with tempfile.TemporaryDirectory(dir=os.getenv('ROUND16_TEST_ROOT')) as folder:
            path = Path(folder)/'row.npz'
            values = np.array([0., math.inf, 10.], dtype=np.float64)
            np.savez(path, first_hits=values)
            checked = inputs.validate_npz_row(path, values.copy(), 3, 10.)
            self.assertEqual((checked['points_verified'], checked['finite_hits'],
                              checked['no_hit_positive_infinity']), (3, 2, 1))
            wrong = values.copy()
            wrong[-1] = np.nextafter(10., 0.)
            with self.assertRaisesRegex(EvidenceError, 'SOURCE_MATRIX_MISMATCH'):
                inputs.validate_npz_row(path, wrong, 3, 10.)
            wrong = values.copy()
            wrong[1] = 1.
            with self.assertRaisesRegex(EvidenceError, 'SOURCE_MATRIX_MISMATCH'):
                inputs.validate_npz_row(path, wrong, 3, 10.)

    def test_npz_rejects_shape_dtype_and_illegal_sentinels(self):
        cases = [np.array([math.nan]), np.array([-math.inf]), np.array([-1.]),
                 np.array([11.]), np.array([1.], dtype=np.float32), np.array([[1.]])]
        with tempfile.TemporaryDirectory(dir=os.getenv('ROUND16_TEST_ROOT')) as folder:
            path = Path(folder)/'row.npz'
            for values in cases:
                with self.subTest(values=values):
                    np.savez(path, first_hits=values)
                    with self.assertRaises(EvidenceError):
                        inputs.validate_npz_row(path, values, 1, 10.)
            np.savez(path, wrong_field=np.array([1.]))
            with self.assertRaisesRegex(EvidenceError, 'GLOBAL_SCHEMA'):
                inputs.validate_npz_row(path, np.array([1.]), 1, 10.)

    def test_context_and_original_row_cannot_cross_bind_assets(self):
        row = dict(altitude_km=700.0, inclination_deg=98.15893063155772,
                   raan_deg=183.1345202161212, arg_lat_deg=340.6300058018238)
        asset = dict(row=row, state=state_key(row), origin={'native_protocol_hash': 'frozen'})
        context = {'canonical_point_sha256': 'column-order-A'}
        key = fingerprint(dict(state=asset['state'], context=context))
        entry = dict(state=asset['state'], original_row=row,
                     context=context, origin=asset['origin'])
        inputs.archived.validate_entry(asset, entry, context, key, 'frozen')
        with self.assertRaisesRegex(EvidenceError, 'PRODUCER_PROTOCOL'):
            inputs.archived.validate_entry(asset, dict(entry, context={
                'canonical_point_sha256': 'column-order-B'}), context, key, 'frozen')
        changed_row = dict(row, arg_lat_deg=0.)
        with self.assertRaisesRegex(EvidenceError, 'ENTRY_STATE_IDENTITY'):
            inputs.archived.validate_entry(asset, dict(entry, original_row=changed_row),
                                           context, key, 'frozen')

    def test_missing_member_blocks_without_donor_deletion(self):
        assets = [dict(global_key='g0', regional_key='r0'),
                  dict(global_key='g1', regional_key='r1')]
        names = inputs.required_asset_members(assets)
        manifest = {'files': dict.fromkeys(names, {})}
        self.assertEqual(inputs.require_asset_inventory(assets, manifest)['required_members'], 8)
        del manifest['files'][names[-1]]
        with self.assertRaisesRegex(Unavailable, 'UNAVAILABLE_FROM_FROZEN_LIBRARY'):
            inputs.require_asset_inventory(assets, manifest)
        self.assertEqual(len(assets), 2)
        self.assertEqual(len(manifest['files']), 7)

    def test_duplicate_catalog_payload_keys_fail(self):
        asset = dict(global_key='same-global', regional_key='same-regional')
        with self.assertRaisesRegex(EvidenceError, 'DUPLICATE_CATALOG_ASSET_MEMBERS'):
            inputs.required_asset_members([asset, dict(asset)])


if __name__ == '__main__':
    unittest.main()
