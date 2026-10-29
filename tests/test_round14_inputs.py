"""Synthetic tests only: no frozen payloads or new candidates are evaluated."""
import math
import unittest
from unittest.mock import patch

import numpy as np

from src.round13.common import EvidenceError, Unavailable, fingerprint
from src.round13.inputs import state_key
from src.round13.metrics import coordinate_permutation, validate_hits
from src.round14 import inputs


def synthetic_catalog():
    assets = []
    for i in range(60):
        row = dict(sat_id='Sat'+str(i), altitude_km=inputs.HEIGHT,
            inclination_deg=98.12982292389323, raan_deg=float(i*5), arg_lat_deg=float(i))
        assets.append(dict(row=row, state=state_key(row)))
    baseline = list(range(28))
    identity = fingerprint(sorted(a['state'] for a in assets[:28]))
    return dict(assets=assets), dict(choice=dict(indices=baseline, identity=identity)), identity


class Round14InputTests(unittest.TestCase):
    def test_full_exact_neighborhood(self):
        cat, pro, identity = synthetic_catalog()
        with patch.object(inputs, 'BASELINE_IDENTITY', identity):
            m = inputs.metadata_from(cat, pro)
        self.assertEqual(len(m['pool_indices']), 60)
        self.assertEqual(len(m['neighborhood']), 896)
        self.assertEqual({(n['remove'], n['add']) for n in m['neighborhood']},
                         {(i, j) for i in range(28) for j in range(28,60)})
        self.assertEqual(len({n['identity'] for n in m['neighborhood']}), 896)
        self.assertTrue(all(len(n['indices']) == len(set(n['indices'])) == 28
                            for n in m['neighborhood']))

    def test_exact_height_rejects_near_neighbor(self):
        cat, pro, identity = synthetic_catalog()
        cat['assets'][-1]['row']['altitude_km'] = np.nextafter(inputs.HEIGHT, math.inf)
        with patch.object(inputs, 'BASELINE_IDENTITY', identity), self.assertRaisesRegex(
                EvidenceError, 'EXACT_HEIGHT_POOL_COUNT'):
            inputs.metadata_from(cat, pro)

    def test_rotation_normalized_duplicate_rejected(self):
        cat, pro, identity = synthetic_catalog()
        row = dict(cat['assets'][0]['row'])
        row['raan_deg'] += 360
        cat['assets'][-1] = dict(row=row, state=state_key(row))
        with patch.object(inputs, 'BASELINE_IDENTITY', identity), self.assertRaisesRegex(
                EvidenceError, 'DUPLICATE_NORMALIZED'):
            inputs.metadata_from(cat, pro)

    def test_producer_state_and_sso_relation(self):
        cat, _, _ = synthetic_catalog()
        inputs.validate_state(cat['assets'][0]['row'])
        for key, value in [('inclination_deg',98.), ('raan_deg',360.),
                           ('altitude_km',692.8318965760105), ('arg_lat_deg',math.nan)]:
            row = dict(cat['assets'][0]['row']); row[key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                inputs.validate_state(row)

    def test_intervals_require_every_exact_target(self):
        good = {'one': [[0,1]], 'two': [], 'three': [[9,10]]}
        self.assertEqual(inputs.validate_intervals(good, list(good), 10), good)
        for bad in [dict(one=[]), dict(good, unknown=[]),
                    dict(good, one=[[-1,1]]), dict(good, one=[[0,11]]),
                    dict(good, one=[[math.nan,1]]), dict(good, one=[[0,math.inf]]),
                    dict(good, one=[[2,1]])]:
            with self.subTest(bad=bad), self.assertRaises(EvidenceError):
                inputs.validate_intervals(bad, list(good), 10)

    def test_no_hit_encoding_is_only_positive_infinity(self):
        self.assertTrue(np.array_equal(validate_hits([0,math.inf,10],10), [0,math.inf,10]))
        for a in [[math.nan], [-math.inf], [-1], [11]]:
            with self.subTest(a=a), self.assertRaises(EvidenceError):
                validate_hits(a, 10)

    def test_duplicate_coordinates_rejected(self):
        with self.assertRaisesRegex(EvidenceError, 'DUPLICATE_COORDINATE'):
            coordinate_permutation([[0,0],[0,360]], [[0,0],[0,360]])

    def test_missing_member_is_unavailable_without_fallback(self):
        arc = inputs.FrozenArchive.__new__(inputs.FrozenArchive)
        arc.check = lambda: None
        arc.locations = {}; arc.manifest = {'files': {}}
        with self.assertRaisesRegex(Unavailable, 'UNAVAILABLE_FROM_FROZEN_LIBRARY'):
            arc.path('competition_v1/missing.json')
        self.assertEqual(arc.locations, {})

    def test_cross_protocol_entry_has_no_native_fallback(self):
        cat, _, _ = synthetic_catalog()
        asset = dict(cat['assets'][0], origin={'native_protocol_hash': 'pinned'})
        context = {'numerical_settings': {'duration_s': 10}}
        key = fingerprint(dict(state=asset['state'], context=context))
        entry = dict(state=asset['state'], original_row=asset['row'], context=context,
                     origin=asset['origin'])
        inputs.validate_entry(asset, entry, context, key, 'pinned')
        with self.assertRaisesRegex(EvidenceError, 'COMPONENT_ENTRY_ORIGIN_PROTOCOL'):
            inputs.validate_entry(asset, entry, context, key, 'other')
        wrong = dict(entry, context={'numerical_settings': {'duration_s': 20}})
        with self.assertRaisesRegex(EvidenceError, 'COMPONENT_PRODUCER_PROTOCOL'):
            inputs.validate_entry(asset, wrong, context, key, 'pinned')

    def test_path_escape_rejected_before_any_materialization(self):
        arc = inputs.FrozenArchive.__new__(inputs.FrozenArchive)
        arc.check = lambda: None
        arc.locations = {}; arc.manifest = {'files': {}}
        with self.assertRaisesRegex(EvidenceError, 'UNSAFE_MEMBER_PATH'):
            arc.path('../missing.json')


if __name__ == '__main__':
    unittest.main()
