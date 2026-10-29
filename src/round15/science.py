"""Complete two-swap enumeration and a frozen-asset internal-gap certificate.

Full numerical evaluation delegates only to round14's immutable pure functions.
Certificate rows deliberately contain no invented coverage or revisit metrics.
"""
import hashlib
import itertools
import math

import numpy as np

from src.round13.common import require, fingerprint
from src.round14.science import evaluate as _evaluate, select, union


TARGET = 'YangtzeRiverDelta_Island_2'
L_EXPECTED = 69292.439694662
R_EXPECTED = 242022.755780764
INTERIOR_ASSET = 1123
FRONT_ASSETS = (911, 1370)
INTERIOR_INTERVAL = [155654.373767399, 155659.896226983]
PROOF_STATUS = 'PROVEN_NO_SUBSTANTIVE_TMAX_IMPROVEMENT'


def _validate_pool(baseline, donors, states):
    baseline, donors = sorted(baseline), sorted(donors)
    require(len(baseline) == 28 and len(set(baseline)) == 28, 'TWO_SWAP_BASELINE_COUNT')
    require(len(donors) == 32 and len(set(donors)) == 32, 'TWO_SWAP_DONOR_COUNT')
    require(not set(baseline) & set(donors), 'TWO_SWAP_DONOR_IN_BASELINE')
    require(all(type(i) is int and i in states for i in baseline+donors), 'TWO_SWAP_MISSING_STATE')
    require(len({states[i] for i in baseline+donors}) == 60, 'TWO_SWAP_DUPLICATE_STATE')
    return baseline, donors


def iter_candidates(baseline, donors, states, check=lambda: None):
    """Lexical remove pair, then lexical donor pair; no zero/single swaps."""
    baseline, donors = _validate_pool(baseline, donors, states)
    ordinal = 0
    for remove in itertools.combinations(baseline, 2):
        retained = set(baseline)-set(remove)
        for add in itertools.combinations(donors, 2):
            if ordinal % 1024 == 0:
                check()
            indices = sorted(retained | set(add))
            yield dict(ordinal=ordinal, remove=list(remove), add=list(add), indices=indices,
                       identity=fingerprint(sorted(states[i] for i in indices)))
            ordinal += 1
    check()


def neighborhood_summary(baseline, donors, states, check=lambda: None):
    """A streaming exact-identity/order commitment, before scientific evaluation."""
    count = 0
    identities = set()
    order_digest, pair_digest = hashlib.sha256(), hashlib.sha256()
    first = last = None
    for item in iter_candidates(baseline, donors, states, check):
        require(item['identity'] not in identities, 'TWO_SWAP_IDENTITY_COLLISION')
        identities.add(item['identity'])
        order_digest.update((item['identity']+'\n').encode('ascii'))
        pair_digest.update((','.join(map(str, item['remove']+item['add']))+'\n').encode('ascii'))
        first = item if first is None else first
        last = item
        count += 1
    require(count == math.comb(28, 2)*math.comb(32, 2), 'TWO_SWAP_DECLARED_CARDINALITY')
    return dict(declared_candidates=count, unique_identities=len(identities),
        identity_order_sha256=order_digest.hexdigest(), pair_order_sha256=pair_digest.hexdigest(),
        baseline_indices=sorted(baseline), donor_indices=sorted(donors),
        first=first, last=last,
        traversal='remove pair ascending lexical, then donor pair ascending lexical',
        candidate_rule='sorted((B - {r1,r2}) union {a1,a2}); r1<r2, a1<a2',
        identity_rule='SHA256 canonical JSON sorted frozen state tokens',
        scope='Complete fixed N28 exact-height two-swap neighborhood')


def _raw_intervals(lib):
    baseline, donors = _validate_pool(lib.baseline_indices, lib.donor_indices, lib.states)
    pool = sorted(baseline+donors)
    require(set(lib.intervals) == set(pool), 'GAP_PROOF_MISSING_OR_EXTRA_ASSET')
    require(set(lib.assets) == set(pool), 'GAP_PROOF_MISSING_SOURCE_ASSET')
    require(len(lib.targets) == 3 and len(set(lib.targets)) == 3 and TARGET in lib.targets,
            'GAP_PROOF_TARGET_SET')
    raw, payload = {}, {}
    for index in pool:
        require(set(lib.intervals[index]) == set(lib.targets), 'GAP_PROOF_TARGET_SET')
        spans = lib.intervals[index][TARGET]
        require(isinstance(spans, list), 'GAP_PROOF_INTERVAL_SCHEMA')
        normalized = []
        for span in spans:
            require(isinstance(span, (list, tuple)) and len(span) == 2
                    and all(type(v) in (int, float) for v in span), 'GAP_PROOF_INTERVAL_SCHEMA')
            start, stop = map(float, span)
            require(math.isfinite(start) and math.isfinite(stop) and 0 <= start <= stop <= 604800,
                    'GAP_PROOF_INVALID_INTERVAL')
            normalized.append([start, stop])
        source = lib.assets[index]
        require(source['state'] == lib.states[index], 'GAP_PROOF_ASSET_STATE_MISMATCH')
        digest = source['regional_data_sha256']
        require(isinstance(digest, str) and len(digest) == 64
                and all(ch in '0123456789abcdef' for ch in digest), 'GAP_PROOF_SOURCE_DIGEST')
        raw[index], payload[index] = normalized, digest
    return baseline, donors, raw, payload


def prove_gap(lib, baseline_report, tolerance=1e-6):
    """Rebuild every prerequisite from all sixty original regional payloads.

    Open-gap intersection is tested without shrinking G by a tolerance.  Thus
    even a zero-duration visit inside G prevents inappropriate certification.
    The tolerance is solely the frozen access-union/numerical comparison rule.
    """
    require(tolerance == 1e-6, 'GAP_PROOF_TOLERANCE')
    baseline, donors, raw, payload = _raw_intervals(lib)
    require(INTERIOR_ASSET in donors and set(FRONT_ASSETS).issubset(baseline),
            'GAP_PROOF_REQUIRED_ASSET_MEMBERSHIP')
    merged = union([span for index in baseline for span in raw[index]], tolerance=tolerance)
    gaps = [(right[0]-left[1], left[1], right[0]) for left, right in zip(merged, merged[1:])]
    require(bool(gaps), 'GAP_PROOF_NO_INTERNAL_GAP')
    length, left, right = max(gaps)
    require(abs(left-L_EXPECTED) <= tolerance and abs(right-R_EXPECTED) <= tolerance,
            'GAP_PROOF_BASELINE_ENDPOINTS')
    require(abs(baseline_report['regional']['pooled_internal']['max_s']-length) <= tolerance,
            'GAP_PROOF_BASELINE_TMAX')
    require(baseline_report['identity'] == fingerprint(sorted(lib.states[i] for i in baseline)),
            'GAP_PROOF_BASELINE_IDENTITY')
    claimed = baseline_report['regional']['targets'][TARGET]['merged_intervals']
    require(len(claimed) == len(merged)
            and all(abs(a-c) <= tolerance and abs(b-d) <= tolerance
                    for (a, b), (c, d) in zip(merged, claimed)), 'GAP_PROOF_BASELINE_UNION')
    inside = {i: [span for span in spans if span[1] > left and span[0] < right]
              for i, spans in raw.items()}
    interior_assets = sorted(i for i, spans in inside.items() if spans)
    require(interior_assets == [INTERIOR_ASSET], 'GAP_PROOF_INTERIOR_ASSET_SET')
    require(inside[INTERIOR_ASSET] == [INTERIOR_INTERVAL], 'GAP_PROOF_INTERIOR_INTERVAL')
    before = sorted(i for i in baseline if any(stop <= left for start, stop in raw[i]))
    after = sorted(i for i in baseline if any(start >= right for start, stop in raw[i]))
    require(before == list(FRONT_ASSETS), 'GAP_PROOF_FRONT_ASSET_SET')
    require(len(after) == 6, 'GAP_PROOF_REAR_ASSET_COUNT')
    # Bind exact endpoint ownership rather than only counting nearby visits.
    left_owners = sorted(i for i in baseline if any(stop == left for _, stop in raw[i]))
    right_owners = sorted(i for i in baseline if any(start == right for start, _ in raw[i]))
    require(bool(left_owners) and bool(right_owners), 'GAP_PROOF_ENDPOINT_OWNERSHIP')
    proof = dict(status='PASS', profile='ROUND15_INTERNAL_GAP_BOUND_V1', target=TARGET,
        L=left, R=right, baseline_Tmax_s=length, merge_tolerance_s=tolerance,
        baseline_indices=baseline, donor_indices=donors, pool_indices=sorted(raw),
        baseline_identity=baseline_report['identity'], interior_assets=interior_assets,
        before_baseline_assets=before, after_baseline_assets=after,
        left_endpoint_owners=left_owners, right_endpoint_owners=right_owners,
        interior_intervals={str(INTERIOR_ASSET): inside[INTERIOR_ASSET]},
        asset_interval_sha256={str(i): fingerprint(raw[i]) for i in sorted(raw)},
        source_payload_sha256={str(i): payload[i] for i in sorted(payload)},
        raw_asset_intervals={str(i): raw[i] for i in sorted(raw)},
        certificate_condition='1123 not in add AND sorted(remove) != [911,1370]',
        proof_scope='No access inside open G; retained accesses before/after force an internal gap at least R-L',
        feasibility_inferred=False, full_candidate_metrics_computed=False,
        native_activation_count=0, source='archived_component_composition')
    proof['proof_sha256'] = fingerprint(proof)
    return proof


def classify(candidate, proof):
    """A/B require full evaluation; C has a sufficient objective lower bound."""
    require(proof.get('status') == 'PASS' and proof.get('interior_assets') == [INTERIOR_ASSET],
            'GAP_CERTIFICATE_NOT_VALIDATED')
    removed, added = candidate['remove'], candidate['add']
    require(len(removed) == len(added) == 2 and removed == sorted(set(removed))
            and added == sorted(set(added)), 'TWO_SWAP_PAIR_SCHEMA')
    require(set(removed).issubset(proof['baseline_indices'])
            and set(added).issubset(proof['donor_indices']), 'TWO_SWAP_PAIR_MEMBERSHIP')
    if INTERIOR_ASSET in added:
        return 'A'
    if removed == proof['before_baseline_assets']:
        return 'B'
    return 'C'


def certificate_record(candidate, proof):
    require(classify(candidate, proof) == 'C', 'CANNOT_CERTIFY_EXCEPTION_PARTITION')
    selected = candidate['indices']
    require(selected == sorted((set(proof['baseline_indices'])-set(candidate['remove']))
                               | set(candidate['add'])) and len(selected) == 28,
            'CERTIFICATE_STATE_SET_MISMATCH')
    # An explicit witness on each side is retained in each compact row.
    before = sorted(set(proof['before_baseline_assets']) & set(selected))
    after = sorted(set(proof['after_baseline_assets']) & set(selected))
    require(before and after and INTERIOR_ASSET not in selected, 'CERTIFICATE_NO_TWO_SIDED_WITNESS')
    return dict(candidate, partition='C', status=PROOF_STATUS, processing_state=PROOF_STATUS,
        proof_sha256=proof['proof_sha256'], Tmax_lower_bound_s=proof['R']-proof['L'],
        before_witness=before[0], after_witness=after[0], metrics_status='NOT_EVALUATED',
        full_grid=None, effective_grid=None, regional=None, feasibility=None,
        first_hits_sha256=None, qualified_improvement=False,
        reason='Objective lower bound rules out conservative >=1 second Tmax improvement; feasibility not evaluated',
        source='archived_component_composition', new_native_validation_performed=False,
        whole_constellation_STK_verified=False, native_verified=False)


def evaluate(*args, **kwargs):
    """Full computation uses the byte-frozen R14 pure numerical implementation."""
    return _evaluate(*args, **kwargs)


def raw_domain_diagnostic(lib, baseline_hits):
    """A property of the saved sixty-row pool, without a physical reachability claim."""
    combined = np.full(np.asarray(baseline_hits).shape, np.inf)
    for row in lib.rows.values():
        np.minimum(combined, row, out=combined)
    baseline_missing = np.flatnonzero(~np.isfinite(baseline_hits)).tolist()
    pool_missing = np.flatnonzero(~np.isfinite(combined)).tolist()
    same = baseline_missing == pool_missing
    return dict(status='PASS', raw_point_count=len(combined), pool_assets=len(lib.rows),
        baseline_uncovered_count=len(baseline_missing), pool_uncovered_count=len(pool_missing),
        uncovered_ids_zero_based=pool_missing, baseline_uncovered_ids_zero_based=baseline_missing,
        uncovered_id_set_sha256=fingerprint(pool_missing), baseline_uncovered_id_set_sha256=fingerprint(baseline_missing),
        same_uncovered_set=same, expected_354_set_confirmed=same and len(pool_missing) == 354,
        saved_pool_subset_conclusion=('Every subset of this saved pool leaves at least these points uncovered' if same else
                                      'Pool and baseline missing sets differ'),
        physical_unreachability_claim=False, official_mask_proof=False)
