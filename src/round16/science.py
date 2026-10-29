"""Complete saved-catalog N28 single replacement and two-sided gap bound.

Only the immutable R14 pure numerical evaluator is reused. No native producer
code, propagation, sampling, or historical neighborhood entrypoint is invoked.
"""
import hashlib
import math

from src.round13.common import fingerprint, require
from src.round14.science import evaluate, select, union

TARGET = 'YangtzeRiverDelta_Island_2'
L_EXPECTED = 69292.439694662
R_EXPECTED = 242022.755780764
FRONT_ASSETS = [911, 1370]
REAR_ASSETS = [38, 548, 974, 1412, 1931, 2049]
PROOF_STATUS = 'PROVEN_NO_SUBSTANTIVE_TMAX_IMPROVEMENT'


def _validate_pool(baseline, donors, states):
    b, d = sorted(baseline), sorted(donors)
    require(len(b) == len(set(b)) == 28, 'SINGLE_SWAP_BASELINE_COUNT')
    require(len(d) == len(set(d)) == 2143 and not set(b) & set(d), 'FULL_CATALOG_DONOR_COUNT')
    require(sorted(b+d) == list(range(2171)), 'FULL_CATALOG_INDEX_SET')
    require(all(type(i) is int and i in states for i in b+d), 'SINGLE_SWAP_MISSING_STATE')
    require(len({states[i] for i in b+d}) == 2171, 'FULL_CATALOG_DUPLICATE_STATE')
    return b, d


def iter_candidates(baseline, donors, states, check=lambda: None):
    b, d = _validate_pool(baseline, donors, states)
    ordinal = 0
    for remove in b:
        retained = set(b)-{remove}
        for add in d:
            if ordinal % 512 == 0:
                check()
            indices = sorted(retained | {add})
            yield dict(ordinal=ordinal, remove=remove, add=add, indices=indices,
                       identity=fingerprint(sorted(states[i] for i in indices)))
            ordinal += 1
    check()


def neighborhood_summary(baseline, donors, states, check=lambda: None):
    count = 0
    identities = set()
    order, pairs = hashlib.sha256(), hashlib.sha256()
    first = last = None
    for item in iter_candidates(baseline, donors, states, check):
        require(item['identity'] not in identities, 'SINGLE_SWAP_IDENTITY_COLLISION')
        identities.add(item['identity'])
        order.update((item['identity']+'\n').encode('ascii'))
        pairs.update((str(item['remove'])+','+str(item['add'])+'\n').encode('ascii'))
        first = item if first is None else first
        last = item
        count += 1
    require(count == 60004, 'FULL_CATALOG_SINGLE_SWAP_CARDINALITY')
    return dict(declared_candidates=count, unique_identities=len(identities),
        identity_order_sha256=order.hexdigest(), pair_order_sha256=pairs.hexdigest(),
        baseline_indices=sorted(baseline), donor_indices=sorted(donors), first=first, last=last,
        traversal='baseline remove index ascending, donor add index ascending',
        candidate_rule='sorted((B - {remove}) union {add})',
        identity_rule='SHA256 canonical JSON sorted frozen producer state tokens',
        scope='Full saved catalog single replacement; conditional mixed-altitude offline research',
        historical_same_height_candidates_included=896,
        historical_results_reused_as_new_evaluations=False)


def intersects_open_gap(span, left, right):
    """Endpoint-only contact is excluded; an interior zero-duration visit counts."""
    return span[0] < right and span[1] > left


def prove_gap(lib, baseline_report, tolerance=1e-6):
    require(tolerance == 1e-6, 'GAP_PROOF_TOLERANCE')
    baseline, donors = _validate_pool(lib.baseline_indices, lib.donor_indices, lib.states)
    pool = sorted(baseline+donors)
    require(set(lib.intervals) == set(lib.assets) == set(pool), 'GAP_PROOF_ASSET_POOL')
    require(len(lib.targets) == len(set(lib.targets)) == 3 and TARGET in lib.targets, 'GAP_PROOF_TARGET_SET')
    raw, payload = {}, {}
    for index in pool:
        require(set(lib.intervals[index]) == set(lib.targets), 'GAP_PROOF_TARGET_SET')
        raw[index] = []
        for span in lib.intervals[index][TARGET]:
            require(isinstance(span, (list, tuple)) and len(span) == 2
                    and all(type(v) in (int, float) for v in span), 'GAP_PROOF_INTERVAL_SCHEMA')
            a, b = map(float, span)
            require(math.isfinite(a) and math.isfinite(b) and 0 <= a <= b <= 604800, 'GAP_PROOF_INTERVAL_WINDOW')
            raw[index].append([a, b])
        asset = lib.assets[index]
        require(asset['state'] == lib.states[index], 'GAP_PROOF_SOURCE_STATE')
        digest = asset['regional_data_sha256']
        require(isinstance(digest, str) and len(digest) == 64
                and all(v in '0123456789abcdef' for v in digest), 'GAP_PROOF_SOURCE_DIGEST')
        payload[index] = digest
    merged = union([span for index in baseline for span in raw[index]], tolerance=tolerance)
    gaps = [(b[0]-a[1], a[1], b[0]) for a, b in zip(merged, merged[1:])]
    require(bool(gaps), 'GAP_PROOF_NO_INTERNAL_GAP')
    length, left, right = max(gaps)
    require(abs(left-L_EXPECTED) <= tolerance and abs(right-R_EXPECTED) <= tolerance, 'GAP_PROOF_ENDPOINTS')
    require(abs(baseline_report['regional']['pooled_internal']['max_s']-length) <= tolerance, 'GAP_PROOF_TMAX')
    require(baseline_report['identity'] == fingerprint(sorted(lib.states[i] for i in baseline)), 'GAP_PROOF_BASELINE_IDENTITY')
    claimed = baseline_report['regional']['targets'][TARGET]['merged_intervals']
    require(merged == claimed, 'GAP_PROOF_BASELINE_UNION')
    inside = {i: [span for span in raw[i] if intersects_open_gap(span, left, right)] for i in pool}
    require(not any(inside[i] for i in baseline), 'GAP_PROOF_BASELINE_ENTERED_GAP')
    bridges = [i for i in donors if inside[i]]
    require(len(bridges) == 223, 'GAP_PROOF_BRIDGE_DONOR_COUNT')
    height = float(lib.assets[baseline[0]]['row']['altitude_km']).hex()
    same_height = [i for i in bridges if float(lib.assets[i]['row']['altitude_km']).hex() == height]
    require(same_height == [1123], 'GAP_PROOF_SAME_HEIGHT_BRIDGE_SET')
    before = [i for i in baseline if any(stop <= left for start, stop in raw[i])]
    after = [i for i in baseline if any(start >= right for start, stop in raw[i])]
    require(before == FRONT_ASSETS and after == REAR_ASSETS, 'GAP_PROOF_SIDE_OWNERS')
    left_owners = [i for i in baseline if any(stop == left for start, stop in raw[i])]
    right_owners = [i for i in baseline if any(start == right for start, stop in raw[i])]
    require(left_owners and right_owners, 'GAP_PROOF_ENDPOINT_OWNERS')
    proof = dict(status='PASS', profile='ROUND16_FULL_CATALOG_SINGLE_SWAP_GAP_V1', target=TARGET,
        L=left, R=right, baseline_Tmax_s=length, merge_tolerance_s=tolerance,
        baseline_indices=baseline, donor_indices=donors, pool_indices=pool,
        baseline_identity=baseline_report['identity'], bridge_donors=bridges,
        nonbridge_donors=[i for i in donors if i not in set(bridges)],
        same_height_bridge_donors=same_height, different_height_bridge_donor_count=len(bridges)-len(same_height),
        before_baseline_assets=before, after_baseline_assets=after,
        left_endpoint_owners=left_owners, right_endpoint_owners=right_owners,
        asset_interval_sha256={str(i): fingerprint(raw[i]) for i in pool},
        source_payload_sha256={str(i): payload[i] for i in pool},
        raw_asset_intervals={str(i): raw[i] for i in pool},
        certificate_condition='add not in bridge_donors; remove exactly one baseline asset',
        proof_scope='No visit enters open G; at least one pre-gap and five post-gap baseline assets survive',
        minimum_retained_before_assets=len(before)-1, minimum_retained_after_assets=len(after)-1,
        boundary_exception_candidates=0, feasibility_inferred=False, full_candidate_metrics_computed=False,
        native_activation_count=0, source='archived_component_composition')
    proof['proof_sha256'] = fingerprint(proof)
    return proof


def classify(candidate, proof):
    require(proof.get('status') == 'PASS' and len(proof.get('bridge_donors', [])) == 223, 'GAP_CERTIFICATE_NOT_VALIDATED')
    require(type(candidate['remove']) is int and type(candidate['add']) is int
            and candidate['remove'] in proof['baseline_indices'] and candidate['add'] in proof['donor_indices'], 'SINGLE_SWAP_MEMBERSHIP')
    return 'A' if candidate['add'] in proof['bridge_donors'] else 'C'


def certificate_record(candidate, proof):
    require(classify(candidate, proof) == 'C', 'CANNOT_CERTIFY_BRIDGE_DONOR')
    indices = sorted((set(proof['baseline_indices'])-{candidate['remove']}) | {candidate['add']})
    require(indices == candidate['indices'] and len(indices) == 28, 'CERTIFICATE_STATE_SET')
    before = sorted(set(proof['before_baseline_assets']) & set(indices))
    after = sorted(set(proof['after_baseline_assets']) & set(indices))
    require(len(before) >= 1 and len(after) >= 5, 'CERTIFICATE_SIDE_WITNESS')
    return dict(candidate, partition='C', status=PROOF_STATUS, processing_state=PROOF_STATUS,
        proof_sha256=proof['proof_sha256'], Tmax_lower_bound_s=proof['R']-proof['L'],
        before_witness=before[0], after_witness=after[0],
        retained_before_asset_count=len(before), retained_after_asset_count=len(after),
        metrics_status='NOT_EVALUATED', full_grid=None, effective_grid=None, regional=None,
        feasibility=None, first_hits_sha256=None, qualified_improvement=False,
        reason='Two-sided internal-gap lower bound excludes conservative one-second Tmax improvement',
        source='archived_component_composition', new_native_validation_performed=False,
        whole_constellation_STK_verified=False, native_verified=False)
