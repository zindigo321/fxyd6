"""Fixed 705-anchor repair space and exact first-hit necessary constraints.

The only full numerical evaluator reused here is R14's frozen pure evaluator.
No historical bridge restriction is applied to the second donor.
"""
import hashlib
import math

import numpy as np

from src.round13.common import fingerprint, require
from src.round14.science import evaluate, select

FIXED_REMOVE = 1284
FIXED_ADD = 705
ANCHOR_IDENTITY = '9258c0d332037e9e5f9cd658aca4c9bf9b61d5aca365aed49a2e05bc109040c8'
BASELINE_IDENTITY = 'c1fbd71e9dfca4e0a7d0d603d496fff8a71e2bc406d12eee113ab2bc4207b71d'
ANCHOR_DONORS = {28, 218, 705, 1801, 2021}


def _pool(baseline, donors, states):
    b, d = sorted(baseline), sorted(donors)
    require(len(b) == len(set(b)) == 28 and FIXED_REMOVE in b, 'R17_BASELINE_POOL')
    require(len(d) == len(set(d)) == 2143 and FIXED_ADD in d and not set(b)&set(d), 'R17_DONOR_POOL')
    require(sorted(b+d) == list(range(2171)) and all(type(i) is int and i in states for i in b+d), 'R17_CATALOG_POOL')
    require(len({states[i] for i in b+d}) == 2171, 'R17_DUPLICATE_STATE')
    return b, d


def iter_candidates(baseline, donors, states, check=lambda: None):
    b, d = _pool(baseline, donors, states)
    ordinal = 0
    for remove in b:
        if remove == FIXED_REMOVE:
            continue
        retained = set(b)-{FIXED_REMOVE, remove}
        for add in d:
            if add == FIXED_ADD:
                continue
            if ordinal % 512 == 0:
                check()
            indices = sorted(retained | {FIXED_ADD, add})
            yield dict(ordinal=ordinal, fixed_remove=FIXED_REMOVE, fixed_add=FIXED_ADD,
                remove=remove, add=add, remove_pair=sorted([FIXED_REMOVE, remove]),
                add_pair=sorted([FIXED_ADD, add]), indices=indices,
                identity=fingerprint(sorted(states[i] for i in indices)))
            ordinal += 1
    check()


def neighborhood_summary(baseline, donors, states, check=lambda: None):
    count, ids = 0, set()
    order, pairs = hashlib.sha256(), hashlib.sha256()
    first = last = None
    for item in iter_candidates(baseline, donors, states, check):
        require(item['identity'] not in ids, 'R17_CANDIDATE_IDENTITY_COLLISION')
        ids.add(item['identity'])
        order.update((item['identity']+'\n').encode('ascii'))
        pairs.update((str(item['remove'])+','+str(item['add'])+'\n').encode('ascii'))
        first = item if first is None else first
        last = item
        count += 1
    require(count == 57834, 'R17_EXACT_SPACE_CARDINALITY')
    return dict(declared_candidates=count, unique_identities=len(ids),
        identity_order_sha256=order.hexdigest(), pair_order_sha256=pairs.hexdigest(),
        baseline_indices=sorted(baseline), donor_indices=sorted(donors), first=first, last=last,
        fixed_remove=FIXED_REMOVE, fixed_add=FIXED_ADD, anchor_identity=ANCHOR_IDENTITY,
        traversal='second remove ascending, then second donor ascending',
        candidate_rule='sorted((B - {1284,r}) union {705,d})',
        identity_rule='SHA256 canonical JSON sorted original float.hex state-token strings',
        scope='Fixed first replacement anchor repair only; 27 x 2142 unique combinations',
        historical_results_reused_as_new_evaluations=False)


def pack_on_time(values, tau):
    values = np.asarray(values)
    require(values.ndim == 1 and not np.isnan(values).any() and not np.isneginf(values).any(), 'R17_INVALID_FIRST_HITS')
    finite = values[np.isfinite(values)]
    require(not (finite < 0).any() and not (finite > 604800).any(), 'R17_FIRST_HIT_OUTSIDE_WINDOW')
    require(math.isfinite(tau) and 0 <= tau <= 604800.000001, 'R17_INVALID_DEADLINE')
    return int.from_bytes(np.packbits(values <= tau, bitorder='little').tobytes(), 'little')


def count_on_time_bits(retained_bits, donor_bits, point_count):
    require(type(point_count) is int and point_count > 0, 'R17_INVALID_POINT_COUNT')
    require(type(retained_bits) is int and type(donor_bits) is int and retained_bits >= 0 and donor_bits >= 0,
        'R17_INVALID_BITSET')
    require((retained_bits >> point_count) == (donor_bits >> point_count) == 0, 'R17_NONZERO_PADDING')
    return (retained_bits | donor_bits).bit_count()


def select_anchor(replays, baseline_report):
    require(baseline_report.get('identity') != ANCHOR_IDENTITY, 'R17_ANCHOR_CANNOT_BE_REFERENCE')
    n = baseline_report['effective_grid']['points']
    threshold = (9*n+9)//10
    tau90 = baseline_report['effective_grid']['T90_s']+1e-6
    ranked = []
    for replay in replays:
        item = dict(replay)
        item['shortfall_points'] = max(0, threshold-item['on_time_count'])
        item['T90_excess_s'] = item['T90_s']-baseline_report['effective_grid']['T90_s']
        ranked.append(item)
    ranked.sort(key=lambda r:(r['shortfall_points'],r['T90_excess_s'],r['identity']))
    require(bool(ranked), 'R17_NO_ANCHOR_REPLAYS')
    return dict(status='PASS', ranked=ranked, selected_add=ranked[0]['add'],
        selected_identity=ranked[0]['identity'], k90=threshold, tau90=tau90,
        reference_identity=baseline_report.get('identity'),
        method='Exact source first-hit count before original-baseline T90+1e-6; then T90 excess, identity',
        anchor_is_admissible_reference=False, new_R17_candidate_evaluations=0)


def anchor_replay(lib, baseline_report, r16_records, check=lambda: None):
    from src.round14.checker import _differences
    require(len(r16_records) == 5 and {r['add'] for r in r16_records} == ANCHOR_DONORS
            and all(r['remove'] == FIXED_REMOVE for r in r16_records), 'R17_OLD_NEAR_FEASIBLE_SET_CHANGED')
    replays = []
    chosen_report = chosen_hits = None
    for old in sorted(r16_records, key=lambda r:r['add']):
        check()
        indices = sorted((set(lib.baseline_indices)-{FIXED_REMOVE})|{old['add']})
        report, hits = evaluate(indices, lib.rows, lib.intervals, lib.keep, lib.targets, lib.states, baseline_report)
        require(report['identity'] == old['identity'] and report['indices'] == old['indices'], 'R17_OLD_ANCHOR_IDENTITY_CHANGED')
        for key in ['full_grid','effective_grid','regional','feasibility','improvement','qualified_improvement','selection_rejection_reasons']:
            require(not _differences(report[key],old[key],1e-6), 'R17_OLD_ANCHOR_REPLAY:'+key)
        require(report['feasibility']['rejection_reasons'] == ['T90_s_WORSE_THAN_BASELINE']
                and report['improvement']['substantive_improvement'], 'R17_ANCHOR_NOT_ONLY_T90_FAILURE')
        tau90 = baseline_report['effective_grid']['T90_s']+1e-6
        c90 = int(np.count_nonzero(hits[lib.keep] <= tau90))
        replays.append(dict(add=old['add'],identity=report['identity'],on_time_count=c90,
            T90_s=report['effective_grid']['T90_s'], report_sha256=fingerprint(report),
            historical_record_sha256=fingerprint(old), replay=report))
        if old['add'] == FIXED_ADD:
            chosen_report, chosen_hits = report, hits
    selection = select_anchor(replays, baseline_report)
    require(selection['selected_add'] == FIXED_ADD and selection['selected_identity'] == ANCHOR_IDENTITY,
        'R17_ANCHOR_SELECTION_CHANGED')
    require(chosen_report['identity'] == ANCHOR_IDENTITY, 'R17_FIXED_ANCHOR_IDENTITY')
    return selection, chosen_report, chosen_hits


class ThresholdGate:
    """Exact T100 exclusive-point proof, followed by a T90 threshold bitset."""
    def __init__(self, lib, baseline_report, check=lambda: None):
        self.lib = lib
        self.baseline, self.donors = _pool(lib.baseline_indices, lib.donor_indices, lib.states)
        expected_reference=fingerprint(sorted(lib.states[i] for i in self.baseline))
        require(baseline_report.get('identity',expected_reference)==expected_reference
                and baseline_report.get('indices',self.baseline)==self.baseline,
            'R17_ORIGINAL_BASELINE_REFERENCE_REQUIRED')
        self.anchor = sorted((set(self.baseline)-{FIXED_REMOVE})|{FIXED_ADD})
        require(np.asarray(lib.keep).dtype==np.bool_ and np.asarray(lib.keep).ndim==1,
            'R17_GATE_MASK_SCHEMA')
        require(np.asarray(lib.coords).shape[0]==len(lib.keep), 'R17_GATE_COORDINATE_SHAPE')
        self.mask_ids = np.flatnonzero(lib.keep)
        self.n = len(self.mask_ids)
        require(self.n == baseline_report['effective_grid']['points'] and self.n > 0, 'R17_GATE_MASK_POINT_COUNT')
        self.k90 = (9*self.n+9)//10
        self.tau100 = baseline_report['effective_grid']['T100_s']+1e-6
        self.tau90 = baseline_report['effective_grid']['T90_s']+1e-6
        self.mask_sha256 = hashlib.sha256(np.asarray(lib.keep,dtype=np.uint8).tobytes()).hexdigest()
        self.coordinate_sha256 = hashlib.sha256(np.asarray(lib.coords,dtype='<f8').tobytes()).hexdigest()
        self.matrix_sha256 = getattr(lib,'evidence',{}).get('matrix',{}).get('sha256')
        self.row_digests, self.bits90 = {}, {}
        for index in sorted(lib.rows):
            check()
            row = np.asarray(lib.rows[index])
            self.row_digests[index] = hashlib.sha256(np.asarray(row,dtype='<f8').tobytes()).hexdigest()
            self.bits90[index] = pack_on_time(row[lib.keep], self.tau90)
        on100 = np.stack([np.asarray(lib.rows[i])[lib.keep] <= self.tau100 for i in self.anchor])
        counts100 = np.count_nonzero(on100,axis=0)
        require(bool(np.all(counts100 > 0)), 'R17_ANCHOR_NOT_FULLY_COVERED_AT_TAU100')
        self.exclusive, self.retained90 = {}, {}
        for position, remove in enumerate(self.anchor):
            if remove == FIXED_ADD:
                continue
            check()
            self.exclusive[remove] = self.mask_ids[on100[position] & (counts100 == 1)]
            bits = 0
            for retained in self.anchor:
                if retained != remove:
                    bits |= self.bits90[retained]
            self.retained90[remove] = bits
        self.reference_identity = baseline_report.get('identity')

    def binding(self, candidate):
        return fingerprint(dict(matrix_sha256=self.matrix_sha256,mask_sha256=self.mask_sha256,
            coordinate_sha256=self.coordinate_sha256,
            rows_sha256=[[i,self.lib.states[i],self.row_digests[i]] for i in candidate['indices']]))

    def evidence(self):
        return dict(status='PASS',profile='ROUND17_EXACT_FIRST_HIT_GATES_V1',
            reference_identity=self.reference_identity, anchor_identity=ANCHOR_IDENTITY,
            tau100=self.tau100,tau90=self.tau90,k90=self.k90,mask_point_count=self.n,
            mask_sha256=self.mask_sha256,coordinate_sha256=self.coordinate_sha256,
            matrix_sha256=self.matrix_sha256,
            exclusive_points={str(r):dict(count=len(ids),point_ids=ids.tolist(),
                point_ids_sha256=hashlib.sha256(np.asarray(ids,dtype='<i8').tobytes()).hexdigest()) for r,ids in self.exclusive.items()},
            bitset_effective_bits=self.n,bitset_padding_bits=(-self.n)%8,bitset_padding_zero=True,
            priority=['T100_BASELINE_DEADLINE','T90_ON_TIME_COUNT','FULL'],
            full_metrics_from_necessary_gates=False,second_donor_bridge_required=False)

    def _certificate(self, candidate, part):
        return dict(candidate,partition=part,status='KNOWN_INFEASIBLE',
            processing_state=part+'_CERTIFICATE_REJECTED',known_infeasible=True,
            verified_constraint_violation='T100_BASELINE_DEADLINE' if part=='T100' else 'T90_ON_TIME_COUNT',
            full_feasibility_evaluation_performed=False,metrics_status='NOT_EVALUATED',
            full_grid=None,effective_grid=None,regional=None,feasibility=None,first_hits_sha256=None,
            T90_s=None,T100_s=None,Tavg_s=None,Tmax_s=None,qualified_improvement=False,
            source='archived_component_composition',new_native_validation_performed=False,
            whole_constellation_STK_verified=False,native_verified=False,
            tau100=self.tau100,tau90=self.tau90,k90=self.k90,
            mask_sha256=self.mask_sha256,coordinate_sha256=self.coordinate_sha256,
            input_binding_sha256=self.binding(candidate))

    def classify(self, candidate):
        remove, add = candidate['remove'],candidate['add']
        require(remove in self.exclusive and add in self.donors and add != FIXED_ADD, 'R17_GATE_OPERATION_SCOPE')
        expected = sorted((set(self.baseline)-{FIXED_REMOVE,remove})|{FIXED_ADD,add})
        require(candidate['indices'] == expected and candidate['identity'] == fingerprint(sorted(self.lib.states[i] for i in expected)),
            'R17_GATE_CANDIDATE_IDENTITY')
        points = self.exclusive[remove]
        failures = points[np.asarray(self.lib.rows[add])[points] > self.tau100]
        if len(failures):
            point = int(failures[0])
            cert = self._certificate(candidate,'T100')
            values=[]
            for index in expected:
                value=float(self.lib.rows[index][point])
                require(value > self.tau100, 'R17_T100_WITNESS_NOT_FAILURE')
                values.append(dict(index=index,first_hit_s=value if math.isfinite(value) else None,
                    classification='FINITE_LATE' if math.isfinite(value) else 'NO_FIRST_HIT'))
            cert.update(point_id=point,coordinates=np.asarray(self.lib.coords[point]).tolist(),source_values=values,
                source_values_sha256=fingerprint(values))
            return 'T100',cert
        c90 = count_on_time_bits(self.retained90[remove],self.bits90[add],self.n)
        if c90 < self.k90:
            bits=self.retained90[remove]|self.bits90[add]
            raw=bits.to_bytes((self.n+7)//8,'little')
            classifications=np.unpackbits(np.frombuffer(raw,dtype=np.uint8),bitorder='little',count=self.n)
            cert=self._certificate(candidate,'T90')
            cert.update(c90=c90,on_time_point_count=c90,
                classification_sha256=hashlib.sha256(classifications.tobytes()).hexdigest())
            return 'T90',cert
        return 'FULL',None
