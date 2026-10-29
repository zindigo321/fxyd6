"""Remaining four-anchor repair enumeration and exact necessary constraints.

The numerical evaluator is the frozen R14 pure evaluator.  Necessary failures
retain null full metrics; no bridge test or approximate screening is used.
"""
import hashlib
import math

import numpy as np

from src.round13.common import fingerprint, require
from src.round14.science import evaluate, select

FIXED_REMOVE = 1284
EXCLUDED_DONOR = 705
ANCHOR_DONORS = {28, 218, 1801, 2021}
BASELINE_IDENTITY = 'c1fbd71e9dfca4e0a7d0d603d496fff8a71e2bc406d12eee113ab2bc4207b71d'
DECLARED = 231066


def _pool(baseline, donors, states):
    b, d = sorted(baseline), sorted(donors)
    require(len(b) == len(set(b)) == 28 and FIXED_REMOVE in b, 'R18_BASELINE_POOL')
    require(len(d) == len(set(d)) == 2143 and EXCLUDED_DONOR in d
            and ANCHOR_DONORS <= set(d) and not set(b) & set(d), 'R18_DONOR_POOL')
    require(sorted(b+d) == list(range(2171)) and all(type(i) is int and i in states for i in b+d),
            'R18_CATALOG_POOL')
    require(len({states[i] for i in b+d}) == 2171, 'R18_DUPLICATE_STATE')
    return b, d


def iter_add_pairs(donors):
    """Lexicographic unordered pairs, with each two-anchor pair emitted once."""
    d = sorted(i for i in donors if i != EXCLUDED_DONOR)
    anchors = sorted(ANCHOR_DONORS)
    for position, a in enumerate(d):
        seconds = d[position+1:] if a in ANCHOR_DONORS else (b for b in anchors if b > a)
        for b in seconds:
            yield a, b


def iter_candidates(baseline, donors, states, check=lambda: None):
    b, d = _pool(baseline, donors, states)
    pairs = list(iter_add_pairs(d))
    require(len(pairs) == 8558 and len(set(pairs)) == 8558, 'R18_ADDITION_PAIR_CARDINALITY')
    ordinal = 0
    for remove in b:
        if remove == FIXED_REMOVE:
            continue
        retained = set(b)-{FIXED_REMOVE, remove}
        for a, second in pairs:
            if ordinal % 512 == 0:
                check()
            pivot = min(i for i in (a, second) if i in ANCHOR_DONORS)
            add = second if a == pivot else a
            indices = sorted(retained | {a, second})
            yield dict(ordinal=ordinal, fixed_remove=FIXED_REMOVE, remove=remove,
                add=add, pivot=pivot, remove_pair=sorted([FIXED_REMOVE, remove]),
                add_pair=[a, second], indices=indices,
                identity=fingerprint(sorted(states[i] for i in indices)))
            ordinal += 1
    check()


def neighborhood_summary(baseline, donors, states, check=lambda: None):
    count, ids = 0, set()
    order, pairs = hashlib.sha256(), hashlib.sha256()
    pivot_counts = {str(i): 0 for i in sorted(ANCHOR_DONORS)}
    first = last = None
    for item in iter_candidates(baseline, donors, states, check):
        require(item['identity'] not in ids, 'R18_CANDIDATE_IDENTITY_COLLISION')
        ids.add(item['identity'])
        order.update((item['identity']+'\n').encode('ascii'))
        pairs.update((','.join(map(str, [item['remove']]+item['add_pair']))+'\n').encode('ascii'))
        pivot_counts[str(item['pivot'])] += 1
        first = item if first is None else first
        last = item
        count += 1
    require(count == DECLARED, 'R18_EXACT_SPACE_CARDINALITY')
    require(pivot_counts == {'28':57807, '218':57780, '1801':57753, '2021':57726},
            'R18_PIVOT_CARDINALITY')
    return dict(declared_candidates=count, unique_identities=len(ids),
        identity_order_sha256=order.hexdigest(), pair_order_sha256=pairs.hexdigest(),
        baseline_indices=sorted(baseline), donor_indices=sorted(donors),
        eligible_donor_indices=sorted(set(donors)-{EXCLUDED_DONOR}),
        pivot_counts=pivot_counts, first=first, last=last,
        fixed_remove=FIXED_REMOVE, anchor_donors=sorted(ANCHOR_DONORS), excluded_donor=EXCLUDED_DONOR,
        traversal='second remove ascending, then unordered numeric (a,b) lexicographic with a<b',
        candidate_rule='sorted((B - {1284,r}) union {a,b}); 705 excluded; {a,b} intersects A4',
        identity_rule='SHA256 canonical JSON sorted original float.hex state-token strings',
        scope='Remaining four R16 anchors, exact R17 intersection removed; 27 x 8558',
        historical_results_reused_as_new_evaluations=False)


def pack_on_time(values, tau):
    values = np.asarray(values)
    require(values.ndim == 1 and not np.isnan(values).any() and not np.isneginf(values).any(),
            'R18_INVALID_FIRST_HITS')
    finite = values[np.isfinite(values)]
    require(not (finite < 0).any() and not (finite > 604800).any(), 'R18_FIRST_HIT_OUTSIDE_WINDOW')
    require(math.isfinite(tau) and 0 <= tau <= 604800.000001, 'R18_INVALID_DEADLINE')
    return int.from_bytes(np.packbits(values <= tau, bitorder='little').tobytes(), 'little')


def count_on_time_bits(retained_bits, donor_bits, point_count):
    require(type(point_count) is int and point_count > 0, 'R18_INVALID_POINT_COUNT')
    require(type(retained_bits) is int and type(donor_bits) is int and retained_bits >= 0 and donor_bits >= 0,
            'R18_INVALID_BITSET')
    require((retained_bits >> point_count) == (donor_bits >> point_count) == 0, 'R18_NONZERO_PADDING')
    return (retained_bits | donor_bits).bit_count()


def anchor_replay(lib, baseline_report, r16_records, check=lambda: None):
    from src.round14.checker import _differences
    old_records = [r for r in r16_records if r['add'] in ANCHOR_DONORS]
    require(len(old_records) == 4 and {r['add'] for r in old_records} == ANCHOR_DONORS
            and all(r['remove'] == FIXED_REMOVE for r in old_records), 'R18_OLD_NEAR_FEASIBLE_SET_CHANGED')
    replays, reports, first_hits = [], {}, {}
    tau90 = baseline_report['effective_grid']['T90_s']+1e-6
    k90 = (9*baseline_report['effective_grid']['points']+9)//10
    expected_shortfalls = {28:78, 218:98, 1801:82, 2021:91}
    for old in sorted(old_records, key=lambda r:r['add']):
        check()
        indices = sorted((set(lib.baseline_indices)-{FIXED_REMOVE})|{old['add']})
        report, hits = evaluate(indices, lib.rows, lib.intervals, lib.keep, lib.targets, lib.states, baseline_report)
        require(report['identity'] == old['identity'] and report['indices'] == old['indices'],
                'R18_OLD_ANCHOR_IDENTITY_CHANGED')
        for key in ['full_grid','effective_grid','regional','feasibility','improvement',
                    'qualified_improvement','selection_rejection_reasons']:
            require(not _differences(report[key],old[key],1e-6), 'R18_OLD_ANCHOR_REPLAY:'+key)
        require(report['feasibility']['rejection_reasons'] == ['T90_s_WORSE_THAN_BASELINE']
                and report['improvement']['substantive_improvement'], 'R18_ANCHOR_NOT_ONLY_T90_FAILURE')
        c90 = int(np.count_nonzero(hits[lib.keep] <= tau90))
        require(k90-c90 == expected_shortfalls[old['add']], 'R18_ANCHOR_SHORTFALL_CHANGED')
        replays.append(dict(add=old['add'], identity=report['identity'], on_time_count=c90,
            shortfall_points=k90-c90, T90_s=report['effective_grid']['T90_s'],
            report_sha256=fingerprint(report), historical_record_sha256=fingerprint(old), replay=report))
        reports[old['add']], first_hits[old['add']] = report, hits
    summary = dict(status='PASS', replays=replays, ranked=sorted(replays,key=lambda r:r['add']),
        k90=k90, tau90=tau90, reference_identity=baseline_report['identity'],
        anchor_is_admissible_reference=False, new_R18_candidate_evaluations=0,
        method='All four existing R16 anchors replayed against the original baseline')
    return summary, reports, first_hits


class ThresholdGate:
    """Exact pivot/r exclusive-point T100 proof, followed by dual-donor T90 OR."""
    def __init__(self, lib, baseline_report, check=lambda: None):
        self.lib = lib
        self.baseline, self.donors = _pool(lib.baseline_indices, lib.donor_indices, lib.states)
        expected_reference = fingerprint(sorted(lib.states[i] for i in self.baseline))
        require(baseline_report.get('identity',expected_reference) == expected_reference
                and baseline_report.get('indices',self.baseline) == self.baseline,
                'R18_ORIGINAL_BASELINE_REFERENCE_REQUIRED')
        require(np.asarray(lib.keep).dtype == np.bool_ and np.asarray(lib.keep).ndim == 1,
                'R18_GATE_MASK_SCHEMA')
        require(np.asarray(lib.coords).shape[0] == len(lib.keep), 'R18_GATE_COORDINATE_SHAPE')
        self.mask_ids = np.flatnonzero(lib.keep)
        self.n = len(self.mask_ids)
        require(self.n == baseline_report['effective_grid']['points'] and self.n > 0, 'R18_GATE_MASK_POINT_COUNT')
        self.k90 = (9*self.n+9)//10
        self.tau100 = baseline_report['effective_grid']['T100_s']+1e-6
        self.tau90 = baseline_report['effective_grid']['T90_s']+1e-6
        self.mask_sha256 = hashlib.sha256(np.asarray(lib.keep,dtype=np.uint8).tobytes()).hexdigest()
        self.coordinate_sha256 = hashlib.sha256(np.asarray(lib.coords,dtype='<f8').tobytes()).hexdigest()
        self.matrix_sha256 = getattr(lib,'evidence',{}).get('matrix',{}).get('sha256')
        self.reference_identity = baseline_report.get('identity')
        self.anchor_identities = {str(p):fingerprint(sorted(lib.states[i] for i in
            (set(self.baseline)-{FIXED_REMOVE})|{p})) for p in sorted(ANCHOR_DONORS)}
        self.row_digests, self.bits90 = {}, {}
        for index in sorted(lib.rows):
            check()
            row = np.asarray(lib.rows[index])
            require(row.shape == lib.keep.shape, 'R18_GATE_ROW_SHAPE')
            self.row_digests[index] = hashlib.sha256(np.asarray(row,dtype='<f8').tobytes()).hexdigest()
            self.bits90[index] = pack_on_time(row[lib.keep], self.tau90)
        self.source_binding = fingerprint(dict(matrix_sha256=self.matrix_sha256,
            mask_sha256=self.mask_sha256, coordinate_sha256=self.coordinate_sha256,
            tau100=self.tau100,tau90=self.tau90, baseline_indices=self.baseline,
            rows=[[i,lib.states[i],self.row_digests[i]] for i in sorted(lib.rows)]))
        self.exclusive, self.cache_bindings, self.retained90 = {}, {}, {}
        for remove in self.baseline:
            if remove == FIXED_REMOVE:
                continue
            retained = [i for i in self.baseline if i not in {FIXED_REMOVE,remove}]
            bits = 0
            for index in retained:
                bits |= self.bits90[index]
            self.retained90[remove] = bits
        for pivot in sorted(ANCHOR_DONORS):
            check()
            anchor = sorted((set(self.baseline)-{FIXED_REMOVE})|{pivot})
            on100 = np.stack([np.asarray(lib.rows[i])[lib.keep] <= self.tau100 for i in anchor])
            counts100 = np.count_nonzero(on100,axis=0)
            require(bool(np.all(counts100 > 0)), 'R18_ANCHOR_NOT_FULLY_COVERED_AT_TAU100')
            for position, remove in enumerate(anchor):
                if remove == pivot:
                    continue
                check()
                points = self.mask_ids[on100[position] & (counts100 == 1)]
                self.exclusive[pivot,remove] = points
                self.cache_bindings[pivot,remove] = self._cache_binding(pivot,remove,points)

    def _cache_binding(self, pivot, remove, points):
        return fingerprint(dict(source_binding=self.source_binding, pivot=pivot, remove=remove,
            point_ids_sha256=hashlib.sha256(np.asarray(points,dtype='<i8').tobytes()).hexdigest()))

    def binding(self, candidate):
        return fingerprint(dict(matrix_sha256=self.matrix_sha256, mask_sha256=self.mask_sha256,
            coordinate_sha256=self.coordinate_sha256,
            rows_sha256=[[i,self.lib.states[i],self.row_digests[i]] for i in candidate['indices']]))

    def evidence(self):
        return dict(status='PASS',profile='ROUND18_EXACT_FIRST_HIT_GATES_V1',
            reference_identity=self.reference_identity, anchor_donors=sorted(ANCHOR_DONORS),
            anchor_identities=self.anchor_identities,
            tau100=self.tau100,tau90=self.tau90,k90=self.k90,mask_point_count=self.n,
            mask_sha256=self.mask_sha256,coordinate_sha256=self.coordinate_sha256,
            matrix_sha256=self.matrix_sha256,source_binding_sha256=self.source_binding,
            exclusive_points={str(p):{str(r):dict(pivot=p,remove=r,count=len(ids),point_ids=ids.tolist(),
                point_ids_sha256=hashlib.sha256(np.asarray(ids,dtype='<i8').tobytes()).hexdigest(),
                cache_binding_sha256=self.cache_bindings[p,r]) for (pv,r),ids in self.exclusive.items() if pv == p}
                for p in sorted(ANCHOR_DONORS)},
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
            input_binding_sha256=self.binding(candidate),
            exclusive_cache_binding_sha256=self.cache_bindings[candidate['pivot'],candidate['remove']])

    def classify(self, candidate):
        remove, add, pivot = candidate['remove'],candidate['add'],candidate['pivot']
        pair = candidate['add_pair']
        require(type(pair) is list and len(pair) == 2 and pair == sorted(set(pair))
                and EXCLUDED_DONOR not in pair and set(pair) <= set(self.donors)
                and bool(set(pair) & ANCHOR_DONORS), 'R18_GATE_OPERATION_SCOPE')
        require(pivot == min(set(pair) & ANCHOR_DONORS) and add == next(i for i in pair if i != pivot)
                and (pivot,remove) in self.exclusive and remove != FIXED_REMOVE,
                'R18_GATE_CANONICAL_PIVOT')
        expected = sorted((set(self.baseline)-{FIXED_REMOVE,remove})|set(pair))
        require(candidate['indices'] == expected and candidate['identity'] == fingerprint(sorted(self.lib.states[i] for i in expected))
                and candidate['remove_pair'] == sorted([FIXED_REMOVE,remove]), 'R18_GATE_CANDIDATE_IDENTITY')
        points = self.exclusive[pivot,remove]
        require(self.cache_bindings[pivot,remove] == self._cache_binding(pivot,remove,points),
                'R18_EXCLUSIVE_CACHE_BINDING')
        failures = points[np.asarray(self.lib.rows[add])[points] > self.tau100]
        if len(failures):
            point = int(failures[0])
            cert = self._certificate(candidate,'T100')
            values = []
            for index in expected:
                value = float(self.lib.rows[index][point])
                require(value > self.tau100, 'R18_T100_WITNESS_NOT_FAILURE')
                values.append(dict(index=index,first_hit_s=value if math.isfinite(value) else None,
                    classification='FINITE_LATE' if math.isfinite(value) else 'NO_FIRST_HIT'))
            cert.update(point_id=point,coordinates=np.asarray(self.lib.coords[point]).tolist(),source_values=values,
                source_values_sha256=fingerprint(values))
            return 'T100',cert
        donor_bits = self.bits90[pair[0]] | self.bits90[pair[1]]
        c90 = count_on_time_bits(self.retained90[remove],donor_bits,self.n)
        if c90 < self.k90:
            bits = self.retained90[remove] | donor_bits
            raw = bits.to_bytes((self.n+7)//8,'little')
            classifications = np.unpackbits(np.frombuffer(raw,dtype=np.uint8),bitorder='little',count=self.n)
            cert = self._certificate(candidate,'T90')
            cert.update(c90=c90,on_time_point_count=c90,
                classification_sha256=hashlib.sha256(classifications.tobytes()).hexdigest())
            return 'T90',cert
        return 'FULL',None
