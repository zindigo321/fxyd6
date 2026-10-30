"""Fixed R18-centered single replacements of freshly verified archived assets.

The R14 pure evaluator is shared; R19 reference policy, certificates and finite
space are local. Native simulation and historical candidate result reuse are
deliberately absent.
"""
from contextlib import ExitStack
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import shutil
import time

import numpy as np

from src.round13.common import fingerprint, read, record, require, sha, write
from src.round14.science import evaluate, union

ROOT = Path(__file__).resolve().parents[2]
DECLARED = 60004
TARGET = 'YangtzeRiverDelta_Island_1'
CENTER_IDENTITY = 'fa31ae444cd7afcf008b9d8d4d10a8ce6a8b8533c4d8f68c27bcf0003106d372'
BASELINE_IDENTITY = 'c1fbd71e9dfca4e0a7d0d603d496fff8a71e2bc406d12eee113ab2bc4207b71d'
PARTITIONS = ('GAP', 'T100', 'T90', 'FULL')


def _pool(center, donors, states):
    s, d = sorted(center), sorted(donors)
    require(len(s) == len(set(s)) == 28 and len(d) == len(set(d)) == 2143,
            'ROUND19_POOL_CARDINALITY')
    require(not set(s) & set(d) and sorted(s+d) == list(range(2171)), 'ROUND19_POOL_EXACT_SET')
    require(all(type(i) is int and i in states for i in s+d)
            and len({states[i] for i in s+d}) == 2171, 'ROUND19_POOL_STATES')
    require({2021, 2023} <= set(s) and {1217, 1284} <= set(d), 'ROUND19_CENTER_MEMBERSHIP')
    require(fingerprint(sorted(states[i] for i in s)) == CENTER_IDENTITY, 'ROUND19_CENTER_IDENTITY')
    return s, d


def iter_candidates(center, donors, states, check=lambda: None):
    s, d = _pool(center, donors, states)
    ordinal = 0
    for remove in s:
        retained = set(s)-{remove}
        for add in d:
            if ordinal % 512 == 0:
                check()
            indices = sorted(retained | {add})
            require(len(set(indices) ^ set(s)) == 2, 'ROUND19_NOT_ONE_SWAP')
            yield dict(ordinal=ordinal, remove=remove, add=add, indices=indices,
                       identity=fingerprint(sorted(states[i] for i in indices)))
            ordinal += 1
    check()


def neighborhood_summary(center, donors, states, check=lambda: None):
    identities = set()
    order, pairs = hashlib.sha256(), hashlib.sha256()
    count, first, last = 0, None, None
    for item in iter_candidates(center, donors, states, check):
        require(item['identity'] not in identities, 'ROUND19_IDENTITY_COLLISION')
        identities.add(item['identity'])
        order.update((item['identity']+'\n').encode('ascii'))
        pairs.update((str(item['remove'])+','+str(item['add'])+'\n').encode('ascii'))
        first = item if first is None else first
        last = item
        count += 1
    require(count == DECLARED, 'ROUND19_SPACE_CARDINALITY')
    return dict(declared_candidates=count, unique_identities=len(identities),
        identity_order_sha256=order.hexdigest(), pair_order_sha256=pairs.hexdigest(),
        center_indices=sorted(center), donor_indices=sorted(donors), first=first, last=last,
        search_center_identity=CENTER_IDENTITY, improvement_reference=CENTER_IDENTITY,
        original_constraint_reference=BASELINE_IDENTITY,
        traversal='remove ascending, donor ascending',
        candidate_rule='sorted((fixed S - {remove}) union {add})',
        identity_rule='SHA256 canonical JSON sorted original producer float.hex state tokens',
        candidate_REUSED=0, history_does_not_supply_R19_candidate_completion=True)


def annotate(report, center_report):
    """Keep the old B0 result explicit and apply the fixed-S improvement gate."""
    require(center_report['identity'] == CENTER_IDENTITY, 'ROUND19_WRONG_IMPROVEMENT_REFERENCE')
    reduction = center_report['regional']['pooled_internal']['max_s']-report['regional']['pooled_internal']['max_s']
    improvement = dict(Tmax_reduction_s=reduction, minimum_required_s=1., uncertainty_margin_s=1e-6,
        substantive_improvement=reduction-1e-6 >= 1., conservative_lower_bound_s=reduction-1e-6)
    report['improvement_vs_original_baseline'] = dict(report['improvement'])
    report['improvement_vs_R18_incumbent'] = improvement
    report['qualified_for_round19'] = bool(report['feasibility']['feasible'] and improvement['substantive_improvement'])
    report['ranking_key'] = [report['regional']['pooled_internal']['max_s'],
        report['regional']['pooled_internal']['mean_s'], report['effective_grid']['T100_s'],
        report['effective_grid']['T90_s'], report['identity']]
    report['round19_selection_rejection_reasons'] = list(report['feasibility']['rejection_reasons'])
    if not improvement['substantive_improvement']:
        report['round19_selection_rejection_reasons'].append('Tmax_REDUCTION_VS_R18_INCUMBENT_BELOW_CONSERVATIVE_ONE_SECOND_GATE')
    return report


def select(reports):
    eligible = [r for r in reports if r['qualified_for_round19']]
    return min(eligible, key=lambda r: tuple(r['ranking_key'])) if eligible else None


def intersects_open_gap(span, left, right):
    return span[0] < right and span[1] > left


def side_witnesses(raw, retained, left, right):
    before = [(i, span) for i in retained for span in raw[i] if span[1] <= left]
    after = [(i, span) for i in retained for span in raw[i] if span[0] >= right]
    return before, after


def pack_on_time(values, tau):
    a = np.asarray(values)
    require(a.ndim == 1 and not np.isnan(a).any() and not np.isneginf(a).any(), 'ROUND19_INVALID_HIT_SENTINEL')
    finite = a[np.isfinite(a)]
    require(not (finite < 0).any() and not (finite > 604800).any(), 'ROUND19_INVALID_HIT_TIME')
    require(math.isfinite(tau) and 0 <= tau <= 604800.000001, 'ROUND19_DEADLINE')
    return int.from_bytes(np.packbits(a <= tau, bitorder='little').tobytes(), 'little')


def count_on_time_bits(retained, donor, point_count):
    require(type(point_count) is int and point_count > 0 and type(retained) is int and type(donor) is int
            and retained >= 0 and donor >= 0, 'ROUND19_BITSET_SCHEMA')
    require(retained >> point_count == donor >> point_count == 0, 'ROUND19_NONZERO_PADDING')
    return (retained | donor).bit_count()


class Gate:
    """Two-sided raw gap proof followed by exact first-visit necessary gates."""
    def __init__(self, lib, baseline_report, center_report, check=lambda: None):
        self.lib = lib
        self.center, self.donors = _pool(lib.center_indices, lib.donor_indices19, lib.states)
        require(baseline_report['identity'] == BASELINE_IDENTITY and center_report['identity'] == CENTER_IDENTITY,
                'ROUND19_GATE_REFERENCE_BINDING')
        self.tau100 = baseline_report['effective_grid']['T100_s']+1e-6
        self.tau90 = baseline_report['effective_grid']['T90_s']+1e-6
        self.mask_ids = np.flatnonzero(lib.keep)
        self.n, self.k90 = len(self.mask_ids), (9*len(self.mask_ids)+9)//10
        require(self.n == 43070 and self.k90 == 38763, 'ROUND19_GATE_MASK')
        self.mask_sha256 = hashlib.sha256(np.asarray(lib.keep, dtype=np.uint8).tobytes()).hexdigest()
        self.coordinate_sha256 = hashlib.sha256(np.asarray(lib.coords, dtype='<f8').tobytes()).hexdigest()
        self.matrix_sha256 = getattr(lib, 'evidence', {}).get('matrix', {}).get('sha256')
        self.raw, self.payload, self.interval_digests = {}, {}, {}
        for i in sorted(lib.states):
            check()
            require(set(lib.intervals[i]) == set(lib.targets) and lib.assets[i]['state'] == lib.states[i],
                    'ROUND19_GAP_SOURCE_SCHEMA')
            spans = []
            for span in lib.intervals[i][TARGET]:
                require(isinstance(span, (list, tuple)) and len(span) == 2, 'ROUND19_INTERVAL_SHAPE')
                a, b = map(float, span)
                require(math.isfinite(a) and math.isfinite(b) and 0 <= a <= b <= 604800, 'ROUND19_INTERVAL_WINDOW')
                spans.append([a, b])
            self.raw[i] = spans
            self.payload[i] = lib.assets[i]['regional_data_sha256']
            self.interval_digests[i] = fingerprint(spans)
        merged = union([span for i in self.center for span in self.raw[i]])
        gaps = [(b[0]-a[1], a[1], b[0]) for a, b in zip(merged, merged[1:])]
        require(bool(gaps), 'ROUND19_CENTER_NO_GAPS')
        self.length, self.left, self.right = max(gaps)
        require(abs(self.left-242031.721879453) <= 1e-6 and abs(self.right-374083.009268146) <= 1e-6,
                'ROUND19_REPLAY_GAP_ENDPOINTS')
        require(abs(self.length-center_report['regional']['pooled_internal']['max_s']) <= 1e-6
                and merged == center_report['regional']['targets'][TARGET]['merged_intervals'], 'ROUND19_REPLAY_GAP_LENGTH')
        require(not any(intersects_open_gap(span,self.left,self.right) for i in self.center for span in self.raw[i]),
                'ROUND19_CENTER_INSIDE_GAP')
        self.inside = {i: [span for span in spans if intersects_open_gap(span,self.left,self.right)]
                       for i,spans in self.raw.items()}
        self.before = [i for i in self.center if any(b <= self.left for a,b in self.raw[i])]
        self.after = [i for i in self.center if any(a >= self.right for a,b in self.raw[i])]
        require(self.before == [911,974,1412,2021,2049] and self.after == [38,263,548,676,974,1412,2049],
                'ROUND19_REPLAY_GAP_OWNERS')
        self.row_digests, self.bits90 = {}, {}
        for i in sorted(lib.rows):
            check()
            row = np.asarray(lib.rows[i])
            require(row.shape == np.asarray(lib.keep).shape, 'ROUND19_ROW_SHAPE')
            self.row_digests[i] = hashlib.sha256(np.asarray(row,dtype='<f8').tobytes()).hexdigest()
            self.bits90[i] = pack_on_time(row[lib.keep], self.tau90)
        self.source_binding = fingerprint(dict(matrix_sha256=self.matrix_sha256, mask_sha256=self.mask_sha256,
            coordinate_sha256=self.coordinate_sha256, center_identity=CENTER_IDENTITY,
            tau100=self.tau100, tau90=self.tau90,
            rows=[[i,lib.states[i],self.row_digests[i],self.payload[i]] for i in sorted(lib.rows)]))
        self.retained90, self.failed100, self.cache_bindings = {}, {}, {}
        for remove in self.center:
            check()
            retained = [i for i in self.center if i != remove]
            bits = 0
            for i in retained:
                bits |= self.bits90[i]
            self.retained90[remove] = bits
            minima = np.min(np.stack([np.asarray(lib.rows[i]) for i in retained]), axis=0)
            points = self.mask_ids[minima[lib.keep] > self.tau100]
            self.failed100[remove] = points
            self.cache_bindings[remove] = self._cache_binding(remove)
        self.proof_sha256 = fingerprint(self.evidence(include_digest=False))

    def evidence(self, include_digest=True):
        result = dict(status='PASS', profile='ROUND19_FIXED_S_GAP_AND_FIRST_HIT_GATES',
            center_identity=CENTER_IDENTITY, original_constraint_reference_identity=BASELINE_IDENTITY,
            center_indices=self.center, donor_indices=self.donors, target=TARGET,
            L=self.left, R=self.right, Tmax_lower_bound_s=self.length, merge_tolerance_s=1e-6,
            tau100=self.tau100,tau90=self.tau90,n=self.n,k90=self.k90,
            mask_sha256=self.mask_sha256, coordinate_sha256=self.coordinate_sha256,
            matrix_sha256=self.matrix_sha256,source_binding_sha256=self.source_binding,
            before_center_assets=self.before,after_center_assets=self.after,
            bridge_donors=[i for i in self.donors if self.inside[i]],
            nonbridge_donors=[i for i in self.donors if not self.inside[i]],
            raw_asset_intervals={str(i):a for i,a in self.raw.items()},
            source_payload_sha256={str(i):v for i,v in self.payload.items()},
            asset_interval_sha256={str(i):v for i,v in self.interval_digests.items()},
            cache_bindings={str(i):v for i,v in self.cache_bindings.items()},
            priority=list(PARTITIONS),bitset_effective_bits=self.n,bitset_padding_bits=(-self.n)%8,
            bitset_padding_zero=True, feasibility_inferred_from_gap=False,
            candidate_REUSED=0, gap_is_internal_only_with_both_side_witnesses=True)
        if include_digest:
            result['proof_sha256'] = self.proof_sha256
        return result

    def binding(self, candidate):
        return fingerprint(dict(source_binding=self.source_binding, center_identity=CENTER_IDENTITY,
            original_constraint_reference_identity=BASELINE_IDENTITY,
            rows=[[i,self.lib.states[i],self.row_digests[i],self.payload[i]] for i in candidate['indices']]))

    def _cache_binding(self, remove):
        return fingerprint(dict(source_binding=self.source_binding,center_identity=CENTER_IDENTITY,
            remove=remove,tolerance_s=1e-6,failed_point_ids=self.failed100[remove].tolist(),
            retained90_sha256=fingerprint(hex(self.retained90[remove]))))

    def _common(self, candidate, part):
        return dict(candidate,partition=part,status='PROVEN_NO_ROUND19_IMPROVEMENT' if part=='GAP' else 'KNOWN_INFEASIBLE',
            processing_state=part+'_CERTIFICATE_REJECTED', metrics_status='NOT_EVALUATED',
            full_grid=None,effective_grid=None,regional=None,feasibility='NOT_EVALUATED',first_hits_sha256=None,
            T90_s=None,T100_s=None,Tavg_s=None,Tmax_s=None,qualified_for_round19=False,
            known_infeasible=None if part=='GAP' else True, full_feasibility_evaluation_performed=False,
            source='archived_component_composition',new_native_validation_performed=False,
            whole_constellation_STK_verified=False,native_verified=False,
            center_identity=CENTER_IDENTITY,original_constraint_reference_identity=BASELINE_IDENTITY,
            tau100=self.tau100,tau90=self.tau90,k90=self.k90,
            mask_sha256=self.mask_sha256,coordinate_sha256=self.coordinate_sha256,
            input_binding_sha256=self.binding(candidate),proof_sha256=self.proof_sha256,
            cache_binding_sha256=self.cache_bindings[candidate['remove']])

    def classify(self, candidate):
        remove, add = candidate['remove'],candidate['add']
        require(remove in self.center and add in self.donors, 'ROUND19_CANDIDATE_OPERATION')
        indices = sorted((set(self.center)-{remove})|{add})
        require(candidate['indices'] == indices and candidate['identity'] == fingerprint(sorted(self.lib.states[i] for i in indices)),
                'ROUND19_CANDIDATE_BINDING')
        require(self.cache_bindings[remove] == self._cache_binding(remove), 'ROUND19_GATE_CACHE_BINDING')
        retained = [i for i in self.center if i != remove]
        before, after = side_witnesses(self.raw,retained,self.left,self.right)
        if not self.inside[add] and before and after:
            cert = self._common(candidate,'GAP')
            def witness(item):
                i,span = item
                return dict(index=i,interval=span,state=self.lib.states[i],source_payload_sha256=self.payload[i])
            cert.update(target=TARGET,L=self.left,R=self.right,Tmax_lower_bound_s=self.length,
                before_witness=witness(before[0]),after_witness=witness(after[0]),
                donor_raw_intervals=self.raw[add],donor_interval_sha256=self.interval_digests[add],
                donor_source_payload_sha256=self.payload[add],
                retained_before_asset_count=len({i for i,_ in before}),retained_after_asset_count=len({i for i,_ in after}),
                minimum_required_improvement_s=1.,uncertainty_margin_s=1e-6)
            return 'GAP',cert
        failures = self.failed100[remove][np.asarray(self.lib.rows[add])[self.failed100[remove]] > self.tau100]
        if len(failures):
            point = int(failures[0])
            cert = self._common(candidate,'T100')
            values = []
            for i in indices:
                value = float(self.lib.rows[i][point])
                require(value > self.tau100, 'ROUND19_T100_WITNESS')
                values.append(dict(index=i,state=self.lib.states[i],first_hit_s=value if math.isfinite(value) else None,
                    classification='FINITE_LATE' if math.isfinite(value) else 'NO_FIRST_HIT'))
            cert.update(point_id=point,coordinates=np.asarray(self.lib.coords[point]).tolist(),in_mask=True,
                source_values=values,source_values_sha256=fingerprint(values))
            return 'T100',cert
        c90 = count_on_time_bits(self.retained90[remove],self.bits90[add],self.n)
        if c90 < self.k90:
            bits = self.retained90[remove] | self.bits90[add]
            classes = np.unpackbits(np.frombuffer(bits.to_bytes((self.n+7)//8,'little'),dtype=np.uint8),
                                   bitorder='little',count=self.n)
            cert = self._common(candidate,'T90')
            cert.update(c90=c90,on_time_point_count=c90,
                classification_sha256=hashlib.sha256(classes.tobytes()).hexdigest(),bitset_padding_zero=True)
            return 'T90',cert
        return 'FULL',None


ThresholdGate = Gate


def prepare(lib, baseline_report, center_report, check=lambda: None):
    return Gate(lib,baseline_report,center_report,check)


def _records(path):
    """A partial final JSONL line is evidence loss, never a verified item."""
    with Path(path).open(encoding='utf8') as stream:
        for line in stream:
            require(line.endswith('\n'), 'ROUND19_PARTIAL_JSONL_LINE')
            if line.strip():
                yield json.loads(line)


def verify_full_report_readback(out, expected_count, targets, check=lambda: None):
    """Read every durable full report against its summary and independent check.

    The projection only shares the representation convention that operation
    fields are metadata. No numerical evaluator or decision primitive is used.
    """
    out=Path(out)
    paths=[out/(name+'.jsonl') for name in ('candidates','candidate_summary','checker')]
    metadata={'ordinal','remove','add','partition','processing_state'}
    seen=set();previous_ordinal=-1;count=0;order=hashlib.sha256()
    fields=('identity','indices','ordinal','remove','add','partition')
    for full,compact,checked in itertools.zip_longest(*[_records(p) for p in paths]):
        check()
        require(full is not None and compact is not None and checked is not None,
                'ROUND19_FULL_REPORT_READBACK_LENGTH')
        require(not full.get('_compact') and full.get('partition')=='FULL' and compact.get('_compact') is True,
                'ROUND19_FULL_REPORT_READBACK_SCHEMA')
        require(all(full.get(key)==compact.get(key) for key in fields)
            and checked.get('identity')==full.get('identity'), 'ROUND19_FULL_REPORT_READBACK_ORDER')
        identity,ordinal=full['identity'],full['ordinal']
        require(identity not in seen and type(ordinal) is int and ordinal>previous_ordinal,
                'ROUND19_FULL_REPORT_READBACK_DUPLICATE_OR_ORDER')
        seen.add(identity);previous_ordinal=ordinal
        scientific={k:v for k,v in full.items() if k not in metadata}
        digest=fingerprint(scientific)
        require(compact.get('main_output_sha256')==digest and checked.get('main_output_sha256')==digest
            and checked.get('status')=='PASS' and checked.get('differences')==[],
            'ROUND19_FULL_REPORT_READBACK_CHECKER_BINDING')
        regional_report=full.get('regional',{})
        require(set(regional_report.get('targets',{}))==set(targets), 'ROUND19_FULL_REPORT_READBACK_TARGETS')
        for target in targets:
            obj=regional_report['targets'][target]
            require(all(isinstance(obj.get(k),list) for k in
                ('raw_intervals','merged_intervals','internal_gaps','boundary_segments'))
                and isinstance(obj.get('internal'),dict) and isinstance(obj.get('boundary_inclusive'),dict),
                'ROUND19_FULL_REPORT_READBACK_REGIONAL_DETAILS')
        require(isinstance(full.get('feasibility'),dict)
            and isinstance(full['feasibility'].get('rejection_reasons'),list)
            and isinstance(full.get('round19_selection_rejection_reasons'),list),
            'ROUND19_FULL_REPORT_READBACK_REJECTION_DETAILS')
        order.update((identity+','+digest+'\n').encode('ascii'))
        count+=1
    require(count==expected_count,'ROUND19_FULL_REPORT_READBACK_COUNT')
    return dict(status='PASS',full_reports_read_back=count,expected_full_reports=expected_count,
        complete_raw_merged_internal_and_boundary_intervals_present=True,
        full_report_scientific_hashes_match_compact_and_independent_checker=True,
        exact_order_and_count_verified=True,ordered_report_hash_sha256=order.hexdigest(),
        sources=[record(p,check) for p in paths],
        shared_representation='Only ordinal/remove/add/partition/processing_state are excluded from scientific hashes',
        numerical_algorithms_called=False)


def _pointwise(old_hits, hits):
    require(old_hits.shape == hits.shape == (43424,), 'ROUND19_REPLAY_POINT_SHAPE')
    require(not np.isnan(old_hits).any() and not np.isneginf(old_hits).any(), 'ROUND19_REPLAY_INVALID_SENTINEL')
    classes = int(np.count_nonzero(np.isfinite(old_hits) != np.isfinite(hits)))
    finite = np.isfinite(old_hits) & np.isfinite(hits)
    error = float(np.max(np.abs(old_hits[finite]-hits[finite]),initial=0.))
    require(classes == 0 and error <= 1e-6, 'ROUND19_R18_POINTWISE_MISMATCH')
    return dict(status='PASS',points_compared=43424,classification_difference_count=classes,max_absolute_error_s=error)


def _export_orbits(out, selected, lib, cfg, retained):
    from src.round13.inputs import state_key, ORBIT_FIELDS
    path = out/'selected_orbits.csv'
    prior = Path(cfg['r18_delivery'])/'sealed/science/selected_orbits.csv'
    if retained:
        shutil.copyfile(prior,path)
        require(sha(path) == sha(prior) == '7b9480f8a1aef119b73cd2e1732ce45845b1634886492a8c5857636ad8654365'
                and path.stat().st_size == 5199, 'ROUND19_RETAINED_CSV_BYTES')
    else:
        rows = [dict(sat_id=f'Sat{n:03d}',catalog_index=i,
            **{k:repr(float(lib.assets[i]['row'][k])) for k in ORBIT_FIELDS})
            for n,i in enumerate(selected['indices'],1)]
        with path.open('w',encoding='utf8',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    with path.open(encoding='utf8',newline='') as stream:
        restored = list(csv.DictReader(stream))
    require(len(restored) == 28,'ROUND19_ORBIT_CSV_COUNT')
    for i,row in zip(selected['indices'],restored):
        require(state_key(row)==lib.states[i] and all(float(row[k]).hex()==float(lib.assets[i]['row'][k]).hex()
            for k in ORBIT_FIELDS),'ROUND19_ORBIT_CSV_ROUNDTRIP')
    write(out/'selection_protocol.json',dict(status='PASS',identity=selected['identity'],indices=selected['indices'],
        original_constraint_reference=BASELINE_IDENTITY,search_center=CENTER_IDENTITY,improvement_reference=CENTER_IDENTITY,
        retained_R18_incumbent=retained,relative_to_S=dict(removed=sorted(set(lib.center_indices)-set(selected['indices'])),
            added=sorted(set(selected['indices'])-set(lib.center_indices))),
        relative_to_B0=dict(removed=sorted(set(lib.baseline_indices)-set(selected['indices'])),
            added=sorted(set(selected['indices'])-set(lib.baseline_indices))),
        saved_altitudes_km={str(i):float(lib.assets[i]['row']['altitude_km']) for i in selected['indices']},
        source='archived_component_composition',new_native_validation_performed=False,
        whole_constellation_STK_verified=False,float_roundtrip_verified=True,csv=record(path)))


def science_job(work, out, life, lock=lambda: None):
    """Generate and independently verify each R19 item in one frozen attempt."""
    from .inputs import load, pool_diagnostic
    from .checker import IndependentChecker, compact_report
    from src.round14.worker import save_details, baseline_assertions
    from src.round14.checker import _differences, verify_baseline_whole
    work,out=Path(work),Path(out)
    cfg=read(ROOT/'configs/round19.json')
    check=lambda:life.check(True)
    begin=time.perf_counter()
    counts=dict(declared_candidates=DECLARED,GAP_generated=0,GAP_verified=0,T100_generated=0,T100_verified=0,
        T90_generated=0,T90_verified=0,FULL_evaluated=0,FULL_verified=0,unprocessed=DECLARED,unknown=0,
        qualified_for_round19=0,candidate_REUSED=0,retained_R18_incumbent=True,B0_replayed=0,S_replayed=0)
    phase_events=[]
    def phase(name):
        phase_events.append(dict(phase=name,since_science_start_s=time.perf_counter()-begin,lifecycle_elapsed_s=life.elapsed()))
        write(out/'phase_timings.json',dict(events=phase_events,overlapping_worker_walls_added=False))
    lib=load(cfg,work,check)
    try:
        lock()
        phase('all_2171_assets_freshly_verified')
        write(out/'asset_context_verification.json',lib.evidence)
        write(out/'input_identity.json',dict(status='PASS',archive=record(cfg['archive'],check),used_members=dict(lib.arc.used)))
        frozen=read(work/'frozen/contract.json')['metadata']
        require(lib.baseline_indices==frozen['baseline_indices'] and lib.center_indices==frozen['center_indices']
            and lib.donor_indices19==frozen['donor_indices19'] and {str(i):v for i,v in lib.states.items()}==frozen['states'],
            'ROUND19_FROZEN_POOL_CHANGED')
        baseline,bhits=evaluate(lib.baseline_indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states)
        center,chits=evaluate(lib.center_indices,lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
        require(baseline['identity']==BASELINE_IDENTITY and center['identity']==CENTER_IDENTITY,'ROUND19_REFERENCE_IDENTITIES')
        checker=IndependentChecker(lib,baseline,center,check)
        for name,report,hits,old in [('baseline',baseline,bhits,lib.r18_baseline),('center',center,chits,lib.r18_selected)]:
            checked=checker.verify(report['indices'],report,hits,baseline if name=='center' else None)
            write(out/(name+'_checker.json'),checked)
            require(checked['status']=='PASS','ROUND19_REFERENCE_INDEPENDENT_CHECK:'+name)
            for key in ['full_grid','effective_grid','regional']:
                require(not _differences(old[key],report[key],1e-6),'ROUND19_R18_REFERENCE_REPLAY:'+name+'/'+key)
            old_name='baseline' if name=='baseline' else 'selected'
            old_path=Path(cfg['r18_delivery'])/('sealed/science/'+old_name+'_first_hits.npy')
            replay=_pointwise(np.load(old_path,allow_pickle=False),hits)
            replay.update(reference=record(old_path),reference_report_identity=old['identity'])
            write(out/(name+'_r18_readback.json'),replay)
            save_details(out,name,report,hits,lib)
        baseline_assertions(baseline,lib.k13_baseline)
        whole=verify_baseline_whole(baseline,bhits,lib.baseline_whole['hits'],lib.baseline_whole['intervals'],lib.targets)
        write(out/'baseline_whole_readback.json',whole)
        require(whole['status']=='PASS','ROUND19_B0_WHOLE_READBACK')
        require(center['regional']['pooled_internal']['gap_count']==175,'ROUND19_CENTER_GAP_DENOMINATOR')
        counts.update(B0_replayed=1,S_replayed=1)
        phase('B0_and_S_pointwise_regional_independent_replays')
        write(out/'expanded_pool_raw_domain_diagnostic.json',pool_diagnostic(lib,bhits))
        write(out/'reference_roles.json',dict(original_constraint_reference=baseline['identity'],search_center=center['identity'],
            improvement_reference=center['identity'],fixed_throughout_traversal=True))
        space=checker.neighborhood_summary(check) if hasattr(checker,'neighborhood_summary') else None
        if space is None:
            from .checker import neighborhood_summary as independent_space
            space=independent_space(lib.center_indices,lib.donor_indices19,lib.states,check)
        for key in ['declared_candidates','unique_identities','identity_order_sha256','pair_order_sha256']:
            require(space[key]==frozen['space_summary'][key],'ROUND19_INDEPENDENT_SPACE:'+key)
        write(out/'independent_space_definition.json',space)
        gate=Gate(lib,baseline,center,check)
        write(out/'necessary_gate_context.json',gate.evidence())
        context_check=checker.verify_gate_evidence(gate.evidence())
        write(out/'independent_necessary_gate_context.json',context_check)
        require(context_check['status']=='PASS','ROUND19_INDEPENDENT_GATE_CONTEXT')
        phase('independent_space_and_certificate_context')
        names=['ledger','candidates','candidate_summary','checker','gap_certificates','gap_certificate_checker',
            't100_certificates','t100_certificate_checker','t90_certificates','t90_certificate_checker']
        best=best_hits=None
        candidate_start=time.perf_counter()
        with ExitStack() as stack:
            streams={n:stack.enter_context((out/(n+'.jsonl')).open('w',encoding='utf8')) for n in names}
            def emit(name,obj):
                streams[name].write(json.dumps(obj,ensure_ascii=False,allow_nan=False,separators=(',',':'))+'\n')
            for item in iter_candidates(lib.center_indices,lib.donor_indices19,lib.states,check):
                part,certificate=gate.classify(item)
                require(checker.partition(item)==part,'ROUND19_INDEPENDENT_PARTITION')
                if part!='FULL':
                    counts[part+'_generated']+=1
                    emit(part.lower()+'_certificates',certificate)
                    checked=checker.verify_certificate(item,certificate)
                    emit(part.lower()+'_certificate_checker',checked)
                    require(checked['status']=='PASS','ROUND19_CERTIFICATE_CHECK:'+part)
                    counts[part+'_verified']+=1
                    emit('ledger',dict(item,partition=part,processing_state=part+'_CERTIFICATE_REJECTED',
                        certificate_sha256=fingerprint(certificate),checker_output_sha256=fingerprint(checked),
                        proof_sha256=checked.get('proof_sha256',gate.proof_sha256)))
                else:
                    check()
                    report,hits=evaluate(item['indices'],lib.rows,lib.intervals,lib.keep,lib.targets,lib.states,baseline)
                    report=annotate(report,center)
                    report.update({k:v for k,v in item.items() if k not in {'indices','identity'}})
                    report['partition']='FULL'
                    require(report['identity']==item['identity'],'ROUND19_FULL_IDENTITY')
                    counts['FULL_evaluated']+=1
                    emit('candidates',report)
                    checked=checker.verify(item['indices'],report,hits,baseline,item['remove'],item['add'])
                    emit('candidate_summary',compact_report(report));emit('checker',checked)
                    require(checked['status']=='PASS','ROUND19_FULL_NUMERICAL_CHECK')
                    counts['FULL_verified']+=1
                    emit('ledger',dict(item,partition=part,processing_state='FULLY_EVALUATED_AND_INDEPENDENTLY_VERIFIED',
                        main_output_sha256=checked['main_output_sha256'],checker_output_sha256=checked['checker_output_sha256']))
                    if report['qualified_for_round19']:
                        counts['qualified_for_round19']+=1
                        chosen=select([report]+([best] if best else []))
                        if chosen is report:
                            best,best_hits=report,hits.copy()
                counts['unprocessed']=DECLARED-counts['GAP_generated']-counts['T100_generated']-counts['T90_generated']-counts['FULL_evaluated']
                if item['ordinal']==1023:
                    batch=time.perf_counter()-candidate_start
                    write(out/'first_batch_throughput.json',dict(status='MEASURED_DURING_FROZEN_FORMAL_ATTEMPT',
                        candidates=1024,wall_s=batch,candidates_per_s=1024/batch,counts=counts.copy(),lifecycle_elapsed_s=life.elapsed()))
                if item['ordinal']%512==0:
                    check()
                    for stream in streams.values():stream.flush()
                    write(out/'progress.json',dict(counts,completed=False,verified_prefix_ordinal=item['ordinal'],
                        scientific_wall_s=time.perf_counter()-begin,optimization_outcome='PARTIAL_NOT_CONCLUDED'))
        phase('all_candidates_live_independently_verified')
        write(out/'independent_full_report_readback.json',verify_full_report_readback(
            out,counts['FULL_evaluated'],lib.targets,check))
        selection=checker.selection()
        require(selection['selected_identity']==(best['identity'] if best else None),'ROUND19_INDEPENDENT_SELECTION')
        selection['status']='PASS'
        write(out/'independent_selection.json',selection)
        terminal=checker.verify_completion(*[_records(out/(n+'.jsonl')) for n in names if n!='candidates'],
            best['identity'] if best else None,check)
        write(out/'independent_terminal_verification.json',terminal)
        require(terminal['status']=='PASS','ROUND19_EXACT_SET_COMPLETION')
        aliases={'FULL_evaluated':'fully_evaluated','FULL_verified':'fully_independently_verified',
            'GAP_generated':'GAP_certificate_rejected','GAP_verified':'GAP_certificate_verified',
            'T100_generated':'T100_certificate_rejected','T100_verified':'T100_certificate_verified',
            'T90_generated':'T90_certificate_rejected','T90_verified':'T90_certificate_verified',
            'unprocessed':'unprocessed','unknown':'unknown','qualified_for_round19':'qualified_for_round19',
            'candidate_REUSED':'candidate_REUSED'}
        for main_key,checker_key in aliases.items():
            require(counts[main_key]==terminal[checker_key],'ROUND19_TERMINAL_COUNT_BINDING:'+main_key)
        selected,shits=(best,best_hits) if best else (center,chits)
        counts['retained_R18_incumbent']=best is None
        save_details(out,'selected',selected,shits,lib)
        selected_check=checker.verify(selected['indices'],selected,shits,baseline,
            best['remove'] if best else None,best['add'] if best else None)
        write(out/'selected_checker.json',selected_check)
        require(selected_check['status']=='PASS','ROUND19_SELECTED_READBACK')
        _export_orbits(out,selected,lib,cfg,best is None)
        write(out/'boundary_tradeoffs.json',dict(baseline=baseline['regional'],center=center['regional'],selected=selected['regional'],
            boundary_is_primary_constraint=False,internal_and_boundary_objectives_distinct=True))
        def delta(reference):
            return dict(T90_s=selected['effective_grid']['T90_s']-reference['effective_grid']['T90_s'],
                T100_s=selected['effective_grid']['T100_s']-reference['effective_grid']['T100_s'],
                Tavg_s=selected['regional']['pooled_internal']['mean_s']-reference['regional']['pooled_internal']['mean_s'],
                Tmax_s=selected['regional']['pooled_internal']['max_s']-reference['regional']['pooled_internal']['max_s'],
                gap_count=selected['regional']['pooled_internal']['gap_count']-reference['regional']['pooled_internal']['gap_count'],
                boundary_Tmax_s=selected['regional']['pooled_boundary_inclusive']['max_s']-reference['regional']['pooled_boundary_inclusive']['max_s'])
        write(out/'metric_comparison.json',dict(relative_to_B0=delta(baseline),relative_to_S=delta(center),
            full_grid=selected['full_grid'],effective_grid=selected['effective_grid'],
            gap_denominator=selected['regional']['pooled_internal']['gap_count']))
        write(out/'research_scope.json',dict(status='PASS',conditional_offline_scope='Fixed R18-centered complete saved-catalog single swap',
            source='archived_component_composition',new_native_validation_performed=False,whole_constellation_STK_verified=False,
            active_protocol_change_authorized=False,official_readiness='UNRESOLVED',official_score=None,
            next_scientific_run_gate='BLOCKED_PENDING_RULE_CONFIRMATION',
            saved_altitudes_km=sorted({float(lib.assets[i]['row']['altitude_km']) for i in lib.states}),
            assumptions=['saved mixed altitudes 500..700 km','0.81 degree half angles and direct AreaTarget conditional',
                'provisional mask','EOP ends in 2019 but scenario is 2027','archived components do not prove continuous geometry completeness'],
            missing_raw_domain_points=selected['full_grid']['uncovered'],physical_unreachability_inferred=False))
        write(out/'source_preservation.json',lib.preserve())
        for name in ['asset_verification.jsonl','input_asset_verification.jsonl']:
            if (work/name).is_file():shutil.copyfile(work/name,out/name)
        outcome='QUALIFIED_FURTHER_IMPROVEMENT_FOUND' if best else 'NO_FURTHER_QUALIFIED_IMPROVEMENT_IN_DECLARED_R18_CENTERED_SINGLE_SWAP_NEIGHBORHOOD'
        completion=dict(counts,status='PASS',completed=True,optimization_outcome=outcome,
            selected_identity=selected['identity'],scientific_wall_s=time.perf_counter()-begin,
            verified_candidates=sum(counts[p+'_verified'] for p in PARTITIONS))
        write(out/'enumeration_completion.json',completion);write(out/'progress.json',completion)
        phase('selected_full_artifacts_and_source_preservation')
        return completion
    except BaseException:
        counts['unknown']=sum(counts[p+'_generated']-counts[p+'_verified'] for p in PARTITIONS if p!='FULL')+counts['FULL_evaluated']-counts['FULL_verified']
        counts['unprocessed']=DECLARED-counts['GAP_generated']-counts['T100_generated']-counts['T90_generated']-counts['FULL_evaluated']
        write(out/'progress.json',dict(counts,completed=False,scientific_wall_s=time.perf_counter()-begin,
            verified_prefix_count=sum(counts[p+'_verified'] for p in PARTITIONS),optimization_outcome='PARTIAL_NOT_CONCLUDED'))
        raise
    finally:
        lib.close()
