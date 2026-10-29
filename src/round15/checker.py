"""Independent two-swap numerics, raw-interval proof, and exact-set readback.

The frozen input decoder and state-token fingerprint format are shared.  Numeric
helpers below come only from round14's independent checker, never its science
module.  Two-swap minima, enumeration, certificate decisions and completion are
implemented here and do not call round15's production implementation.
"""
import hashlib
import itertools
import math

import numpy as np

from src.round13.common import require, fingerprint
from src.round14.checker import (_coverage, _regional, _decision, _differences,
                                 _digest, verify_baseline_whole)

TARGET='YangtzeRiverDelta_Island_2'
META={'remove','add','ordinal','partition','processing_state'}
CERT_STATUS='PROVEN_NO_SUBSTANTIVE_TMAX_IMPROVEMENT'


def _pool(baseline,donors,states):
    b,d=sorted(baseline),sorted(donors)
    require(len(b)==len(set(b))==28 and len(d)==len(set(d))==32 and not set(b)&set(d),
            'CHECKER_TWO_SWAP_POOL')
    require(all(type(i) is int and i in states for i in b+d)
            and len({states[i] for i in b+d})==60,'CHECKER_STATE_POOL')
    return b,d


def iter_candidates(baseline,donors,states,check=lambda:None):
    """Independent nested-position loops, rather than combination iterators."""
    b,d=_pool(baseline,donors,states);ordinal=0
    for left in range(len(b)-1):
        for right in range(left+1,len(b)):
            retained=[index for pos,index in enumerate(b) if pos!=left and pos!=right]
            for first in range(len(d)-1):
                for second in range(first+1,len(d)):
                    if ordinal%1024==0:check()
                    indices=sorted(retained+[d[first],d[second]])
                    yield dict(ordinal=ordinal,remove=[b[left],b[right]],add=[d[first],d[second]],
                        indices=indices,identity=fingerprint(sorted(states[i] for i in indices)))
                    ordinal+=1
    check()


def neighborhood_summary(baseline,donors,states,check=lambda:None):
    identities=set();order=hashlib.sha256();pairs=hashlib.sha256();count=0;first=last=None
    for item in iter_candidates(baseline,donors,states,check):
        require(item['identity'] not in identities,'CHECKER_IDENTITY_COLLISION')
        identities.add(item['identity']);count+=1
        order.update((item['identity']+'\n').encode('ascii'))
        pairs.update((','.join(map(str,item['remove']+item['add']))+'\n').encode('ascii'))
        first=item if first is None else first;last=item
    return dict(declared_candidates=count,unique_identities=len(identities),identity_order_sha256=order.hexdigest(),
        pair_order_sha256=pairs.hexdigest(),first=first,last=last,baseline_indices=sorted(baseline),donor_indices=sorted(donors),
        method='Independent nested-position enumeration with exact state-set identities')


def _scientific(report):
    return {key:value for key,value in report.items() if key not in META}


def _rank(report):
    return [report['regional']['pooled_internal']['max_s'],report['regional']['pooled_internal']['mean_s'],
            report['effective_grid']['T100_s'],report['effective_grid']['T90_s'],report['identity']]


def compact_report(report):
    """Small completion record; full raw intervals remain in streamed JSONL."""
    if report.get('_compact') is True:return report
    result={key:report[key] for key in ['identity','indices','remove','add','ordinal','partition','source',
        'new_native_validation_performed','whole_constellation_STK_verified','native_verified','first_hits_sha256'] if key in report}
    result.update(_compact=True,qualified_improvement=report['qualified_improvement'],rank=_rank(report),
                  main_output_sha256=fingerprint(_scientific(report)))
    return result


class IndependentChecker:
    def __init__(self,lib,duration=604800,tolerance=1e-6,required_count=28):
        self.lib=lib;self.baseline_indices,self.donors=_pool(lib.baseline_indices,lib.donor_indices,lib.states)
        self.rows,self.intervals,self.states=lib.rows,lib.intervals,lib.states
        self.targets=list(lib.targets);self.keep=np.asarray(lib.keep)
        self.duration,self.tolerance,self.required_count=duration,tolerance,required_count
        shape=np.asarray(self.rows[self.baseline_indices[0]]).shape
        require(len(shape)==1 and self.keep.dtype==np.bool_ and self.keep.shape==shape,'CHECKER_ROW_MASK_SHAPE')
        require(set(self.rows)==set(self.baseline_indices+self.donors),'CHECKER_ROW_POOL')
        self.row_digests={}
        for index,source in self.rows.items():
            a=np.asarray(source);finite=a[np.isfinite(a)]
            require(a.shape==shape and not np.isnan(a).any() and not np.isneginf(a).any()
                    and not (finite<0).any() and not (finite>duration).any(),'CHECKER_INVALID_SOURCE_ROW')
            require(index in self.intervals and set(self.intervals[index])==set(self.targets),'CHECKER_REGIONAL_TARGET_SET')
            self.row_digests[index]=_digest(a)
        self.retained_min={};self.expected={};self.certified={};self.proof_state=None
        self.baseline_reference=self.recompute(self.baseline_indices)[0]

    def enumerate_space(self,check=lambda:None):
        return iter_candidates(self.baseline_indices,self.donors,self.states,check)

    def _hits(self,indices,remove_pair=None,add_pair=None):
        require(len(indices)==len(set(indices)),'CHECKER_DUPLICATE_INDEX')
        original,selected=set(self.baseline_indices),set(indices)
        if selected==original:
            require(remove_pair is None and add_pair is None,'CHECKER_BASELINE_WITH_SWAP_LABEL')
            hits=np.full(self.keep.shape,np.inf)
            for index in self.baseline_indices:np.minimum(hits,self.rows[index],out=hits)
            return hits
        removed,added=sorted(original-selected),sorted(selected-original)
        require(len(removed)==len(added)==2 and set(added).issubset(self.donors),'CHECKER_NOT_TWO_REPLACEMENTS')
        require((remove_pair is None or list(remove_pair)==removed)
                and (add_pair is None or list(add_pair)==added),'CHECKER_TWO_SWAP_LABEL_MISMATCH')
        key=tuple(removed)
        if key not in self.retained_min:
            kept=np.full(self.keep.shape,np.inf)
            for index in self.baseline_indices:
                if index not in removed:np.minimum(kept,self.rows[index],out=kept)
            kept.flags.writeable=False;self.retained_min[key]=kept
        return np.minimum(np.minimum(self.retained_min[key],self.rows[added[0]]),self.rows[added[1]])

    def recompute(self,indices,baseline_report=None,remove_pair=None,add_pair=None):
        indices=list(indices)
        require(all(type(i) is int and i in self.rows and i in self.states for i in indices),'CHECKER_UNAVAILABLE_COMPONENT')
        require(len({self.states[i] for i in indices})==len(indices),'CHECKER_DUPLICATE_STATE')
        hits=self._hits(indices,remove_pair,add_pair)
        raw={target:[] for target in self.targets}
        for index in indices:
            require(set(self.intervals[index])==set(self.targets),'CHECKER_REGIONAL_TARGET_SET')
            for target in self.targets:raw[target]+=self.intervals[index][target]
        report=dict(indices=indices,identity=fingerprint(sorted(self.states[i] for i in indices)),
            unique_state_count=len({self.states[i] for i in indices}),full_grid=_coverage(hits,self.duration),
            effective_grid=_coverage(hits[self.keep],self.duration),regional=_regional(raw,self.targets,self.duration,self.tolerance),
            first_hits_sha256=_digest(hits),input_state_identity=fingerprint([[i,self.states[i]] for i in sorted(indices)]),
            source='archived_component_composition',new_native_validation_performed=False,
            whole_constellation_STK_verified=False,native_verified=False)
        reference=self.baseline_reference if baseline_report is not None else None
        report['feasibility']=_decision(report,reference,self.required_count,self.duration,self.tolerance)
        old=reference['regional']['pooled_internal']['max_s'] if reference else None
        new=report['regional']['pooled_internal']['max_s'];change=old-new if old is not None and new is not None else None
        lower=change-self.tolerance if change is not None else None;substantive=lower is not None and lower>=1.
        report['improvement']=dict(Tmax_reduction_s=change,minimum_required_s=1.,uncertainty_margin_s=self.tolerance,
            substantive_improvement=substantive,conservative_lower_bound_s=lower)
        report['qualified_improvement']=bool(report['feasibility']['feasible'] and substantive)
        report['selection_rejection_reasons']=list(report['feasibility']['rejection_reasons'])
        if not substantive:report['selection_rejection_reasons'].append('Tmax_REDUCTION_BELOW_CONSERVATIVE_ONE_SECOND_GATE')
        return report,hits

    def verify(self,indices,reported,reported_hits,baseline_report=None,remove_pair=None,add_pair=None):
        expected,hits=self.recompute(indices,baseline_report,remove_pair,add_pair)
        scientific=_scientific(reported);differences=_differences(expected,scientific,self.tolerance)
        a=np.asarray(reported_hits);classification=maximum=None
        if a.shape!=hits.shape:differences.append(dict(path='first_hits',reason='SHAPE_MISMATCH'))
        else:
            classification=int(np.count_nonzero(np.isfinite(a)!=np.isfinite(hits)))
            finite=np.isfinite(a)&np.isfinite(hits)
            maximum=float(np.max(np.abs(a[finite]-hits[finite]),initial=0.))
            if classification or maximum>self.tolerance or np.isnan(a).any() or np.isneginf(a).any():
                differences.append(dict(path='first_hits',reason='POINTWISE_MISMATCH'))
            if _digest(a)!=scientific.get('first_hits_sha256'):
                differences.append(dict(path='first_hits_sha256',reason='REPORTED_ARRAY_DIGEST_MISMATCH'))
        comparisons={}
        for target in self.targets:
            spans=expected['regional']['targets'][target]['merged_intervals']
            claimed=reported.get('regional',{}).get('targets',{}).get(target,{}).get('merged_intervals')
            comparisons[target]=dict(expected_merged_count=len(spans),checker_intervals_sha256=fingerprint(spans),
                main_intervals_sha256=fingerprint(claimed),differences=_differences(spans,claimed,self.tolerance,target))
        result=dict(identity=expected['identity'],status='FAIL' if differences else 'PASS',differences=differences,
            points_compared=len(hits),classification_difference_count=classification,max_absolute_first_hit_error_s=maximum,
            absolute_tolerance_s=self.tolerance,relative_tolerance=0,
            input_sha256=fingerprint([[i,self.states[i],self.row_digests[i]] for i in sorted(indices)]),
            main_first_hits_sha256=scientific.get('first_hits_sha256'),checker_first_hits_sha256=_digest(hits),
            main_output_sha256=fingerprint(scientific),checker_output_sha256=fingerprint(expected),
            interval_comparisons=comparisons,qualified_improvement=expected['qualified_improvement'],rank=_rank(expected),
            shared_schema='Frozen validated Library decoding, coordinates, mask and state-token fingerprint format',
            independent_methods='Retained26 iterative minima then two donors; sorted order statistic; cumulative-frontier regions; separate decisions/ranking')
        if not differences:
            self.expected[expected['identity']]=dict(identity=expected['identity'],indices=list(indices),
                qualified_improvement=expected['qualified_improvement'],rank=_rank(expected),
                main_output_sha256=result['main_output_sha256'],checker_output_sha256=result['checker_output_sha256'])
        return result

    def verify_gap_proof(self,proof,baseline_report=None):
        """Rebuild the proof from every original decoded regional payload."""
        self.proof_state=None
        require(self.tolerance==1e-6 and self.duration==604800,'CHECKER_PROOF_FROZEN_NUMERICAL_RULE')
        pool=sorted(self.baseline_indices+self.donors);raw={};payload={}
        require(set(self.intervals)==set(pool) and set(self.lib.assets)==set(pool),'CHECKER_PROOF_ASSET_POOL')
        require(len(self.targets)==len(set(self.targets))==3 and TARGET in self.targets,'CHECKER_PROOF_TARGETS')
        for index in pool:
            require(set(self.intervals[index])==set(self.targets),'CHECKER_PROOF_MISSING_TARGET')
            spans=self.intervals[index][TARGET]
            require(isinstance(spans,list),'CHECKER_PROOF_INTERVAL_SCHEMA')
            converted=[]
            for pair in spans:
                require(isinstance(pair,(list,tuple)) and len(pair)==2
                        and all(type(v) in (int,float) for v in pair),'CHECKER_PROOF_INTERVAL_SCHEMA')
                a,b=map(float,pair);require(math.isfinite(a) and math.isfinite(b) and 0<=a<=b<=self.duration,'CHECKER_PROOF_INVALID_INTERVAL')
                converted.append([a,b])
            asset=self.lib.assets[index];digest=asset['regional_data_sha256']
            require(asset['state']==self.states[index],'CHECKER_PROOF_SOURCE_STATE')
            require(isinstance(digest,str) and len(digest)==64 and all(c in '0123456789abcdef' for c in digest),'CHECKER_PROOF_PAYLOAD_DIGEST')
            raw[index]=converted;payload[index]=digest
        # Independent cumulative-frontier baseline; no main union or proof function.
        baseline_raw={t:[] for t in self.targets}
        for index in self.baseline_indices:
            for target in self.targets:baseline_raw[target]+=self.intervals[index][target]
        regional=_regional(baseline_raw,self.targets,self.duration,self.tolerance)
        gaps=regional['targets'][TARGET]['internal_gaps'];require(gaps,'CHECKER_PROOF_NO_GAP')
        left,right=max(gaps,key=lambda pair:pair[1]-pair[0]);length=right-left
        require(abs(left-69292.439694662)<=self.tolerance and abs(right-242022.755780764)<=self.tolerance,
                'CHECKER_PROOF_ENDPOINTS')
        require(abs(regional['pooled_internal']['max_s']-length)<=self.tolerance,'CHECKER_PROOF_NOT_BASELINE_TMAX')
        inside={i:[p for p in raw[i] if not (p[1]<=left or p[0]>=right)] for i in pool}
        interior=sorted(i for i in pool if inside[i])
        require(interior==[1123] and 1123 in self.donors,'CHECKER_PROOF_INTERIOR_ASSETS')
        require(inside[1123]==[[155654.373767399,155659.896226983]],'CHECKER_PROOF_INTERIOR_INTERVAL')
        before=[i for i in self.baseline_indices if any(b<=left for a,b in raw[i])]
        after=[i for i in self.baseline_indices if any(a>=right for a,b in raw[i])]
        require(before==[911,1370] and len(after)==6,'CHECKER_PROOF_SIDE_ASSETS')
        derived=dict(target=TARGET,L=left,R=right,baseline_Tmax_s=length,merge_tolerance_s=self.tolerance,
            baseline_indices=self.baseline_indices,donor_indices=self.donors,pool_indices=pool,
            baseline_identity=fingerprint(sorted(self.states[i] for i in self.baseline_indices)),interior_assets=interior,
            before_baseline_assets=before,after_baseline_assets=after,
            left_endpoint_owners=[i for i in self.baseline_indices if any(b==left for a,b in raw[i])],
            right_endpoint_owners=[i for i in self.baseline_indices if any(a==right for a,b in raw[i])],
            interior_intervals={'1123':inside[1123]},asset_interval_sha256={str(i):fingerprint(raw[i]) for i in pool},
            source_payload_sha256={str(i):payload[i] for i in pool},raw_asset_intervals={str(i):raw[i] for i in pool})
        require(derived['left_endpoint_owners'] and derived['right_endpoint_owners'],'CHECKER_PROOF_ENDPOINT_OWNERS')
        differences=[]
        for key,value in derived.items():differences+=_differences(value,proof.get(key),self.tolerance,'proof/'+key)
        flags=dict(status='PASS',profile='ROUND15_INTERNAL_GAP_BOUND_V1',feasibility_inferred=False,
                   full_candidate_metrics_computed=False,native_activation_count=0,source='archived_component_composition')
        for key,value in flags.items():differences+=_differences(value,proof.get(key),0,'proof/'+key)
        body={k:v for k,v in proof.items() if k!='proof_sha256'}
        if proof.get('proof_sha256')!=fingerprint(body):differences.append(dict(path='proof/proof_sha256',reason='PROOF_DIGEST'))
        if baseline_report is not None:
            differences+=_differences(regional['pooled_internal'],baseline_report['regional']['pooled_internal'],self.tolerance,'baseline/gaps')
        if not differences:
            self.proof_state=dict(derived,proof_sha256=proof['proof_sha256'],
                interior_flags={i:bool(inside[i]) for i in pool},
                before_flags={i:any(b<=left for a,b in raw[i]) for i in pool},
                after_flags={i:any(a>=right for a,b in raw[i]) for i in pool})
        return dict(status='FAIL' if differences else 'PASS',differences=differences,
            main_proof_sha256=proof.get('proof_sha256'),checker_proof_sha256=fingerprint(derived),
            independently_derived=derived,method='Independent cumulative-frontier baseline and sixty-asset open-gap/side scan',
            schema_shared='Original regional JSON decoded by validated Library; source payload SHA freshly bound')

    def partition(self,candidate):
        require(self.proof_state is not None,'CHECKER_PROOF_NOT_VALIDATED')
        removed,added=list(candidate['remove']),list(candidate['add'])
        require(removed==sorted(set(removed)) and added==sorted(set(added)) and len(removed)==len(added)==2,
                'CHECKER_PAIR_SCHEMA')
        require(set(removed).issubset(self.baseline_indices) and set(added).issubset(self.donors),'CHECKER_PAIR_MEMBERSHIP')
        if any(self.proof_state['interior_flags'][i] for i in added):return 'A'
        if not (set(self.proof_state['before_baseline_assets'])-set(removed)):return 'B'
        return 'C'

    def verify_certificate(self,candidate,record,proof=None):
        require(self.proof_state is not None,'CHECKER_PROOF_NOT_VALIDATED')
        state=self.proof_state;removed,added=candidate['remove'],candidate['add']
        expected_indices=sorted([i for i in self.baseline_indices if i not in removed]+list(added))
        require(self.partition(candidate)=='C','CHECKER_CANNOT_CERTIFY_EXCEPTION')
        require(candidate['indices']==expected_indices and len(expected_indices)==len(set(expected_indices))==28,'CHECKER_CERTIFICATE_STATE_SET')
        identity=fingerprint(sorted(self.states[i] for i in expected_indices))
        require(candidate['identity']==identity,'CHECKER_CERTIFICATE_IDENTITY')
        inside=[i for i in expected_indices if state['interior_flags'][i]]
        before=[i for i in expected_indices if state['before_flags'][i]]
        after=[i for i in expected_indices if state['after_flags'][i]]
        require(not inside and before and after,'CHECKER_CERTIFICATE_NO_INTERNAL_LOWER_BOUND')
        differences=[]
        for key in ['ordinal','remove','add','indices','identity']:
            differences+=_differences(candidate[key],record.get(key),0,'certificate/'+key)
        assertions=dict(partition='C',status=CERT_STATUS,processing_state=CERT_STATUS,
            proof_sha256=state['proof_sha256'],Tmax_lower_bound_s=state['R']-state['L'],metrics_status='NOT_EVALUATED',
            full_grid=None,effective_grid=None,regional=None,feasibility=None,first_hits_sha256=None,
            qualified_improvement=False,source='archived_component_composition',new_native_validation_performed=False,
            whole_constellation_STK_verified=False,native_verified=False)
        for key,value in assertions.items():differences+=_differences(value,record.get(key),self.tolerance,'certificate/'+key)
        if record.get('before_witness') not in before or record.get('after_witness') not in after:
            differences.append(dict(path='certificate/witness',reason='INVALID_SIDE_WITNESS'))
        if proof is not None and proof.get('proof_sha256')!=state['proof_sha256']:
            differences.append(dict(path='certificate/proof',reason='CHANGED_PROOF'))
        result=dict(identity=identity,status='FAIL' if differences else 'PASS',differences=differences,ordinal=candidate['ordinal'],
            proof_sha256=state['proof_sha256'],main_certificate_sha256=fingerprint(record),
            checker_input_sha256=fingerprint([[i,state['asset_interval_sha256'][str(i)],state['source_payload_sha256'][str(i)]] for i in expected_indices]),
            no_open_gap_access=not inside,retained_before_witness=before[0],retained_after_witness=after[0],
            Tmax_lower_bound_s=state['R']-state['L'],full_metrics_evaluated=False,feasibility_evaluated=False,
            verification_kind='Independent raw-asset flags and exact candidate/proof mapping')
        if not differences:self.certified[identity]=result['main_certificate_sha256']
        return result

    def selection(self,candidate_identities=None):
        allowed=set(candidate_identities) if candidate_identities is not None else set(self.expected)
        records=[r for key,r in self.expected.items() if key in allowed and r['qualified_improvement']]
        records.sort(key=lambda r:tuple(r['rank']))
        return dict(selected_identity=records[0]['identity'] if records else None,qualified_count=len(records),
                    ranking=[r['identity'] for r in records])

    def verify_completion(self,ledger,reports,checks,certificates,certificate_checks,reported_selected_identity,check=lambda:None):
        return terminal_verification(self.baseline_indices,self.donors,self.states,ledger,reports,checks,
            certificates,certificate_checks,reported_selected_identity,len(self.keep),self.tolerance,
            self.proof_state,numeric_expected=self.expected,certificate_expected=self.certified,check=check)


def terminal_verification(baseline,donors,states,ledger,reports,checks,certificates,certificate_checks,
                          reported_selected_identity,point_count=43424,tolerance=1e-6,proof=None,
                          numeric_expected=None,certificate_expected=None,check=lambda:None):
    """Stream disk records; exact coverage/partition and independently checked choice.

    Full point vectors were compared before discard.  This stage binds those
    comparison records to the exact main report rather than claiming to reload
    discarded candidate vectors.  Passing runtime expected maps adds a second
    binding to the checker instance's actual independently computed results.
    """
    require(proof is not None,'CHECKER_TERMINAL_PROOF_REQUIRED')
    require(proof.get('target')==TARGET and proof.get('interior_assets')==[1123]
            and proof.get('before_baseline_assets')==[911,1370]
            and len(proof.get('after_baseline_assets',[]))==6,'CHECKER_TERMINAL_PROOF_PRECONDITIONS')
    expected={};expected_ids=set();full_expected=set();cert_expected=set();order=hashlib.sha256()
    for candidate in iter_candidates(baseline,donors,states,check):
        key=tuple(candidate['remove']+candidate['add']);identity=candidate['identity']
        part='A' if 1123 in candidate['add'] else 'B' if candidate['remove']==[911,1370] else 'C'
        require(identity not in expected_ids,'CHECKER_TERMINAL_IDENTITY_COLLISION');expected_ids.add(identity)
        expected[key]=(identity,part,candidate['ordinal']);order.update((identity+'\n').encode())
        (cert_expected if part=='C' else full_expected).add(identity)
    differences=[];seen_ledger=set();ledger_ids=set();full_seen=set();cert_seen=set();qualified=[];ledger_counts={}
    full_verified=set();cert_verified=set()
    actual_order=hashlib.sha256();previous_full=-1;previous_certificate=-1
    b=set(baseline)
    def metadata_valid(item):
        key=tuple(item.get('remove',[])+item.get('add',[]));entry=expected.get(key)
        return (entry is not None and item.get('identity')==entry[0] and item.get('partition')==entry[1]
            and item.get('ordinal')==entry[2] and item.get('indices')==sorted((b-set(key[:2]))|set(key[2:])))
    if numeric_expected is not None and fingerprint(sorted(states[i] for i in baseline)) not in numeric_expected:
        differences.append(dict(path='baseline',reason='BASELINE_NOT_INDEPENDENTLY_CHECKED'))
    for n,item in enumerate(ledger):
        if n%1024==0:check()
        key=tuple(item.get('remove',[])+item.get('add',[]));entry=expected.get(key)
        if entry is None or key in seen_ledger:
            differences.append(dict(path='ledger',reason='UNKNOWN_OR_DUPLICATE_PAIR',key=key));continue
        seen_ledger.add(key);identity,part,ordinal=entry;ledger_ids.add(item.get('identity'))
        actual_order.update((str(item.get('identity'))+'\n').encode())
        state=item.get('processing_state',item.get('status'));ledger_counts[state]=ledger_counts.get(state,0)+1
        if (item.get('identity')!=identity or item.get('ordinal')!=ordinal or item.get('ordinal')!=n or item.get('partition')!=part
                or item.get('indices')!=sorted((b-set(key[:2]))|set(key[2:]))):
            differences.append(dict(path='ledger',reason='PAIR_IDENTITY_STATE_OR_ORDER',identity=identity))
        if part=='C' and state!=CERT_STATUS:differences.append(dict(path='ledger',reason='CERTIFICATE_STATUS',identity=identity))
        if part!='C' and state not in {'FULLY_EVALUATED_AND_INDEPENDENTLY_VERIFIED','FULLY_EVALUATED','EVALUATED_AND_VERIFIED'}:
            differences.append(dict(path='ledger',reason='FULL_EVALUATION_STATUS',identity=identity))
    for n,pair in enumerate(itertools.zip_longest(reports,checks)):
        if n%128==0:check()
        report,checked=pair
        if report is None or checked is None:
            differences.append(dict(path='full',reason='REPORT_CHECK_LENGTH'));continue
        compact=compact_report(report);identity=compact.get('identity')
        before_differences=len(differences)
        current_ordinal=compact.get('ordinal',-1)
        if type(current_ordinal) is not int or current_ordinal<=previous_full:
            differences.append(dict(path='full',reason='TRAVERSAL_ORDER',identity=identity))
        previous_full=current_ordinal if type(current_ordinal) is int else previous_full
        if not metadata_valid(compact):differences.append(dict(path='full',reason='PAIR_IDENTITY_OR_STATE_SET',identity=identity))
        if identity in full_seen or identity not in full_expected:
            differences.append(dict(path='full',reason='UNKNOWN_OR_DUPLICATE_IDENTITY',identity=identity))
        full_seen.add(identity)
        maximum=checked.get('max_absolute_first_hit_error_s')
        if (checked.get('identity')!=identity or checked.get('status')!='PASS' or checked.get('differences')!=[]
                or checked.get('points_compared')!=point_count or checked.get('classification_difference_count')!=0
                or type(checked.get('points_compared')) is not int or type(checked.get('classification_difference_count')) is not int
                or not isinstance(maximum,(int,float)) or isinstance(maximum,bool) or not math.isfinite(maximum)
                or not 0<=maximum<=tolerance or checked.get('absolute_tolerance_s')!=tolerance or checked.get('relative_tolerance')!=0
                or checked.get('main_output_sha256')!=compact['main_output_sha256']):
            differences.append(dict(path='full',reason='INCOMPLETE_OR_UNBOUND_POINT_CHECK',identity=identity))
        if checked.get('qualified_improvement')!=compact.get('qualified_improvement') or _differences(compact['rank'],checked.get('rank'),tolerance):
            differences.append(dict(path='full',reason='CHECKER_DECISION_OR_RANK',identity=identity))
        comparisons=checked.get('interval_comparisons',{})
        if len(comparisons)!=3 or any(c.get('differences')!=[] for c in comparisons.values()):
            differences.append(dict(path='full',reason='INCOMPLETE_INTERVAL_CHECK',identity=identity))
        if checked.get('main_first_hits_sha256')!=checked.get('checker_first_hits_sha256'):
            differences.append(dict(path='full',reason='POINT_DIGEST_MISMATCH',identity=identity))
        if (compact.get('source')!='archived_component_composition'
                or compact.get('new_native_validation_performed') is not False
                or compact.get('whole_constellation_STK_verified') is not False or compact.get('native_verified') is not False
                or compact.get('first_hits_sha256')!=checked.get('main_first_hits_sha256')):
            differences.append(dict(path='full',reason='NATIVE_SCOPE_OR_POINT_IDENTITY',identity=identity))
        if numeric_expected is not None:
            old=numeric_expected.get(identity)
            if old is None or old['main_output_sha256']!=compact['main_output_sha256'] or old['qualified_improvement']!=compact['qualified_improvement']:
                differences.append(dict(path='full',reason='RUNTIME_CHECKER_RECORD_MISMATCH',identity=identity))
        if len(differences)==before_differences:full_verified.add(identity)
        if compact['qualified_improvement']:qualified.append((compact['rank'],identity))
    for n,pair in enumerate(itertools.zip_longest(certificates,certificate_checks)):
        if n%1024==0:check()
        record,checked=pair
        if record is None or checked is None:
            differences.append(dict(path='certificate',reason='RECORD_CHECK_LENGTH'));continue
        identity=record.get('identity')
        before_differences=len(differences)
        current_ordinal=record.get('ordinal',-1)
        if type(current_ordinal) is not int or current_ordinal<=previous_certificate:
            differences.append(dict(path='certificate',reason='TRAVERSAL_ORDER',identity=identity))
        previous_certificate=current_ordinal if type(current_ordinal) is int else previous_certificate
        if not metadata_valid(record):differences.append(dict(path='certificate',reason='PAIR_IDENTITY_OR_STATE_SET',identity=identity))
        if identity in cert_seen or identity not in cert_expected:
            differences.append(dict(path='certificate',reason='UNKNOWN_OR_DUPLICATE_IDENTITY',identity=identity))
        cert_seen.add(identity)
        if (checked.get('identity')!=identity or checked.get('status')!='PASS' or checked.get('differences')!=[]
                or checked.get('main_certificate_sha256')!=fingerprint(record)
                or checked.get('proof_sha256')!=proof.get('proof_sha256') or record.get('proof_sha256')!=proof.get('proof_sha256')
                or checked.get('no_open_gap_access') is not True or checked.get('full_metrics_evaluated') is not False
                or checked.get('feasibility_evaluated') is not False or record.get('feasibility') is not None
                or record.get('metrics_status')!='NOT_EVALUATED'
                or record.get('status')!=CERT_STATUS or record.get('processing_state')!=CERT_STATUS
                or record.get('qualified_improvement') is not False
                or record.get('source')!='archived_component_composition'
                or record.get('new_native_validation_performed') is not False
                or record.get('whole_constellation_STK_verified') is not False or record.get('native_verified') is not False
                or any(record.get(k) is not None for k in ['full_grid','effective_grid','regional','first_hits_sha256'])):
            differences.append(dict(path='certificate',reason='UNBOUND_OR_FALSE_CERTIFICATE',identity=identity))
        lower=proof['R']-proof['L']
        if (_differences(float(lower),record.get('Tmax_lower_bound_s'),tolerance)
                or _differences(float(lower),checked.get('Tmax_lower_bound_s'),tolerance)):
            differences.append(dict(path='certificate',reason='LOWER_BOUND_MISMATCH',identity=identity))
        if certificate_expected is not None and certificate_expected.get(identity)!=fingerprint(record):
            differences.append(dict(path='certificate',reason='RUNTIME_CERTIFICATE_RECORD_MISMATCH',identity=identity))
        if len(differences)==before_differences:cert_verified.add(identity)
    if seen_ledger!=set(expected) or ledger_ids!=expected_ids:differences.append(dict(path='ledger',reason='NOT_EXACT_FULL_SPACE'))
    if actual_order.hexdigest()!=order.hexdigest():differences.append(dict(path='ledger',reason='FROZEN_TRAVERSAL_DIGEST'))
    if full_seen!=full_expected or cert_seen!=cert_expected or full_seen&cert_seen:
        differences.append(dict(path='partition',reason='NOT_EXACT_DISJOINT_PROCESSING_SETS'))
    qualified.sort(key=lambda p:tuple(p[0]));selected=qualified[0][1] if qualified else None
    if selected!=reported_selected_identity:differences.append(dict(path='selection',reason='INDEPENDENT_SELECTION_MISMATCH',expected=selected,reported=reported_selected_identity))
    return dict(status='FAIL' if differences else 'PASS',differences=differences,declared_candidates=len(expected),
        fully_evaluated=len(full_seen&full_expected),fully_independently_verified=len(full_verified&full_expected),
        certificate_rejected=len(cert_seen&cert_expected),certificate_independently_verified=len(cert_verified&cert_expected),
        unprocessed=len(expected_ids-(full_seen|cert_seen)),unknown=len((full_seen|cert_seen)-expected_ids),qualified_count=len(qualified),
        selected_identity=selected,retained_baseline=selected is None,identity_order_sha256=actual_order.hexdigest(),
        expected_identity_order_sha256=order.hexdigest(),
        baseline_checked=(numeric_expected is None or fingerprint(sorted(states[i] for i in baseline)) in numeric_expected),
        method='Independent nested-position exact sets; streamed main/check digest binding; separate checked-result ranking')
