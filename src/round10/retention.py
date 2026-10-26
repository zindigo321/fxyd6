"""Post-seal holdout reader, independent full-interval and cost calculations."""
import math
import time
from collections import Counter
from pathlib import Path
from src.round8.common import KEYS, file_record, read, write
from .evidence import verify_record
from .ledger import measure, require_cost, validate_coverage, validate_windows


def interval_contains(window, event, tolerance=0.):
    return window[0] <= event[0]+tolerance and window[1] >= event[1]-tolerance


def require_full_retention(events, windows, reported=None, tolerance=2e-5):
    rows=[]
    for e in events:
        interval=[e['start_epsec'],e['stop_epsec']]
        if not all(map(math.isfinite,interval)) or interval[0]>interval[1]:raise ValueError('EVENT_INTERVAL_INVALID')
        same=[w for w in windows if (w['sat_id'],w['point_id'])==(e['sat_id'],e['point_id'])]
        strict=[w for w in same if interval_contains(w['interval_s'],interval)]
        tolerant=[w for w in same if interval_contains(w['interval_s'],interval,tolerance)]
        rows.append(dict(record_id=e['record_id'],sat_id=e['sat_id'],point_id=e['point_id'],original_interval_s=interval,
                         strict_containment=bool(strict),tolerance_containment=bool(tolerant),
                         matched_window_ids=[w['window_id'] for w in strict],matched_intervals_s=[w['interval_s'] for w in strict],
                         missing_reason=None if strict else 'FULL_INTERVAL_NOT_CONTAINED',tolerance_s=tolerance))
    if reported is not None and any(a['strict_containment']!=b.get('strict_containment') for a,b in zip(rows,reported)):
        raise ValueError('MIDPOINT_OR_FALSE_RETENTION_CLAIM')
    if reported is not None and len(rows)!=len(reported):raise ValueError('RETENTION_INVENTORY')
    return rows


def statistics(raw, points, cfg, old_events):
    # Deliberately separate sweep from candidate window union implementation.
    point_rows=[];gaps=[];edges=[]
    for point in points:
        pid=point['point_id'];intervals=sorted((e['start_epsec'],e['stop_epsec']) for e in raw if e['point_id']==pid)
        merged=[]
        for a,b in intervals:
            if merged and a<=merged[-1][1]:merged[-1][1]=max(merged[-1][1],b)
            else:merged.append([a,b])
        pg=[b[0]-a[1] for a,b in zip(merged,merged[1:])]
        pe=[merged[0][0],cfg['duration_s']-merged[-1][1]] if merged else [cfg['duration_s']]
        gaps.extend(pg);edges.extend(pe)
        point_rows.append(dict(point_id=pid,raw_event_count=len(intervals),union=merged,gaps_s=pg,edges_s=pe))
    seven=[e for e in raw if e['sat_id'] in cfg['round7']['original_seven']];matched=set()
    for e in old_events:
        found=[r for r in seven if (r['sat_id'],r['point_id'])==(e['sat_id'],e['point_id'])
               and max(abs(r[k]-e[k]) for k in ['start_epsec','stop_epsec'])<=2e-5]
        if len(found)!=1:raise ValueError('ORIGINAL_SEVEN_ATTRIBUTION')
        matched.add(found[0]['record_id'])
    return dict(event_count=len(raw),covered_points=sum(bool(p['union']) for p in point_rows),point_denominator=len(points),
                insufficient_points=sum(len(p['union'])<2 for p in point_rows),internal_gap_count=len(gaps),
                internal_mean_s=math.fsum(gaps)/len(gaps) if gaps else None,internal_max_s=max(gaps,default=None),
                edge_count=len(edges),edge_inclusive_denominator=len(gaps)+len(edges),
                edge_inclusive_mean_s=math.fsum(gaps+edges)/len(gaps+edges) if gaps+edges else None,edge_inclusive_max_s=max(gaps+edges,default=None),
                original_seven_events=len(seven),additional21_events=len(raw)-len(seven),search_repair_new_events=sum(e['record_id'] not in matched for e in seven),
                points=point_rows,official_metric=False,official_score=None)


def independent_cost_review(groups, duration, padding, expected):
    """Independent interval sweep: does not call ledger.union or measure."""
    rows=[]
    for key in sorted(groups):
        intervals=sorted((max(0.,float(a)-padding),min(duration,float(b)+padding)) for a,b in groups[key] if b+padding>=0 and a-padding<=duration)
        result=[]
        for begin,end in intervals:
            if not math.isfinite(begin+end) or begin>end:raise ValueError('COST_INPUT_INVALID')
            if result and begin<=result[-1][1]:result[-1][1]=max(result[-1][1],end)
            else:result.append([begin,end])
        rows.append(dict(sat_id=key[0],point_id=key[1],intervals_s=result,union_duration_s=math.fsum(b-a for a,b in result)))
    for actual,wanted in zip(rows,expected['pairs']):
        if (actual['sat_id'],actual['point_id'],actual['intervals_s'])!=(wanted['sat_id'],wanted['point_id'],wanted['intervals_s']) or abs(actual['union_duration_s']-wanted['union_duration_s'])>1e-7:
            raise ValueError('INDEPENDENT_COST_PAIR_MISMATCH')
    total=math.fsum(r['union_duration_s'] for r in rows)
    if len(rows)!=len(expected['pairs']) or abs(total-expected['union_pair_seconds'])>1e-7:raise ValueError('INDEPENDENT_COST_TOTAL_MISMATCH')
    return dict(status='PASS',pairs_checked=len(rows),union_pair_seconds=total,method='Separate sorted interval sweep and math.fsum; no ledger union/measure call.')


def verify_and_compare(candidate_dir, source, cfg, projected, out, subject):
    seal=read(candidate_dir/'candidate_seal.json')
    for row in seal['files']:verify_record(row)
    read_start=time.time()
    if read_start<=seal['created_epoch']:raise ValueError('HOLDOUT_BEFORE_CANDIDATE_SEAL')
    # First event content read on this route, after candidate bytes are sealed.
    raw=read(source/'G/T7/raw_intervals.json');queries=read(source/'G/T7/raw_access_queries.json');old_candidates=read(source/'G/T7/candidate_ledger.json')
    if len({r['record_id'] for r in raw})!=len(raw):raise ValueError('EVENT_DUPLICATE_ID')
    if any(any(r[k]!=subject[k] for k in KEYS) for r in raw+queries+old_candidates):raise ValueError('HOLDOUT_SOURCE_IDENTITY')
    points=read(source/'grid/frozen.json')['points'];expected={(s,p['point_id']) for s in cfg['round7']['satellites'] for p in points}
    ledger=read(candidate_dir/'coverage_ledger.json');window_doc=read(candidate_dir/'candidate_windows.json');windows=window_doc['windows']
    step=ledger['domain']['step_s'];duration=cfg['duration_s'];padding=window_doc['padding_s'];tol=window_doc['merge_tolerance_s'];n=ledger['domain']['cell_count_per_pair']
    coverage=validate_coverage(ledger['pairs'],expected,n,step);validate_windows(windows,ledger['pairs'],step,duration,padding,tol)
    old_raw={key:[] for key in expected};old_original={key:[] for key in expected};prototype_raw={key:[] for key in expected}
    processed={key:[] for key in expected};unknown={key:[] for key in expected}
    for pair in projected['pairs']:
        key=(pair['sat_id'],pair['point_id'])
        old_raw[key]=[w for c in pair['candidates'] for w in c['possible_intervals']]
    for c in old_candidates:old_original[(c['sat_id'],c['point_id'])].append(c['local_query_window'])
    for p in ledger['pairs']:
        key=(p['sat_id'],p['point_id'])
        for r in p['ranges']:
            w=[r['first']*step,r['stop']*step]
            if r['state']=='UNKNOWN':unknown[key].append(w);prototype_raw[key].append(w)
            elif r['decision']=='KEEP':processed[key].append(w);prototype_raw[key].append(w)
    old=measure(old_raw,duration,padding,tol);original=measure(old_original,duration);new=measure(prototype_raw,duration,padding,tol)
    actual_windows={key:[] for key in expected}
    for w in windows:actual_windows[(w['sat_id'],w['point_id'])].append(w['interval_s'])
    measured_windows=measure(actual_windows,duration)
    if any(a['intervals_s']!=b['intervals_s'] for a,b in zip(new['pairs'],measured_windows['pairs'])):
        raise ValueError('CANDIDATE_COST_WINDOW_MISMATCH')
    if any(a['intervals_s']!=b['intervals_s'] for a,b in zip(old['pairs'],original['pairs'])):
        raise ValueError('HISTORICAL_UNIFIED_WINDOW_MISMATCH')
    require_cost(new,prototype_raw,duration,padding,tol)
    independent=dict(historical=independent_cost_review(old_raw,duration,padding,old),prototype=independent_cost_review(prototype_raw,duration,padding,new))
    denominator=len(expected)*duration;cost=dict(status='PASS',coverage=coverage,definition=dict(padding_s=padding,merge_tolerance_s=tol,clip_s=[0,duration],units='satellite-point seconds',no_cross_pair_union=True),
        historical_original=original,historical_unified=old,prototype=new,full_domain_pair_seconds=denominator,
        historical_retention_fraction=old['union_pair_seconds']/denominator,prototype_retention_fraction=new['union_pair_seconds']/denominator,
        increment_pair_seconds=new['union_pair_seconds']-old['union_pair_seconds'],ratio=new['union_pair_seconds']/old['union_pair_seconds'] if old['union_pair_seconds'] else None,
        processed_retained=measure(processed,duration,padding,tol),unknown_retained_upper_bound=measure(unknown,duration,padding,tol),
        processed_unpadded=measure(processed,duration),unknown_unpadded=measure(unknown,duration),
        fallback_pair_seconds=new['union_pair_seconds'],fallback_fraction=1. if new['union_pair_seconds'] else None,
        unknown_marginal_pair_seconds=new['union_pair_seconds']-measure(processed,duration,padding,tol)['union_pair_seconds'],
        caution='Padded processed and UNKNOWN windows can overlap; do not add their separate padded costs. Unpadded partitions are disjoint. This is candidate work volume, not measured STK runtime or executed Access count.',
        measured_stk_wall_s=None,access_executed=False,independent_review=independent)
    write(out/'candidate_cost_comparison.json',cost)
    retained=require_full_retention(raw,windows);old_by={(p['sat_id'],p['point_id']):p['intervals_s'] for p in old['pairs']};unknown_by={(p['sat_id'],p['point_id']):p['intervals_s'] for p in cost['unknown_unpadded']['pairs']}
    classes=Counter();origins=Counter()
    for row in retained:
        key=(row['sat_id'],row['point_id']);interval=row['original_interval_s']
        already=any(interval_contains(w,interval) for w in old_by[key]);in_unknown=any(interval_contains(w,interval) for w in unknown_by[key])
        row.update(old_candidate_retained=already,prototype_requires_fallback=True,
                   prototype_retention_origin='UNKNOWN_CONSERVATIVE' if in_unknown else 'PROCESSED_OR_MIXED_FALLBACK',
                   comparison_category='NOT_RETAINED' if not row['strict_containment'] else 'OLD_CANDIDATE_RETAINED' if already else 'UNKNOWN_CONSERVATIVE_ADDED' if in_unknown else 'FALLBACK_ADDED')
        classes[row['comparison_category']]+=1;origins[row['prototype_retention_origin']]+=1
    errors=[]
    if len(raw)!=53 or not all(r['strict_containment'] for r in retained):errors.append('HISTORICAL_FULL_INTERVAL_LOST')
    if len(queries)!=102 or sum(not q['intervals'] for q in queries)!=49:errors.append('HISTORICAL_QUERY_INVENTORY')
    if len(old_candidates)!=len(queries) or len({q['query_id'] for q in queries})!=len(queries):errors.append('QUERY_BIJECTION')
    # Preserve explicit query/event forward and reverse relations, including empty queries.
    for q in queries:
        events=[r for r in raw if r['query_id']==q['query_id']]
        if len(events)!=q['event_count'] or len(events)!=len(q['intervals']):errors.append('QUERY_EVENT_COUNT')
    baseline=statistics(raw,points,cfg,read(Path(cfg['round7']['source_round6'])/'G/T6/raw_intervals.json'))
    if [baseline[k] for k in ['event_count','internal_gap_count','covered_points','insufficient_points','original_seven_events','additional21_events','search_repair_new_events']]!=[53,37,16,2,12,41,0]:errors.append('SCIENTIFIC_BASELINE_COUNTS')
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,events=len(raw),strictly_retained=sum(r['strict_containment'] for r in retained),
                tolerance_retained=sum(r['tolerance_containment'] for r in retained),comparison_categories={k:classes[k] for k in ['OLD_CANDIDATE_RETAINED','FALLBACK_ADDED','UNKNOWN_CONSERVATIVE_ADDED','NOT_RETAINED']},
                prototype_origins=dict(origins),fallback_required_count=sum(r['prototype_requires_fallback'] for r in retained),fallback_fraction=1.,
                original_query_count=len(queries),original_empty_queries=sum(not q['intervals'] for q in queries),
                original_empty_query_ids=[q['query_id'] for q in queries if not q['intervals']],source_queries=file_record(source/'G/T7/raw_access_queries.json'),
                source_events=file_record(source/'G/T7/raw_intervals.json'),candidate_seal=file_record(candidate_dir/'candidate_seal.json'),holdout_read_started_epoch=read_start,
                candidates_sealed_epoch=seal['created_epoch'],rows=retained,
                interpretation='Historical retention is due to full conservative fallback. Comparison OLD means old windows already contained the event; it does not remove prototype fallback dependence. No zero-miss theorem or efficiency claim.')
    for r in seal['files']:verify_record(r)
    write(out/'historical_53_retention.json',result);write(out/'engineering_statistics.json',baseline)
    write(out/'candidate_readback.json',dict(status='PASS',files=len(seal['files']),sealed_before_holdout=True,unchanged_after_verification=True))
    return result,cost,baseline
