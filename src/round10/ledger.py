"""Exact domain partitions and per-pair window accounting; no cross-pair union."""
import math
from collections import Counter


def union(windows, duration, padding=0., tolerance=0.):
    if min(duration, padding, tolerance) < 0 or not all(map(math.isfinite, (duration, padding, tolerance))):
        raise ValueError('WINDOW_POLICY')
    clipped = []
    for interval in windows:
        a, b = map(float, interval)
        if not math.isfinite(a+b) or b < a:
            raise ValueError('INVALID_WINDOW')
        a, b = max(0., a-padding), min(duration, b+padding)
        if b >= a:
            clipped.append([a, b])
    merged = []
    for a, b in sorted(clipped):
        if merged and a <= merged[-1][1] + tolerance:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def partition(selected, cell_count):
    rows = []; cursor = 0
    for index in sorted(selected):
        if not isinstance(index, int) or index < cursor or index >= cell_count:
            raise ValueError('SELECTED_INDEX_INVALID')
        if cursor < index:
            rows.append(dict(first=cursor, stop=index, state='UNKNOWN', reason='UNPROCESSED_CONSERVATIVELY_RETAINED'))
        rows.append(dict(first=index, stop=index+1, state='PROCESSED', reason=selected[index]['reason'],
                         decision=selected[index]['decision'], decision_id=selected[index]['decision_id']))
        cursor = index+1
    if cursor < cell_count:
        rows.append(dict(first=cursor, stop=cell_count, state='UNKNOWN', reason='UNPROCESSED_CONSERVATIVELY_RETAINED'))
    return rows


def validate_coverage(pairs, expected_pairs, cell_count, step):
    found = [(p['sat_id'], p['point_id']) for p in pairs]
    if len(found) != len(set(found)) or set(found) != set(expected_pairs):
        raise ValueError('COVERAGE_PAIR_INVENTORY')
    counts = Counter()
    for p in pairs:
        cursor = 0
        for r in p['ranges']:
            a, b = r['first'], r['stop']
            if not isinstance(a, int) or not isinstance(b, int) or a != cursor or not a < b <= cell_count:
                raise ValueError('COVERAGE_GAP_OVERLAP_OR_RANGE')
            if r['state'] not in {'UNKNOWN', 'PROCESSED'}:
                raise ValueError('COVERAGE_STATE')
            if r['state'] == 'UNKNOWN' and r['reason'] != 'UNPROCESSED_CONSERVATIVELY_RETAINED':
                raise ValueError('UNKNOWN_NOT_RETAINED')
            if r['state'] == 'PROCESSED' and (b-a != 1 or r['decision'] not in {'KEEP', 'CERTIFIED_REJECT'}):
                raise ValueError('PROCESSED_DECISION_SCHEMA')
            counts[r['state']] += b-a; cursor = b
        if cursor != cell_count:
            raise ValueError('COVERAGE_GAP_OVERLAP_OR_RANGE')
    return dict(status='PASS', pair_count=len(found), total_cells=len(found)*cell_count,
                processed_cells=counts['PROCESSED'], unknown_cells=counts['UNKNOWN'],
                step_s=step, full_domain_pair_seconds=len(found)*cell_count*step)


def windows_from_ranges(pair, step, duration, padding, tolerance):
    kept = [r for r in pair['ranges'] if r['state'] == 'UNKNOWN' or r.get('decision') == 'KEEP']
    raw = [[r['first']*step, r['stop']*step] for r in kept]
    return [dict(window_id=f"{pair['sat_id']}/{pair['point_id']}/W{i:03d}",
                 sat_id=pair['sat_id'], point_id=pair['point_id'], interval_s=w,
                 access_executed=False, event_count=None, event_status='UNKNOWN',
                 reason='UNION_OF_RETAINED_DECISIONS_AND_UNKNOWN',
                 range_indices=[j for j,r in enumerate(pair['ranges'])
                                if (r['state']=='UNKNOWN' or r.get('decision')=='KEEP')
                                and r['stop']*step+padding >= w[0] and r['first']*step-padding <= w[1]])
            for i,w in enumerate(union(raw, duration, padding, tolerance))]


def validate_windows(windows, pairs, step, duration, padding, tolerance):
    if any(w.get('access_executed') is not False or w.get('event_count') is not None or w.get('event_status') != 'UNKNOWN' for w in windows):
        raise ValueError('UNQUERIED_EVENT_COUNT_NOT_NULL')
    expected = [w for p in pairs for w in windows_from_ranges(p, step, duration, padding, tolerance)]
    if windows != expected:
        raise ValueError('WINDOW_NOT_DERIVED_FROM_DECISIONS')
    return dict(status='PASS', count=len(windows))


def measure(groups, duration, padding=0., tolerance=0.):
    pairs = []; raw_count = 0
    for pair, windows in sorted(groups.items()):
        merged = union(windows, duration, padding, tolerance)
        raw_count += len(windows)
        pairs.append(dict(sat_id=pair[0], point_id=pair[1], raw_count=len(windows),
                          padded_count=sum(bool(union([w], duration, padding, tolerance)) for w in windows),
                          merged_count=len(merged), intervals_s=merged,
                          union_duration_s=sum(b-a for a,b in merged)))
    return dict(pairs=pairs, raw_window_count=raw_count, padded_window_count=sum(p['padded_count'] for p in pairs),
                merged_window_count=sum(p['merged_count'] for p in pairs),
                union_pair_seconds=sum(p['union_duration_s'] for p in pairs),
                longest_window_s=max((b-a for p in pairs for a,b in p['intervals_s']), default=0.))


def require_cost(reported, groups, duration, padding=0., tolerance=0.):
    actual = measure(groups, duration, padding, tolerance)
    if reported != actual:
        raise ValueError('COST_PER_PAIR_UNION_MISMATCH')
    return actual
