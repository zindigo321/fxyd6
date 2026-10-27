"""Point-count coverage and per-object internal gaps from raw records."""
import math
import numpy as np
from .common import require


def validate_hits(values, duration, allow_positive_inf=True):
    a = np.asarray(values, dtype=np.float64)
    require(a.ndim == 1, 'FIRST_HITS_SHAPE')
    require(not np.isnan(a).any(), 'NAN_FIRST_HIT')
    require(not np.isneginf(a).any(), 'NEGATIVE_INFINITY_FIRST_HIT')
    require(allow_positive_inf or not np.isinf(a).any(), 'INFINITY_NOT_ALLOWED_IN_SOURCE')
    finite = a[np.isfinite(a)]
    require(not (finite < 0).any(), 'NEGATIVE_FIRST_HIT')
    require(not (finite > duration).any(), 'FIRST_HIT_OUTSIDE_WINDOW')
    return a


def csv_hits(rows, duration):
    values = []
    for r in rows:
        text = r['first_hit_s']
        if text == '':
            values.append(np.inf)
        else:
            value = float(text)
            require(math.isfinite(value), 'NONFINITE_CSV_FIRST_HIT')
            values.append(value)
    return validate_hits(values, duration)


def coverage(values, duration):
    a = validate_hits(values, duration)
    n = len(a)
    hits = np.sort(a[np.isfinite(a)])
    k90 = (9 * n + 9) // 10
    reached90 = bool(n and len(hits) >= k90)
    reached100 = bool(n and len(hits) == n)
    return dict(points=n, covered=len(hits), uncovered=n-len(hits), coverage_end_fraction=float(len(hits)/n) if n else None,
                threshold_90_count=k90, T90_s=float(hits[k90-1]) if reached90 else None,
                T100_s=float(hits[-1]) if reached100 else None, reached_90=reached90, reached_100=reached100,
                status='AVAILABLE' if n else 'EMPTY_DOMAIN')


def normalized_coords(values):
    a = np.asarray(values, dtype=np.float64)
    require(a.ndim == 2 and a.shape[1] == 2 and np.isfinite(a).all(), 'COORDINATE_SHAPE_OR_NONFINITE')
    require((np.abs(a[:, 0]) <= 90 + 1e-10).all(), 'INVALID_LATITUDE')
    a = a.copy(); a[:, 1] = (a[:, 1] + 180) % 360 - 180
    keys = [tuple(p) for p in np.round(a, 8)]
    require(len(set(keys)) == len(keys), 'DUPLICATE_COORDINATE')
    return a, keys


def coordinate_permutation(source, target, tolerance=1e-8):
    a, ak = normalized_coords(source); b, bk = normalized_coords(target)
    require(len(a) == len(b), 'COORDINATE_ROW_COUNT')
    index = {k: i for i, k in enumerate(ak)}
    require(set(ak) == set(bk), 'NEW_OR_MISSING_COORDINATE')
    order = np.asarray([index[k] for k in bk], dtype=np.int64)
    require(np.max(np.abs(a[order]-b), initial=0) <= tolerance, 'COORDINATE_TOLERANCE')
    return order


def validate_ids(rows, key, count):
    ids = [int(r[key]) for r in rows]
    require(len(ids) == len(set(ids)), 'DUPLICATE_POINT_ID')
    require(len(ids) == count and set(ids) == set(range(count)), 'MISSING_POINT_ROWS')
    return ids


def fixed_mask(coords, stored, expected_count, limit):
    a, _ = normalized_coords(coords)
    keep = np.abs(a[:, 0]) <= limit
    require(np.asarray(stored).dtype == np.bool_, 'INVALID_MASK_ENCODING')
    require(len(stored) == len(keep) and np.array_equal(stored, keep), 'MASK_RULE_MISMATCH')
    require(int(keep.sum()) == expected_count, 'MASK_COUNT_MISMATCH')
    return keep


def union(intervals, duration, tolerance):
    duration = float(duration)
    prepared = []
    for a, b in intervals:
        a, b = float(a), float(b)
        require(math.isfinite(a) and math.isfinite(b) and a <= b, 'INVALID_ACCESS_INTERVAL')
        if b < 0 or a > duration:
            continue
        prepared.append([max(0., a), min(duration, b)])
    merged = []
    for a, b in sorted(prepared):
        if merged and a <= merged[-1][1] + tolerance:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return merged


def gap_summary(gaps):
    durations = [b-a for a, b in gaps]
    return dict(gap_count=len(gaps), mean_s=math.fsum(durations)/len(durations) if durations else None,
                max_s=max(durations) if durations else None,
                longest_endpoints_s=gaps[durations.index(max(durations))] if durations else None)


def regional(intervals, duration, tolerance=1e-6):
    duration = float(duration)
    targets, all_gaps, all_boundary = {}, [], []
    for name, raw in intervals.items():
        merged = union(raw, duration, tolerance)
        gaps = [[merged[i-1][1], merged[i][0]] for i in range(1, len(merged))]
        edges = [[0., merged[0][0]], [merged[-1][1], duration]] if merged else [[0., duration]]
        boundary = gaps + [v for v in edges if v[1] > v[0]]
        all_gaps.extend(gaps); all_boundary.extend(boundary)
        targets[name] = dict(raw_count=len(raw), raw_intervals=raw, merged_count=len(merged), merged_intervals=merged,
                             internal_gaps=gaps, internal=gap_summary(gaps), boundary_segments=edges,
                             boundary_inclusive=gap_summary(boundary), valid_revisit=len(merged) >= 2)
    return dict(targets=targets, raw_count=sum(len(v) for v in intervals.values()),
                pooled_internal=gap_summary(all_gaps), pooled_boundary_inclusive=gap_summary(all_boundary),
                semantics='Pool individual internal gaps across objects; never average per-object means',
                boundary_gaps_included_in_primary=False)


def compare_hits(left, right, tolerance):
    a, b = np.asarray(left), np.asarray(right)
    require(a.shape == b.shape, 'COMPOSITION_SHAPE_MISMATCH')
    mismatch = np.flatnonzero(np.isfinite(a) != np.isfinite(b))
    require(len(mismatch) == 0, 'COMPOSITION_HIT_CLASSIFICATION_MISMATCH')
    finite = np.isfinite(a)
    errors = np.abs(a[finite] - b[finite])
    maximum = float(np.max(errors, initial=0))
    require(maximum <= tolerance, 'COMPOSITION_FIRST_HIT_TIME_MISMATCH')
    return dict(points=len(a), finite_points=int(finite.sum()), hit_classification_exact_match=True,
                max_finite_first_hit_error_s=maximum, absolute_tolerance_s=tolerance)
