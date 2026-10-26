"""Whitelisted saved-trajectory -> selected cells -> decisions -> windows."""
import json
import math
import time
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
from src.round8.common import KEYS, canonical, file_record, read, sha, write
from .bounds import decide, TERMS
from .ledger import partition, validate_coverage, windows_from_ranges, validate_windows

SPEC_KEYS = {'code_sha256', 'protocol', 'config', 'grid', 'screening', 'source_identity', 'output', 'allowed_reads'}


def checked_read(record):
    actual = file_record(record['path'])
    if actual['sha256'] != record['sha256'] or ('bytes' in record and actual['bytes'] != record['bytes']):
        raise ValueError('INPUT_RAW_HASH_MISMATCH')
    return read(record['path'])


def validate_spec(spec):
    if set(spec) != SPEC_KEYS:
        raise ValueError('FORBIDDEN_EVENT_OR_EXTRA_DEPENDENCY')
    if len(spec['code_sha256']) != 64:
        raise ValueError('CODE_IDENTITY_INVALID')


def project_screening(screen):
    """Drop every non-whitelisted field, including placeholder query counts."""
    return dict(run_id=screen['run_id'], complete=screen['complete'], pairs=[
        dict(sat_id=p['sat_id'], point_id=p['point_id'],
             identity={k:p[k] for k in KEYS}, point_set_sha256=p['point_set_sha256'],
             trajectory={k:p['trajectory'][k] for k in ('path','sha256')},
             screening_window=p['screening_window'], cell_dispositions=p['cell_dispositions'],
             candidates=[{k:c[k] for k in ('cell_index','coarse_bracket','bernstein_upper_km','possible_intervals','reason_code','source_id')}
                         for c in p['candidates']]) for p in screen['pairs']])


def select(pair, count, tolerance):
    reasons = defaultdict(list)
    fixed = {0, 1, count//4, count//2, 3*count//4, count-2, count-1}
    present = set()
    for c in pair['candidates']:
        index=c['cell_index']
        if index in present or not 0 <= index < count or c['coarse_bracket'] != [index*5., (index+1)*5.]:
            raise ValueError('SCREEN_CELL_INVALID')
        present.add(index); reasons['old_reason:'+c['reason_code']].append(index)
        upper=np.asarray(c['bernstein_upper_km'], dtype=float)
        if upper.shape != (5,) or not np.isfinite(upper).all():
            raise ValueError('SCREEN_ENVELOPE_INVALID')
        for value in upper:
            category = 'NEGATIVE' if value < -tolerance else 'POSITIVE' if value > tolerance else 'NEAR_ZERO'
            reasons['boundary:'+category].append(index)
    # The aggregate along-rejected cells are the complement of stored sources.
    complement = (i for i in range(count) if i not in present)
    first = next(complement, None)
    last = next((i for i in range(count-1, -1, -1) if i not in present), None)
    if first is not None:
        reasons['old_reason:ALONG_ENCLOSURE_REJECTED']=[first,last]
    if pair['cell_dispositions']['along_enclosure_rejected'] != count-len(present):
        raise ValueError('SCREEN_AGGREGATE_COUNT')
    tags=defaultdict(list)
    for i in fixed: tags[i].append('fixed_time_position')
    for reason, indices in reasons.items():
        for i in {min(indices),max(indices)}:tags[i].append(reason)
    return {i:sorted(v) for i,v in sorted(tags.items())}, sorted(set(['boundary:NEGATIVE','boundary:POSITIVE','boundary:NEAR_ZERO'])-set(reasons))


def trajectory_arrays(data, count, step, expected_identity=None):
    if expected_identity and any(data.get(k)!=expected_identity[k] for k in KEYS):
        raise ValueError('TRAJECTORY_IDENTITY')
    t=np.asarray(data['times_epsec'],dtype=float); requested=np.asarray(data['requested_times_epsec'],dtype=float)
    r=np.asarray(data['positions_fixed_km'],dtype=float); b=np.asarray(data['bases_screening'],dtype=float)
    if t.shape!=(count+1,) or requested.shape!=t.shape or r.shape!=(count+1,3) or b.shape!=(count+1,3,3):
        raise ValueError('TRAJECTORY_SHAPE_UNRESOLVED')
    if not all(np.isfinite(x).all() for x in (t,requested,r,b)):
        raise ValueError('TRAJECTORY_NONFINITE_UNRESOLVED')
    if np.any(np.diff(t)<=0) or not np.array_equal(t, np.arange(count+1)*step) or not np.array_equal(t,requested):
        raise ValueError('TRAJECTORY_TIME_UNRESOLVED')
    if np.max(np.abs(np.einsum('nji,njk->nik',b,b)-np.eye(3)))>1e-8:
        raise ValueError('TRAJECTORY_BASIS_UNRESOLVED')
    return t,r,b


def target_fixed(point, earth):
    lat,lon=map(math.radians,(point['latitude_deg'],point['longitude_deg']))
    a,b=earth['ellipsoid_a_km'],earth['ellipsoid_b_km']; e2=1-b*b/(a*a)
    n=a/math.sqrt(1-e2*math.sin(lat)**2); h=point['altitude_km']
    return np.array([(n+h)*math.cos(lat)*math.cos(lon),(n+h)*math.cos(lat)*math.sin(lon),(n*(1-e2)+h)*math.sin(lat)])


def process_cell(t, position, basis, target, index, along, coarse_cross, margin, tolerance):
    j=max(0,min(index-1,len(t)-4)); nodes=np.arange(j,j+4); dt=t[index+1]-t[index]
    u=(t[nodes]-t[index])/dt
    body=np.einsum('nji,nj->ni',basis[nodes],target-position[nodes])
    try:
        coeff=np.linalg.solve(np.vander(u,4,increasing=True),body)
    except np.linalg.LinAlgError as exc:
        raise ValueError('INTERPOLATION_UNRESOLVED') from exc
    x,y,z=coeff.T; ta,tc=math.tan(math.radians(along)),math.tan(math.radians(coarse_cross))
    polynomial=np.array([ta*z-x,ta*z+x,tc*z-y,tc*z+y,z])
    decision=decide(polynomial,[t[index],t[index+1]],margin_km=margin,tolerance_km=tolerance)
    decision.update(node_indices=nodes.tolist(),node_times_s=t[nodes].tolist(),body_node_vectors_km=body.tolist(),
                    polynomial_coefficients_km=polynomial.tolist(),coarse_cross_half_deg=coarse_cross,
                    old_horizon_gate_applied_after_fallback=False)
    return decision


def execute(spec):
    validate_spec(spec); started=time.perf_counter(); cpu=time.process_time(); out=Path(spec['output']);out.mkdir(parents=True,exist_ok=True)
    protocol=checked_read(spec['protocol']);cfg=checked_read(spec['config'])['config'];grid=checked_read(spec['grid']);screen=checked_read(spec['screening'])
    domain=protocol['domain']; count=domain['cell_count_per_pair'];step=domain['step_s'];duration=domain['stop_s']
    sats=cfg['round7']['satellites'];points={p['point_id']:p for p in grid['points']};expected={(s,p) for s in sats for p in points}
    if len(sats)!=28 or len(points)!=16 or len(screen['pairs'])!=448 or set((p['sat_id'],p['point_id']) for p in screen['pairs'])!=expected:
        raise ValueError('INPUT_DOMAIN_IDENTITY')
    if grid['point_set_sha256']!=sha(canonical(grid['points'])) or cfg['duration_s']!=duration or cfg['round4']['coarse_step_s']!=step:
        raise ValueError('INPUT_DOMAIN_CONFIGURATION')
    if any(any(p['identity'][k]!=spec['source_identity'][k] for k in KEYS) or p['point_set_sha256']!=grid['point_set_sha256'] or p['screening_window']!=[0,duration] for p in screen['pairs']):
        raise ValueError('SCREEN_IDENTITY')
    padding=cfg['round3']['search']['candidate_half_window_s'];tolerance=protocol['selection']['boundary_tolerance_km'];merge=protocol['windows']['merge_tolerance_s']
    selected=[];pairs=[];windows=[];counts=Counter(); old_reason_counts=Counter(); traj_evidence=[]
    decision_path=out/'candidate_decisions.jsonl'
    with decision_path.open('w',encoding='utf-8',newline='\n') as stream:
        for sat in sats:
            group=[p for p in screen['pairs'] if p['sat_id']==sat]; ref=group[0]['trajectory']
            if any(p['trajectory']!=ref for p in group):raise ValueError('TRAJECTORY_REFERENCE_CONFLICT')
            data=checked_read(ref)
            if data['sat_id']!=sat:raise ValueError('TRAJECTORY_SATELLITE')
            t,r,b=trajectory_arrays(data,count,step,spec['source_identity']);del data
            traj_evidence.append(dict(**ref,validated_nodes=len(t),orthogonal_basis_checked=True))
            for pair in group:
                chosen, absent=select(pair,count,tolerance); decisions={};point=points[pair['point_id']];target=target_fixed(point,cfg['earth'])
                oldmap={c['cell_index']:c for c in pair['candidates']}
                for index,tags in chosen.items():
                    row=process_cell(t,r,b,target,index,cfg['camera']['along_half_deg'],2*cfg['camera']['cross_half_deg'],cfg['round7']['candidate_guard_km'],tolerance)
                    reason=oldmap.get(index,{}).get('reason_code','ALONG_ENCLOSURE_REJECTED')
                    row.update(decision_id=f"{sat}/{pair['point_id']}/C{index:06d}",sat_id=sat,point_id=pair['point_id'],cell_index=index,
                               selection_tags=tags,old_screening_reason=reason,trajectory=ref,target=point,
                               fine_cross_half_deg=cfg['camera']['cross_half_deg'],code_sha256=spec['code_sha256'],protocol_sha256=spec['protocol']['sha256'])
                    stream.write(json.dumps(row,ensure_ascii=False,allow_nan=False)+'\n');decisions[index]=row;counts[row['decision']]+=1;old_reason_counts[reason]+=1
                ledger=dict(sat_id=sat,point_id=pair['point_id'],ranges=partition(decisions,count))
                pairs.append(ledger);windows.extend(windows_from_ranges(ledger,step,duration,padding,merge))
                selected.append(dict(sat_id=sat,point_id=pair['point_id'],indices=list(chosen),tags=chosen,absent_categories=absent))
            del t,r,b
            print('CANDIDATE',sat,'processed',sum(counts.values()),flush=True)
    coverage=validate_coverage(pairs,expected,count,step);validate_windows(windows,pairs,step,duration,padding,merge)
    write(out/'coverage_ledger.json',dict(domain=domain,validation=coverage,pairs=pairs,code_sha256=spec['code_sha256']))
    write(out/'selection.json',dict(rule=protocol['selection'],pairs=selected))
    write(out/'candidate_windows.json',dict(windows=windows,padding_s=padding,merge_tolerance_s=merge,clip_s=[0,duration],code_sha256=spec['code_sha256']))
    write(out/'bound_provenance.json',dict(status='UNRESOLVED',real_verified_continuous_bounds=0,missing_terms=list(TERMS),trajectories=traj_evidence,
          fixed_margin_scope='Only first four FOV inequalities; never z, horizon or root uncertainty',empirical_residuals_used_as_bounds=False,
          conditional_math='For an exact polynomial on a closed cell, the Bernstein convex hull bounds it. A bound on polynomial approximation plus node/frame/target/roundoff errors is additionally required for the true trajectory.',
          labels=dict(polynomial_math='CONDITIONAL_MATHEMATICAL_PROPERTY',floating_fixtures='NUMERICAL_FIXTURE',fallback='TESTED_BEHAVIOR',real_search='UNRESOLVED')))
    result=dict(status='PASS',coverage=coverage,decision_counts=dict(counts),selected_old_reason_counts=dict(old_reason_counts),candidate_count=len(windows),
                offline_wall_s=time.perf_counter()-started,offline_cpu_s=time.process_time()-cpu,all_fallback=not counts['CERTIFIED_REJECT'],
                trajectory_files=len(traj_evidence),source_config=spec['config'],source_grid=spec['grid'],source_screening=spec['screening'],
                access_executed=False,code_sha256=spec['code_sha256'],protocol_sha256=spec['protocol']['sha256'])
    from .resources import usage
    result['resources']=usage()
    result['output_bytes_before_seal']=sum(p.stat().st_size for p in out.iterdir() if p.is_file())
    write(out/'prototype_result.json',result)
    files=[file_record(p) for p in sorted(out.iterdir()) if p.is_file() and p.name!='candidate_seal.json']
    write(out/'candidate_seal.json',dict(files=files,created_epoch=time.time(),code_sha256=spec['code_sha256'],protocol_sha256=spec['protocol']['sha256'],holdout_read_before_seal=False))
    return result
