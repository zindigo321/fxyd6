"""Pure saved-data calculations. No source-writing audit entrypoint is used."""
import csv
import json
import math
import re
from collections import Counter
from pathlib import Path
import numpy as np
from src.constellation import generate
from src.round4.experiments import parameter_check
from src.round5.audit import validate_events
from src.round7.audit import validate_config, audit_constraints
from src.round7.integrity import audit_ledger
from src.round4.frozen import EXPECTED
from .common import KEYS, canonical, read, sha, owned


def identity_audit(subject,cfg,source):
    validate_config(cfg)
    frozen=read(source/'grid/frozen.json');selection=read(source/'selection.json')
    old=Path(cfg['round7']['source_round6']);prior=read(old/'grid/frozen.json')
    rows,_=generate(**cfg['constellation'],constants=cfg['earth'])
    point_hash=sha(canonical(frozen['points']))
    checks=dict(wrapper=owned([frozen,selection],subject),point_hash=point_hash==frozen['point_set_sha256']==prior['point_set_sha256']==EXPECTED,
                frozen_points=frozen['points']==prior['points'],baseline=selection['baseline']==read(old/'selection.json')['baseline']==rows,
                all28=[r['sat_id'] for r in selection['tiers'][0]['selected']]==cfg['round7']['satellites'],
                point_count=len(frozen['points'])==16,points_unique=len({p['point_id'] for p in frozen['points']})==16,
                surface=all(p['altitude_km']==0 and p['use_terrain'] is False for p in frozen['points']),
                period=cfg['duration_s']==604800 and cfg['round7']['window']==[0,604800])
    return dict(status='PASS' if all(checks.values()) else 'FAIL',checks=checks,point_set_sha256=point_hash,
                satellites=cfg['round7']['satellites'],points=frozen['points'],window=cfg['round7']['window'],walker=dict(N=cfg['constellation']['n'],P=cfg['constellation']['planes'],S=cfg['constellation']['n']//cfg['constellation']['planes'],F=cfg['constellation']['phase_factor']))


def query_audit(subject,cfg,points,opps,candidates,queries,raw,geometry):
    phash=sha(canonical(points))
    ledger=audit_ledger(subject,phash,opps,candidates,queries,raw,'MAIN_FINE',cfg['round3']['search']['candidate_half_window_s'],cfg['duration_s'])
    valid=validate_events(subject,cfg,points,raw,queries,geometry,'round7')
    errors=list(ledger['errors'])
    if valid['status']!='PASS':errors+=valid['errors']+[issue for e in valid['events'] for issue in e['issues']]
    if not owned(raw+queries+candidates+opps,subject):errors.append('SOURCE_IDENTITY')
    if any(r.get('point_set_sha256')!=phash for r in raw+queries+candidates+opps):errors.append('POINT_IDENTITY')
    ids={p['point_id'] for p in points};sats=set(cfg['round7']['satellites'])
    if len(opps)!=len(sats)*len(ids) or {(o['sat_id'],o['point_id']) for o in opps}!={(s,p) for s in sats for p in ids}:errors.append('OPPORTUNITY_INVENTORY')
    for o in opps:
        matching=[q for q in queries if (q['sat_id'],q['point_id'])==(o['sat_id'],o['point_id'])]
        if sorted(o['queries'])!=sorted(q['query_id'] for q in matching) or len(o['queries'])!=len(set(o['queries'])):errors.append('OPPORTUNITY_QUERY_SET')
        if o['event_count']!=sum(q['event_count'] for q in matching):errors.append('OPPORTUNITY_EVENT_COUNT')
        if o['window']!=cfg['round7']['window'] or o['evaluation_window']!=o['window'] or o['screening_window']!=[max(0,o['window'][0]-cfg['round3']['search']['padding_s']),min(cfg['duration_s'],o['window'][1]+cfg['round3']['search']['padding_s'])]:errors.append('OPPORTUNITY_WINDOW')
    return dict(status='FAIL' if errors else 'PASS',errors=sorted(set(errors)),ledger=ledger,event_validation=valid,
                candidates=len(candidates),queries=len(queries),empty_queries=sum(not q['intervals'] for q in queries),positive_queries=sum(bool(q['intervals']) for q in queries),events=len(raw),
                reconstruction='Independent audit_ledger unions padded possible_intervals from every opportunity source, checks source reverse links and bijective candidates/queries/events. Production normalize_sources is not called.')


def trajectory_audit(subject,cfg,source,opps):
    grouped={}
    for o in opps:grouped.setdefault(o['trajectory']['path'],[]).append(o)
    rows=[];allrefs=[];wanted=np.arange(0,cfg['duration_s']+1,5,dtype=float)
    for path,refs in sorted(grouped.items()):
        p=Path(path);blob=p.read_bytes();digest=sha(blob);data=json.loads(blob);del blob
        times=np.asarray(data['times_epsec'],dtype=float);requested=np.asarray(data['requested_times_epsec'],dtype=float)
        pos=np.asarray(data['positions_fixed_km'],dtype=float);axes=np.asarray(data['bases_screening'],dtype=float)
        checks=dict(identity=owned([data],subject),satellite=data['sat_id'] in cfg['round7']['satellites'] and all(o['sat_id']==data['sat_id'] for o in refs),
                    path=p.resolve().is_relative_to((source/'G/T7').resolve()) and data['sat_id'] in p.parts,
                    declaration=data['window']==[0,604800] and data['step_s']==5 and data['phase_s']==0,
                    actual_grid=np.array_equal(times,wanted),requested_grid=np.array_equal(requested,wanted),
                    monotonic=bool(np.all(np.diff(times)>0)),finite_times=bool(np.isfinite(times).all()),
                    state_dimensions=pos.shape==(len(wanted),3) and axes.shape==(len(wanted),3,3),
                    finite_states=bool(np.isfinite(pos).all() and np.isfinite(axes).all()),
                    references=len(refs)==16 and len({o['point_id'] for o in refs})==16,
                    declarations=all((o['coarse_samples'],o['coarse_step_s'],o['phase_s'],o['screening_window'])==(len(wanted),5,0,[0,604800]) for o in refs))
        for o in refs:
            ok=o['trajectory']['sha256']==digest
            allrefs.append(dict(sat_id=o['sat_id'],point_id=o['point_id'],path=path,sha256=digest,status='PASS' if ok else 'FAIL'))
        rows.append(dict(path=path,sat_id=data['sat_id'],sha256=digest,checks={k:bool(v) for k,v in checks.items()},status='PASS' if all(checks.values()) else 'FAIL',actual_count=len(times),requested_count=len(requested),first=float(times[0]),last=float(times[-1]),max_gap_s=float(np.diff(times).max())))
        del data,times,requested,pos,axes
        print('TRAJECTORY',len(rows),'/',len(grouped),rows[-1]['status'],flush=True)
    ok=len(rows)==28 and len(allrefs)==448 and len({x['sat_id'] for x in rows})==28 and all(x['status']=='PASS' for x in rows+allrefs)
    return dict(status='PASS' if ok else 'FAIL',files=rows,references=allrefs,algorithm='One file at a time; independent arange grid; full arrays checked, no 448-fold trajectory parsing.',unique_files=len(rows),reference_count=len(allrefs))


def camera_audit(project,prior,sats,ids):
    result=audit_constraints(project,prior,sats,ids)
    errors=[]
    if not result['inventory_matches']:errors.append('CAMERA_OBJECT_INVENTORY')
    if any(x['status']!='PASS' for x in result['satellite_sensor_bindings']):errors.append('CAMERA_CHILD_BINDING')
    if any(x['status']!='PASS' for x in result['files']):errors.append('CONSTRAINT_BLOCK_CHANGED')
    # Scenario references are stronger than the 45-file inventory alone.
    scenario=(Path(project)/'Round4.sc').read_text(encoding='utf-8')
    sub=re.search(r'BEGIN SubObjects(.*?)END SubObjects',scenario,re.S)
    groups=re.findall(r'Class (\w+)\s+(.*?)END Class',sub.group(1),re.S) if sub else []
    objects={kind:[line.strip() for line in body.splitlines() if line.strip()] for kind,body in groups}
    if objects!={'Satellite':list(sats),'Facility':list(ids)} and not (set(objects)=={'Satellite','Facility'} and set(objects['Satellite'])==set(sats) and len(objects['Satellite'])==len(sats) and set(objects['Facility'])==set(ids) and len(objects['Facility'])==len(ids)):
        errors.append('SCENARIO_OBJECT_INVENTORY')
    result.update(status='FAIL' if errors else 'PASS',errors=errors,scenario_objects=objects)
    return result


def endpoint_sweep(points,raw,window):
    rows=[];gaps=[];phenomena=dict(same_point_multiple_satellites=False,cross_satellite_same_point_revisit=False,natural_overlap_or_touch=False,natural_cross_satellite_union=False)
    for point in points:
        pid=point['point_id'];events=[r for r in raw if r['point_id']==pid]
        endpoints=sorted({r[k] for r in events for k in ('start_epsec','stop_epsec')})
        segments=[]
        for a,b in zip(endpoints,endpoints[1:]):
            active=[r for r in events if r['start_epsec']<=a and r['stop_epsec']>=b]
            if not active:continue
            if segments and segments[-1][1]==a:segments[-1][1]=b
            else:segments.append([a,b])
        local=[b[0]-a[1] for a,b in zip(segments,segments[1:])];gaps.extend(local)
        sources=[[r['record_id'] for r in events if r['start_epsec']>=a and r['stop_epsec']<=b] for a,b in segments]
        for a,b in zip(segments,segments[1:]):
            left={r['sat_id'] for r in events if r['stop_epsec']==a[1]};right={r['sat_id'] for r in events if r['start_epsec']==b[0]}
            phenomena['cross_satellite_same_point_revisit']|=any(x!=y for x in left for y in right)
        phenomena['same_point_multiple_satellites']|=len({r['sat_id'] for r in events})>=2
        phenomena['natural_overlap_or_touch']|=any(len(x)>1 for x in sources)
        phenomena['natural_cross_satellite_union']|=any(len({r['sat_id'] for r in events if r['record_id'] in x})>1 for x in sources)
        rows.append(dict(point_id=pid,segments=segments,internal_gaps_s=local,raw_event_count=len(events),source_record_ids=sources,
                         edge_censoring=dict(leading_s=segments[0][0]-window[0] if segments else window[1]-window[0],trailing_s=window[1]-segments[-1][1] if segments else None,excluded_from_internal_gap_mean=True)))
    return dict(points=rows,event_count=len(raw),denominator=len(points),covered_points=sum(bool(r['segments']) for r in rows),insufficient_access_points=sum(len(r['segments'])<2 for r in rows),gap_count=len(gaps),conditional_mean_gap_s=sum(gaps)/len(gaps) if gaps else None,conditional_max_gap_s=max(gaps) if gaps else None,minimum_gap_s=min(gaps) if gaps else None,phenomena=phenomena)


def numerical_audit(cfg,source,points,raw):
    result=endpoint_sweep(points,raw,cfg['round7']['window']);stats=read(source/'G/T7/statistics.json');errors=[]
    if len(stats['points'])!=len(points):errors.append('STATISTICS_POINT_INVENTORY')
    for a,b in zip(result['points'],stats['points']):
        if a['point_id']!=b['point_id'] or a['segments']!=[[x['start_epsec'],x['stop_epsec']] for x in b['merged_intervals']] or a['internal_gaps_s']!=b['internal_gaps_s']:errors.append('POINT_SWEEP:'+a['point_id'])
    for ours,theirs in [('denominator','denominator'),('covered_points','covered_points'),('insufficient_access_points','insufficient_access_points'),('gap_count','effective_gap_count'),('conditional_mean_gap_s','conditional_mean_gap_s'),('conditional_max_gap_s','conditional_max_gap_s')]:
        if result[ours]!=stats[theirs]:errors.append('STATISTICS:'+ours)
    sevenraw=[r for r in raw if r['sat_id'] in cfg['round7']['original_seven']]
    seven=endpoint_sweep(points,sevenraw,cfg['round7']['window']);old=read(Path(cfg['round7']['source_round6'])/'G/T6/raw_intervals.json')
    history=[];matched=set()
    for oldrow in old:
        matches=[r for r in sevenraw if (r['sat_id'],r['point_id'])==(oldrow['sat_id'],oldrow['point_id']) and max(abs(r[k]-oldrow[k]) for k in ['start_epsec','stop_epsec'])<=cfg['tolerances']['convergence_s']]
        if len(matches)!=1:errors.append('HISTORICAL_EVENT_MATCH')
        matched.update(r['record_id'] for r in matches)
        history.append(dict(old_record_id=oldrow['record_id'],source_run_id=oldrow['run_id'],matched=[r['record_id'] for r in matches]))
    expansion=[]
    for a,b in zip(seven['points'],result['points']):
        contained=all(any(v[0]<=u[0] and v[1]>=u[1] for v in b['segments']) for u in a['segments'])
        expansion.append(dict(point_id=a['point_id'],seven_segments=a['segments'],all28_segments=b['segments'],subset_contained=contained))
        if not contained:errors.append('SUBSET_NOT_CONTAINED')
    contributions={s:sum(r['sat_id']==s for r in raw) for s in cfg['round7']['satellites']}
    result.update(status='FAIL' if errors else 'PASS',errors=errors,original_seven=seven,history_matches=history,
                  added_search_repair_events=[r['record_id'] for r in sevenraw if r['record_id'] not in matched],
                  additional21_event_count=sum(v for s,v in contributions.items() if s not in cfg['round7']['original_seven']),satellite_contributions=contributions,expansion=expansion,
                  method='Independent endpoint sweep, all 16 points kept in denominator; pooled internal gaps; no project aggregation function imported or called.')
    return result


def csv_audit(source,cfg,raw):
    folder=source/'G/T7';errors=[]
    with (folder/'raw_intervals.csv').open(encoding='utf-8',newline='') as f:rows=list(csv.DictReader(f))
    if len(rows)!=len(raw) or any(any(str(r[k])!=c[k] for k in c if k in r) for r,c in zip(raw,rows)):errors.append('COMBINED_CSV')
    for sat in cfg['round7']['satellites']:
        with (folder/sat/'raw_intervals.csv').open(encoding='utf-8',newline='') as f:back=list(csv.DictReader(f))
        if back!=[r for r in rows if r['sat_id']==sat] or read(folder/sat/'raw_intervals.json')!=[r for r in raw if r['sat_id']==sat]:errors.append('SATELLITE_CSV_JSON:'+sat)
    return dict(status='FAIL' if errors else 'PASS',errors=errors,records=len(rows),satellites=len(cfg['round7']['satellites']))


def deep_diff(a,b,path=''):
    if isinstance(a,dict) and isinstance(b,dict):
        if set(a)!=set(b):return [path+':KEYS']
        return [e for k in a for e in deep_diff(a[k],b[k],path+'/'+str(k))]
    if isinstance(a,list) and isinstance(b,list):
        if len(a)!=len(b):return [path+':LENGTH']
        return [e for i,(x,y) in enumerate(zip(a,b)) for e in deep_diff(x,y,path+'/'+str(i))]
    if isinstance(a,(float,int)) and not isinstance(a,bool) and isinstance(b,(float,int)) and not isinstance(b,bool):return [] if math.isfinite(a) and math.isfinite(b) and abs(a-b)<=1e-9 else [path]
    return [] if a==b else [path]


def geometry_audit(subject,cfg,source,points,raw,geometry):
    errors=[];rows=[];gm={g['record_id']:g for g in geometry};bypt={p['point_id']:p for p in points}
    reopened=read(source/'reopen/instance/access_comparison.json');positive=[r for r in reopened if not r.get('negative')];rm={r['record_id']:r for r in positive}
    if len(gm)!=len(geometry) or len(rm)!=len(positive) or set(gm)!=set(rm):errors.append('GEOMETRY_REOPEN_BIJECTION')
    if set(gm)!={r['record_id'] for r in raw} or set(rm)!={r['record_id'] for r in raw}:errors.append('EVENT_SET')
    for event in raw:
        g=gm[event['record_id']];r=rm[event['record_id']];point=bypt[event['point_id']];a=cfg['earth']['ellipsoid_a_km'];b=cfg['earth']['ellipsoid_b_km']
        lat=math.radians(point['latitude_deg']);lon=math.radians(point['longitude_deg']);e2=1-b*b/(a*a);n=a/math.sqrt(1-e2*math.sin(lat)**2);h=point['altitude_km']
        target=[(n+h)*math.cos(lat)*math.cos(lon),(n+h)*math.cos(lat)*math.sin(lon),(n*(1-e2)+h)*math.sin(lat)]
        issues=[];position_error=max(abs(x-y) for x,y in zip(target,g['target_fixed_km']))
        if position_error>cfg['tolerances']['position_km']:issues.append('TARGET_COORDINATE')
        states={v['time_epsec']:v for v in g['exact_states']};probes=[]
        if len(states)!=len(g['exact_states']):issues.append('DUPLICATE_GEOMETRY_STATE')
        for probe in g['angular_reference']['probes']:
            state=states[probe['time_epsec']];m=np.asarray(state['body_to_fixed']);p=np.asarray(state['position_fixed_km'])
            if m.shape!=(3,3) or p.shape!=(3,) or not np.isfinite(m).all() or not np.isfinite(p).all():issues.append('GEOMETRY_STATE_SHAPE');continue
            ortho=float(np.max(np.abs(m.T@m-np.eye(3))))
            body=m.T@(np.array(target)-p);along=math.degrees(math.atan2(body[0],body[2]));cross=math.degrees(math.atan2(body[1],body[2]))
            margin=min(cfg['camera']['along_half_deg']-abs(along),cfg['camera']['cross_half_deg']-abs(cross)) if body[2]>0 else -1
            error=abs(margin-probe['margin_deg']);inside=event['start_epsec']<probe['time_epsec']<event['stop_epsec']
            if error>1e-9 or ortho>cfg['tolerances']['orthogonal'] or (margin>0)!=inside:issues.append('GEOMETRY_PROBE')
            probes.append(dict(time_epsec=probe['time_epsec'],margin_deg=margin,error_deg=error,orthogonality_error=ortho,inside=inside))
        endpoints={}
        for name,values,tol in [('angle',g['angular_reference']['intervals'],cfg['tolerances']['independent_event_s']),('medium',g['medium_access']['intervals'],cfg['tolerances']['convergence_s']),('reopen',r['query']['intervals'],cfg['tolerances']['convergence_s'])]:
            differences=[[max(v['start_epsec'],0)-event['start_epsec'],min(v['stop_epsec'],cfg['duration_s'])-event['stop_epsec']] for v in values]
            endpoints[name]=dict(differences_s=differences,tolerance_s=tol)
            if len(differences)!=1 or max(abs(x) for x in differences[0])>tol:issues.append('ENDPOINT_'+name)
        for label,query,settings,kind in [('medium',g['medium_access'],cfg['access_tiers'][1],'MEDIUM_CONVERGENCE'),('reopen',r['query'],cfg['round3']['search'],'REOPEN_POSITIVE')]:
            rb=query['settings_readback']
            if query['query_type']!=kind or query['query_status']!='COMPLETE' or any(rb[k]!=settings[k] for k in ['min_step_s','max_step_s','time_convergence_s']) or not rb['precise_events'] or rb['fixed_step'] or rb['light_time']:issues.append('QUERY_SETTINGS_'+label)
        if g['medium_access']['parent_query_id']!=event['query_id'] or g['medium_access']['record_id']!=event['record_id']:issues.append('MEDIUM_EVENT_BINDING')
        if len(probes)!=5:issues.append('PROBE_COUNT')
        rows.append(dict(record_id=event['record_id'],status='FAIL' if issues else 'PASS',errors=issues,target_fixed_km=target,target_error_km=position_error,probes=probes,endpoints=endpoints))
    # Legacy negative records have no sat_id: bind their serialization order to
    # the frozen reopen loop, parameter order and per-satellite saved commands.
    ordered=[];cursor=0
    for sat in cfg['round7']['satellites']:
        for event in [r for r in raw if r['sat_id']==sat]:
            if cursor>=len(reopened) or reopened[cursor].get('record_id')!=event['record_id']:errors.append('REOPEN_ORDER')
            cursor+=1
        if cursor>=len(reopened):errors.append('MISSING_NEGATIVE');continue
        negative=reopened[cursor];q=negative['query'];cursor+=1
        rb=q['settings_readback'];settings=cfg['round3']['search']
        settings_ok=all(rb[k]==settings[k] for k in ['min_step_s','max_step_s','time_convergence_s']) and rb['precise_events'] and not rb['fixed_step'] and not rb['light_time']
        ok=negative.get('negative') is True and q['window']==cfg['round7']['reopen_negative_window'] and not q['intervals'] and q['event_count']==0 and q['query_type']=='REOPEN_NEGATIVE' and q['query_status']=='COMPLETE' and settings_ok
        if not ok:errors.append('NEGATIVE_QUERY')
        command=read(source/'reopen/instance'/sat/'connect_commands.json')
        ordered.append(dict(sat_id=sat,point_id=points[0]['point_id'],index=cursor-1,status='PASS' if ok else 'FAIL',settings_readback=rb,settings_match=settings_ok,command_run_id=command['run_id'],binding='Frozen ordered reopen loop + parameter order + per-satellite command evidence; source negative record itself lacks sat_id.'))
        if command['run_id']!=subject['run_id']:errors.append('REOPEN_COMMAND_IDENTITY')
    if cursor!=len(reopened):errors.append('EXTRA_REOPEN_QUERY')
    parameters=read(source/'G/T7/parameters.json');rparams=read(source/'reopen/instance/parameter_comparison.json');selection=read(source/'selection.json')['baseline'];param=[]
    if list(parameters)!=cfg['round7']['satellites'] or [x['sat_id'] for x in rparams]!=cfg['round7']['satellites']:errors.append('PARAMETER_OBJECT_ORDER')
    for orbit,item in zip(selection,rparams):
        sat=orbit['sat_id'];first=parameter_check(parameters[sat]['readback'],orbit,cfg,len(selection),points);second=parameter_check(item['parameter_check']['readback'],orbit,cfg,len(selection),points)
        delta=deep_diff(parameters[sat]['readback'],item['parameter_check']['readback'])
        param.append(dict(sat_id=sat,status='PASS' if first['status']==second['status']=='PASS' and not delta else 'FAIL',first_checks=first['checks'],reopen_checks=second['checks'],recomputed_differences=delta))
    ok=not errors and all(x['status']=='PASS' for x in rows+param+ordered)
    return dict(status='PASS' if ok else 'FAIL',errors=errors,events=rows,probe_count=sum(len(x['probes']) for x in rows),positive_queries=len(positive),negative_queries=ordered,parameters=param,fresh_reopen_performed=False,independence='Target and angle arithmetic recomputed independently; physical states still originate from historical STK, not independent physical truth.')
