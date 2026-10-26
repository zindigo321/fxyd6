"""Reason-specific counterexamples and numerical behavior, with positive controls."""
import copy
from pathlib import Path
import numpy as np
from src.round8.common import file_record, write
from .bounds import analytic_certificate, decide, envelope
from .binding import require_transition, transition
from .evidence import verify_record
from .ledger import measure, partition, validate_coverage, validate_windows, windows_from_ranges, require_cost, union
from .prototype import SPEC_KEYS, process_cell, trajectory_arrays, validate_spec
from .retention import require_full_retention


def fixture_data():
    return dict(times_epsec=[0.,5.,10.,15.],requested_times_epsec=[0.,5.,10.,15.],
                positions_fixed_km=[[0.,0.,0.]]*4,bases_screening=np.tile(np.eye(3),(4,1,1)).tolist())


def fixture_pair():
    selected={1:dict(decision='KEEP',reason='KEEP_NO_VERIFIED_CONTINUOUS_BOUND',decision_id='s/p/C1')}
    return dict(sat_id='s',point_id='p',ranges=partition(selected,3))


def run(folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True);cases=[];behaviors=[]
    def reject(name,positive,negative,reason):
        positive();observed=None
        try:negative()
        except ValueError as exc:observed=str(exc)
        cases.append(dict(case=name,positive_control_pass=True,expected_reason=reason,actual_reason=observed,
                          status='PASS' if observed==reason or observed and observed.startswith(reason+':') else 'FAIL',kind='TESTED_BEHAVIOR'))
    c=analytic_certificate();poly=c['polynomial']
    def certificate_case(value):return decide(poly,[0.,1.],certificate=value,real_data=False,boresight_known=True,horizon_known=True,roots_known=True)
    good=lambda:certificate_case(c)
    for name,key,value,reason in [('forged_bound_source','source','OBSERVED_MAXIMUM','BOUND_SOURCE_UNTRUSTED'),('wrong_units','units','m','BOUND_UNITS_OR_FRAME'),
                                  ('invalid_assumptions','assumptions',{},'BOUND_ASSUMPTION_INVALID'),('missing_error_terms','terms',{},'BOUND_TERMS_MISSING')]:
        changed=copy.deepcopy(c);changed[key]=value;reject(name,good,lambda changed=changed:certificate_case(changed),reason)
    reject('fixture_on_real_data',good,lambda:decide(poly,[0.,1.],certificate=c,real_data=True),'FIXTURE_BOUND_USED_ON_REAL_DATA')
    bad=copy.deepcopy(c);bad['polynomial'][0][0]=99
    reject('bound_input_substitution',good,lambda:certificate_case(bad),'BOUND_INPUT_BINDING')
    data=fixture_data();positive=lambda:trajectory_arrays(data,3,5.)
    for name,key,value,reason in [('bad_shape','positions_fixed_km',[[1.,2.]],'TRAJECTORY_SHAPE_UNRESOLVED'),
        ('nonfinite','positions_fixed_km',[[float('nan'),0.,0.]]*4,'TRAJECTORY_NONFINITE_UNRESOLVED'),
        ('unordered_time','times_epsec',[0.,10.,5.,15.],'TRAJECTORY_TIME_UNRESOLVED'),
        ('duplicate_time','times_epsec',[0.,5.,5.,15.],'TRAJECTORY_TIME_UNRESOLVED')]:
        bad=copy.deepcopy(data);bad[key]=value
        reject(name,positive,lambda bad=bad:trajectory_arrays(bad,3,5.),reason)
    pair=fixture_pair();coverage=lambda:validate_coverage([pair],[('s','p')],3,5.)
    bad=copy.deepcopy(pair);bad['ranges'].pop(0)
    reject('deleted_unknown',coverage,lambda:validate_coverage([bad],[('s','p')],3,5.),'COVERAGE_GAP_OVERLAP_OR_RANGE')
    reject('missing_pair',coverage,lambda:validate_coverage([], [('s','p')],3,5.),'COVERAGE_PAIR_INVENTORY')
    overlap=copy.deepcopy(pair);overlap['ranges'][1]['first']=0
    reject('duplicate_coverage',coverage,lambda:validate_coverage([overlap],[('s','p')],3,5.),'COVERAGE_GAP_OVERLAP_OR_RANGE')
    beyond=copy.deepcopy(pair);beyond['ranges'][-1]['stop']=4
    reject('coverage_out_of_range',coverage,lambda:validate_coverage([beyond],[('s','p')],3,5.),'COVERAGE_GAP_OVERLAP_OR_RANGE')
    spec={k:None for k in SPEC_KEYS};spec['code_sha256']='a'*64
    reject('event_seeded_dependency',lambda:validate_spec(spec),lambda:validate_spec(dict(spec,historical_events=[1,2])),'FORBIDDEN_EVENT_OR_EXTRA_DEPENDENCY')
    windows=windows_from_ranges(pair,5.,15.,.05,0.)
    good_windows=lambda:validate_windows(windows,[pair],5.,15.,.05,0.)
    bad_window=copy.deepcopy(windows);bad_window[0]['interval_s']=[1.,2.]
    reject('event_seeded_window',good_windows,lambda:validate_windows(bad_window,[pair],5.,15.,.05,0.),'WINDOW_NOT_DERIVED_FROM_DECISIONS')
    bad_count=copy.deepcopy(windows);bad_count[0]['event_count']=0
    reject('unqueried_zero',good_windows,lambda:validate_windows(bad_count,[pair],5.,15.,.05,0.),'UNQUERIED_EVENT_COUNT_NOT_NULL')
    reject('wrong_checker',lambda:require_transition(transition),lambda:require_transition(lambda a,b:True),'CHECKER_ROUTE_NOT_ROUND10_TRANSITION')
    events=[dict(record_id='e',sat_id='s',point_id='p',start_epsec=.2,stop_epsec=.8)]
    short=[dict(window_id='w',sat_id='s',point_id='p',interval_s=[.4,.6])]
    full=[dict(short[0],interval_s=[0.,1.])]
    reject('midpoint_only',lambda:require_full_retention(events,full,[dict(strict_containment=True)]),
           lambda:require_full_retention(events,short,[dict(strict_containment=True)]),'MIDPOINT_OR_FALSE_RETENTION_CLAIM')
    groups={('s','p'):[[0.,2.]],('t','p'):[[0.,2.]]};correct=measure(groups,5.);incorrect=dict(correct,union_pair_seconds=2.)
    reject('cross_pair_cost_merge',lambda:require_cost(correct,groups,5.),lambda:require_cost(incorrect,groups,5.),'COST_PER_PAIR_UNION_MISMATCH')
    old={'src/round9/unchanged.py':b'x=1\n'};new=dict(old,**{'src/round10/new.py':b'x=2\n'})
    def require_code(value):
        r=transition(old,value)
        if r['status']!='PASS':raise ValueError(r['errors'][0])
    reject('bad_code_hash',lambda:require_code(new),lambda:require_code(dict(new,**{'src/round9/unchanged.py':b'x=2\n'})),'K9_RAW_BYTES_CHANGED')
    reject('unauthorized_new_module',lambda:require_code(new),lambda:require_code(dict(new,**{'src/round11/new.py':b'x=2\n'})),'K10_ADDITION_NOT_ALLOWED')
    p=folder/'historical_positive_control.txt';p.write_bytes(b'frozen input');row=file_record(p)
    reject('bad_history_hash',lambda:verify_record(row),lambda:verify_record(dict(row,sha256='0'*64)),'HISTORICAL_RAW_HASH_MISMATCH')
    def behavior(name,ok,detail):behaviors.append(dict(case=name,status='PASS' if ok else 'FAIL',kind='NUMERICAL_FIXTURE',detail=detail))
    t,r,b=positive();cell=process_cell(t,r,b,np.array([100.,20.,600.]),1,.001622,1.62,.05,1e-9)
    behavior('actual_connected_cell_pipeline',cell['decision']=='KEEP' and len(cell['body_node_vectors_km'])==4 and cell['missing_bound_terms'],cell)
    behavior('analytic_strict_rejection_only',good()['decision']=='CERTIFIED_REJECT',good())
    for key,reason in [('boresight_known','KEEP_BORESIGHT_UNRESOLVED'),('horizon_known','KEEP_HORIZON_UNRESOLVED'),('roots_known','KEEP_ROOT_UNRESOLVED')]:
        opts=dict(boresight_known=True,horizon_known=True,roots_known=True);opts[key]=False
        d=decide(poly,[0.,1.],certificate=c,real_data=False,**opts)
        keep_pair=dict(sat_id='s',point_id='p',ranges=partition({0:dict(d,decision_id='x')},1))
        behavior(reason,d['reason']==reason and windows_from_ranges(keep_pair,1.,1.,0.,0.)[0]['interval_s']==[0.,1.],d)
    for name,pcoef,domain in [('tangency',[.25,-1.,1.,0.],[0.,1.]),('near_repeated_root',[.25-1e-14,-1.,1.,0.],[0.,1.]),('endpoint',[0.,1.,0.,0.],[0.,1.]),('short_window',[-1.,0.,0.,0.],[0.,1e-8])]:
        polynomial=[pcoef]*5;d=decide(polynomial,domain)
        behavior(name,d['decision']=='KEEP',d)
    behavior('zero_margin_on_z',cell['margin_added_km']==[.05]*4+[0.],cell['margin_added_km'])
    clipped=union([[-.1,.1],[.1,.2],[.15,.4],[14.9,16.]],15.,.05,0.)
    behavior('clip_touch_overlap_short',clipped==[[0.,.45],[14.85,15.]],clipped)
    result=dict(status='PASS' if all(r['status']=='PASS' for r in cases+behaviors) else 'FAIL',
                counterexample_count=len(cases),counterexamples=cases,numerical_fixture_count=len(behaviors),numerical_fixtures=behaviors,
                mutation_source_executed=False,analytic_certificates_never_used_for_real_trajectory=True)
    write(folder/'counterexamples_and_fixtures.json',result);return result
