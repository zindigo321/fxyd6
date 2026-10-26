"""Empirical frozen-state errors and explicitly conditional polynomial claims."""
import math
import time
from pathlib import Path
import numpy as np
from src.round7.candidates import coefficients,bernstein,cell_windows,normalize_sources
from src.round8.common import file_record,read,sha,text,write

def interpolate(times,values,targets):
    """Independent four-node Lagrange evaluator, no production coefficients."""
    t=np.asarray(times,float);v=np.asarray(values,float);x=np.atleast_1d(targets).astype(float)
    if len(t)<4 or not np.all(np.isfinite(t)) or not np.all(np.diff(t)>0) or not np.isfinite(v).all():raise ValueError('UNRESOLVED_INPUT')
    if np.any(x<t[0]) or np.any(x>t[-1]) or not np.isfinite(x).all():raise ValueError('UNRESOLVED_TARGET')
    cell=np.clip(np.searchsorted(t,x,side='right')-1,0,len(t)-2);j=np.clip(cell-1,0,len(t)-4)
    nodes=t[j[:,None]+np.arange(4)];weights=np.ones_like(nodes)
    for k in range(4):
        for m in range(4):
            if m!=k:weights[:,k]*=(x-nodes[:,m])/(nodes[:,k]-nodes[:,m])
    estimated=sum(v[j+k]*weights[:,k].reshape((len(x),)+(1,)*(v.ndim-1)) for k in range(4))
    return estimated,nodes,weights

def conservative_decision(fitted_upper,error_bounds=None,valid=True,boundary_uncertain=False):
    """Offline proposal only: unknown never means no access."""
    if not valid:return dict(action='UNRESOLVED',reason='INVALID_INTERPOLATION_STOP_CERTIFICATION')
    if error_bounds is None:return dict(action='KEEP_CANDIDATE',reason='NO_PROVEN_ERROR_BOUND')
    u=np.asarray(fitted_upper,float);e=np.asarray(error_bounds,float)
    if u.shape!=(5,) or e.shape!=(5,) or not np.isfinite(u).all() or not np.isfinite(e).all() or np.any(e<0):return dict(action='UNRESOLVED',reason='INVALID_BOUND_STOP_CERTIFICATION')
    if boundary_uncertain:return dict(action='KEEP_CANDIDATE',reason='ROOT_OR_HORIZON_BOUNDARY_UNCERTAIN')
    if np.any(u+e<0):return dict(action='REJECT_UNDER_BOUND_ASSUMPTIONS',reason='ONE_CONTINUOUS_INEQUALITY_STRICTLY_NEGATIVE')
    return dict(action='KEEP_CANDIDATE',reason='POSSIBLE_OR_UNCERTAIN')

def synthetic():
    cases=[]
    def record(name,ok,detail,claim='PROVEN_UNDER_ASSUMPTIONS'):
        cases.append(dict(case=name,kind='CONSTRUCTED_OFFLINE_NOT_REAL_EVENT',status='PASS' if ok else 'FAIL',classification=claim,detail=detail))
    grid=np.array([0.,1.,2.,3.]);along=.1;cross=.8;aa=math.tan(math.radians(along));z=600.
    for name,f,probe in [('constant_inside',lambda t:t*0,1.5),('short_window',lambda t:aa*z+((t-1.5)**2-1e-8),1.5),
                         ('multiple_crossings',lambda t:aa*z+10*(t-.8)*(t-1.5)*(t-2.2),1.6),('endpoint_inside',lambda t:aa*z+t,0.),
                         ('tangent_inside',lambda t:aa*z-(t-1.5)**2,1.5),('critical_margin',lambda t:t*0+aa*z+.049,1.5)]:
        body=np.column_stack([f(grid),grid*0,grid*0+z]);records,counts=cell_windows(grid,body,along,cross,.05)
        intervals=[w for r in records for w in r['possible_intervals']]
        # These analytical points satisfy guarded inequalities; positive intervals exist.
        retained=any(a-1e-9<=probe<=b+1e-9 for a,b in intervals)
        record(name,retained,dict(probe=probe,intervals=intervals,counts=counts))
    # Nonuniform interpolation reproduced against exact cubic values at all probes.
    nonuniform=np.array([0.,.371,2.371,4.371,5.]);val=np.column_stack([nonuniform**3-3*nonuniform**2+2,nonuniform**2,nonuniform*0+600])
    power=coefficients(nonuniform,val);worst=0.
    for i in range(len(nonuniform)-1):
        for u in [.0,.1,.4,.8,1.]:
            x=nonuniform[i]+u*(nonuniform[i+1]-nonuniform[i]);truth=np.array([x**3-3*x*x+2,x*x,600])
            worst=max(worst,float(np.max(np.abs(sum(power[i,k]*u**k for k in range(4))-truth))))
    record('nonuniform_exact_cubic',worst<1e-9,dict(max_absolute_error_km=worst))
    for name,t,b in [('nan',grid,np.full((4,3),np.nan)),('inf',grid,np.full((4,3),np.inf)),('short_grid',grid[:3],np.ones((3,3))),('degenerate_grid',[0,1,1,2],np.ones((4,3)))]:
        try:coefficients(t,b);ok=False;reason='ACCEPTED'
        except ValueError as exc:ok='UNRESOLVED' in str(exc);reason=str(exc)
        record(name,ok,dict(reason=reason,proposal=conservative_decision(None,valid=False)),claim='UNRESOLVED')
    for name,value in [('boresight_negative',-1.),('boresight_boundary',0.),('boresight_positive',1.)]:
        b=np.column_stack([grid*0,grid*0,grid*0+value]);records,counts=cell_windows(grid,b,along,cross,.05)
        any_interval=any(r['possible_intervals'] for r in records)
        record(name,any_interval==(value>=0),dict(z_km=value,retained=any_interval,proposal=conservative_decision([0,0,0,0,value],None,boundary_uncertain=value==0)),claim='EMPIRICAL_ONLY')
    # All four nodes are outside. A smooth quartic bump between them enters the
    # guarded cone. This refutes extrapolation without a derivative bound, not
    # the explicitly conditional fitted-cubic guarantee in the production docstring.
    node_x=np.full(4,aa*z+.2);b=np.column_stack([node_x,grid*0,grid*0+z]);records,_=cell_windows(grid,b,along,cross,.05)
    xtrue=lambda t:aa*z+.2-.8*t*(t-1)*(t-2)*(t-3)
    hidden=xtrue(1.5)<aa*z and not any(r['possible_intervals'] for r in records)
    record('unsampled_quartic_bump',hidden,dict(node_values_km=node_x.tolist(),interior_x_km=xtrue(1.5),physical_stk_evidence=False,violates_existing_qualified_guarantee=False,refuted_claim='Identical nodes or fixed 0.05 km allowance prove all underlying smooth trajectories retained',proposal=conservative_decision([-0.1]*5,None)),claim='COUNTEREXAMPLE_FOUND')
    # Endpoint horizon samples alone cannot bound an interior excursion.
    horizon=lambda t:-2+4*(1-(2*t-1)**2)
    record('horizon_interior_excursion',horizon(0)<-1 and horizon(1)<-1 and horizon(.5)>0,dict(endpoints_deg=[horizon(0),horizon(1)],midpoint_deg=horizon(.5),proposal=conservative_decision([1]*5,None,boundary_uncertain=True),violates_existing_qualified_guarantee=False),claim='COUNTEREXAMPLE_FOUND')
    for name,upper,bound,valid,uncertain,expected in [('unknown_bound',[-1]*5,None,True,False,'KEEP_CANDIDATE'),('known_bound',[-1]*5,[.1]*5,True,False,'REJECT_UNDER_BOUND_ASSUMPTIONS'),('uncertain_root',[1]*5,[.1]*5,True,True,'KEEP_CANDIDATE'),('failed_fit',[1]*5,None,False,False,'UNRESOLVED'),('nan_bound',[1]*5,[float('nan')]*5,True,False,'UNRESOLVED')]:
        decision=conservative_decision(upper,bound,valid,uncertain);record('fallback_'+name,decision['action']==expected,decision)
    windows=normalize_sources([dict(possible_intervals=[[1.,1.001]]),dict(possible_intervals=[[1.005,1.006]])],.0001,3)
    record('short_distinct_windows',len(windows)==2,dict(windows=windows))
    return dict(status='PASS' if all(r['status']=='PASS' for r in cases) else 'FAIL',cases=cases,case_count=len(cases),production_modified=False,proposed_policy_deployed=False)

METHOD=r"""# 搜索误差依据与筛除链

## 实际生产链

固定 STK r/v 的 5 s 零相位节点 → omega×r 修正的近似姿态基 → 目标差向量的机体系分量 u=(x,y,z)，单位 km → 每单元四节点三次插值 → 五个不等式的 Bernstein 包络 → 数值根切分共同区间 → 采样地平线门 → ±0.05 s padding 与相接并集 → 原生 Camera Access。

生产粗筛沿迹半角为 camera.along_half_deg=0.001622°，交叉迹半角为 **2×camera.cross_half_deg=1.62°**；精细 Camera 交叉迹半角为 0.81°，两者不能混用。0.05 km 加在 tan(alpha)z±x 和 tan(beta)z±y 四式的常数项；z≥0 的 boresight 条件没有这一余量。地平线门用相邻两个样本仰角最大值与 -horizon_guard_deg 比较。

## 条件成立的数学性质

精确算术下，三次多项式 p(u)=Σ c_k u^k 在 u∈[0,1] 可写成四个非负且和为 1 的 Bernstein 权重乘控制值。因此 p(u)≤max(b_k)。某一个不等式包络严格小于零可排除该**拟合多项式**；各式上界都非负只是必要条件，仍需共同可行区间。分类 PROVEN_UNDER_ASSUMPTIONS：给定精确多项式、完整根分割、精确符号判定。浮点转换和根误差需另加可追溯界。

生产内部节点通常是 [t_i-5,t_i,t_i+5,t_i+10]，边界改用最前/最后四个节点。对真实标量分量 u(t)，若四阶导数存在且整个节点凸包 |u''''|≤M4，则 Lagrange 余项满足 |u(t)-I3u(t)|≤M4/24·|Π_j(t-t_j)|。含节点误差 ε_j 时再加 Σ_j|L_j(t)|ε_j。这里 M4 的单位为 km/s^4；时间积单位 s^4。

节点机体系误差可由欧氏/谱范数界给出：ε_j≤||Btilde_j-B_j||2·||q-r_j||2 + ||Btilde_j||2·||rtilde_j-r_j||2。还需位置/姿态模型误差和四阶导数界；原端点姿态校准不能认证内部所有节点。四个视场不等式误差分别≤tan(alpha)ε_z+ε_x、tan(beta)ε_z+ε_y，加数值误差。只有这些总界≤0.05 km 且 boresight、地平线、根分割也受界约束，才可把余量用于真实轨迹认证。

现存数据没有全窗口 M4、全节点真姿态误差、boresight 与地平线连续界、浮点根严格隔离界。固定余量、节点残差和有限样本最大误差均不能补出这些界。根实现截去 |高阶系数|<1e-14，接受 |虚部|<1e-7、[-1e-10,1+1e-10] 根并裁剪；中点符号阈值 -1e-10。切触、近重根及根间极短区间需要数值不确定性处理。

## 本轮实验与限制

代理网格：28 颗卫星各取原 5 s 网格的偶序号形成 10 s 节点，用全部奇序号留点作参考；独立 Lagrange 比较位置与近似姿态。所有比较时刻和残差逐星存 NPZ。此实验只能说明 10 s→5 s 代理误差，不能认证生产 5 s 亚格误差。

真实历史局部比较：所有主任务 geometry_audit 中已有 exact_states 均纳入，按各自卫星/目标计算生产四节点 5 s 插值与已有 STK 精确状态的机体系差值、五式差值及姿态差值；绝不调用新 state。样本由已观测事件及其角度探针/求根产生，有显著选择偏差，没有覆盖所有被拒绝单元。诊断证据另作有限历史证据清单，不能替代这些缺失单元。

本轮提出的保守策略仅离线验证：无严格界则 KEEP_CANDIDATE；插值失败或非有限数据则 UNRESOLVED 并停止认证；根、boresight 或地平线边界不确定则保留候选。仅在完整连续上界证明一个不等式全负时才拒绝。生产链不改、策略不部署、STK 不作为回退。

四节点相同但中间有四次光滑凸起的构造例及端点以下地平线、中间以上的构造例，反驳未经声明的全局外推，并不反驳生产代码已限定的“拟合三次多项式”性质。若受控正例违反后者则工程验收必须 FAIL。

“历史 53 个正事件被保留”“有限诊断未见遗漏”“全局搜索完备”分别报告；第三项仍 UNRESOLVED，下一次科学运行门保持 BLOCKED。
"""

def analyze(policy,cfg,out,deadline):
    source=Path(policy['source_dir']);opps=read(source/'G/T7/opportunities.json');geometry=read(source/'G/T7/geometry_audit.json');raw=read(source/'G/T7/raw_intervals.json')
    grouped={}
    for o in opps:grouped.setdefault(o['sat_id'],o['trajectory'])
    folder=out/'residuals';folder.mkdir();summaries=[];exact_rows=[];errors=[];started=time.perf_counter()
    aa=math.tan(math.radians(cfg['camera']['along_half_deg']));cc=math.tan(math.radians(2*cfg['camera']['cross_half_deg']))
    def inequalities(v):
        x,y,z=v;return np.array([aa*z-x,aa*z+x,cc*z-y,cc*z+y,z])
    for sat,ref in sorted(grouped.items()):
        if time.perf_counter()>deadline:raise TimeoutError('SEARCH_BUDGET_EXCEEDED')
        begin=time.perf_counter();path=Path(ref['path']);blob=path.read_bytes()
        if sha(blob)!=ref['sha256']:raise ValueError('TRAJECTORY_RAW_HASH:'+sat)
        data=__import__('json').loads(blob);del blob
        t=np.asarray(data['times_epsec'],float);pos=np.asarray(data['positions_fixed_km'],float);basis=np.asarray(data['bases_screening'],float);del data
        indices=np.arange(1,len(t)-1,2);x=t[indices]
        pp,nodes,_=interpolate(t[::2],pos[::2],x);bb,_,_=interpolate(t[::2],basis[::2],x)
        perr=pp-pos[indices];berr=np.linalg.norm(bb-basis[indices],axis=(1,2));pnorm=np.linalg.norm(perr,axis=1)
        cache=folder/(sat+'_proxy.npz');np.savez_compressed(cache,times_epsec=x,position_error_vector_km=perr,position_error_norm_km=pnorm,basis_error_frobenius=berr,node_times_epsec=nodes)
        sat_exact=[];body=None
        for g in [g for g in geometry if g['sat_id']==sat]:
            target=np.asarray(g['target_fixed_km'],float);states=g['exact_states'];times=np.array([v['time_epsec'] for v in states])
            body=np.einsum('nji,nj->ni',basis,target-pos)
            fitted,node_times,weights=interpolate(t,body,times);pfit,_,_=interpolate(t,pos,times);bfit,_,_=interpolate(t,basis,times)
            for index,state in enumerate(states):
                truthp=np.asarray(state['position_fixed_km']);truthb=np.asarray(state['body_to_fixed']);truebody=truthb.T@(target-truthp)
                delta=fitted[index]-truebody;ineq_error=inequalities(fitted[index])-inequalities(truebody)
                r=dict(sat_id=sat,point_id=g['point_id'],record_id=g['record_id'],time_epsec=state['time_epsec'],node_times_epsec=node_times[index].tolist(),lagrange_weights=weights[index].tolist(),body_error_vector_km=delta.tolist(),body_error_norm_km=float(np.linalg.norm(delta)),inequality_error_km=ineq_error.tolist(),position_error_norm_km=float(np.linalg.norm(pfit[index]-truthp)),basis_error_spectral=float(np.linalg.norm(bfit[index]-truthb,ord=2)),max_four_inequality_error_km=float(max(abs(ineq_error[:4]))),boresight_error_km=float(abs(ineq_error[4])),selection='Observed-event exact_states; not rejected-cell coverage')
                sat_exact.append(r);exact_rows.append(r)
        summaries.append(dict(sat_id=sat,input=file_record(path),source_reference=ref,actual_points=len(t),proxy_comparisons=len(indices),proxy_position_max_km=float(pnorm.max()),proxy_position_rms_km=float(np.sqrt(np.mean(pnorm**2))),proxy_basis_frobenius_max=float(berr.max()),exact_state_comparisons=len(sat_exact),residual_file=file_record(cache),elapsed_s=time.perf_counter()-begin,array_bytes=int(t.nbytes+pos.nbytes+basis.nbytes+perr.nbytes+berr.nbytes),scope='EMPIRICAL_ONLY; 10s proxy errors are not 5s subcell certification'))
        write(out/'search_progress.json',dict(satellites=summaries,completed=False));print('SEARCH_RESIDUAL',sat,len(indices),len(sat_exact),flush=True)
        del t,pos,basis,pp,bb,perr,berr,pnorm,body
    retention=[]
    bypair={(o['sat_id'],o['point_id']):o for o in opps}
    for event in raw:
        o=bypair[(event['sat_id'],event['point_id'])];windows=normalize_sources(o['candidates'],cfg['round3']['search']['candidate_half_window_s'],cfg['duration_s'])
        ok=any(w['window'][0]<=event['start_epsec'] and w['window'][1]>=event['stop_epsec'] for w in windows)
        retention.append(dict(record_id=event['record_id'],retained_in_frozen_candidate_union=ok))
        if not ok:errors.append('HISTORICAL_POSITIVE_NOT_RETAINED:'+event['record_id'])
    constructed=synthetic();write(out/'search_constructed_cases.json',constructed);write(out/'exact_state_residuals.json',exact_rows)
    diagnostics=[]
    availability=[]
    for foldername in ['diagnostics','reliability/known_extra']:
        for path in sorted((source/foldername).rglob('experiment.json')):diagnostics.append(dict(file=file_record(path),content=read(path),role='Historical finite diagnostic evidence; not new native execution'))
        for path in sorted((source/foldername).rglob('geometry_audit.json')):
            saved=read(path)
            availability.append(dict(file=file_record(path),events=len(saved),exact_state_records=sum(len(g.get('exact_states',[])) for g in saved),included_in_main_residuals=False,reason='Predeclared residual experiment uses full main 5s grid and all main exact_states. Historical diagnostic phases/targets/windows are separately inventoried; not selected by error magnitude.'))
    empirical=dict(proxy_points=sum(r['proxy_comparisons'] for r in summaries),exact_state_records=len(exact_rows),unique_exact_satellite_times=len({(r['sat_id'],r['time_epsec']) for r in exact_rows}),proxy_position_max_km=max(r['proxy_position_max_km'] for r in summaries),exact_body_error_max_km=max(r['body_error_norm_km'] for r in exact_rows),exact_four_inequality_error_max_km=max(r['max_four_inequality_error_km'] for r in exact_rows),exact_boresight_error_max_km=max(r['boresight_error_km'] for r in exact_rows),guard_km=cfg['round7']['candidate_guard_km'])
    empirical['observed_four_inequality_error_exceeds_guard']=empirical['exact_four_inequality_error_max_km']>empirical['guard_km']
    empirical['finite_maximum_is_not_a_bound']=True
    result=dict(status='FAIL' if errors or constructed['status']!='PASS' else 'PASS',errors=errors,search_error_basis='EMPIRICAL_ONLY',global_search_completeness='UNRESOLVED',next_scientific_run_gate='BLOCKED',classification={'fitted_polynomial_enclosure':'PROVEN_UNDER_ASSUMPTIONS','frozen_residuals':'EMPIRICAL_ONLY','unconditional_node_to_continuous_extrapolation':'COUNTEREXAMPLE_FOUND','true_j2_all_cells_error_bound':'UNRESOLVED'},empirical=empirical,satellites=summaries,retention=retention,diagnostic_evidence=diagnostics,other_exact_state_inventory=availability,constructed_case_count=constructed['case_count'],sample_rule=policy['sampling'],elapsed_s=time.perf_counter()-started,production_modified=False,raw_event_records_modified=False,
                missing_bounds=['continuous fourth derivatives','true attitude error at all nodes','continuous boresight and horizon bounds','validated floating root isolation'],selection_bias='Every available main exact state included, but states were saved around positive events. Rejected cells have no independent exact reference.')
    write(out/'search_error_analysis.json',result);text(out/'search_error_method.md',METHOD);write(out/'search_progress.json',dict(satellites=summaries,completed=True));return result
