"""Re-read the original OOXML, preserving mathematical structure and locators."""
import math
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from src.round8.common import file_record,read,sha,text,write

W='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
M='http://schemas.openxmlformats.org/officeDocument/2006/math'
NS={'w':W,'m':M}

def plain(node):
    return ''.join(n.text or '' for n in node.iter() if n.tag in {'{'+W+'}t','{'+M+'}t'})

def math_text(node):
    tag=node.tag.split('}')[-1]
    def child(n):
        x=node.find('m:'+n,NS);return math_text(x) if x is not None else ''
    if tag=='f':return '('+child('num')+')/('+child('den')+')'
    if tag=='sSub':return child('e')+'_{'+child('sub')+'}'
    if tag=='sSup':return child('e')+'^{'+child('sup')+'}'
    if tag=='sSubSup':return child('e')+'_{'+child('sub')+'}^{'+child('sup')+'}'
    if tag=='nary':return 'SUM['+child('sub')+'..'+child('sup')+']('+child('e')+')'
    if tag=='t':return node.text or ''
    return ''.join(math_text(x) for x in node)

def extract(source):
    blocks=[];media=[]
    with zipfile.ZipFile(source) as z:
        body=ET.fromstring(z.read('word/document.xml')).find('w:body',NS)
        for i,node in enumerate(body,1):
            if node.tag=='{'+W+'}tbl':
                for j,row in enumerate(node.findall('w:tr',NS),1):
                    blocks.append(dict(locator=f'body[{i}]/table/row[{j}]',text=' | '.join(plain(c) for c in row.findall('w:tc',NS))))
            else:
                formulas=[dict(readable=math_text(x),omml_xml=ET.tostring(x,encoding='unicode')) for x in node.findall('.//m:oMath',NS)]
                blocks.append(dict(locator=f'body[{i}]/paragraph',text=plain(node),formulas=formulas))
        for name in z.namelist():
            if name.startswith('word/media/') and not name.endswith('/'):
                blob=z.read(name);media.append(dict(zip_member=name,sha256=sha(blob),bytes=len(blob)))
    return dict(source=file_record(source),method='Fresh OOXML paragraphs/tables/math with structural fraction, subscript and sum rendering; no inferred page numbers.',blocks=blocks,media=media)

def review(policy,cfg,out):
    old=read(Path(policy['source_dir'])/'baseline/official_document_extract.json');original=Path(old['source']);extraction=extract(original)
    errors=[]
    if extraction['source']['sha256']!=old['sha256']:errors.append('OFFICIAL_ORIGINAL_HASH_CHANGED')
    write(out/'official_original_extract.json',extraction)
    byloc={r['locator']:r for r in extraction['blocks']};rows=[]
    def row(key,locations,engineering,status,assumption,impact,quote):
        evidence=[byloc[x] for x in locations]
        if quote and not any(quote in e['text'] for e in evidence):errors.append('SOURCE_LOCATOR_QUOTE:'+key)
        rows.append(dict(id=key,source_path=str(original),source_sha256=extraction['source']['sha256'],locations=locations,short_evidence=quote,
                         official_text=[e['text'] for e in evidence],formula_structures=[f for e in evidence for f in e.get('formulas',[])],engineering_definition=engineering,
                         implementation=['configs/round7.json','src/round3/statistics.py','src/round7/production.py'],status=status,assumption_or_difference=assumption,impact=impact))
    p=lambda i:f'body[{i}]/paragraph';t=lambda i,j:f'body[{i}]/table/row[{j}]'
    row('complete_window',[t(12,11),t(12,12)],dict(epoch=cfg['epoch_utcg'],window=[0,cfg['duration_s']]),'OFFICIAL_DOCUMENT_SUPPORTED','Dates fixed; exact time system reviewed separately.','Same seven-day duration; no new run.','2027年1月1日')
    row('time_system',[t(12,11),t(12,12)],cfg['time_system'],'UNRESOLVED','Table omits UTC/UTCG/TAI. Coverage screenshot says UTCG but shows 21–28 July 2026, different from normative 1–8 January 2027.','Organizer confirmation required.','2027年1月8日')
    row('orbit_model_coordinates',[t(12,2),t(12,3),t(12,5),t(12,6),t(12,10)],dict(earth=cfg['earth'],orbit=cfg['constellation'],frame=cfg['reference_frame']),'OFFICIAL_DOCUMENT_SUPPORTED','J2, 30s, J2000, circular orbit and height range stated; exact Earth constants are engineering assumptions.','Do not infer external physical accuracy from matched labels.','J2000')
    row('body_attitude',[t(12,9),p(15),p(16),p(17)],cfg['camera'],'ENGINEERING_ASSUMPTION','+Z toward Earth center and +X forward are stated; NadirECIVel and inertial-vs-fixed velocity, mounting quaternion not uniquely specified.','No attitude change or synthesized Access.','卫星运动的前进方向')
    row('fov_full_or_half',[t(49,6),t(49,7)],dict(along_half_deg=cfg['camera']['along_half_deg'],cross_half_deg=cfg['camera']['cross_half_deg']),'UNRESOLVED','Numbers 0.001622 and 0.81 are not labelled full or half angle.','Changing angle needs new physical events: NOT_COMPUTABLE_WITH_FROZEN_EVIDENCE.','0.81')
    row('swath',[t(12,8)],dict(formula_km=15*cfg['constellation']['h_km']/530,flat_half_angle_width_km=2*cfg['constellation']['h_km']*math.tan(math.radians(cfg['camera']['cross_half_deg']))),'UNRESOLVED','Near numerical agreement supports an interpretation but does not settle exact spherical/ellipsoidal footprint or rounded angles.','Physical sensitivity NOT_COMPUTABLE_WITH_FROZEN_EVIDENCE.','15×h')
    row('global_denominator',[p(71),p(72),p(76),p(78),p(79),t(49,2)],'No global experiment; fixed 16 mainland points only.','UNRESOLVED','Organizer selects effective region; authoritative boundary and valid grid list absent.','No global T90/T100, all-region certificate or area reweighting.','有效评价区域及评价网格')
    row('regional_denominator',[p(117),p(133),t(49,3)],'16 fixed mainland points; local 3264-point AT grid not official certification.','UNRESOLVED','0.1 degree spacing stated; boundary inclusion and organizer exact region unavailable.','Full regional metrics cannot be certified.','全部统一评价网格')
    row('grid_weights',[p(76),p(78),p(79)],'Equal point counts; denominator stays 16.','OFFICIAL_DOCUMENT_SUPPORTED','Coverage formula uses number of valid grid points, not area weighting.','No unapproved cos(latitude) area weights.','有效评价网格总数')
    row('zero_once_access',[p(126),p(133),p(135),p(190)],'Zero/one-visit points remain in coverage denominator; internal-gap count zero and mean null.','ENGINEERING_ASSUMPTION','Document defines successive visits but no exported null/empty numeric convention. Two sample points have fewer than two visits.','Conditional mean must disclose missing revisits.','至少两次有效访问')
    row('edge_censoring',[p(126),p(131),p(140),p(142)],'Leading/trailing gaps reported separately; omitted from conditional internal mean.','UNRESOLVED','Successive-visit formula omits edges, while longest continuous no-observation prose may be read more broadly. No explicit censoring rule.','Report edge-inclusive sensitivity separately; no invented official answer.','最长连续无有效观测机会时间')
    row('cross_satellite_union',[p(125),p(126),p(131)],'Per-point intervals from all satellites unioned, overlap/touch merged; tolerance 0 seconds.','ENGINEERING_ASSUMPTION','All satellites and consecutive valid accesses support union interpretation, but exact touching/positive tolerance rule not specified.','Synthetic tests do not count as natural overlaps.','全部卫星')
    row('gap_definition',[p(130),p(131)],'next_start minus previous_stop after point union.','OFFICIAL_DOCUMENT_SUPPORTED','No start-to-start substitution.','Engineering statistic follows stated interval definition.','ΔT')
    row('gap_aggregation',[p(133),p(134),p(135),p(139),p(140)],'Pool all valid internal gaps; sum divided by total gap count.','OFFICIAL_DOCUMENT_SUPPORTED','Equal-point average of per-point means differs and is only a sensitivity case.','Do not substitute per-point mean-of-means as official formula.','全部有效重访时间间隔的数量')
    row('insufficient_revisit_scoring',[p(190)],'Official score remains null; engineering H3 is not an official passing score.','OFFICIAL_DOCUMENT_SUPPORTED','Document says revisit component may be directly scored zero when some region cannot form two visits. Precise scope of some region needs confirmation.','Current two insufficient sample points cannot be concealed by mean.','重访项可直接判0分')
    row('coverage_thresholds',[p(83),p(84),p(89),p(90),p(181),p(183),p(188)],'Only local descriptive first-visit thresholds, never named official global metrics.','OFFICIAL_DOCUMENT_SUPPORTED','T90/T100 are first crossings of 90/100%; failure below 90 zeros both; failure below 100 zeros S100.','Organizer denominator still required.','首次达到90%')
    row('analysis_cadence',[t(49,4),t(49,5)],'5s screening, 0.001s local Access, 30s propagation setting.','UNRESOLVED','Official regional 1s instruction is not the same workflow as coarse candidate screening plus fine local Access. Neither equivalence nor conflict resolved by finer local step alone.','Confirm evaluator interface and required calculation cadence.','1S')
    row('scoring_formula',[p(103),p(108),p(158),p(160),p(167),p(174)],'No official score produced.','OFFICIAL_DOCUMENT_SUPPORTED','Weights 28,12,42,18; benchmark optima from valid entrants unavailable.','Sample data cannot produce official relative score.','SN')
    row('final_counts',[p(59),p(60),p(61),p(63),p(169),p(170)],'Only original 28 satellites tested; counts not expanded.','UNRESOLVED','30/60/100 introduced as examples and explicitly subject to later adjustment.','Need final organizer count list; 28-file submission distinct from scoring counts.','例如')
    row('interface_submission',[p(23),p(24),p(26),p(27),p(28),p(29),p(30),p(36),p(47),p(196)],'Generator accepts N and emits orbit parameters; current delivery is offline evidence only.','UNRESOLVED','N range and per-star h/i/RAAN/u stated; exact interface format absent, full 28-star global/regional artifacts required.','Not a complete official submission.','输出格式不满足接口要求')
    row('ideal_geometry',[p(13)],'Frozen ellipsoid, no terrain/cloud/energy constraints.','ENGINEERING_ASSUMPTION','No weather/energy/storage stated; ellipsoid surface and zero-height specifics are implementation choices.','Keep physical assumptions frozen.','不考虑云、雨')
    questions=[dict(id=r['id'],question=r['assumption_or_difference'],impact=r['impact']) for r in rows if r['status'] in {'UNRESOLVED','ENGINEERING_ASSUMPTION'}]
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,official_contract_review='COMPLETED_WITH_OPEN_ITEMS',official_readiness='UNRESOLVED',official_score=None,source=extraction['source'],rows=rows,open_questions=questions,
                images_reviewed=dict(image1='Body-axis illustration agrees with textual axes but does not define inertial vs Earth-fixed forward.',image2='Example coverage plot has UTCG dates July 21–28 2026; not normative January 2027 window.'),physical_sensitivity='NOT_COMPUTABLE_WITH_FROZEN_EVIDENCE',explicit_conflicts=[])
    write(out/'official_contract.json',result)
    lines=['# 正式评价合同核对','\n原始 DOCX 已重新读取；公式保留 OMML 分式、下标及求和结构。工程口径与官方支持分栏。官方准备状态：UNRESOLVED；不计算官方评分。','\n|条目|原文定位|结论|工程口径与差异|','|---|---|---|']
    lines += [f"|{r['id']}|{', '.join(r['locations'])}|{r['status']}|{r['assumption_or_difference']} {r['impact']}|" for r in rows]
    text(out/'official_contract.md','\n'.join(lines)+'\n')
    text(out/'organizer_questions.md','# 待主办方确认\n\n'+'\n'.join('- '+q['id']+': '+q['question']+' '+q['impact'] for q in questions)+'\n\n本轮未发送询问。\n')
    return result

def statistics(policy,cfg,out):
    s=Path(policy['source_dir']);raw=read(s/'G/T7/raw_intervals.json');points=read(s/'grid/frozen.json')['points'];rows=[];allgaps=[];edges=[]
    for p in points:
        events=sorted([r for r in raw if r['point_id']==p['point_id']],key=lambda r:(r['start_epsec'],r['stop_epsec']))
        union=[]
        for event in events:
            a,b=event['start_epsec'],event['stop_epsec']
            if union and a<=union[-1][1]:union[-1][1]=max(union[-1][1],b)
            else:union.append([a,b])
        gaps=[b[0]-a[1] for a,b in zip(union,union[1:])];allgaps.extend(gaps)
        edge=[union[0][0],cfg['duration_s']-union[-1][1]] if union else [cfg['duration_s']];edges.extend(edge)
        rows.append(dict(point_id=p['point_id'],event_count=len(events),union=union,gaps_s=gaps,edges_s=edge,mean_gap_s=math.fsum(gaps)/len(gaps) if gaps else None))
    old=read(Path(policy['k8_dir'])/'independent_arithmetic.json');errors=[]
    avg=math.fsum(allgaps)/len(allgaps);maximum=max(allgaps)
    if abs(avg-old['conditional_mean_gap_s'])>policy['tolerances']['statistics_s'] or abs(maximum-old['conditional_max_gap_s'])>policy['tolerances']['statistics_s']:errors.append('STATISTICS_MISMATCH')
    seven=[r for r in raw if r['sat_id'] in cfg['round7']['original_seven']];historic=read(Path(cfg['round7']['source_round6'])/'G/T6/raw_intervals.json')
    matched=set()
    for e in historic:
        matches=[r for r in seven if r['sat_id']==e['sat_id'] and r['point_id']==e['point_id'] and max(abs(r[k]-e[k]) for k in ['start_epsec','stop_epsec'])<=policy['tolerances']['historical_event_endpoint_s']]
        if len(matches)!=1:errors.append('HISTORICAL_SEVEN_ATTRIBUTION')
        matched.update(r['record_id'] for r in matches)
    pointmeans=[r['mean_gap_s'] for r in rows if r['mean_gap_s'] is not None]
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,event_count=len(raw),point_denominator=len(points),covered_points=sum(bool(r['union']) for r in rows),insufficient_points=sum(len(r['union'])<2 for r in rows),gap_count=len(allgaps),conditional_mean_gap_s=avg,conditional_max_gap_s=maximum,points=rows,original_seven_events=len(seven),additional21_events=len(raw)-len(seven),search_repair_new_events=sum(r['record_id'] not in matched for r in seven),
                sensitivities=dict(equal_point_mean_of_defined_means_s=math.fsum(pointmeans)/len(pointmeans),equal_point_mean_defined_points=len(pointmeans),internal_plus_edges_mean_s=math.fsum(allgaps+edges)/len(allgaps+edges),internal_plus_edges_max_s=max(allgaps+edges),edge_segment_count=len(edges),interpretation='Descriptive sensitivities on frozen events only, not official metrics; zero/one visit counts retained.'),physical_fov_or_orbit_sensitivity='NOT_COMPUTABLE_WITH_FROZEN_EVIDENCE',method='Independent sorted interval union and math.fsum; no project aggregate/endpoint_sweep called.',official_score=None)
    write(out/'engineering_statistics.json',result);return result
