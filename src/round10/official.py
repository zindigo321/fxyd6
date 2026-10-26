"""Reuse the identity-bound original extraction; ask six Chinese question groups."""
from pathlib import Path
from src.round8.common import file_record, read, text, write


def review(k9, out):
    contract=read(k9/'official_contract.json');extract=read(k9/'official_original_extract.json')
    original=extract['source'];actual=file_record(original['path'])
    if actual!=original or contract['source']!=original:raise ValueError('OFFICIAL_ORIGINAL_IDENTITY')
    blocks={b['locator']:b for b in extract['blocks']};errors=[]
    for r in contract['rows']:
        if r['source_sha256']!=actual['sha256'] or [blocks[p]['text'] for p in r['locations']]!=r['official_text']:
            errors.append('ORIGINAL_LOCATOR_BINDING:'+r['id'])
    # Local discovery is explicit and bounded, not a claim about unknown sources.
    folder=Path(original['path']).parent
    inventory=[dict(file_record(p),role='ORIGINAL_OFFICIAL' if str(p)==original['path'] else 'PROJECT_AUTHORING_NOT_OFFICIAL_CLARIFICATION')
               for p in sorted(folder.iterdir()) if p.is_file()]
    expected_names={Path(original['path']).name,'Astra_Extra_High_星座构型优化立项书写作Prompt.txt','立项书-version1_排版修订版.docx'}
    unknown=[r for r in inventory if Path(r['path']).name not in expected_names]
    if unknown:errors.append('NEW_LOCAL_MATERIAL_REQUIRES_REVIEW')
    specs=[
      ('时间系统',['complete_window','time_system'],'2027-01-01 00:00:00 至 01-08 00:00:00 采用 UTC、UTCG、TAI 还是其他时间系统？','当前暂用 UTCG；图示的 2026 年 7 月 UTCG 不能确认 2027 年历元。','历元偏移会改变地固几何与访问。','带版本的历元及时间系统说明；改变历元需新 Access。'),
      ('视场、幅宽与姿态',['fov_full_or_half','swath','body_attitude'],'0.001622°/0.81°是全角还是半角？15×h/530 km 的幅宽采用何种地球模型？前进方向采用惯性速度还是地固速度？','当前视场按半角；粗筛交叉迹半角为精细 Camera 的两倍；姿态暂用 NadirECIVel。','角度、地表与姿态改变不能从冻结事件推算。','Camera 参数、安装矩阵、速度参考系及幅宽定义的正式补充。'),
      ('有效网格与分母',['global_denominator','regional_denominator','grid_weights'],'请提供全球及区域有效网格清单、边界包含规则、永久不可达点处理及固定计分分母。','固定16个诊断点；等点权；不是官方完整有效网格。','16/16覆盖不代表全球或整个区域覆盖。','官方网格/边界文件、版本与摘要、分母生成规则。'),
      ('首尾、零次与一次访问',['edge_censoring','zero_once_access','gap_aggregation','insufficient_revisit_scoring'],'首尾无观测段是否计入均值和最大值？零/一次访问点如何进入分母及评分？不足两次访问导致零分的作用范围是什么？','当前内部 gap 池化均值；首尾段另作敏感性；不足两次点不删除。','内部37段与含首尾69段口径不同；统计可复算，官方分数仍不可定。','边界删失规则、缺失值输出约定、重访零分判定伪代码与示例。'),
      ('1秒分析与跨星合并',['analysis_cadence','cross_satellite_union','gap_definition'],'区域1秒要求是否允许5秒筛查加局部0.001秒 Access？跨星重叠、相接和正容差怎样合并？','当前跨星按点求并集、相接合并、容差0秒；局部细步长不证明全窗等价。','筛查完备性与访问合并都影响重访数及 gap。','评价器版本、采样/事件求解要求、合并容差和边界案例。'),
      ('星数、接口与提交版本',['final_counts','interface_submission','scoring_formula'],'最终计分星数是否仍为示例30/60/100？请提供参数接口、28星提交要求与最终版本清单。','本轮仍限28星冻结样本；未产生官方提交包或相对评分。','示例星数可调整；缺评价基准和接口不能计算正式得分。','最终赛题版本、接口schema、示例输入输出、计分工况及提交清单。')]
    byid={r['id']:r for r in contract['rows']};groups=[];lines=['# 六组正式评价确认项','', '原件及 K9 提取、合同身份已核验。当前本地目录无新增可靠正式澄清；复用受绑定提取，不重复提取，不代发询问。','']
    for index,(title,ids,question,current,impact,needed) in enumerate(specs,1):
        evidence=[dict(id=i,locations=byid[i]['locations'],short_evidence=byid[i]['short_evidence'],official_text=byid[i]['official_text'],formula_structures=byid[i]['formula_structures']) for i in ids]
        groups.append(dict(group=index,title=title,evidence=evidence,current=current,question=question,impact=impact,needed=needed,status='UNRESOLVED'))
        lines += [f'## {index}. {title}', '',f'原文：'+ '；'.join(', '.join(e['locations'])+'：'+e['short_evidence'] for e in evidence), '',f'工程现状：{current}', '',f'待确认：{question}', '',f'影响：{impact}', '',f'需要补充：{needed}', '']
    result=dict(status='FAIL' if errors else 'PASS',errors=errors,official_contract_review='COMPLETED_WITH_OPEN_ITEMS',official_readiness='UNRESOLVED',official_score=None,
                original=actual,reused_extraction=file_record(k9/'official_original_extract.json'),reused_contract=file_record(k9/'official_contract.json'),
                local_scan=inventory,new_reliable_official_material=[],groups=groups,physical_sensitivity='NOT_COMPUTABLE_WITH_FROZEN_EVIDENCE')
    write(out/'official_contract_review.json',result);text(out/'organizer_questions.md','\n'.join(lines))
    text(out/'K9_erratum_notes.md','# K9 后续勘误附注\n\n保留 K9 原件。26项是绑定反例总数，含模块、回调和路由案例，并非全为函数头部反例。有限数值案例标 NUMERICAL_FIXTURE，回退程序行为标 TESTED_BEHAVIOR；Bernstein 凸包界仅为假设成立时的条件数学性质。K9 的 82.823 秒是 worker 时间，不是全生命周期。K9 的 4780 COMPLETE 与独立审计 4351 匹配、429 不可读分别属于不同核验主体。\n')
    return result
