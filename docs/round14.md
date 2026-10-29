# 第十四轮：冻结组件库同高度单星替换

默认入口：`D:\conda_envs\fmb\python.exe -X utf8 -B G:\fmb666\tools\run_round14.py`。

本轮在保存的 TEAM_COMPETITION_V3 条件下开展有限离线研究。两轴半角0.81°、不划网格直接对三个AreaTarget求Access尚未经用户确认，不改变我方现行协议或官方成绩。日期2027-01-01至2027-01-08，604800秒，J2000/J2；地球资源、安装、目标及采样设置从冻结数据验证。EOP止2019、场景在2027；mask非官方，保存结果不证明连续几何完备性。

仅从固定N28基线删除一个资产、从同一精确浮点高度的32个donor加入一个。全部60资产、28基线、32donor及896组合的身份由catalog和promotion原字节导出。遍历按remove索引升序，再按add索引升序，不扩展到下一邻域。

评价前完成代码、合成测试、配置和本文；冻结完整合同、源码清单与快照。真实加载验证60资产的原始状态、归一化唯一性、生产者太阳同步关系、state/key/context/origin协议、payload大小和摘要、43424点原始首访与只读mmap行，以及三对象原始区间。缺证不补采，不执行vendor代码，不访问历史D盘来源路径。

每个候选直接求28行首访最小值。原43424点及暂定43070点mask分别报告覆盖、未覆盖、T90、T100。90%门为ceil(9*n/10)严格次序统计；不完全覆盖时T100为null。各对象分别合并区间，容差1e-6秒；所有内部gap池化求Tavg/Tmax。首尾空窗另列；不足两次访问的对象导致不可行。

主可行门：恰28个合法唯一状态；三个目标各至少两次合并访问；mask精确全覆盖；T100有限且不超过604800；T90/T100/Tavg各不超过本轮重放基线对应值加1e-6秒。改善门保守固定为`基线Tmax-候选Tmax-1e-6 >= 1秒`。合格改善按Tmax、Tavg、T100、T90、identity依次排序。所有候选和拒绝原因保留，不按代理指标筛选。

独立checker共享已验证输入schema、坐标和mask。其计算不调用主评价、区间并集、可行性或选择函数：采用基线前后缀min加donor、排序次序统计、累积停止前沿聚类。对基线和每个候选逐点比较全部43424个分类/时间，并比较区域区间、计数、指标、门和选择。分类和整数计数精确，有限时间绝对容差1e-6秒，rtol=0。基线和最终选择另保存完整逐点及逐对象明细。

旧149项加R13的53项共202项测试在隔离副本中运行，使用当前168文件显式子清单，包括两项R13修复，保留运行前后路径映射及摘要。历史26项绑定反例继续使用冻结142文件子清单。新R14测试单独执行。历史全包审计与未重跑77/49记录仅标REUSED。

R13活跃修复自包含：封存重入拒绝显式新评价参数，保留纯历史复核；新封存验证实际五类attempt、consumer_code、命令、源码快照及产物摘要。旧K13按旧profile校验，文件不变。R14使用自己的ROUND14_V1封存profile和变化白名单，不调用R13整轮封存。

总墙钟7200秒，从首次准备起包含作者编写、等待、失败、子进程和导出；科学/回归在6600秒截止，父进程timeout取共享剩余预算，循环分块检查，最后最多600秒收尾。没有独立阶段硬截止。FAIL优先于随后超时；失败尝试及源码快照保留，修改源码后须新attempt完整重跑受影响工作。

退出0表示两项修复、60资产、基线、896枚举/独立核对、旧新测试、保全与封存全部通过，可包含无合格改善。退出2表示缺证或截止下的真实未完成前缀；退出1表示实质错误、测试失败、源码错绑、未授权行为或封存错误。无改善只对声明邻域下结论，不是全局最优。

产物先写报告、状态和日志，再创建精确成员manifest、独立读回和单向receipt绑定。receipt不自哈希，后续入口完成/Shell退出码和导出记录放在传输层，封存内容不回写。新组合始终标记source=archived_component_composition、new_native_validation_performed=false、whole_constellation_STK_verified=false。

始终保持active_protocol_change_authorized=false、official_readiness=UNRESOLVED、official_score=null、next_scientific_run_gate=BLOCKED_PENDING_RULE_CONFIRMATION、native_activation_count=0、git_write_operations=0。K12仍BLOCKED/2、0单元、成本NOT_RUN。完成后停止，不创建正式提交包、不执行Git写操作或启动下一轮。
