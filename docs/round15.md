# 第十五轮完整双星替换离线研究

默认入口：`D:\conda_envs\fmb\python.exe -X utf8 -B G:\fmb666\tools\run_round15.py`。使用现有环境，不安装依赖。185个R14冻结消费文件全部只读，R15使用新增适配层和ROUND15_V1合同、版本绑定、封存profile。

研究条件为保存的TEAM_COMPETITION_V3，2027-01-01至2027-01-08、604800秒、J2000/J2、两轴半角0.81°、三个冻结AreaTarget。两项规则修订未获用户确认，不改变我方现行协议或官方成绩。EOP止2019、场景2027；mask非官方，保存结果不证明连续几何完备性。

从catalog/promotion原始字节读取精确高度692.8318965760104km的60资产、28基线及32donor。验证全部60状态、归一化唯一性、生产者太阳同步关系、context/key/origin protocol、payload大小和SHA、原NPZ全部43424值与只读mmap行一致、坐标和三个对象区间。缺证不删资产、不补采、不访问历史D盘origin、不执行vendor。

完整空间为C(28,2)×C(32,2)=187488。删除对r1<r2升序字典序，内层新增对a1<a2升序字典序；构型sorted((B-{r1,r2})∪{a1,a2})。身份沿用排序冻结状态token的规范摘要。主路径combinations与独立嵌套位置循环分别生成精确集合及实际遍历顺序摘要。实现、合成测试、配置与本文完成后冻结源码/合同/输入身份/规则，再评价真实新构型。

先重放基线，逐点与保存整星座比较，并与R14及K13指标对照。T90为ceil(9*n/10)严格次序统计，原域43424与暂定mask43070并列，不完全覆盖时T100=null。每目标分别以1e-6秒容差合并原Access；全部内部gap跨目标池化求Tavg/Tmax，不平均对象均值。首尾与包含边界指标另列。

主约束保持R14：恰28合法唯一状态，三个目标各至少两次合并访问，mask精确全覆盖，T100有限且≤604800；mask T90/T100及池化内部Tavg≤本轮基线+1e-6。改善门固定baseline_Tmax-candidate_Tmax-1e-6≥1秒。合格改善按Tmax、Tavg、T100、T90、identity排序。首尾不加可行门或主目标，不事后放宽约束。

证书从全部60资产原始Island_2区间重新验证：基线最长内部gap为G=(L,R)，仅1123在G内部有[155654.373767399,155659.896226983]；基线前侧资产恰911、1370，后侧恰6资产，端点和payload摘要绑定。新增对不含1123且删除对不是{911,1370}时，候选保留两侧访问、内部无访问，因此内部Tmax≥R-L，无法通过保守1秒改善门。

分区A：新增含1123，11718；B：删除911和1370且新增不含1123，465；C：其余175305证书排除。A/B共12183全部精算并逐点独立核对。B不能删去：删除全部前侧访问可能把原内部gap变为首窗。证书C不是可行性拒绝，完整指标/可行性/首访为NOT_EVALUATED/null，逐候选引用共同证明与两侧见证，不伪造数值。证明缺证BLOCKED，实质矛盾FAIL，不自动套预计数量或改筛选规则。

独立checker共享验证过的输入解析、坐标、mask和identity格式。它不调用主评价/并集/可行门/排序/证书判定；首访采用保留26行独立逐行min再加两个donor，按删除对缓存；主路径仍直接28行min。次序统计partition/sort不同，区间增量并集/累计前沿聚类不同。对基线与全部12183在丢弃向量前核对43424分类/时间、三对象区间及全部指标、首尾、门和选择。分类/整数精确，atol=1e-6秒、rtol=0。所有175305证书逐项由原区间派生的独立证明核验候选归属、内部无访问和保留两侧访问。

台账每候选仅一个处理状态。分别统计声明、精算、精算独立核对、证书排除、证书独立核验、未处理、UNKNOWN、合格数、是否保留基线。完成依据独立精确集合和摘要绑定，不只数量相加。完整报告/核对记录流式JSONL，基线和最终选择完整NPY/CSV及区间另存；全60原域并集相同354缺失点ID和摘要另存，不推导物理不可达或官方mask证明。

旧202项用168源文件隔离副本运行；R14的89项用185文件隔离副本运行，单独计数。原测试文件/ID/断言不改；适配层仅选择测试文件模式，其生成源码与摘要留证。历史26绑定反例继续用冻结142子清单。子集路径映射、前后字节和SHA核验，不与完整R15清单直接判等。新增R15测试单独执行。

从首次准备起总墙钟7200秒，包括编写、失败、等待、子进程和导出，科学/回归在6600秒截止。父进程timeout共享剩余计算/总预算，流式循环分块检查并保存真实前缀。FAIL优先于后续超时。科学执行后改消费源码或配置，必须保留旧attempt/结果，在新attempt重跑受影响证明、基线、精算、checker和回归；不足则真实BLOCKED。

旧离线guard复用；科学worker禁止网络/原生/子进程/vendor执行/越界写，历史测试保留受控模拟例外。真实原生激活和受控拒绝分开计数。所有选中作业绑定真实attempt、argv、源码清单/ZIP、输出集合、父子返回码、timeout和监督结果。报告/状态/日志先完成，再manifest、独立读回、单向receipt；receipt不自哈希。入口完成、Shell退出与导出回执在传输层，不回写封存。

PASS/0表示精确完整双换空间被精算或有效证书互斥穷尽处理、独立核验/回归/绑定/保全/封存/导出均通过；没有合格改善也可PASS，结论仅NO_FEASIBLE_IMPROVEMENT_IN_DECLARED_TWO_SWAP_NEIGHBORHOOD。缺证或截止BLOCKED/2保留前缀，不下全邻域结论；实质不一致/测试失败/源码错绑/越权/封存错误FAIL/1。

新组合source=archived_component_composition，new_native_validation_performed=false，whole_constellation_STK_verified=false；基线历史整星座来源不转移给新组合。始终active_protocol_change_authorized=false、official_readiness=UNRESOLVED、official_score=null、next_scientific_run_gate=BLOCKED_PENDING_RULE_CONFIRMATION、native_activation_count=0、git_write_operations=0。K12仍BLOCKED/2、0单元、成本NOT_RUN；R14历史PASS与0改善不改写。完成后停止，不扩三换/其他高度/全库，不提交Git、不启动原生或下一轮。
