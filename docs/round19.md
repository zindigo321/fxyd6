# 第十九轮：固定 R18 中心的完整 catalog 单换

运行入口为 `tools/run_round19.py`，使用现有 `D:\conda_envs\fmb\python.exe`。
配置采用独立 `ROUND19_V1` profile，不修改 R18 的268个消费文件或4个检查点。

约束参考 B0 为原28星 promotion；固定搜索中心与改善参考 S 为 R18 选择。
候选为 `(S-{r})∪{d}`，全部28个删除项与2143个 `U-S` donor，按删除项、donor升序遍历。
60004个唯一组合全部本轮重新处理和逐项独立核验，候选 REUSED=0。
相对 B0 的 mask T90/T100、内部池化 Tavg 可行性门保持原值。
合格改善需满足 `S.Tmax-candidate.Tmax-1e-6 >= 1`，排名依次为 Tmax、Tavg、T100、T90、identity。
没有合格改善时保留 S，复制 R18 CSV 原字节，元数据另存 `selection_protocol.json`。

处理优先级为 GAP、T100、T90、FULL。GAP 从 S 的原区间重建 Island_1 最长内部空窗，
逐候选证明 donor 不进入开区间，且27颗保留星的左右原访问见证均存续。
GAP 只说明不能通过本轮改善门，完整可行性未评价、known_infeasible=null。
T100 保存一个失败 mask 点和28个原源值；T90 使用主位集与独立 Boolean OR/count。
三个有效负证书均不虚构完整指标。其余候选全部完整精算。
数值 checker 使用独立最小值、次序统计、累计边界区间合并、可行门与选择，
共享边界仅为经过重新验证的解码、坐标、mask和原始状态 token。

历史回归464项分别用168/185/203/223/245/268文件版本一致隔离子集，26项绑定用142文件。
旧测试文件、ID和断言字节不改，新适配层只处理发现范围、路径和追加 socket 审计。
执行副本与源文件保留运行前后路径/大小/SHA映射，测试ID集合与原绑定日志逐项比对。

所有角色在本进程安装 Python 审计保护，拒绝全部 `socket.*` 事件、原生模块导入、
vendor代码执行、越界写和非白名单进程。白名单核对解释器、完整argv、cwd、work、destination。
导出子进程与finalizer不创建子进程。保护仅覆盖 Python 审计和导入边界，不声称操作系统级隔离。
监督器使用现有Windows Job Object机制，实际验证正常返回及超时后自己的后代均终止。

所有准备、失败、阅读、科学、回归、等待与导出共用首次准备有效起点。
科学和回归截止6600秒，总墙钟7200秒，父子重叠不重复相加，准备offset只消费一次。
冻结全部实际消费源码JSON/ZIP、输入、三种参考、空间和门后才处理真实候选。
改变消费源码必须保留旧attempt并完整重跑受影响作业，不能旧PASS配新源码。
只允许忽略最后一个未换行且无法解析的JSONL半行作为中断诊断；中间损坏、重复和缺项不能计完成。
PASS要求四分区精确集合互斥并集等于声明空间，逐项核验与全部回归、绑定、监督、交付均通过。
缺证或截止为BLOCKED/2；数值错误、测试失败、错绑、越权或封存导出错误为FAIL/1。

报告与状态先完成，再封存精确manifest及单向receipt；封存不可回写。
交付分sealed、原transport、completion delivery三层，每层读回精确集合/大小/SHA。
直接Python子进程没有Shell时其Shell退出字段为null；真实外层PowerShell退出后另行记录。
receipt创建边界与最终全部读回完成边界分别记录，最终观察单向绑定原receipt，存于work。
中文使用显式UTF-8并读回。

此轮只授权保存组件的条件离线研究。正式规则、评分、半角、直接AreaTarget、暂定mask、
500–700km混合保存高度可采纳性仍未确认；EOP止2019而场景为2027。
保存组件不证明连续几何完备性，新组合未做整星座STK验证。
active_protocol_change_authorized=false，official_readiness=UNRESOLVED，official_score=null，
next_scientific_run_gate=BLOCKED_PENDING_RULE_CONFIRMATION。
原生激活预算0，Git写操作预算0，完成后不自动开始下一轮。
