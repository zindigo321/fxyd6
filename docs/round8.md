# 第八轮：冻结科学数据的复合离线验收

以提交 `6c73dc3293fdeeb02b632c7c7ea876fbb7b1cb82` 为基线，仅新增第八轮验证器、测试、配置和本文档。第五至七轮入口与原状态语义保留。

入口：`D:\conda_envs\fmb\python.exe -B tools/run_round8.py`。默认交付目录为 `G:\gpt-file\Codex\outputs\bd-fmb\round8\<唯一运行目录>`；工作文件位于 `G:\fmb666\work\round8\<validator_run_id>`。可用 `--output` 指定一个全新的交付目录。没有 STK 参数，也没有原生补验分支。

验收政策在 `configs/round8.json` 预先声明。每次运行先冻结完整代码 K，保存代码清单和 ZIP，再开启只读验证子进程。结果以本次 `final_status.json`、`command_result.json` 和 `delivery_verification.json` 为准，本文不预填验收状态。

`validate(subject_ctx, validator_ctx, source_dir, historical_validator_dir, output_dir, work_dir, policy)` 中，subject 始终保留 S 的 run/config/input/code 身份和原输出路径；validator 使用新的 K 身份。旧 `audit_dataset` 与写文件的 `integrity` 不会被调用。复用的 `validate_events`、`audit_ledger`、`audit_constraints`、`parameter_check` 只返回计算结果；其代码包含在依赖审查中。

原生调用绑定包括监督器的 r7 动态分发、诊断的显式 Model/search/integrity 回调、Model 的 BaseModel 继承、原七轮生产链、cold_old 的隔离 R6 动态加载、原重开所用 R3 Model。全体既有 src/tools 模块纳入保守闭包；不能仅凭单函数 AST 一致放过全局、别名、默认值或 dispatch 改动。S→V 中唯一允许的执行代码变化是审查过的后置约束核验；README/.gitignore 保留在完整清单内。

所有写入均受路径保护，限定本轮 output/work；原生导入和未经审查的子进程被拒绝。离线回归复制当前源码与两份 GeoJSON、三份 AT 到本轮 work，测试安装探测默认为受控 missing，显式 missing/error 用例保持原语义。生产源文件不改。测试使用的原生对象均为既有模拟对象，不代表原生运行。

原始字节保全与规范化文本解释分开。历史 S 的 FAIL/退出 1、V 的 BLOCKED/退出 1、官方 UNRESOLVED 必须同时出现在新报告。即使新的离线验收通过，也只表示冻结科学数据通过修正版与依赖绑定复核，不表示 K 新做过 STK、原命令变成退出 0、全区域覆盖或官方评分通过。

关键证据不可读、损坏或依赖影响不明时输出 FAIL/BLOCKED，并列明缺口。不启动原生补验、不改变历史预算、不执行 Git 写操作。新产物先定稿再生成清单，清单与后验核验单向绑定。

测试清单：原始/LF 哈希和算法标签；subject/validator 分离；全局/导入/回调/dispatch 改动；缺原生证据与坏 ZIP；完整 49 空查询正例及逐项删除；查询重复/孤立/失败/窗口与事件篡改；45 文件和 28 Camera 绑定正例及对象/约束反例；独立数值、轨迹、几何和历史重开；输入与 K 原始字节保全；完整离线回归；最终 UTF-8 与产物清单读回。

本次接手时已有第八轮未跟踪文件，修改前原始字节另存 execution_start.json/zip。历史 C 快照另由只读 git show/ls-tree 核对到提交树；旧快照与本次工作树起点分别保存。辅助独立审计目录为可选参考，其缺失不替代或否定 S/V 的直接科学核验。非关键测试材料只允许权限导致的未核验，已读取的字节不符仍失败。

最终编码与交付读回参加汇总状态及退出码判定，验证子进程退出码单独保留。状态或报告更新后重新生成最终字节清单，避免出现汇总 PASS 而命令退出 1 的冲突。
