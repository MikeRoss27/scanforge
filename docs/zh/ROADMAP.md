# 产品路线图 — ScanForge

本文档记录了产品评审（定位、竞品分析、分阶段覆盖）以及按时间线组织的改进方向，作为开发优先级排序的参考。

## 1. 定位

ScanForge 是一个 Go CLI，将侦察/安全工具编排为基于产物的流水线，并**严格执行范围（scope）**——这是核心差异化：ProjectDiscovery 生态中没有工具会强制授权边界。DAG + 产物 + dry-run 使其成为授权渗透测试中安全、确定性、可审计的工具。

| 工具 | 类型 | 相比 ScanForge 的优势 | ScanForge 的优势 |
|---|---|---|---|
| ProjectDiscovery 套件 (pdtm) | 工具套件 + SaaS 云 | 持续集成、社区模板、截图 | 范围执行、产物流水线、dry-run、整合报告 |
| reconftw | bash 脚本 | 模块数量、社区 | 可靠性、范围、确定性 |
| Osmedeus | Go 编排器 | 模块/插件可扩展、Web API、工作区 | 简单、安全（范围）、TUI |
| reNgine | 开源 ASM Web | UI、调度、通知、组织 | 适合手动渗透的 CLI + dry-run + 范围 |
| Trickest / PD Cloud / Intruder | 商业 ASM | 持续扫描、优先级排序、工单 | — |

**结论**：真正的竞争对手是 **reNgine**（持续性/ASM）和 **reconftw**（模块覆盖）。ScanForge 最大的两个缺口正在于此：覆盖（DNS 爆破、被动源）和持续性（运行间 diff、调度、通知）。

## 2. 分阶段覆盖

| 阶段 | ScanForge | Best-in-class | 差距 |
|---|---|---|---|
| 子域枚举 | subfinder + gau | + DNS 爆破（shuffledns/puredns+massdns）、置换（gotator/altdns）、被动源（Chaos、CDX） | 🔴 重大——无爆破时仅达可能覆盖的 ≤30 % |
| 解析 | dnsx | — | ✅ |
| 端口 | naabu + nmap | + masscan（超大范围） | 🟡 |
| HTTP 探测 | httpx | + 截图（httpx 原生支持） | 🟡 容易 |
| 爬取 | katana | — | ✅ |
| 模糊测试 | ffuf | — | ✅ |
| 漏洞 | nuclei + techcve | + EPSS / CISA KEV / CVSS 优先级 | 🟡 techcve 位置理想 |
| 密钥 | jssecrets 原生 | + gitleaks/trufflehog（Git 仓库） | 🟡 |
| 报告 | report.json/.md | HTML、SARIF、DefectDojo、通知 | 🔴 ——客户/CI 的期望 |
| 持续性 | 一次性运行 | 调度、运行间 diff、告警 | 🔴 ——商业 ASM 的价值 |

## 3. 时间线

### H1 — 快速、即时价值

| # | 想法 | 状态 |
|---|---|---|
| H1.1 | `scanforge diff <run1> <run2>`：两次运行之间的子域 / 端口 / 漏洞差异（`--json` 选项供 CI 使用） | ✅ 已实现 |
| H1.2 | `scanforge export --format sarif\|defectdojo <run>`：生态标准输出（GitHub/GitLab CI、DefectDojo） | ✅ 已实现 |
| H1.3 | 多目标：`run`/`plan` 支持 `--targets <文件>`（10 个域名 + 网段），全局去重，按目标定义范围 | ✅ 已实现 |
| H1.4 | techcve 中的 EPSS + CISA KEV 优先级（内置数据集、真实分数），报告展示 | ✅ 已实现 |

### H2 — 中期

| # | 想法 |
|---|---|
| H2.1 | DNS 爆破 + 置换模块：shuffledns/puredns + gotator，通过 `scanforge auth` 被动丰富（Chaos、CDX） |
| H2.2 | 截图：基于 `httpx -screenshot` 的模块——客户视觉反馈 |
| H2.3 | 中断运行恢复：通过 manifest 从当前 wave 继续 |
| H2.4 | 运行结束 Webhook 通知（Slack/Discord/通用） |
| H2.5 | `scanforge watch`：简单调度 + 自动 diff |
| H2.6 | 模型中加入 CVSS（分数/基准）以支持 SARIF/DefectDojo 和排序 |

### H3 — 愿景

| # | 想法 | 状态 |
|---|---|---|
| H3.1 | 发现结果 AI 分诊：LLM 摘要 + 去重 | ✅ 已实现 |
| H3.2 | 类 nuclei 的 HTML 报告（客户报告） | |
| H3.3 | 实时数据：获取最新 EPSS/KEV/NVD，而非内置数据集 | |

## 4. 范围外（防止范围蔓延）

- sqlmap / dalfox / smuggler：nuclei + httpcheck 已覆盖主要需求，引入会破坏 DAG 的一致性。
- 被动 amass：内存开销大，subfinder + chaos 已足够。
- 完整 Web UI：reNgine 已存在——ScanForge 的差异化仍是安全、确定性的 CLI。

## 5. 数据来源

- EPSS：https://api.first.org/data/v1/epss（2026-08-09 获取，用于 techcve 数据集）
- CISA KEV：https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
