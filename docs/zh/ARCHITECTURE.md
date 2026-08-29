# 架构

## 产物驱动的流水线

每个模块声明它需要和产生的产物。ScanForge 构建 DAG，拒绝重复的生产者、缺失的依赖和循环依赖，然后按波次运行就绪的模块。

主要链路：

```text
subfinder → subdomains → dnsx → resolved_hosts
resolved_hosts → httpx → alive_urls
resolved_hosts → naabu → open_ports → nmap
alive_urls → tlsx / whatweb / wafw00f / katana / ffuf / nuclei
target → gau → historical_urls
```

`scanforge plan TARGET --preset deep` 显示已验证的波次，而不运行任何工具或创建运行。

## 安全边界

有效范围在应用层构建并传递给 `RunContext`。在发布前，包含主机、IP、端口或 URL 的文本产物会被集中过滤。因此被拒绝的值永远不会到达下游模块，并记录在拒绝日志中。

`exact` 模式始终在 Subfinder 输出中保留根目标，以便 DNSX 和 HTTPX 可以继续处理，而不会隐式扩大范围。Nmap 接收 Naabu 生成的已验证主机/端口对，并仅对这些端口执行扫描。

## 输出组织

一次运行存储在 `runs/<目标>/<时间戳>/` 下：

```text
00_meta/       清单、命令、stderr、范围和拒绝记录
01_subdomains/ Subfinder 和 DNS 结果
02_http/       HTTP 探测与 TLS 增强
03_ports/      Naabu 结果与 Nmap XML
04_web/        技术与 WAF 检测
05_content/    爬取、历史 URL 与模糊测试
06_vulns/      Nuclei 结果
report.json    规范化报告
report.md      可读摘要
```

清单区分 `completed`、`partial` 和 `failed` 状态，引用已产生的产物，并保留范围来源以供审计。

## 分诊层（H3.1）

`scanforge triage <run>` 从报告中派生解释，而绝不修改报告本身：

```text
report.json ──► finding.FromReport ──► 规范化发现结果（确定性 ID）
                                          │
                                          ▼
                              finding.BuildRelations（L0/L1）
                                          │
                                          ▼
                              分诊引擎：group → bundle → analyze → validate
                                          │
                                          ▼
                          <run>/triage/（manifest、relations、insights、report.md）
```

边界是严格的：**ScanForge 拥有事实，AI 拥有解释，验证位于两者之间。**

- `internal/finding` 将报告投影为扁平发现结果，使用确定性 ID
  （`F-` + source|template|asset|matched_at|evidence 的哈希），并计算确定性
  关系（重复 1.00、共享 CVE 0.99、相同端点 0.95、相同资产 0.80）。语义关系
  （L2）可以补充它们，但绝不能覆盖它们。
- `internal/triage` 运行流水线：分组（对关系图做 union-find）、确定性洞察
  （摘要 + 去重组）、可选的 LLM 分析、验证与协调（按优先级排序、ID 稳定）。
- LLM 只收到精简投影（`TriageBundle`）：证据被截断、绝不发送工具原始输出、
  上限 150 条发现。其输出会对照事实进行验证——未知的发现 ID、CVE 或证据
  字符串会拒绝整个洞察——因此模型无法注入新的事实。
- `internal/inference` 将传输抽象为 `Client` 接口；内置实现使用 OpenAI 兼容
  chat completions API（llama.cpp、vLLM、Ollama 等）。
- 来源记录在 `triage/manifest.json` 中（模型、提示词版本、输入摘要、温度），
  当输入摘要、模型和提示词版本不变时，缓存会复用结果（`--force` 可绕过）。
