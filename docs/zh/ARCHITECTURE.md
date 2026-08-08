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
