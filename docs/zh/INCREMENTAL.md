# 增量扫描

> 中文译文，原文见 [../INCREMENTAL.md](../INCREMENTAL.md)（法语）。

ScanForge 为每个目标在一个简单文件中保存其观察到的资产历史：
`runs/<目标>/assets.jsonl`。没有数据库：该文件可读、可复制、可纳入版本管理，
与运行的其余内容一样。

## 历史（`assets.jsonl`）

**仅追加**文件（每条记录一行 JSON），在每次**已完成**（`status: completed`，
非 `--dry-run`）的运行结束时以原子方式更新（临时文件 + `rename`）。它根据运行的
整合报告（`internal/report`）构建，而不是重新解析工具输出。

| 字段 | 含义 |
|------|------|
| `type` | `subdomain`、`host`（IP）、`url`（HTTP 服务）、`path`（katana/ffuf）、`port`、`tech`、`finding`、`run` |
| `value` | 资产标识（`host:port/proto`、`host\|技术` 等） |
| `first_seen` / `last_seen` | 首次 / 最近一次观察（RFC 3339） |
| `last_run_id` | 最近一次涉及该资产的运行 |
| `status` | `new`、`unchanged`、`changed`、`gone` |
| `host` | 在任何复用之前都要对照范围校验的字符串 |
| `fingerprint` | 其变化会导致 `changed` 的属性指纹（HTTP 状态、标题、服务器、服务版本、IP、严重程度） |

资产的当前状态是它的**最后一行**。每次运行追加一行 `run`（范围哈希、工具版本），
然后为每个观察到的资产追加一行，并为每个不再出现的已知资产追加一行 `gone`。

- `new`：从未见过，或在 `gone` 之后重新出现（保留原来的 `first_seen`）。
- `changed`：指纹相对上次运行发生了变化。
- `gone`：本次运行本可观察到却不存在。只有当能够产生该类型的模块已完成时，
  才会将其类型声明为 `gone`（例如没有 naabu/nmap 时，端口不会被声明为 `gone`）。
  在经过过滤的 `--incremental` 运行中，`path` 和 `finding` 永远不会被声明为
  `gone`：nuclei/katana/ffuf 有意没有重新检查全部内容。
- `partial`、`failed`、`aborted` 或 `--dry-run` 的运行**不会写入任何内容**：
  否则会错误地出现 `gone` 资产。
- 对同一次运行重复记录（例如对已完成的运行执行 `resume`）没有任何效果。

## `scanforge run TARGET --incremental`

在模块运行之前先加载历史，然后**每个条目都会根据当前有效范围重新过滤**
（范围外或没有范围键的条目绝不会被使用）。随后 nuclei、ffuf、katana 和
jssecrets 只处理**新增或变化的** URL：

- ffuf 和 katana：过滤 `alive_urls`；
- nuclei：过滤 `attack_surface_urls`；
- jssecrets：过滤 `crawled_urls`（`historical_urls` 和 `discovered_paths`
  语料仍然完整读取）。

如果 URL 未知、上次运行为 `gone`，或其 httpx 指纹（状态、标题、服务器、重定向、
类型、favicon；不含大小或响应时间）发生了变化，就会被保留。有疑问时保留。
聚焦**只能删除**已经过范围过滤的产物中的行（`RunContext.FocusedInput` 也会再次按
范围过滤）：它绝不会扩大目标。没有 `--incremental` 时行为不变。

如果聚焦后没有任何内容需要扫描，该模块会被标记为 `skipped`
（“incremental: no new or changed URLs”），并发布一个空产物，以便下游模块正常工作。

需要了解的后果：增量运行的 `report.json` 只包含被重新检查的 URL 的发现结果/路径；
历史则保留之前的内容。

### 缓存失效

保守策略：如果**有效范围的哈希**（`scope_sha256`）或**某个工具的版本**（两次运行
都存在的工具）与上一次记录的运行不同，则一切都视为新增：不做任何过滤，
所有观察到的资产都写为 `new`。

### 恢复

对增量运行执行 `scanforge resume` 仍然是增量的（该选项保存在清单中）。聚焦摘要会
加入相关模块的输入哈希（`internal/orchestrator/checkpoint.go`）：用其他聚焦计算
出的结果绝不会被复用。

## `scanforge assets <目标>`

```
scanforge assets example.com            # 所有资产的当前状态
scanforge assets example.com --new      # 状态为 new
scanforge assets example.com --gone     # 已消失的资产
scanforge assets example.com --json
```

## 限制

- 写入历史时，假定每个目标同一时间只有一次运行。
- 文件每次运行都会增长（完整快照）；可以手动归档或删除：下一次运行将从空历史开始。
