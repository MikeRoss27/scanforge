# 递归发现（`--recursive`）

> 中文译文，原文见 [../RECURSIVE.md](../RECURSIVE.md)（法语）。

混合模型：产物 DAG 仍然负责编排主要阶段（subfinder、dnsx、httpx、katana、
jssecrets……）。此外，这些模块的产物会作为**类型化事件**（`internal/events`）
发出，小型订阅者对**新的**发现作出反应。默认关闭。

```bash
scanforge run example.com --preset web --recursive
scanforge run example.com --preset web --recursive --recursive-depth 3 --recursive-budget 100
```

配置（`scanforge.yaml`），非零的命令行参数优先：

```yaml
recursive:
  enabled: false
  depth: 2     # 最大发现深度
  budget: 200  # 每次运行的最大后续命令数
```

`--recursive` 同时启用事件总线（`--events` 仍可单独使用，并保持其演示行为：
`subdomains` -> `DNS_NAME`）。`scanforge plan` 不变：递归发现不会向 DAG 添加任何
模块，而是在 DAG 之后运行。`--dry-run` 下无效。

## 发出的事件

| 产物 | 事件 |
|---|---|
| `subdomains`、`brute_subdomains`、`resolved_hosts` | `DNS_NAME` |
| `open_ports` | `OPEN_PORT` |
| `alive_urls` | `LIVE_URL`（+ 主机的 `DNS_NAME`） |
| `crawled_urls`、`historical_urls` | `JS_URL`（`.js`/`.mjs` 文件）、`DNS_NAME`（URL 的主机） |
| `js_secrets` | `JS_URL`、`API_ROUTE`（kind `endpoint`）、`DNS_NAME`（kind `internal-host`、`cloud-storage`） |

相对的 `API_ROUTE` 会根据包含它的 JS 文件的源进行解析；该源就是它的
`scope_ref`，因此路由绝不会比提供它的主机“更在范围内”。

## 订阅者（后续动作）

- 较晚（JS、爬取等）发现的、在范围内的**新** `DNS_NAME`：仅对该名称进行有界的
  `dnsx` 再 `httpx`。DAG 已知的名称（目标、`subdomains`、`resolved_hosts`、
  `alive_urls`）不会触发任何动作。
- 由后续流程发现的 `LIVE_URL`：对该 URL 进行深度为 1 的 `katana`。DAG 的存活 URL
  已经由 DAG 爬取过。
- `OPEN_PORT`、`JS_URL`、`API_ROUTE`：写入 `events.jsonl`，不执行任何动作。

订阅者只负责把任务放入队列；任务在 DAG 结束后逐个执行，从而保持顺序确定。

## 防护措施

1. **范围优先。** 每个事件在任何订阅者之前都要经过 `Scope.IsAllowed`。OSINT/JS 的
   发现**绝不会**被自动授权：范围外的发现会被丢弃并记录到
   `00_meta/scope-rejections.jsonl`（产物 `event:<TYPE>`）。后续流程的输出还会被
   `RunContext.AddArtifact`（唯一通道）过滤，且只重新读取过滤后的文件。
2. **注入的执行器。** 命令通过运行的 `runner.Executor`（因此经过调度器：并发、
   req/s、`--max-requests`），并写入 `commands.log`。绝不直接使用 `os/exec`。
3. **防循环。** 一个事件（类型 + 规范化值）在每次运行中只投递一次；A -> B -> A 会停止。
4. **深度。** DAG 产物的事件深度为 0；由后续流程产生的事件继承 `parent + 1`。超过
   `--recursive-depth` 的事件会被丢弃。
5. **预算。** `--recursive-budget` 限制后续命令的总数（dnsx、httpx 和 katana 各计 1）。
   用尽后，剩余的后续任务会被忽略并给出警告。

## 产生的文件

- `00_meta/events.jsonl`：被接受的事件（id、类型、值、来源、父级、深度、判定、
  `scope_ref`）。
- `07_recursive/NNN-<值>-*`：每条后续命令的输入/输出。后续产物
  （`recursive.resolved_hosts`、`recursive.alive_urls`、`recursive.crawled_urls`）
  使用不同的名称：它们绝不会替换 DAG 的产物，目前也尚未整合进 `report.json`。
