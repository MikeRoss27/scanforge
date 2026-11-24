# MCP 服务器（`scanforge mcp`）

> 中文译文，原文见 [../MCP.md](../MCP.md)（法语）。

通过 MCP 协议（JSON-RPC 2.0，每条消息一行，经 stdin/stdout）向 AI 代理提供基于文件的
运行存储（`runs/<目标>/<时间戳>/`）。没有数据库：一切都从 `manifest.json`、
`report.json` 和 `01_` 至 `06_` 的产物中读取。

```json
{ "mcpServers": { "scanforge": { "command": "scanforge", "args": ["mcp"] } } }
```

## 工具

| 工具 | 模式 | 作用 |
|---|---|---|
| `scanforge.list_runs` | 只读 | 列出运行（过滤 `target`、`limit`） |
| `scanforge.get_run` | 只读 | 状态、模块、范围来源、计数 |
| `scanforge.get_assets` | 只读 | 资产（端口、HTTP、TLS、技术） |
| `scanforge.get_findings` | 只读 | 发现结果，严重程度高者优先（过滤 `severity`、`asset`、`source`、`kind`） |
| `scanforge.get_evidence` | 只读 | 某个 `finding_id` 的证据，或产物文件的片段（`file`、`offset`、`max_bytes`） |
| `scanforge.plan_scan` | 只读 | 已校验流水线的执行波次；不创建运行 |
| `scanforge.start_authorized_scan` | **主动** | 启动 `scanforge run`（默认禁用） |
| `scanforge.stop_scan` | **主动** | 干净地中断由本服务器启动的扫描 |

`run_id` 的形式为 `<目标目录>/<时间戳>`（见 `list_runs`）。任何包含 `..`、多余 `/`、
绝对路径或跳出工作区（包括符号链接）的标识符都会被拒绝。

## 权限模型

除非服务器以如下方式启动，否则主动工具会被拒绝：

```
scanforge mcp --allow-active --scope scope.txt [--audit-log audit.jsonl]
```

- `--allow-active` **和** `--scope <文件>` 必须同时提供。范围是严格的（与
  `scanforge run` 的 `--scope` 语义相同）：没有隐式范围，没有交互确认。每次启动扫描
  时都会重新读取该文件。
- 代理无法提供自己的范围：只有目标是参数，并且必须被该文件授权（`!` 排除项优先）。
  子进程会再次校验范围。
- 未知参数会被拒绝：不存在用于请求头、Cookie、代理或密钥的参数。
- 最多同时 2 个扫描。`stop_scan` 只作用于由本服务器启动的扫描（SIGINT，15 秒后 kill）。
- 每次主动调用（被允许**或被拒绝**）都会追加到 JSONL 日志（0600），默认
  `<工作区>/.scanforge-audit.jsonl`：时间、调用方、动作、决定、原因、目标、配置文件、
  `scan_id`、PID、范围文件。其中不写入任何密钥。
- 所启动扫描的输出位于 `<工作区>/.scanforge-active/scan-<id>.log`。

## 密钥规则

- **在目标上发现的值**（AWS 密钥、JS 中的令牌等）会**原样**返回：它们是赏金报告的证据。
  发现结果不做任何遮蔽。
- **操作者的凭据**（`~/.scanforge/auth.yaml` 中的 API 密钥、配置中的 AI 密钥、传给扫描的
  请求头/Cookie/代理，从 `00_meta/commands.log` 重新读取）在所有输出中都会被替换为
  `[REDACTED-OPERATOR-SECRET]`。`00_meta/` 永远不会被提供。
