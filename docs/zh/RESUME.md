# 扫描恢复、检查点与运行跟踪

> 中文译文，原文见 [../RESUME.md](../RESUME.md)（法语）。

每次运行都会把各模块的状态记录在 `00_meta/manifest.json` 中（仅文件，无数据库）。
清单在每次状态变化时以原子方式写入（临时文件 + `rename`），因此被中断的运行
（Ctrl+C、崩溃、断电）始终可以恢复。

## 命令

```bash
scanforge runs list [--target example.com] [--json]   # 工作区中的运行，从新到旧
scanforge status <run-id> [--json]                    # 每个模块的状态 + “可恢复”提示
scanforge resume <run-id>                             # 只重新执行剩余部分
```

`<run-id>` 可以是带时间戳的标识符（`2026-08-18_10-00-00`）、`目标/id`
（同一 id 存在于多个目标时），或运行目录的路径。

## 模块状态

`pending`、`running`、`completed`、`failed`、`skipped`、`cancelled`。
被强制终止的运行会留下 `running` 或 `pending` 模块：恢复时它们会被直接重新执行。

## 恢复规则

只有以下条件**全部**成立时，模块才会被**复用**（不重新执行）：

1. 状态为 `completed`（或由模块自身标记为 `skipped`，即“不适用”）；
2. `input_hash` 相同；
3. 其产物和输出文件仍然存在。

否则（`pending`、`running`、`failed`、`cancelled`、输入已变化、输出被删除）
会重新执行。被复用的模块通过 `RunContext.AddArtifact` 重新发布其产物，
因此范围过滤会被再次应用。

`input_hash` 是以下内容的 sha256：哈希版本、模块、目标、配置文件、dry-run、
有效范围、模块参数（代理、请求头、相关工具选项：nuclei、ffuf、nmap、WordPress；
已配置的超时）、外部工具版本（通过 `-version`/`--version` 获取，dry-run 除外）
以及所需产物的内容指纹。如果上游模块被重新执行但输出相同，下游模块仍使用缓存。

## 范围安全

`resume` 会重新加载 `00_meta/effective-scope.txt`，并将其 sha256 与清单中的
`scope_sha256` 比较；任何修改（包括扩大）都会使恢复被拒绝。`resume` 没有任何
范围选项。运行过程中新增的主机（`scope-additions.jsonl`）不会被重新应用。
在此功能之前创建的运行（没有 `scope_sha256`）不可恢复：请启动新的运行。

## 代理与请求头

`--proxy` 和 `--header` 可能包含密钥：它们**不会**写入清单。要恢复带认证的运行，
请重新传入相同的值；否则其指纹不同，相关模块会被重新执行。其他选项
（nuclei、ffuf、nmap、WordPress）和模块列表保存在 `params` 中并自动恢复。
