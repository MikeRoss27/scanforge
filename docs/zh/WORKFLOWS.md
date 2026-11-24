# YAML 工作流

> 中文译文，原文见 [../WORKFLOWS.md](../WORKFLOWS.md)（法语）。

工作流是配置文件（profile）的声明式替代方案：它选择已注册的 ScanForge 模块并设置其
执行策略。它会被**编译为与配置文件相同的模块列表**：DAG、编排器和范围过滤
（`RunContext.AddArtifact`）保持不变。工作流永远无法执行任意命令。

```bash
scanforge workflow validate workflows/web-recon.yaml   # 仅校验
scanforge plan example.com --workflow workflows/web-recon.yaml   # 显示执行波次
scanforge run example.com --workflow workflows/web-recon.yaml
```

`--workflow` 与 `--profile`、`--preset` 和 `--wp` 互斥。显式的命令行参数
（如 `--nuclei-severity`）优先于 `params`。

## 格式

```yaml
name: web-recon          # 字母、数字、. _ -
version: 1               # 仅支持的版本
steps:
  - id: probe            # 唯一
    module: httpx        # 已注册的模块名
    needs: [resolve]     # 之前步骤的 id
    timeout: 15m         # 1s 到 24h（默认：模块自身的值）
    retries: 1           # 0 到 5，重试间隔递增
    on_error: fail       # fail（默认） | continue | skip
    when:                # 可选，仅一个键
      artifact_nonempty: alive_urls   # 或 artifact_present: <产物>
    params: {}           # 见下文
```

- `on_error: continue`：该步骤标记为 `failed`，运行继续。`skip`：该步骤标记为
  `skipped`。两种情况下，依赖其产物的模块都会被编排器跳过。用户中断永远不会被弱化。
- `when` 只接受对 `needs` 中所列步骤所产生产物的 `artifact_present` 或
  `artifact_nonempty`（无表达式、无代码）。条件为假：步骤 `skipped`。在 `--dry-run`
  下条件视为真，以便显示命令。
- `params`（白名单，类型经过检查）：
  `nuclei`：`severity`、`exclude_severity`、`tags`、`exclude_tags`、
  `rate_limit`、`templates`、`update_templates`、`headless`、`include_custom`、
  `full_scan`、`scan_timeout`；`ffuf`：`wordlist`、`filter_codes`；
  `nmap`：`concurrency`；`wpplugins`/`wpthemes`：`detection_mode`
  （`passive|mixed|aggressive`）、`wordlist`。其他模块不接受任何参数。

## 校验（在任何执行之前）

拒绝：任意层级的 `run`/`exec`/`shell`/`command`/`cmd`/`script`/`sh`/`bash`/`eval`/`args`
键、YAML 锚点/别名、多文档、未知键、未知模块、重复模块、`wpbrute`（仅保留给命令行参数）、
重复 id、未知/指向自身/循环的 `needs`、与产物不一致的 `needs`（`Requires()` 在 `needs`
中没有生产者，或 `needs` 没有真实的产物关联，因为顺序由产物推导）、无效的时长、
未知或类型错误的参数、超过 256 KiB 的文件、超过 64 个步骤。

## 示例

见 `workflows/web-recon.yaml` 和 `workflows/ports-light.yaml`
（CI 中由 `TestExampleWorkflowsAreValid` 校验）。
