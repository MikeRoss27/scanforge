# 使用指南

## 安装

### 一行命令（预编译二进制，无需 Go）

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash
```

```powershell
Invoke-Expression (Invoke-RestMethod https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.ps1)
```

### 包含外部工具（需要 Go）

```bash
curl -fsSL https://raw.githubusercontent.com/MikeRoss27/scanforge/main/install.sh | bash -s -- --full
```

在仓库克隆目录下，本地脚本可完成相同操作：

```bash
./install.sh --full
```

```powershell
.\install.ps1 -Full
```

在 Arch 上，`--full` 只通过 `pacman -S --needed` 安装官方仓库软件包，不会执行完整系统升级。其余自动化依赖使用固定版本的 Go 工具、隔离的 pipx 环境以及经过 SHA-256 验证的上游文件；WhatWeb 仍需手动或通过 AUR 安装。安装器不会执行全局 `pip install`，因此兼容 PEP 668。最终检查与 `scanforge doctor --profile NAME` 会明确列出仍缺少的项目。

你也可以在本地构建二进制文件：

```bash
make build      # 或：go build -o scanforge ./cmd/scanforge
```

## 开发命令

从源码构建需要 Go 1.27.x（见 `go.mod`）。

克隆仓库后，`Makefile` 封装了 Go 工具链。最常用的目标：

| 命令 | 作用 |
| --- | --- |
| `make dev` / `make run` | 通过 `go run` 运行 CLI，无需构建；用 `ARGS="plan example.com --preset deep"` 传参 |
| `make test` / `make race` | 测试套件（快速 / 带竞态检测） |
| `make check` | 推送前检查：格式检查、`go vet`、golangci-lint 和测试 |
| `make cover` | 带覆盖率报告的测试及按函数汇总 |
| `make fmt` / `make fmt-check` | 格式化代码 / 仅列出未格式化的文件而不改写 |
| `make vet` / `make lint` | 静态分析；`make tools` 安装 CI 固定版本的 golangci-lint |
| `make tidy` | 清理 `go.mod` / `go.sum` |
| `make clean` | 删除二进制文件和 `coverage.out` |

## 配置

`scanforge init` 创建 `scanforge.yaml`、可选的 `scope.txt` 和 `runs/` 目录。
配置的查找顺序如下：

1. `--config 路径.yaml`
2. `SCANFORGE_CONFIG` 环境变量
3. `./scanforge.yaml`

可执行文件路径在 `tools` 下配置。内置配置文件可以被覆盖：

```yaml
workspace: runs
default_profile: safe

tools:
  subfinder: /opt/bin/subfinder

profiles:
  internal-web:
    - subfinder
    - dnsx
    - httpx
    - nuclei
```

每个模块的时间限制在 `module_timeouts` 下配置，使用 Go 时长格式。超过限制的
模块会被终止并标记为失败，其依赖模块会被标记为 `skipped`；未配置的模块使用
各自的默认值：

```yaml
module_timeouts:
  nuclei: 45m
  katana: 20m
```

全局资源限制在 `limits` 下配置（均为可选，`0`/未设置表示不限制）。它们由所有模块共享的调度器强制执行，统计的是已启动的命令（而非 HTTP 请求），并可被 `run` 的对应参数 `--concurrency`、`--rps`、`--max-requests` 和 `--command-timeout` 覆盖：

```yaml
limits:
  concurrency: 4          # 同时运行的命令数
  rps: 10                 # 每秒启动的命令数（同时降低工具自身的速率参数）
  max_requests: 500       # 每次运行的命令预算；用尽后后续命令失败
  command_timeout: 20m    # 每条命令超时的上限
```

`ai` 部分配置 `scanforge triage` 使用的 LLM 后端。任何提供 OpenAI 兼容
chat completions API 的服务器都可以（llama.cpp、vLLM、Ollama、LM Studio 等）。
省略该部分时，triage 以纯确定性模式运行（无模型的去重和分组）：

```yaml
ai:
  base_url: http://127.0.0.1:8080/v1
  model: qwen3.5-9b
  api_key: ""        # 本地服务器可省略
  timeout: 5m
  temperature: 0.1   # 低值可保持 triage 输出稳定
```

## WordPress（wp）

`scanforge run example.com --preset wp` 运行 WordPress 渗透链：
`subfinder → dnsbrute → dnsx → httpx → whatweb → wpdetect → wpplugins → wpthemes → wpusers → wpexposure → wpxmlrpc → wpcve → techcve → httpcheck → attacksurface → nuclei → screenshot`。

- 默认**被动检测**：插件/主题版本从爬取到的资源（`?ver=`）、暴露的 `readme.html`、REST 索引和 RSS 订阅中读取。没有你的许可不会发出模糊测试流量。
- `--wp-detection-mode mixed` 会为被动检测到的 slug 读取 `readme.txt`（版本确认）。`--wp-detection-mode aggressive --wp-wordlist slugs.txt` 对内置热门 slug 列表（或你自定义文件，每行一个）进行探测，达到与 wpscan 最接近的覆盖度。侵略模式噪声大，请按项目强度谨慎使用。
- `--wp` 可以把 WordPress 链叠加到任意其他预设（`scanforge run example.com --profile web --wp`）。
- `wpcve` 将 core/插件/主题版本与内置漏洞数据集匹配（离线；已对照 NVD 验证，见 `internal/modules/wpcve/cves_wp.yaml`），无需 API 密钥。
- `wpbrute`（针对已枚举用户的凭据探测）**默认关闭**，仅在三者齐备时运行：`--wp-bruteforce` + `--confirm-scope`（隐式范围）+ `--wp-passwords <wordlist>`。每个用户最多 `--wp-bruteforce-max` 次尝试（默认 100），首个成功或出现锁定信号即停止；若 `wpusers` 未枚举到任何用户名则拒绝运行。内置不含任何密码字典。
- `scanforge doctor --profile wp` 检查内置字典/数据集和外部工具的可用性。

## 推荐流程

首先检查依赖和计划：

```bash
scanforge doctor --profile safe
scanforge plan example.com --preset safe
```

然后启动运行。没有适用的文件时，隐式范围会在创建任何目录之前显示并确认：

```bash
scanforge run example.com --preset safe
```

检查命令而不执行：

```bash
scanforge run example.com --preset ports --dry-run
```

使用隐式范围时，dry-run 需要相同的确认。在非交互终端中：

```bash
scanforge plan example.com --scope-mode domain
scanforge run example.com --scope-mode domain --confirm-scope
```

## 常用命令

| 命令 | 功能 |
| --- | --- |
| `scanforge init` | 创建初始配置。 |
| `scanforge doctor --profile NAME` | 检查配置文件所需的工具。 |
| `scanforge plan TARGET` | 显示范围与 DAG 波次。 |
| `scanforge run TARGET` | 运行已授权的配置文件。 |
| `scanforge scan TARGET` | `run` 的别名。 |
| `scanforge resume RUN-ID` | 恢复被中断的运行，仅重新执行未完成或输入已变化的部分（见 `RESUME.md`）。 |
| `scanforge status RUN-ID [--json]` | 显示每个模块的检查点状态和范围来源。 |
| `scanforge runs list [--target T] [--json]` | 按从新到旧列出工作区中的运行。 |
| `scanforge workflow validate FILE.yaml` | 校验 YAML 工作流而不执行任何内容（见 `WORKFLOWS.md`）。 |
| `scanforge intel update\|status` | 下载 / 查看 `techcve` 使用的本地 NVD、CISA KEV 和 EPSS 缓存。 |
| `scanforge mcp` | 通过 stdio 以 MCP 协议向 AI 代理提供 ScanForge（见 `MCP.md`）。 |
| `scanforge api` | 通过本地 HTTP JSON API 提供运行存储（见 `API.md`）。 |
| `scanforge triage RUN` | 对一次运行的发现结果去重、分组并（配置 `ai:` 后端时）分析。 |
| `scanforge auth` | 管理某些工具所需的密钥。 |
| `scanforge version` | 显示二进制版本。 |

查看 `scanforge <命令> --help` 获取完整选项列表。

## 恢复、工作流、情报与代理访问

详细指南：[RESUME](RESUME.md)、[WORKFLOWS](WORKFLOWS.md)、[MCP](MCP.md)、[API](API.md)（中文译文）。

```bash
scanforge runs list --target example.com
scanforge status example.com/2026-08-18_10-00-00
scanforge resume example.com/2026-08-18_10-00-00
```

运行状态以检查点形式保存在 `00_meta/manifest.json`；`resume` 会跳过输入未变的已完成模块，复用已保存的有效范围，且绝不会扩大范围。`--proxy` 与 `--header` 不会被保存，请重新传入。

```bash
scanforge workflow validate workflows/web-recon.yaml
scanforge plan example.com --workflow workflows/web-recon.yaml
scanforge run example.com --scope scope.txt --workflow workflows/web-recon.yaml --rps 20
```

工作流取代配置文件（`--workflow` 与 `--profile`、`--preset`、`--wp` 互斥）；它编译为同一个 DAG，不能执行 shell 命令，并保持相同的范围强制检查。

`scanforge run --events`（实验性，默认关闭）还会把发现事件（子域名变为 `DNS_NAME`）写入 `00_meta/events.jsonl`；每个事件在记录前都要经过范围过滤。

`scanforge intel update` 是唯一会下载漏洞情报（NVD、CISA KEV、EPSS；可用 `--source nvd|kev|epss` 限定）的命令；`scanforge intel status` 离线查看缓存。扫描本身不会为情报访问网络。`techcve` 在缓存存在时使用它，并将匹配标记为 `exact-cpe-range`、`version-range` 或 `name-only`（name-only 永远不会被确认）。设置 `SCANFORGE_NVD_API_KEY` 可获得更高的 NVD 速率限制；缓存位于 `SCANFORGE_INTEL_DIR` 或 `~/.cache/scanforge/vulnintel`。

```bash
scanforge mcp                                    # 通过 stdio 的只读 MCP
scanforge mcp --allow-active --scope scope.txt   # 同时允许受范围约束的主动扫描
scanforge api --listen 127.0.0.1:8787 --token-file ./token
```

通过 MCP/API 的主动扫描默认禁用，需要 `--allow-active` 并配合严格的 `--scope` 文件；每次主动调用都会写入审计日志。除非使用 `--unsafe-bind`，API 仅监听回环地址。

**密钥规则：** 目标泄露的密钥值（AWS 密钥、JavaScript 中发现的令牌等）在发现结果中保持完整，因为它们是报告的证据。只有操作者自己的凭据（`auth` 的 API 密钥、`ai:` 密钥、传给扫描的代理/请求头值）会在日志以及 API/MCP 输出中被遮蔽。

## 发现结果分诊

`scanforge triage <run>` 将合并后的报告投影为规范化的发现结果，计算确定性关系
（重复、共享 CVE、相同端点、相同资产），并将结果写入 `<run>/triage/`：

```text
triage/manifest.json    来源：模型、提示词版本、输入摘要
triage/relations.json   发现结果之间的确定性关系
triage/insights.json    洞察（去重组 + 已验证的 LLM 洞察）
triage/report.md        人类可读摘要
```

配置 `ai:` 后端后，模型只收到刻意精简的发现结果投影（证据截断、绝不发送工具
原始输出），其洞察在存储前会经过验证：任何引用未知发现 ID、CVE 或证据字符串
的洞察都会被拒绝。模型可以解释发现结果，但绝不能创建它们。输入未变化时重新
运行会命中缓存（0 次推理）；`--force` 可绕过缓存：

```bash
scanforge triage runs/example.com/2026-08-19T10:00:00Z
scanforge triage runs/example.com/2026-08-19T10:00:00Z --force
scanforge triage runs/example.com/2026-08-19T10:00:00Z --model qwen3.5-9b
```

## 多目标评估

`run` 和 `plan` 接受目标文件，而非单一位置参数目标。每个目标都有独立的范围验证、运行目录和报告（`runs/<target>/`）；一个目标失败不会中断其余评估。

```bash
scanforge plan --targets targets.txt --preset web
scanforge run --targets targets.txt --preset web --confirm-scope
```

文件每行一个目标（忽略 `#` 注释和空行）。`--targets` 与位置参数目标互斥。

## 比较运行与导出

`scanforge diff` 重新整合两个运行目录并列出变化——新增或消失的资产、端口和漏洞（无需基础设施的轻量周期 ASM 循环）：

```bash
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00
scanforge diff runs/example.com/2026-08-09_10-00-00 runs/example.com/2026-08-10_10-00-00 --json
```

`scanforge export` 将整合报告序列化为第三方工具格式：

```bash
scanforge export runs/example.com/2026-08-10_10-00-00 --format sarif          # GitHub/GitLab code scanning
scanforge export runs/example.com/2026-08-10_10-00-00 --format defectdojo     # import-scan "Generic Findings Import"
```
