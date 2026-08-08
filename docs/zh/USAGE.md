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

你也可以在本地构建二进制文件：

```bash
go build -o scanforge ./cmd/scanforge
```

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
| `scanforge auth` | 管理某些工具所需的密钥。 |
| `scanforge version` | 显示二进制版本。 |

查看 `scanforge <命令> --help` 获取完整选项列表。
