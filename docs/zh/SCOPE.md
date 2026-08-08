# 范围管理

范围始终是强制性的安全护栏，但 `scope.txt` 文件并非必需。ScanForge 在创建运行前解析有效范围，然后过滤模块之间传递的产物。

## 隐式范围

没有适用的文件时，`exact` 模式仅允许目标：

```bash
scanforge plan example.com --scope-mode exact
```

`domain` 模式允许根域名及其子域名：

```bash
scanforge plan example.com --scope-mode domain
```

使用可重复的选项添加或排除条目：

```bash
scanforge run example.com --scope-mode domain \
  --scope-add api.other.test \
  --scope-add 10.20.0.0/24 \
  --exclude admin.example.com \
  --exclude '*.legacy.example.com'
```

排除项优先。CIDR 仅可作为显式添加项接受；`domain` 模式拒绝 IP、CIDR 和单标签名称。

## 范围文件

文件可以包含主机、通配符、CIDR 以及以 `!` 为前缀的排除项：

```text
example.com
*.example.com
10.20.0.0/24
!admin.example.com
!*.legacy.example.com
```

通过 `--scope scope-client.txt` 显式使用，或配置 `default_scope`。通过 `--scope` 提供的文件是严格的：如果目标不被允许，运行将失败且无回退。它不能与 `--scope-mode`、`--scope-add` 或 `--exclude` 组合使用。

如果默认配置文件缺失或未覆盖目标，ScanForge 会提出隐式范围并要求确认。覆盖目标的合法文件则无需额外确认。

## 可追溯性与 CI

每次运行都会保留：

- `00_meta/effective-scope.txt`：实际应用的规则；
- 清单中的 `scope_source` 和 `scope_mode`；
- `00_meta/scope-rejections.jsonl`：被拒绝的值。

在 CI 中，先用 `plan` 预览，然后仅对隐式范围传递 `--confirm-scope`。该选项确认显示的范围；它绝不会禁用过滤。
