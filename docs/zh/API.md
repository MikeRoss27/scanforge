# 本地 HTTP API（`scanforge api`）

> 中文译文，原文见 [../API.md](../API.md)（法语）。

基于文件运行存储的 JSON API，与 MCP 服务器共享索引读取器和权限规则
（见 [MCP.md](MCP.md)）。

```
scanforge api [--listen 127.0.0.1:8787] [--token-file ./token] [--allow-active --scope scope.txt]
```

## 安全

- 仅监听 `127.0.0.1`；其他地址会被拒绝，除非使用 `--unsafe-bind`。`Host` 请求头必须是
  本地地址（防止 DNS 重绑定）。
- 每次启动都会生成一个 bearer 令牌（输出到 stderr，或使用 `--token-file` 以 0600 写入）。
  只读的 `GET` 不需要令牌；其余都需要：`Authorization: Bearer <令牌>`。
- 主动扫描默认禁用；规则与 MCP 相同（必须同时提供 `--allow-active` 和 `--scope`，
  目标在范围内，JSONL 审计日志）。
- 返回的发现结果不做遮蔽；操作者的凭据始终被遮蔽。

## 端点

| 方法 | 路径 | 令牌 |
|---|---|---|
| GET | `/v1/health` | 否 |
| GET | `/v1/runs?target=&limit=` | 否 |
| GET | `/v1/runs/{目标}/{时间戳}` | 否 |
| GET | `/v1/runs/{目标}/{时间戳}/assets?filter=&limit=&offset=` | 否 |
| GET | `/v1/runs/{目标}/{时间戳}/findings?severity=&asset=&source=&kind=&limit=&offset=` | 否 |
| GET | `/v1/runs/{目标}/{时间戳}/evidence?finding_id=` 或 `?file=06_vulns/x.jsonl&offset=&max_bytes=` | 否 |
| POST | `/v1/plan` `{"target","profile","wp"}` | 是 |
| POST | `/v1/scans` `{"target","profile","dry_run"}`（202） | 是 |
| GET | `/v1/scans` | 是 |
| DELETE | `/v1/scans/{id}` | 是 |

状态码：400 标识符/路径无效，401 令牌，403 主动扫描被禁用或目标不在范围内，
404 未找到，429 扫描过多。

```
curl -s localhost:8787/v1/runs
curl -s -H "Authorization: Bearer $TOKEN" -d '{"target":"example.com"}' localhost:8787/v1/plan
```
