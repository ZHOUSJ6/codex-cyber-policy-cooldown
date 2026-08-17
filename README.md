# codex-cyber-policy-cooldown

一个独立的 CPA（CLIProxyAPI）原生插件：当 Codex 请求失败内容匹配 `cyber_policy` 时，冷却该请求所使用的**整份凭据**，而不是只冷却“凭据 + 当前模型”。

本插件只处理可配置的策略错误，不处理 429。需要 429 限额封禁时，可以独立安装原项目 [`codex-429-autoban`](https://github.com/ysxk/codex-429-autoban)。

## 工作方式

1. `usage.handle` 接收 CPA 已完成请求的用量记录。
2. 仅检查 `provider=codex` 且 `failed=true` 的记录。
3. 对 `Failure.Body` 做不区分大小写的子串匹配；默认匹配 `cyber_policy`。
4. 命中后以 `AuthID` 为键保存冷却结束时间。
5. `scheduler.pick` 在后续所有模型请求中排除该 `AuthID`，因此冷却作用于整份凭据。
6. 冷却到期后惰性恢复；如果所有候选凭据都在冷却，插件会返回明确错误，不会退回内置调度器重新选中冷却凭据。

冷却状态保存在 CPA 进程内存中，CPA 重启后会清空。本插件不会修改凭据文件，也不会修改 CPA 核心的 `Unavailable` 或 `NextRetryAfter` 字段。

## 配置

```yaml
plugins:
  enabled: true
  configs:
    codex-cyber-policy-cooldown:
      enabled: true
      priority: 100
      match_errors:
        - cyber_policy
      cooldown_seconds: 3600
```

配置项：

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `match_errors` | `[cyber_policy]` | 对失败响应体进行不区分大小写的子串匹配，可配置多个错误标记 |
| `cooldown_seconds` | `3600` | 整份凭据冷却秒数，范围为 1–2592000（30 天） |

插件重新配置后，新触发的冷却使用新时长；已经存在的冷却不会被缩短。

## 在线安装

推荐使用统一的个人插件商店 [`ZHOUSJ6/CLIProxyAPI-Plugins-Store`](https://github.com/ZHOUSJ6/CLIProxyAPI-Plugins-Store)。将下面的地址加入 CPA 配置：

```yaml
plugins:
  enabled: true
  store-sources:
    - https://raw.githubusercontent.com/ZHOUSJ6/CLIProxyAPI-Plugins-Store/main/registry.json
  configs:
    codex-cyber-policy-cooldown:
      enabled: true
      priority: 100
      match_errors:
        - cyber_policy
      cooldown_seconds: 3600
```

重启 CPA 或在管理界面刷新插件商店，搜索 `Codex Cyber Policy Cooldown` 并安装。CPA 会根据当前系统自动下载 `v0.1.0` Release 中对应的 ZIP，并使用 `checksums.txt` 验证 SHA256。

本仓库根目录的单插件 `registry.json` 继续保留以兼容旧配置；新安装建议只添加上面的统一商店源，避免重复登记。

当前发布平台：

| 系统 | 架构 | Release 资产 |
|---|---|---|
| Linux | amd64 | `codex-cyber-policy-cooldown_0.1.0_linux_amd64.zip` |
| Linux | arm64 | `codex-cyber-policy-cooldown_0.1.0_linux_arm64.zip` |
| macOS | arm64 | `codex-cyber-policy-cooldown_0.1.0_darwin_arm64.zip` |
| Windows | amd64 | `codex-cyber-policy-cooldown_0.1.0_windows_amd64.zip` |

以后推送形如 `v0.2.0` 的版本标签，仓库中的 GitHub Actions 会自动构建各平台动态库、打包 ZIP、生成 `checksums.txt` 并发布 Release。CPA 会自动把最新 Release 识别为可用更新。

## 编译

CPA 原生插件使用 CGO 动态库格式，需要 Go 1.21+ 和 C 编译器：

```bash
bash build.sh
```

当前平台会生成：

- Windows：`codex-cyber-policy-cooldown.dll`
- macOS：`codex-cyber-policy-cooldown.dylib`
- Linux：`codex-cyber-policy-cooldown.so`

测试：

```bash
GOWORK=off go test ./...
```

## 安装

把动态库放到 CPA 对应插件目录，例如：

```text
plugins/windows/amd64/codex-cyber-policy-cooldown.dll
plugins/darwin/arm64/codex-cyber-policy-cooldown.dylib
plugins/linux/amd64/codex-cyber-policy-cooldown.so
```

然后使用上面的 `config.yaml` 配置启用插件。插件 ID 来自动态库文件名，即 `codex-cyber-policy-cooldown`。

## 管理接口

资源页：

```text
/v0/resource/plugins/codex-cyber-policy-cooldown/status
```

使用 CPA 管理密钥调用：

```bash
# 查看当前处于冷却中的凭据
curl -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://localhost:8317/v0/management/plugins/codex-cyber-policy-cooldown/cooldowns

# 手动解除单个凭据
curl -X POST \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"auth_id":"<AUTH_ID>"}' \
  http://localhost:8317/v0/management/plugins/codex-cyber-policy-cooldown/clear

# 解除所有凭据
curl -X POST \
  -H "Authorization: Bearer $CPA_MANAGEMENT_KEY" \
  http://localhost:8317/v0/management/plugins/codex-cyber-policy-cooldown/clear-all
```

## 来源

调度和管理接口结构基于 MIT 许可的 [`codex-429-autoban`](https://github.com/ysxk/codex-429-autoban) 改造。本插件具有独立的插件 ID、配置、构建产物和发布流程。
