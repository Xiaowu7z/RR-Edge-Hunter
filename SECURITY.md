# 安全策略 / Security Policy

## 报告安全问题

请勿在公开 Issue、截图或日志中粘贴 Cloudflare API Token、Zone ID 与域名组合、节点链接、订阅地址或本地网络信息。请使用 GitHub Private Vulnerability Reporting，或通过仓库列出的项目频道联系维护者。

## 测速边界

- 默认模式不要求用户域名，从公开维护接口取得候选网段、动态测速地址与数据中心表；接口失败时使用本机缓存，缓存也不可用时回退 Cloudflare 官方网段。
- 导入 IP 不必与动态测速域名当前 DNS 求交，也不要求预先属于 Cloudflare 官方 CIDR；非公网、私网、回环、链路本地、保留地址和错误协议族会被拒绝。
- 每轮最多 100 个候选、50 并发预检、延迟前 10 个逐个最多下载 5 秒。未达标会进入下一轮，因此总轮数与总流量由用户停止操作和实际网络结果决定。
- TLS 443 模式保留系统证书、SNI、Host 与实际 TCP 对端验证；非 TLS 80 必须由用户显式选择。探针不继承系统 HTTP 代理。
- Argo 域名、端口和 WS Path 只在用户显式开启高级兼容复核时使用。最终输出仍是裸 IP，节点原端口、UUID、SNI、Host 与 Path 不变。

## 本地应用与导入

- Web UI 仅绑定回环地址，每个浏览器会话使用随机请求令牌保护状态修改接口。
- 测速结果和历史默认保存在本机，不上传到项目服务器。
- HTTPS 订阅限制为公网目标、默认 443、有限跳转和有限响应大小，并逐跳复核以降低 SSRF 与 DNS rebinding 风险。

## Cloudflare DNS 同步

DNS 写入默认关闭，必须由用户明确开启：

- 只允许将当前实时测速达标的 IPv4 写入 `A`，或 IPv6 写入 `AAAA`；强制 DNS-only（灰云）。
- 必须提供 32 位 Zone ID 和完整 FQDN；API Token 最小权限为指定 Zone 的 **DNS: Edit**。
- Token 只存在于本次运行内存和发往 Cloudflare API 的认证头；不得写入日志、历史、JSON/CSV 导出、异常文本或发布包。
- 写入采用“只读检查与预览 → 用户明确确认 → 写入后回读验证”。预览后状态变化必须重新预览。
- 同名 CNAME、多个同类型记录或任何歧义状态都会拒绝；工具不会自动删除、合并或转换 DNS 记录。
- 定时同步失败不会删除测速结果；认证或权限错误会暂停自动 DNS 同步，并只记录脱敏原因。

## 不支持的用途

本项目不提供端口扫描、漏洞探测、压力测试、任意 hosts/路由修改、代理服务、凭据收集或访问控制绕过。

---

The default scan uses a cached public maintained pool and a dynamically supplied speed target, with official Cloudflare ranges as an offline fallback. TLS 443 preserves certificate, SNI, Host, and actual-peer verification; plain HTTP 80 requires explicit selection. Optional Argo checks and DNS writes require explicit user activation. DNS synchronization uses preview-before-confirmation, DNS-only A/AAAA records, and never logs or exports the token.
