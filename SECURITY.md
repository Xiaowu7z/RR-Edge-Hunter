# 安全策略 / Security Policy

## 报告安全问题

请勿在公开 Issue、截图或日志中粘贴 Cloudflare API Token、Zone ID 与域名组合、节点链接、订阅地址或本地网络信息。请使用 GitHub Private Vulnerability Reporting，或通过仓库列出的项目频道联系维护者。

## 测速边界

- 默认模式不要求用户域名，固定使用 `speed.cloudflare.com:443` 对 Cloudflare 官方网段候选执行 HTTPS 测量。
- 导入 IP 不必与当前 DNS 求交，但必须属于 Cloudflare 官方 CIDR；非 CF、私网、回环、链路本地、保留地址和错误协议族会被拒绝。
- 候选量、CIDR 抽样、并发、超时和下载流量都有硬上限。
- TLS 证书、SNI、Host 和实际 TCP 对端验证不会关闭；探针不继承系统 HTTP 代理。
- Argo 域名、端口和 WS Path 只在用户显式开启高级兼容复核时使用。最终输出仍是裸 IP，节点原端口、UUID、SNI、Host 与 Path 不变。

## 本地应用

- Web UI 仅绑定回环地址。
- 每个浏览器会话使用随机请求令牌保护状态修改接口。
- 测速结果和历史默认保存在本机，不上传到项目服务器。
- HTTPS 订阅限制为公网目标、默认 443、有限跳转和有限响应大小，并逐跳复核以降低 SSRF 与 DNS rebinding 风险。

## Cloudflare DNS 同步

DNS 写入功能默认关闭，必须由用户明确开启：

- 只允许将优选出的官方 CF IPv4 写入 `A`，或 IPv6 写入 `AAAA`；记录强制为 DNS-only（灰云）。
- 必须提供 32 位 Zone ID 和完整 FQDN；API Token 最小权限为该指定 Zone 的 **DNS: Edit**。
- Token 只存在于本次运行内存和发往 Cloudflare API 的认证头；不得写入日志、历史、JSON/CSV 导出、异常文本或发布包。
- 写入采用“只读检查与预览 → 用户明确确认 → 写入后回读验证”流程。预览后状态变化必须重新预览。
- 同名 CNAME、多个同类型记录或任何歧义状态都会拒绝；工具不会自动删除、合并或转换 DNS 记录。
- 定时同步失败不会停止测速或后续优选；认证/权限错误应暂停 DNS 自动同步，并只记录脱敏原因。

## 不支持的用途

本项目不提供端口扫描、漏洞探测、压力测试、任意 hosts/路由修改、代理服务、凭据收集或访问控制绕过。

---

The default scan pins `speed.cloudflare.com:443` to bounded candidates from official Cloudflare ranges; no user hostname is required. TLS certificate, SNI, Host, and actual-peer verification remain enabled. Optional Argo checks and DNS writes require explicit user activation.

Cloudflare DNS synchronization accepts only a selected-Zone API Token with DNS Edit permission, uses preview-before-confirmation, writes DNS-only A/AAAA records, rejects CNAME/duplicate ambiguity, and never logs or exports the token.
