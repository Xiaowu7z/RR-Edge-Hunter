# 更新日志 / Changelog

## 1.0.0

- 建立 RR Edge Hunter 独立电脑端仓库和 Windows 免安装发布包。
- 默认流程改为免域名 Cloudflare IP 优选：固定 `speed.cloudflare.com:443`，默认使用官方池，也可把用户导入的安全公网地址作为受限候选执行严格 TLS、多阶段、多轮实测。
- UI 默认设为 IPv4、100 Mbps、亚洲狩猎；稳定速度与成功率优先，亚洲 POP 仅在同档成绩中加分。
- 快筛改为三轮有界 TCP RTT；均衡/亚洲狩猎保留达标复测早停，最大带宽扩大到 20 个分散候选并按两次真实下载样本选择最快 IP。
- 复测失败会继续向后补位；过短响应、跳转页和缺少严格 TLS/CF 身份的样本不会进入结果。
- 结果输出裸 IP，只用于节点 `address/server`；节点端口、UUID、协议、SNI、Host 与 WS Path 保持不变。
- 增加高级可选 Argo 兼容复核，支持原域名、TLS 端口与严格 WebSocket 101 校验，但不改变默认免域名流程。
- 支持长粘贴、TXT/CSV/TSV/JSON/Base64、受控 CIDR、文件和 HTTPS 订阅；导入 IP 无需命中当前 DNS 或属于官方 CIDR，但只有通过三轮 TCP、两次严格 Cloudflare 身份下载复测（Argo 再加兼容门禁）的安全公网地址才会输出。
- 增加 Cloudflare DNS 可选同步：IPv4=A、IPv6=AAAA、强制 DNS-only；Zone ID 与完整 FQDN 必填，采用预览确认与写后回读验证，拒绝 CNAME 和重复记录。
- Cloudflare Token 最小权限为指定 Zone 的 DNS Edit；Token 不进入日志、历史或导出。
- 桌面定时任务可选择优选成功后自动同步 DNS；DNS 同步失败不会终止测速与后续优选。
- 保留本地历史、JSON/CSV 导出、网络变化作废、停止取消、回环 UI 与会话请求令牌保护。
- Windows 正式发布仅保留免安装便携 ZIP 与 SHA-256，不再生成安装程序。

### English summary

- Default hostname-free scan through pinned `speed.cloudflare.com:443` using official Cloudflare candidates.
- IPv4 / 100 Mbps / Asia Hunt UI defaults; output changes node `address/server` only.
- Optional advanced Argo compatibility verification and optional two-phase DNS-only A/AAAA synchronization.
- Zone-scoped DNS Edit tokens are never logged, stored in history, or exported; ambiguous CNAME/duplicate states are rejected.
