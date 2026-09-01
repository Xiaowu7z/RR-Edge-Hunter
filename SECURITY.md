# 安全说明

## 测速边界

- 应用不收集或需要 VMess/VLESS 节点、UUID、订阅链接或代理凭据。
- RR Python 外壳不生成候选、不探测 IP、不计算速度或排名；这些操作由固定原版 Go 程序完成。
- 原版程序会访问 `www.baipiao.eu.org` 维护数据，并对随机候选进行真实 RTT、CF-RAY 和下载测速。
- 未达到期望带宽时原版程序会继续换轮；用户应留意流量并可随时停止。
- 参考数据位于当前用户缓存目录，不修改系统 hosts、路由或代理。

## Cloudflare DNS

- 单次测试默认不写 DNS，只能由用户从当前结果页主动开启；自动测试只有在用户启动任务时明确勾选并确认后才会逐轮写入。
- IPv4 只写 A，IPv6 只写 AAAA，并强制 DNS-only 与自动 TTL。
- 写入采用“只读预览 → 明确确认 → 写后回读”。
- 同名 CNAME、NS、多条同类型记录或预览后状态变化会拒绝。
- 自动任务与手动操作都只处理本轮唯一 IP 和用户指定的一条记录，不创建多 IP 轮询记录。
- API Token 不进入日志、状态快照或本地设置；自动任务停止或程序关闭后从进程内存清除。
- 建议 Token 仅授予目标 Zone 的 DNS Edit 权限。

安全问题请使用 GitHub Private Vulnerability Reporting，不要在公开 Issue 中粘贴 API Token、Zone ID 与域名组合。
