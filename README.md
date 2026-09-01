# RR Edge Hunter

**CF 优选 IP · 电脑端**

RR Edge Hunter 是一款在当前电脑、当前网络出口上运行的 Cloudflare 入口 IP 优选工具。每轮从在线维护网段中随机生成 100 个地址，以 50 并发对每个地址执行三次 RTT + `CF-RAY` 验证，保留延迟最低的 10 个，再逐个做最多 5 秒真实下载。只统计完整的一秒速度窗口，最后不足一秒的数据不计峰值；第一个达到期望带宽的 IP 立即返回，否则自动换一批继续。

优选结果是一个裸 IPv4 或 IPv6。把它填入 VMess / VLESS 等节点的 `address` 或 `server` 字段即可；节点原来的端口、UUID、协议、TLS SNI、HTTP Host、WS Path 等参数全部保持不变。

> 结果只代表本轮电脑、网络出口、运营商和时间。切换宽带、Wi-Fi、VPN、代理或出口后应重新测试。

## 一键默认值

| 项目 | 默认值 |
| --- | --- |
| IP 协议 | IPv4 |
| 期望带宽 | 100 Mbps |
| 测速流程 | 快速优选：100 IP → 三次 RTT → 最低延迟 10 个 → 首个达标即停 |
| 连接方式 | TLS 443（默认、严格证书校验）/ 非 TLS 80 |
| 测速地址 | 由公开维护接口动态下发；离线时使用缓存/官方备用 |
| 候选来源 | `baipiao.eu.org` 公开维护池；可叠加用户导入的安全公网 IP |
| 输出用途 | 只替换节点 `address/server` |

界面只保留这一条可解释的流程，不再让用户在“均衡 / 亚洲狩猎 / 最大带宽”之间猜测。未达到目标会继续测试甚至自动换轮，直到找到结果或用户点击停止，因此实际流量取决于线路情况，不显示虚假的固定总流量上限。

## 下载与运行

### Windows 便携版（唯一正式版）

[📦 下载最新版 Windows x64 便携包](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip)

解压 ZIP，进入 `CF-IP-Optimizer` 文件夹后双击 `CF-IP-Optimizer.exe`。便携包已内置运行环境，无需安装 Python；请保留 EXE 与 `_internal` 文件夹的相对位置。仓库不再发布安装程序。

### 源码运行

要求 Python 3.11 或更高版本，不需要第三方 Python 包。

- Windows：双击 `start-windows.bat`
- macOS / Linux：运行 `./start-unix.sh`
- 通用：`python rr_optimizer.py ui`

界面只监听 `127.0.0.1`，测速记录不会上传。

## 工作方式

1. 从 `https://www.baipiao.eu.org/cloudflare/` 获取 IPv4/IPv6 网段、动态测速地址与数据中心表，成功数据在本机缓存 6 小时。
2. 每轮随机抽取最多 100 个网段：IPv4 保留前三段并随机最后一段；IPv6 保留前三个 hextet 并随机后五段。用户导入的安全公网 IP 会占用本轮一部分名额。
3. 以 50 并发对每个候选连续验证三次。单次包含 TCP 连接、可选 TLS 和 `Host: cloudflare.com` 请求；任一次失败或缺少 `CF-RAY` 即淘汰。
4. 按三次 TCP 延迟平均值升序，只保留前 10 个候选。
5. 按延迟顺序逐个连接动态测速主机，固定真实 TCP 目标为候选 IP；TLS 模式保留系统证书与 SNI/Host 校验，非 TLS 模式使用 80 端口。
6. 每个候选最多下载 5 秒，以 32 KiB 读取；每个完整一秒窗口计算一次 kB/s 峰值，最后不足一秒窗口不参与。
7. 第一个达到 `期望 Mbps × 128 kB/s` 的 IP 成为结果；若启用了 Argo 高级复核，还必须通过原节点域名验证。
8. 10 个候选均未达到目标时自动进入新一轮。复制 IP 和 Cloudflare A/AAAA DNS-only 同步只对达标结果开放。

默认流程测量“当前电脑网络到 Cloudflare 入口”的质量，不需要 VPS 源站 IP，也不要求填写 Argo 域名。

## 自定义 IP 池

支持长粘贴、本地文件和 HTTPS 订阅链接：

| 输入 | 支持内容 |
| --- | --- |
| 文本 | IPv4、IPv6、`IP:443`、`[IPv6]:443`、空格/逗号分隔、`#` 注释 |
| CIDR | 受控抽样，不展开整个大网段 |
| 文件 | TXT、CSV、TSV、JSON、Base64 文本 |
| 链接 | 仅 HTTPS 默认 443；限制大小和跳转，并逐跳复核公网目标 |

导入 IP 不要求与动态测速域名当前 DNS 求交，也不要求预先属于 Cloudflare 官方 CIDR。私网、回环、链路本地、组播、保留地址和错误协议族会被拒绝；外部公网候选只有通过同样的三次 RTT/`CF-RAY` 与真实下载门禁后才可复制或同步 DNS。

默认维护数据来自 [badafans/better-cloudflare-ip](https://github.com/badafans/better-cloudflare-ip) 所使用的公开接口。本项目只复现其公开描述与可观察的测速流程，代码为独立实现；上游仓库当前未声明开源许可证，因此没有复制或内嵌其源代码。

## 高级：Argo 兼容复核

普通优选不需要域名。只有希望确认候选 IP 是否兼容自己的 Argo 节点时，才在高级设置中开启，并填写原节点域名、TLS 端口和可选 WS Path。

开启后，达标 IP 还必须使用原域名完成证书、SNI、Host 与真实对端校验；填写 Path 时必须通过标准 WebSocket `101` 握手。它只是附加复核，最终仍只复制裸 IP，节点端口、UUID、SNI、Host 与 Path 不会被工具改写。

## 可选：同步到 Cloudflare DNS

结果页可以把达标 IP 写入自己指定的 Cloudflare DNS 记录。此功能默认关闭，普通测速与复制 IP 不需要 Cloudflare 凭据。

- IPv4 只写 `A`，IPv6 只写 `AAAA`；
- 强制使用 **DNS-only（灰云）**；
- 必须填写 32 位 **Zone ID** 和完整记录名 **FQDN**，例如 `edge.example.com`；
- 只接受目标 Zone 具有 **DNS: Edit** 的 Cloudflare API Token，不接受 Global API Key；
- Token 只存在于本次运行内存与 Cloudflare API 请求头，不进入日志、历史或导出；
- 第一步生成只读预览，第二步必须再次确认，写入后会回读验证；
- 同名 CNAME、多个同类型记录或其他歧义会直接拒绝，不自动删除、合并或转换。

DNS 同步是独立可选输出，不会修改 Argo 域名或节点的端口、UUID、SNI、Host 与 Path。

## 定时自动优选

电脑端可按用户设定的 5–1,440 分钟间隔自动运行：

1. 开启后第一轮立即运行；下一轮从上一轮完成后计时，不会重叠。
2. 开启前只显示“首个下载候选即达标”的流量估算，并明确提示未达标或换轮会增加流量。
3. 停止任务会取消当前轮次及后续计划。
4. 可选择“优选成功后自动同步 DNS”；开启时需要对目标记录和写入行为再次确认。
5. DNS 同步失败只记录脱敏错误并暂停/跳过该次同步，不会删除测速结果。

## 命令行

```bash
# IPv4、100 Mbps、TLS 443
python rr_optimizer.py run --purpose direct --family ipv4 --mode reference --target-mbps 100

# 叠加自己的 IP 名单
python rr_optimizer.py run --purpose direct --family ipv4 --mode reference --ips my-ip-list.txt --csv result.csv

# 非 TLS 80
python rr_optimizer.py run --purpose direct --family ipv4 --mode reference --target-mbps 100 --no-tls

# 高级 Argo 兼容复核
python rr_optimizer.py run --purpose argo --target-host argo.example.com --node-port 8443 --ws-path /vless --family ipv4 --mode reference
```

## 安全与隐私

- 本地界面仅绑定回环地址，并为状态修改请求使用随机会话令牌。
- TLS 模式保留系统证书、SNI、Host 与实际远端验证；非 TLS 80 必须由用户主动选择。
- 维护池在线更新失败时使用本机缓存，再失败则回退 Cloudflare 官方网段。
- HTTPS 订阅实施公网目标、大小、跳转和 DNS rebinding 防护。
- Cloudflare API Token 不写日志、历史或导出；错误信息会脱敏。
- 不提供端口扫描、漏洞探测、压力测试、任意 hosts/路由修改或访问控制绕过。

详见 [SECURITY.md](SECURITY.md) 与 [NOTICE.md](NOTICE.md)。

## 开发与验证

```bash
python -m unittest discover -s tests -v
python -m py_compile rr_optimizer.py cfopt/*.py
node --check web/app.js
```

## 发布

`main` 通过测试后，GitHub Actions 会替换唯一的正式 Release，只生成 Windows x64 免安装便携 ZIP 及其 SHA-256。旧正式包、安装版与测试通道不会继续保留。当前应用版本保持 **1.0.0**。

项目尚未选择开源许可证；复用或分发本项目代码前请先取得版权所有者许可。
