# RR Edge Hunter

**CF 优选 IP · 电脑端**

RR Edge Hunter 是一款本机运行的 Cloudflare 入口 IP 优选工具。默认不需要填写域名：应用把 `speed.cloudflare.com` 固定到每个候选 IP 的 `443` 端口，保留严格 TLS 证书、SNI 与 Host 校验，再通过分层、多轮真实下载找出当前网络更快、更稳定的入口。

优选结果是一个裸 IPv4 或 IPv6。把它填入 VMess / VLESS 等节点的 `address` 或 `server` 字段即可；节点原来的端口、UUID、协议、TLS SNI、HTTP Host、WS Path 等参数全部保持不变。

> Cloudflare 官方网段表示地址归属，不是官方速度排名。Anycast 入口会随地区、运营商、网络出口和时间变化；请在实际使用网络中重新测试。

## 一键默认值

| 项目 | 默认值 |
| --- | --- |
| IP 协议 | IPv4 |
| 期望带宽 | 100 Mbps |
| 测速策略 | 亚洲狩猎 |
| 测速身份 | `speed.cloudflare.com:443` |
| 候选来源 | Cloudflare 官方池；可叠加用户导入的官方 IP |
| 输出用途 | 只替换节点 `address/server` |

亚洲狩猎仍以成功率、复核底线、最低与平均吞吐和波动为主；HKG、NRT、SIN、ICN、TPE 等 POP 只在成绩接近时加分，不会让明显更慢的亚洲入口排到高速稳定入口之前。

## 下载与运行

### Windows 安装版（推荐）

[⬇️ 下载最新版 Windows 安装程序](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Setup.exe)

双击 `CF-IP-Optimizer-Setup.exe` 按提示安装即可。安装包已经包含运行环境，无需另外安装 Python，也无需选择压缩包或 CPU 架构。

### Windows 便携版（免安装）

[📦 下载最新版 Windows x64 便携包](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip)

解压 `CF-IP-Optimizer-Windows-x64.zip`，进入 `CF-IP-Optimizer` 文件夹后双击 `CF-IP-Optimizer.exe` 即可运行。便携包同样内置运行环境，无需安装 Python；请保留 `CF-IP-Optimizer.exe` 与 `_internal` 文件夹的相对位置，不要只把 EXE 单独移出。

### 源码运行

要求 Python 3.11 或更高版本，不需要第三方 Python 包。

- Windows：双击 `start-windows.bat`
- macOS / Linux：运行 `./start-unix.sh`
- 通用：`python rr_optimizer.py ui`

界面只监听 `127.0.0.1`，测速记录不会上传。

## 工作方式

1. 获取 `speed.cloudflare.com` 当前 DNS 种子，并加载 Cloudflare 官方 CIDR 的确定性受控抽样。
2. 如用户导入名单，将其中属于 Cloudflare 官方网段的地址加入候选；非 CF 地址不会进入默认测试池。
3. 固定 `speed.cloudflare.com:443` 到每个候选 IP，保留系统证书验证、TLS SNI、HTTP Host 与真实 TCP 对端校验。
4. 执行 Pre 快筛、Micro 复核和多轮 Full 下载；失败轮次按 `0 Mbps` 纳入稳定性与可靠下限。
5. 按成功率、复核底线、最低/平均吞吐、波动、TTFB 排名，并标注是否达到用户设定的带宽目标。

默认模式测的是“用户当前网络到 Cloudflare 入口”的质量，不需要知道 VPS 源站 IP，也不会更改节点配置。

## 自定义 IP 池

支持长粘贴、本地文件和 HTTPS 订阅链接：

| 输入 | 支持内容 |
| --- | --- |
| 文本 | IPv4、IPv6、`IP:443`、`[IPv6]:443`、空格/逗号分隔、`#` 注释 |
| CIDR | 确定性受控抽样，不展开整个大网段 |
| 文件 | TXT、CSV、TSV、JSON、Base64 文本 |
| 链接 | 仅 HTTPS 默认 443；限制大小和跳转，并逐跳复核公网目标 |

导入不要求与 `speed.cloudflare.com` 当前 DNS 求交，但必须属于 Cloudflare 官方 CIDR。私网、回环、链路本地、保留地址、非 CF 地址和错误协议族都会被拒绝或忽略；候选量、并发和真实下载流量均有硬上限。

第三方非官方反代不会混入默认官方池。

## 高级：Argo 兼容复核

普通优选不需要域名。只有希望确认候选 IP 是否能用于自己的 Argo 节点时，才在高级设置中开启兼容复核，并填写：

- 原节点 TLS SNI / HTTP Host 域名；
- 原节点 TLS 端口；
- 可选 WS Path。

开启后，候选除公共测速外还必须使用原域名完成证书、SNI、Host 和真实远端校验；填写 Path 时必须完成标准 WebSocket `101` 握手。这个步骤只是附加门禁，最终仍只复制裸 IP，节点的其他字段不会被工具改写。

## 可选：同步到 Cloudflare DNS

优选结束后，可以把冠军 IP 写入自己指定的 Cloudflare DNS 记录；默认关闭，测速和复制 IP 不需要任何 Cloudflare 凭据。

同步规则：

- IPv4 只写 `A`，IPv6 只写 `AAAA`；
- 写入记录强制为 **DNS-only（灰云）**，避免再次经过 Cloudflare 代理形成错误链路；
- 必须填写 32 位 **Zone ID** 和完整记录名 **FQDN**，例如 `edge.example.com`；
- 只接受 Cloudflare API Token，不接受 Global API Key；最小权限为目标 Zone 的 **DNS: Edit**；
- Token 只放在请求内存和 Cloudflare API 的认证头中，不进入日志、测速历史、JSON/CSV 导出或发布包；
- 第一步只读取现有记录并显示变更预览，第二步必须由用户明确确认后才写入；预览后记录发生变化会要求重新预览；
- 同名存在 CNAME、多个同类型记录或其他歧义时直接拒绝，不自动删除、合并或转换记录；
- 写入后会重新读取记录验证类型、IP 和灰云状态。

DNS 同步是一个独立可选输出。它不会修改 Argo 域名、节点 UUID、端口、SNI、Host 或 Path。

## 定时自动优选

电脑端可按用户设定的 5–1,440 分钟间隔自动运行：

1. 开启后第一轮立即运行，下一轮从上一轮完成后计时，不会重叠。
2. 开启前显示单轮预计流量和理论 24 小时上限。
3. 停止任务会取消当前轮次及后续计划。
4. 可选择“优选成功后自动同步 DNS”；开启时需要对目标记录和写入行为再次确认。
5. DNS 同步失败只记录经过脱敏的错误并暂停/跳过该次同步，不会终止测速、结果保存或下一轮优选。

## 命令行

直接优选 IPv4，使用与界面一致的 100 Mbps 和亚洲狩猎目标：

```bash
python rr_optimizer.py run --purpose direct --family ipv4 --mode asia --target-mbps 100
```

叠加本地官方 IP 名单：

```bash
python rr_optimizer.py run --purpose direct --family ipv4 --mode asia --ips my-ip-list.txt --csv result.csv
```

高级 Argo 兼容复核：

```bash
python rr_optimizer.py run --purpose argo --target-host argo.example.com --node-port 8443 --ws-path /vless --family ipv4 --mode asia
```

## 安全与隐私

- 本地界面仅绑定回环地址，并为状态修改请求使用随机会话令牌。
- 测速始终保留 TLS 证书与真实远端验证，不继承系统 HTTP 代理。
- 导入订阅实施 HTTPS、公网目标、大小、跳转和 DNS rebinding 防护。
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

`main` 通过测试后，GitHub Actions 会替换唯一的正式 Release，同时生成 Windows x64 安装版、免安装便携版及各自的 SHA-256。旧正式包与测试通道不会继续保留。当前应用版本保持 **1.0.0**。

项目尚未选择开源许可证；复用或分发代码前请先取得版权所有者许可。
