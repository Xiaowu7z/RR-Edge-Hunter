# RR Edge Hunter

**CF 优选IP · 电脑端**

RR Edge Hunter 是一个仅在本机运行的 Argo / Cloudflare 入口 IP 优选工具。默认模式会从当前 DNS、内置 Cloudflare 官方网段受控抽样和用户导入官方网段组成候选；结果 IP 可直接填入节点的 `address` / `server`，原 Argo 域名继续作为 TLS SNI 与 HTTP Host，端口和 WebSocket 路径保持原节点配置。

> 这不是“全网优质 IP 榜单”。Cloudflare 公共地址是 anycast 共享边缘地址，结果会随网络出口、运营商、时间与测试主机变化。请在实际使用网络中重新测量。

## 核心能力

- IPv4、IPv6、双栈独立测量。
- 自动、移动、电信、联通线路标签与本地历史分类。
- 均衡模式与“亚洲狩猎”；两者都先保证成功率和持续速度，亚洲 POP 只在性能接近时作为偏好。
- 每个入围 IP 经 Pre、Micro、固定多轮 Full 复核；完整复核任一轮失败按 `0 Mbps` 计入底线。
- 直接粘贴长 IP 列表、导入 TXT / CSV / TSV / JSON / Base64 文件、读取 HTTPS 列表链接；支持 IPv4、IPv6、`IP:443`、`[IPv6]:443` 和受限 CIDR 抽样。
- Argo 默认模式使用“当前 DNS + 内置官方 CIDR 抽样 + 用户导入官方网段”的并集；非 Cloudflare 官方地址会被隔离。原“当前 DNS 交集”逻辑保留在辅助体检模式。
- Argo 域名兼容门禁：固定连接候选 IP，但始终使用用户域名验证证书、SNI、Host；填写 WS 路径时还必须完成真实 `101` WebSocket 握手。
- 每条结果提供“复制 IP”和“复制 Argo 参数”，JSON / CSV 同时带出 server、端口、SNI、Host 与 WS 路径。
- 本地 JSON / CSV 导出、最近 50 条本地历史记录、停止任务与网络出口变化作废保护。
- 可选定时自动优选：用户自定义 5–1,440 分钟间隔，首次立即运行、后续从上一轮完成时开始计时。

## 重要边界

Cloudflare 的公共 IP 范围是归属范围，不是官方速度排名。内置候选是对官方 CIDR 的确定性、受控抽样，只有通过用户 Argo 域名证书与 SNI/Host 兼容验证的地址才会进入排名。本工具不会改写 A/AAAA、hosts 或节点文件，也不会关闭证书验证；第三方非官方反代地址不混入默认池。

## 快速开始

### Windows 免安装版（推荐）

正式版发布后，下载并解压 [最新版 Windows 便携包](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip)，双击其中的 `CF-IP-Optimizer.exe` 即可。运行环境已内置，**不需要安装 Python**；请保留同目录的 `_internal` 文件夹。

### 测试通道

[🧪 **手动下载当前 Windows 测试包**](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/download/testing/CF-IP-Optimizer-Windows-x64-testing.zip)

测试包与正式版暂时都保留内部版本号 **1.0.0**，不会触发自动升级；请手动下载、解压并覆盖旧目录。测试通道是独立的预发布，不会替换上面的正式版 `latest` 链接。

### 源码运行

要求：Python 3.11 或更高版本，不需要第三方 Python 包。

Windows：双击 `start-windows.bat`。

macOS / Linux：

```bash
chmod +x start-unix.sh
./start-unix.sh
```

也可以：

```bash
python rr_optimizer.py ui
```

界面只监听 `127.0.0.1`，不上传测速记录。

## 命令行

优选可填入 Argo 节点的 IPv4 地址：

```bash
python rr_optimizer.py run --purpose argo --target-host argo.example.com --ws-path /vless --family ipv4
```

只测指定主机当前 DNS 分配的 IPv4（辅助体检）：

```bash
python rr_optimizer.py run --purpose dns --target-host speed.cloudflare.com --family ipv4
```

将本地 IP 名单加入 Argo 智能候选池：

```bash
python rr_optimizer.py run --purpose argo --target-host argo.example.com --ips my-ip-list.txt --family dual --mode asia --csv result.csv
```

## 导入格式与限制

| 输入 | 支持 |
| --- | --- |
| 文本 | 每行一个 IP、空格/逗号分隔、`#` 注释、`IP:443` |
| IPv6 | 原生 IPv6、`[IPv6]:443` |
| CIDR | 安全、确定性抽样；每段最多 96 个地址，避免大网段与 IPv6 爆炸 |
| 表格 | CSV / TSV 中的 `ip`、`address`、`server`、`host` 等列 |
| JSON | 字符串数组，或 `ips` / `addresses` / `items` / `data` 下的 IP 字段 |
| Base64 | 整份 TXT、CSV 或 JSON 的 Base64 包装 |
| 链接 | 仅 HTTPS、默认 443、最多 3 次跳转、1 MiB、每次跳转重新检查公网目标 |

单次最多 2,000 个公网地址。私网、回环、链路本地、保留地址和无效字段会被拒绝。Argo 模式不会再与当前 DNS 强制求交，但只接受 Cloudflare 官方 CIDR；DNS 体检模式仍严格使用当前 DNS 交集。

为控制真实下载和亚洲 POP 探测，每个协议族每轮最多保留 128 个已验证候选。开始前会显示该轮的最高计划流量，必须由用户确认。

## 定时自动优选

在桌面界面勾选“按间隔自动重测”后，设置 5–1,440 分钟的间隔并确认即可开启：

1. 第一轮立即开始。
2. 后续从上一轮结束开始等待指定间隔，绝不与上一轮重叠。
3. 开启前会显示每轮流量与按当前间隔计算的理论 24 小时上限；实际次数会因每轮耗时而更少。
4. “停止”会取消当前测试和后续所有定时轮次。
5. 定时模式只重测、保存本地历史、刷新结果并提供导出/复制；不会修改任何 DNS 记录。
6. HTTPS 订阅每轮通过原有 SSRF、重定向、大小与公网目标检查后刷新；刷新失败会使用上次已载入快照。粘贴和文件导入始终使用本次快照。

## 测量方法

1. 解析用户 Argo 域名，确认它当前由 Cloudflare 代理。
2. 合并当前 DNS、内置官方 CIDR 抽样与用户导入官方网段；每族按来源均衡保留最多 128 个。
3. 固定连接每个候选 IP，用 Argo 域名做 TLS SNI、Host、证书与可选 WS 握手门禁。
4. 对通过门禁的候选固定连接 `speed.cloudflare.com`，执行 Pre 初筛 → Micro 小流量复核 → Full 固定多轮下载。普通 Argo 节点没有 `/__down`，因此不能直接承担吞吐测试。
5. 依次比较：完整复核最低轮次、成功率、最低速度、平均速度、波动率、TTFB；亚洲 POP 只作同档偏好。

测速端点和身份验证域名是两个角色：前者负责可比较的入口吞吐，后者保证该 IP 确实能以原 Argo 域名使用。结果是本地性能观察，不保证其他网络、其他时段的表现。

## 开发与验证

```bash
python -m unittest discover -s tests -v
python -m py_compile rr_optimizer.py cfopt/*.py
node --check web/app.js
```

## 发布

创建标签 `vX.Y.Z` 后，GitHub Actions 会运行回归测试并生成两类产物：面向普通 Windows 用户的 `CF-IP-Optimizer-Windows-x64.zip`（内置 `CF-IP-Optimizer.exe`，无需 Python），以及跨平台源码 ZIP、manifest 与 SHA-256。标签版本会同时写入产物名、manifest 和运行时 `VERSION` 文件；解压后的界面/API/导出结果会读取该文件，不会一直显示开发版 `0.1.0`。两个构建器都只读取标签提交中的源码，未跟踪文件和本地密钥不会进入发布包。也可本地执行：

```bash
python tools/build_release.py --version X.Y.Z
# 在 Windows 上：
python -m pip install pyinstaller==6.11.1
python tools/build_portable_release.py --version X.Y.Z --target Windows-x64
```

项目尚未选择开源许可证；在复用或分发代码前，请先取得版权所有者许可。

## 免责声明

Cloudflare 是 Cloudflare, Inc. 的商标；本项目为独立第三方工具，未获 Cloudflare 认可或关联。详见 [NOTICE.md](NOTICE.md) 与 [SECURITY.md](SECURITY.md)。
