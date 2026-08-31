# RR Edge Hunter

**CF 优选IP · 电脑端**

RR Edge Hunter 是一个仅在本机运行的 Cloudflare 边缘连通性诊断工具。它以已授权测试主机的当前 DNS 分配结果为候选，使用固定 IP、TLS SNI、证书校验与 Pre / Micro / Full 分层下载，在当前设备和当前网络下筛选更稳定的 IPv4 / IPv6 地址。

> 这不是“全网优质 IP 榜单”。Cloudflare 公共地址是 anycast 共享边缘地址，结果会随网络出口、运营商、时间与测试主机变化。请在实际使用网络中重新测量。

## 核心能力

- IPv4、IPv6、双栈独立测量。
- 自动、移动、电信、联通线路标签与本地历史分类。
- 均衡模式与“亚洲狩猎”：HKG > NRT > SIN > ICN > TPE，并复核 POP 漂移。
- 每个入围 IP 经 Pre、Micro、固定多轮 Full 复核；完整复核任一轮失败按 `0 Mbps` 计入底线。
- 直接粘贴长 IP 列表、导入 TXT / CSV / TSV / JSON / Base64 文件、读取 HTTPS 列表链接；支持 IPv4、IPv6、`IP:443`、`[IPv6]:443` 和受限 CIDR 抽样。
- 自定义 IP 列表只作为本地筛选名单：程序仅保留与测试主机**当前 DNS 实际分配结果**相交的地址。
- 本地 JSON / CSV 导出、最近 50 条本地历史记录、停止任务与网络出口变化作废保护。
- 可选定时自动优选：用户自定义 5–1,440 分钟间隔，首次立即运行、后续从上一轮完成时开始计时。

## 重要边界

Cloudflare 的公共 IP 范围是归属范围，不是官方“优选 IP 池”。本工具不会把任意 IP 写入 A/AAAA、生成 hosts/代理配置，也不会把流量强制导向未由测试主机 DNS 分配的地址。请只对自有或明确获授权的网络与主机进行测量，并遵守网络提供商和服务商条款。

## 快速开始

### Windows 免安装版（推荐）

正式版发布后，下载并解压 [最新版 Windows 便携包](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip)，双击其中的 `CF-IP-Optimizer.exe` 即可。运行环境已内置，**不需要安装 Python**；请保留同目录的 `_internal` 文件夹。

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

只测指定主机当前 DNS 分配的 IPv4：

```bash
python rr_optimizer.py run --target-host speed.cloudflare.com --family ipv4
```

使用本地 IP 筛选名单（不会绕过当前 DNS 校验）：

```bash
python rr_optimizer.py run --target-host edge.example.com --ips my-ip-list.txt --family dual --mode asia --csv result.csv
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

单次最多 2,000 个公网地址。私网、回环、链路本地、保留地址和无效字段会被拒绝。导入名单不是自动信任池；真正开测前仍要与测试主机的当前 A/AAAA 记录取交集。

为控制真实下载和亚洲 POP 探测，每个协议族每轮最多保留 128 个已验证候选。开始前会显示该轮的最高计划流量，必须由用户确认。

## 定时自动优选

在桌面界面勾选“按间隔自动重测”后，设置 5–1,440 分钟的间隔并确认即可开启：

1. 第一轮立即开始。
2. 后续从上一轮结束开始等待指定间隔，绝不与上一轮重叠。
3. 开启前会显示每轮流量与按当前间隔计算的理论 24 小时上限；实际次数会因每轮耗时而更少。
4. “停止”会取消当前测试和后续所有定时轮次。
5. 定时模式只重测、保存本地历史、刷新结果并提供导出/复制；不会修改任何 DNS 记录。

## 测量方法

1. 解析用户填写的测试主机，确认当前获分配的 Cloudflare 边缘地址。
2. 按 IPv4 / IPv6 过滤候选；亚洲模式先读取 POP。
3. Pre 初筛 → Micro 小流量复核 → Full 固定多轮复核。
4. 依次比较：完整复核最低轮次、成功率、最低速度、平均速度、波动率、TTFB；亚洲模式先比较 POP 优先级和漂移。

测试主机、SNI、Host 和证书校验始终一致。结果是本地性能观察，不保证其他网络、其他时段或其他主机的表现。

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
