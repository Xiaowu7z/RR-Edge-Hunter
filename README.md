# RR Edge Hunter · CF 优选IP 电脑版

> 无需节点、无需订阅，在 Windows 本机优选 Cloudflare IPv4/IPv6；支持定时运行和每轮自动解析。
>
> [下载 Windows 版](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest) · [查看 Android 版](https://github.com/Xiaowu7z/RR-Edge-Hunter-Android)

RR Edge Hunter 会在用户当前电脑和当前网络上生成候选 Cloudflare IP，依次完成三次 RTT / CF-RAY 检测、延迟筛选和下载测速，直到找到达到期望带宽的 IP。整个过程不需要 VMess/VLESS 节点、订阅链接、UUID 或其他代理信息。

## 主要功能

- 支持 IPv4、IPv6，以及非 TLS 80 / TLS 443；
- 支持单次测试，或每 1、2、4、6、12、24 小时自动测试；
- 开启自动任务后立即运行第一轮，上一轮结束后才开始计算下次间隔；
- 每轮只保留 1 个达标 IP；
- 可在结果页手动解析，也可让自动任务每轮更新同一条 Cloudflare A/AAAA 灰云记录；
- 支持停止当前测试、停止后续轮次、复制结果和更新 IP 池；
- 界面与任务仅在本机运行，不需要部署服务器。

新版界面沿用 RR Edge Atlas 的双栏卡片、动态路由图、实时状态台和冠军结果卡设计；内部命令行菜单不会再显示给用户。

## 下载与使用

正式版提供 Windows x64 免安装便携包：

[下载最新版 CF-IP-Optimizer-Windows-x64.zip](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest)

解压完整 ZIP 后运行 `CF-IP-Optimizer.exe`，程序会打开本机网页界面。不要单独移动 EXE，也不要删除 `_internal` 目录。

1. 选择 IPv4/IPv6、TLS/非 TLS，并填写期望带宽；
2. 选择“仅运行一次”或一个自动测试间隔；
3. 如需每轮自动解析，启动前填写 Cloudflare 信息并明确确认；
4. 点击开始，程序会显示每轮结果、下一轮时间和自动解析状态。

默认值：

| 项目 | 默认值 |
| --- | --- |
| IP 协议 | IPv4 |
| 连接方式 | 非 TLS 80 |
| 期望带宽 | 1 Mbps |
| RTT 并发数 | 50 |

未达到期望带宽时会继续换轮，因此目标越高，耗时和流量越大。点击“停止本次任务”可随时终止当前测试。

## 定时自动测试

运行方式可选择单次测试，或每 1、2、4、6、12、24 小时自动测试：

- 开启后第一轮立即运行；
- 从上一轮完整结束后才开始计算下一次间隔，不会重叠启动两个测速进程；
- 每轮只保留 1 个达标 IP；
- 可开启“每轮自动解析”，也可关闭后在结果页手动添加解析；
- 点击停止会同时取消当前测试与后续轮次；
- 自动任务只在电脑版程序保持运行时生效。

“全天模式”对应每 24 小时自动运行一轮。自动任务依赖电脑版程序持续运行；关闭程序后不会在后台继续，也不会注册系统服务。

## IP 优选流程

1. 准备并缓存 IPv4 / IPv6 候选池和数据中心信息；
2. 从候选子网随机生成测试 IP；
3. 对每个候选连续执行三次 RTT 与 CF-RAY 校验；
4. 保留低延迟候选进入下载测速；
5. 找到达到期望带宽的 IP 后结束本轮，否则自动换一批继续；
6. 用户可点击“更新 IP 池”随时刷新本机缓存。

第三方代码与许可信息统一收录在 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，不占用普通用户的操作界面。

## Cloudflare DNS

结果页允许用户手动把本轮唯一 IP 添加到指定 Cloudflare 域名；电脑端自动测试也可在每轮结束后自动更新同一条记录。测速和复制 IP 不需要 Cloudflare 凭据。

- IPv4 写 `A`，IPv6 写 `AAAA`；
- 强制 DNS-only（灰云）与自动 TTL；
- 手动模式由用户填写 Zone ID、完整记录名和 API Token，先执行只读预览，再二次确认；
- 自动模式在启动任务时一次性确认，每轮只创建或更新这一条记录，不增加多 IP 解析；
- 写入后回读验证；
- 同名 CNAME、NS 或多条同类型记录会拒绝，不自动删除或合并；
- Token 不写入日志、状态或本地设置；自动任务停止或窗口关闭后即从内存清除。

API Token 只需目标 Zone 的 DNS Edit 权限。

## 源码运行

需要 Python 3.11+ 和 Go 1.22+：

```bash
python rr_optimizer.py ui
```

命令行：

```bash
python rr_optimizer.py run --family ipv4 --bandwidth 20
python rr_optimizer.py run --family ipv6 --bandwidth 20 --tls
python rr_optimizer.py update
```

测试：

```bash
python -m unittest discover -s tests -v
python -m py_compile rr_optimizer.py cfopt/*.py
node --check web/app.js
```

详见 [第三方说明](THIRD_PARTY_NOTICES.md) 与 [安全说明](SECURITY.md)。
