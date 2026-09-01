# RR Edge Hunter · CF 优选IP

> Windows 电脑版 · [Android 版](https://github.com/Xiaowu7z/RR-Edge-Hunter-Android)

电脑版测速不再使用 RR 自写算法，也不需要任何节点链接。候选池、随机 IP、三次 RTT / CF-RAY、延迟排序、下载测速、速度计算、达标早停和换轮逻辑，全部由固定的 `better-cloudflare-ip` 原版 Go 程序执行。

RR 只做四件事：

1. 提供桌面界面，把 IPv4/IPv6、TLS/非 TLS 和期望带宽交给原版程序；
2. 显示并复制原版程序返回的结果；
3. 在电脑端按用户选择的小时档位，重复调用同一个原版程序；
4. 按用户选择，手动或在每轮完成后自动把唯一结果写入同一条 Cloudflare A/AAAA 灰云记录。

没有节点输入、Xray、运营商模式、自定义 IP 池或 RR 二次测速算法。

## 下载与使用

正式版提供 Windows x64 免安装便携包：

[下载最新版 CF-IP-Optimizer-Windows-x64.zip](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest)

解压完整 ZIP 后运行 `CF-IP-Optimizer.exe`，程序会打开本机网页界面。不要单独移动 EXE，也不要删除 `_internal` 目录。

默认值与参考 App 一致：

| 项目 | 默认值 |
| --- | --- |
| IP 协议 | IPv4 |
| 连接方式 | 非 TLS 80 |
| 期望带宽 | 1 Mbps |
| RTT 进程数 | 50（由外壳固定传给原版程序） |

原版程序未达到期望带宽时会继续换轮，因此目标越高，耗时和流量越大。点击“停止本次任务”会终止当前原版进程。

## 电脑端自动测试

运行方式可选择单次测试，或每 1、2、4、6、12、24 小时自动测试：

- 开启后第一轮立即运行；
- 从上一轮完整结束后才开始计算下一次间隔，不会重叠启动两个测速进程；
- 每轮只接收原版程序返回的 1 个达标 IP；
- 可开启“每轮自动解析”，也可关闭后在结果页手动添加解析；
- 点击停止会同时取消当前测试与后续轮次；
- 自动任务只在电脑版程序保持运行时生效，不注册系统服务。

“全天模式”对应每 24 小时自动运行一轮。

## 原版引擎来源

仓库内的 [main.go](third_party/better-cloudflare-ip/main.go) 是以下上游文件的未修改副本：

- 上游：`badafans/better-cloudflare-ip`
- 固定提交：`c4f4cdd4c44243c964e68881a451d8e1f3fd5210`
- `main.go` SHA-256：`83663f1e2655943ebae2d99d520a35f8c5dd58142ac58cf2169220e35deb11ab`

CI 先校验源码哈希，再直接编译 Windows 程序并放入便携包。Python 不生成候选、不发送 RTT/测速请求，也不参与排名，只向原版程序的标准输入写入菜单参数并读取其标准输出。

上游原版流程会从 `https://www.baipiao.eu.org/cloudflare/` 获取：

- `ips-v4`
- `ips-v6`
- `url`
- `locations`

数据缓存在当前用户目录；界面中的“更新参考程序数据”直接调用原版菜单第 8 项。

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

命令行调用同一个原版程序：

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

构建流程会再次核对固定源码哈希。详见 [第三方说明](THIRD_PARTY_NOTICES.md) 与 [安全说明](SECURITY.md)。
