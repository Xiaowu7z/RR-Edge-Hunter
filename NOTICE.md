# 使用与商标说明 / Notice

RR Edge Hunter 是独立第三方 Cloudflare 入口 IP 测量工具，与 Cloudflare, Inc. 不存在隶属、合作、赞助、认证或背书关系。“Cloudflare”及相关名称和商标归其权利人所有。

默认测量固定使用 Cloudflare 公共测速主机 `speed.cloudflare.com:443`，候选限定在 Cloudflare 官方公布网段及用户导入后通过同一官方范围校验的地址。测试结果仅代表当前设备、网络出口、运营商和时间，不构成线路质量保证。

优选出的裸 IP 只用于替换用户节点的 `address/server`。节点端口、UUID、协议、SNI、Host 与 WS Path 应保持原配置；高级 Argo 复核仅用于额外兼容验证。

Cloudflare DNS 同步为用户主动开启的可选功能，只操作用户明确指定的 Zone 与完整记录名，并采用 DNS-only A/AAAA、预览确认和回读验证。使用者负责保护 API Token、确认记录用途与变更影响，并遵守 Cloudflare 条款及所在地法律。

用户应仅在自己拥有或获授权的网络、节点、域名和 Cloudflare Zone 上使用本项目。项目不对不当配置、DNS 变更、第三方 IP 池、网络波动或违反服务条款造成的损失承担责任。

---

RR Edge Hunter is an independent third-party project and is not affiliated with, sponsored by, endorsed by, or maintained by Cloudflare, Inc. Users are responsible for authorized testing, protecting API tokens, reviewing optional DNS changes, and complying with applicable laws and provider terms.
