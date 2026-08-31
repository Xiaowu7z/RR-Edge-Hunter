# RR Edge Hunter

**CF IP Selector · Desktop**

RR Edge Hunter is a local-only Argo / Cloudflare ingress IP optimizer. The default workflow combines an Argo hostname's current DNS answers, a bounded deterministic sample of Cloudflare's published CIDRs, and optional user-imported Cloudflare addresses. A winning IP is intended for the node `address` / `server`; the original Argo hostname remains TLS SNI and HTTP Host.

Candidates must pass pinned-IP certificate, SNI and Host validation; an optional WS path must complete a real WebSocket upgrade. Comparable throughput is measured separately through `speed.cloudflare.com`, because ordinary Argo nodes do not expose its download endpoint. IPv4, IPv6, dual stack, Asian POP hunting, local history, JSON/CSV export, bounded imports/subscriptions, and recurring measurement are supported. The legacy current-DNS diagnostic remains available.

The project never changes DNS/node files or disables certificate validation. Non-Cloudflare third-party relays are isolated from the default pool.

## Windows portable build

After the first formal release, download and extract the [latest Windows portable package](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/latest/download/CF-IP-Optimizer-Windows-x64.zip), then double-click `CF-IP-Optimizer.exe`. Python is bundled; keep the adjacent `_internal` directory intact.

### Testing channel

[🧪 **Manually download the current Windows testing package**](https://github.com/Xiaowu7z/RR-Edge-Hunter/releases/download/testing/CF-IP-Optimizer-Windows-x64-testing.zip)

The testing package intentionally keeps internal version **1.0.0**, so it will not trigger an automatic upgrade. Download, extract, and replace the previous folder manually. This prerelease channel does not replace the stable `latest` link above.

See the Chinese README for setup, format limits, safety boundaries, and release instructions.
