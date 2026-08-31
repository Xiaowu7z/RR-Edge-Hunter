# RR Edge Hunter

**CF IP Selector · Desktop**

RR Edge Hunter is a local-only Cloudflare edge connectivity diagnostic. It measures only the Cloudflare addresses currently assigned by DNS to an authorized test hostname, then ranks them with pinned-IP TLS, certificate validation, and staged Pre / Micro / multi-round Full downloads.

It supports IPv4, IPv6, dual stack, Asian POP hunting, local history, JSON/CSV export, long-paste/file/HTTPS IP-list import, and an optional user-controlled recurring measurement interval. Imported addresses are only a local filter and must intersect the test hostname's current DNS assignment before measurement.

The project does not write arbitrary IPs to DNS, generate proxy/hosts configurations, or force traffic to an unassigned edge address.

See the Chinese README for setup, format limits, safety boundaries, and release instructions.
