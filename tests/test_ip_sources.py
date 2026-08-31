from __future__ import annotations

import base64
import json
import unittest
from email.message import Message
from unittest.mock import patch

from cfopt.ip_sources import IpSourceError, fetch_ip_subscription, normalize_ip_values, parse_ip_source


class IpSourceTest(unittest.TestCase):
    def test_plain_text_port_ipv6_cidr_and_deduplication(self) -> None:
        result = parse_ip_source("104.16.0.1\n104.16.0.1:443\n[2606:4700:4700::1111]:443\n104.16.1.0/30\n10.0.0.1")
        self.assertEqual(result.ips[:2], ["104.16.0.1", "2606:4700:4700::1111"])
        self.assertIn("104.16.1.1", result.ips)
        self.assertNotIn("10.0.0.1", result.ips)
        self.assertEqual(result.cidr_count, 1)

    def test_only_https_443_ports_are_accepted(self) -> None:
        result = parse_ip_source(
            "1.1.1.1:443\n"
            "1.1.1.1:8443\n"
            "[2606:4700:4700::1111]:443\n"
            "[2606:4700:4700::1111]:8443\n"
        )
        self.assertEqual(result.ips, ["1.1.1.1", "2606:4700:4700::1111"])
        self.assertEqual(result.ignored, 2)

    def test_json_csv_and_base64_content_detection(self) -> None:
        json_result = parse_ip_source(json.dumps({"items": [{"ip": "104.16.0.1"}, {"address": "2606:4700::1111"}]}), "list.json")
        self.assertEqual(json_result.ips, ["104.16.0.1", "2606:4700::1111"])
        csv_result = parse_ip_source("name,ip\na,104.16.0.2\nb,104.16.0.3", "list.csv")
        self.assertEqual(csv_result.ips, ["104.16.0.2", "104.16.0.3"])
        encoded = base64.b64encode(b"104.16.0.4\n104.16.0.5").decode("ascii")
        self.assertEqual(parse_ip_source(encoded, "encoded.txt").ips, ["104.16.0.4", "104.16.0.5"])

    def test_only_public_ips_are_accepted(self) -> None:
        with self.assertRaisesRegex(IpSourceError, "没有识别到"):
            parse_ip_source("127.0.0.1\n192.168.1.1\nnot-an-ip")

    def test_parser_bounds_deep_json_and_oversized_csv_rows(self) -> None:
        deeply_nested = "[" * 70 + '"104.16.0.1"' + "]" * 70
        with self.assertRaisesRegex(IpSourceError, "层级过深"):
            parse_ip_source(deeply_nested, "deep.json")
        with self.assertRaisesRegex(IpSourceError, "CSV 单行"):
            parse_ip_source("ip\n" + "x," * 40_000, "large-row.csv")

    def test_normalize_values_keeps_order(self) -> None:
        self.assertEqual(normalize_ip_values(["104.16.0.9", "104.16.0.9", "2606:4700::1111"]), ["104.16.0.9", "2606:4700::1111"])

    def test_https_subscription_returns_resolved_final_url(self) -> None:
        class FakeResponse:
            status = 200

            def __init__(self) -> None:
                self.headers = Message()
                self.headers["Content-Type"] = "text/plain"
                self.payload = b"104.16.0.1\n2606:4700::1111\n"

            def getheader(self, name: str, default: str | None = None) -> str | None:
                return self.headers.get(name, default)

            def read(self, _: int | None = None) -> bytes:
                limit = len(self.payload) if _ is None else _
                chunk, self.payload = self.payload[:limit], self.payload[limit:]
                return chunk

        class FakeConnection:
            def __init__(self, *_: object) -> None:
                self.request_path = ""

            def request(self, _method: str, path: str, **_: object) -> None:
                self.request_path = path

            def getresponse(self) -> FakeResponse:
                return FakeResponse()

            def close(self) -> None:
                return None

        def resolver(_host: str, _port: int, **_: object) -> list[tuple]:
            return [(None, None, None, None, ("8.8.8.8", 443))]

        with patch("cfopt.ip_sources._PinnedHTTPSConnection", FakeConnection):
            result, final_url = fetch_ip_subscription("https://pool.example/list.txt", resolver=resolver)
        self.assertEqual(result.ips, ["104.16.0.1", "2606:4700::1111"])
        self.assertEqual(final_url, "https://pool.example/list.txt")

    def test_subscription_rejects_http_and_private_resolutions(self) -> None:
        with self.assertRaisesRegex(IpSourceError, "只支持 HTTPS"):
            fetch_ip_subscription("http://pool.example/list.txt")

        def private_resolver(_host: str, _port: int, **_: object) -> list[tuple]:
            return [(None, None, None, None, ("127.0.0.1", 443))]

        with self.assertRaisesRegex(IpSourceError, "内网"):
            fetch_ip_subscription("https://pool.example/list.txt", resolver=private_resolver)

        def site_local_resolver(_host: str, _port: int, **_: object) -> list[tuple]:
            return [(None, None, None, None, ("fec0::1", 443, 0, 0))]

        with self.assertRaisesRegex(IpSourceError, "非公网"):
            fetch_ip_subscription("https://pool.example/list.txt", resolver=site_local_resolver)

    def test_https_subscription_revalidates_redirect_target(self) -> None:
        class FakeResponse:
            def __init__(self, status: int, location: str = "") -> None:
                self.status = status
                self.headers = Message()
                self.headers["Content-Type"] = "text/plain"
                self.payload = b"104.16.0.2\n" if status == 200 else b""
                if location:
                    self.headers["Location"] = location

            def getheader(self, name: str, default: str | None = None) -> str | None:
                return self.headers.get(name, default)

            def read(self, _: int | None = None) -> bytes:
                limit = len(self.payload) if _ is None else _
                chunk, self.payload = self.payload[:limit], self.payload[limit:]
                return chunk

        requests: list[str] = []

        class FakeConnection:
            def __init__(self, *_: object) -> None:
                return None

            def request(self, _method: str, path: str, **_: object) -> None:
                requests.append(path)

            def getresponse(self) -> FakeResponse:
                return FakeResponse(302, "/final.txt") if len(requests) == 1 else FakeResponse(200)

            def close(self) -> None:
                return None

        def resolver(_host: str, _port: int, **_: object) -> list[tuple]:
            return [(None, None, None, None, ("8.8.8.8", 443))]

        with patch("cfopt.ip_sources._PinnedHTTPSConnection", FakeConnection):
            result, final_url = fetch_ip_subscription("https://pool.example/first.txt", resolver=resolver)
        self.assertEqual(result.ips, ["104.16.0.2"])
        self.assertEqual(final_url, "https://pool.example/final.txt")
        self.assertEqual(requests, ["/first.txt", "/final.txt"])


if __name__ == "__main__":
    unittest.main()
