from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from unittest.mock import patch

from cfopt.cloudflare_dns import (
    CloudflareDnsClient,
    CloudflareDnsError,
    HttpResponse,
    UrlLibTransport,
    normalize_champion_ip,
    normalize_record_name,
    normalize_zone_id,
)


ZONE_ID = "a" * 32
RECORD_ID = "b" * 32
CREATED_RECORD_ID = "c" * 32
TOKEN = "secret-token-that-must-never-leak"


def _response(result: object, status: int = 200, result_info: object | None = None) -> HttpResponse:
    value: dict[str, object] = {"success": 200 <= status < 300, "result": result}
    if result_info is not None:
        value["result_info"] = result_info
    return HttpResponse(status, json.dumps(value).encode("utf-8"))


class FakeCloudflareTransport:
    def __init__(self) -> None:
        self.zones: dict[str, str] = {"example.com": ZONE_ID}
        self.records: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.ignore_patch = False

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> HttpResponse:
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path.removeprefix("/client/v4")
        query = urllib.parse.parse_qs(parsed.query)
        payload = json.loads(body) if body is not None else None
        self.calls.append({
            "method": method,
            "url": url,
            "headers": dict(headers),
            "payload": payload,
            "timeout_seconds": timeout_seconds,
            "max_response_bytes": max_response_bytes,
        })
        if method == "GET" and path == "/zones":
            name = query.get("name", [""])[0]
            zone_id = self.zones.get(name)
            rows = [] if not zone_id else [{"id": zone_id, "name": name, "status": "active"}]
            return _response(rows, result_info={"total_pages": 1})
        if method == "GET" and path == f"/zones/{ZONE_ID}/dns_records":
            name = query.get("name.exact", [""])[0]
            record_type = query.get("type", [""])[0]
            rows = [row.copy() for row in self.records if row.get("name") == name and row.get("type") == record_type]
            return _response(rows, result_info={"total_pages": 1})
        if method == "POST" and path == f"/zones/{ZONE_ID}/dns_records":
            row = {"id": CREATED_RECORD_ID, **payload}
            self.records.append(row)
            return _response(row)
        patch_prefix = f"/zones/{ZONE_ID}/dns_records/"
        if method == "PATCH" and path.startswith(patch_prefix):
            record_id = path.removeprefix(patch_prefix)
            row = next(item for item in self.records if item["id"] == record_id)
            if not self.ignore_patch:
                row.update(payload)
            return _response(row.copy())
        raise AssertionError(f"unexpected request: {method} {url}")


class OneShotTransport:
    def __init__(self, response: HttpResponse | Exception) -> None:
        self.response = response
        self.calls = 0

    def request(self, *_args: object, **_kwargs: object) -> HttpResponse:
        self.calls += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class CloudflareDnsValidationTest(unittest.TestCase):
    def test_normalizes_zone_record_and_ip_family(self) -> None:
        self.assertEqual(normalize_zone_id("A" * 32), ZONE_ID)
        self.assertEqual(normalize_record_name("Edge.Example.COM."), "edge.example.com")
        self.assertEqual(normalize_record_name("测速.example.com"), "xn--0zwy65e.example.com")
        self.assertEqual(normalize_champion_ip("104.16.0.1"), ("104.16.0.1", "A"))
        self.assertEqual(normalize_champion_ip("2606:4700:4700::1111"), ("2606:4700:4700::1111", "AAAA"))

    def test_rejects_invalid_zone_record_and_non_public_ip(self) -> None:
        invalid_calls = (
            lambda: normalize_zone_id("not-a-zone"),
            lambda: normalize_record_name("https://edge.example.com/path"),
            lambda: normalize_record_name("104.16.0.1"),
            lambda: normalize_record_name("localhost"),
            lambda: normalize_champion_ip("127.0.0.1"),
            lambda: normalize_champion_ip("8.8.8.8"),
            lambda: normalize_champion_ip("fe80::1%3"),
        )
        for call in invalid_calls:
            with self.subTest(call=call), self.assertRaises(CloudflareDnsError):
                call()


class CloudflareDnsSyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = FakeCloudflareTransport()
        self.client = CloudflareDnsClient(
            TOKEN,
            transport=self.transport,
            timeout_seconds=7,
            max_response_bytes=32_768,
        )

    @staticmethod
    def _a_record(**overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "id": RECORD_ID,
            "name": "edge.example.com",
            "type": "A",
            "content": "104.16.0.2",
            "ttl": 300,
            "proxied": True,
            "comment": "must be preserved",
            "tags": ["owner:rr"],
        }
        value.update(overrides)
        return value

    def test_inspect_previews_explicit_create_without_writing(self) -> None:
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID,
            record_name="edge.example.com",
            champion_ip="104.16.0.1",
        )
        self.assertEqual(plan.action, "create")
        self.assertEqual(plan.record_type, "A")
        self.assertTrue(plan.requires_create_confirmation)
        self.assertFalse(any(call["method"] in {"POST", "PATCH"} for call in self.transport.calls))
        self.assertNotIn(TOKEN, json.dumps(plan.to_dict()))

    def test_create_requires_second_confirmation_then_reads_back(self) -> None:
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
        )
        with self.assertRaises(CloudflareDnsError) as raised:
            self.client.apply_sync(
                zone_id=ZONE_ID,
                record_name="edge.example.com",
                champion_ip="104.16.0.1",
                expected_fingerprint=plan.fingerprint,
            )
        self.assertEqual(raised.exception.code, "create_confirmation_required")
        self.assertFalse(any(call["method"] == "POST" for call in self.transport.calls))

        result = self.client.apply_sync(
            zone_id=ZONE_ID,
            record_name="edge.example.com",
            champion_ip="104.16.0.1",
            expected_fingerprint=plan.fingerprint,
            confirm_create=True,
        )
        self.assertEqual(result.action, "created")
        self.assertTrue(result.verified)
        post = next(call for call in self.transport.calls if call["method"] == "POST")
        self.assertEqual(post["payload"], {
            "type": "A", "name": "edge.example.com", "content": "104.16.0.1", "ttl": 1, "proxied": False,
        })
        self.assertNotIn(TOKEN, json.dumps(result.to_dict()))

    def test_unique_record_patch_changes_owned_fields_only_and_reads_back(self) -> None:
        self.transport.records = [self._a_record()]
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
        )
        self.assertEqual(plan.action, "update")
        result = self.client.apply_sync(
            zone_id=ZONE_ID,
            record_name="edge.example.com",
            champion_ip="104.16.0.1",
            expected_fingerprint=plan.fingerprint,
        )
        self.assertEqual(result.action, "updated")
        patch = next(call for call in self.transport.calls if call["method"] == "PATCH")
        self.assertEqual(patch["payload"], {"content": "104.16.0.1", "ttl": 1, "proxied": False})
        self.assertEqual(self.transport.records[0]["comment"], "must be preserved")
        self.assertEqual(self.transport.records[0]["tags"], ["owner:rr"])

    def test_ipv6_uses_aaaa(self) -> None:
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID,
            record_name="v6.example.com",
            champion_ip="2606:4700:4700::1111",
        )
        self.assertEqual(plan.record_type, "AAAA")
        self.client.apply_sync(
            zone_id=ZONE_ID,
            record_name="v6.example.com",
            champion_ip="2606:4700:4700::1111",
            expected_fingerprint=plan.fingerprint,
            confirm_create=True,
        )
        post = next(call for call in self.transport.calls if call["method"] == "POST")
        self.assertEqual(post["payload"]["type"], "AAAA")

    def test_equivalent_expanded_ipv6_is_unchanged(self) -> None:
        self.transport.records = [{
            "id": RECORD_ID,
            "name": "v6.example.com",
            "type": "AAAA",
            "content": "2606:4700:4700:0:0:0:0:1111",
            "ttl": 1,
            "proxied": False,
        }]
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID,
            record_name="v6.example.com",
            champion_ip="2606:4700:4700::1111",
        )
        self.assertEqual(plan.action, "unchanged")
        self.assertEqual(plan.previous_content, "2606:4700:4700::1111")

    def test_unchanged_record_does_not_mutate(self) -> None:
        self.transport.records = [self._a_record(content="104.16.0.1", ttl=1, proxied=False)]
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
        )
        self.assertEqual(plan.action, "unchanged")
        result = self.client.apply_sync(
            zone_id=ZONE_ID,
            record_name="edge.example.com",
            champion_ip="104.16.0.1",
            expected_fingerprint=plan.fingerprint,
        )
        self.assertEqual(result.action, "unchanged")
        self.assertFalse(any(call["method"] in {"POST", "PATCH"} for call in self.transport.calls))

    def test_cname_conflict_is_clear_and_never_deleted(self) -> None:
        self.transport.records = [{
            "id": RECORD_ID,
            "name": "edge.example.com",
            "type": "CNAME",
            "content": "origin.example.net",
            "ttl": 1,
            "proxied": False,
        }]
        with self.assertRaises(CloudflareDnsError) as raised:
            self.client.inspect_sync(
                zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
            )
        self.assertEqual(raised.exception.code, "cname_conflict")
        self.assertIn("不会自动删除", str(raised.exception))
        self.assertFalse(any(call["method"] in {"DELETE", "POST", "PATCH"} for call in self.transport.calls))

    def test_ns_conflict_is_clear_and_never_deleted(self) -> None:
        self.transport.records = [{
            "id": RECORD_ID,
            "name": "edge.example.com",
            "type": "NS",
            "content": "ns1.example.net",
            "ttl": 300,
            "proxied": False,
        }]
        with self.assertRaises(CloudflareDnsError) as raised:
            self.client.inspect_sync(
                zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
            )
        self.assertEqual(raised.exception.code, "ns_conflict")
        self.assertIn("不会自动删除", str(raised.exception))
        self.assertFalse(any(call["method"] in {"DELETE", "POST", "PATCH"} for call in self.transport.calls))

    def test_multiple_same_type_records_are_refused_to_preserve_round_robin(self) -> None:
        self.transport.records = [
            self._a_record(id="b" * 32),
            self._a_record(id="c" * 32, content="104.16.0.3"),
        ]
        with self.assertRaises(CloudflareDnsError) as raised:
            self.client.inspect_sync(
                zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
            )
        self.assertEqual(raised.exception.code, "multiple_records")
        self.assertIn("轮询", str(raised.exception))
        self.assertFalse(any(call["method"] in {"POST", "PATCH"} for call in self.transport.calls))

    def test_plan_fingerprint_detects_toctou_change(self) -> None:
        self.transport.records = [self._a_record()]
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
        )
        self.transport.records[0]["content"] = "104.16.0.4"
        with self.assertRaises(CloudflareDnsError) as raised:
            self.client.apply_sync(
                zone_id=ZONE_ID,
                record_name="edge.example.com",
                champion_ip="104.16.0.1",
                expected_fingerprint=plan.fingerprint,
            )
        self.assertEqual(raised.exception.code, "plan_changed")
        self.assertFalse(any(call["method"] == "PATCH" for call in self.transport.calls))

    def test_write_is_verified_by_readback(self) -> None:
        self.transport.records = [self._a_record()]
        plan = self.client.inspect_sync(
            zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
        )
        self.transport.ignore_patch = True
        with self.assertRaises(CloudflareDnsError) as raised:
            self.client.apply_sync(
                zone_id=ZONE_ID,
                record_name="edge.example.com",
                champion_ip="104.16.0.1",
                expected_fingerprint=plan.fingerprint,
            )
        self.assertEqual(raised.exception.code, "verification_failed")

    def test_zone_id_can_be_discovered_from_full_record_name(self) -> None:
        plan = self.client.inspect_sync(
            record_name="edge.sub.example.com", champion_ip="104.16.0.1"
        )
        self.assertEqual(plan.zone_id, ZONE_ID)
        self.assertEqual(plan.zone_name, "example.com")
        zone_queries = [urllib.parse.parse_qs(urllib.parse.urlsplit(call["url"]).query)["name"][0]
                        for call in self.transport.calls if urllib.parse.urlsplit(call["url"]).path.endswith("/zones")]
        self.assertEqual(zone_queries, ["edge.sub.example.com", "sub.example.com", "example.com"])

    def test_transport_receives_bounded_timeout_and_token_only_in_header(self) -> None:
        self.client.inspect_sync(
            zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1"
        )
        for call in self.transport.calls:
            self.assertEqual(call["timeout_seconds"], 7)
            self.assertEqual(call["max_response_bytes"], 32_768)
            self.assertEqual(call["headers"]["Authorization"], f"Bearer {TOKEN}")
            self.assertNotIn(TOKEN, call["url"])
            self.assertNotIn(TOKEN, json.dumps(call["payload"]))
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(call["url"]).query)
            if "/dns_records" in urllib.parse.urlsplit(call["url"]).path and call["method"] == "GET":
                self.assertIn("name.exact", query)
                self.assertEqual(query["match"], ["all"])


class CloudflareDnsFailureTest(unittest.TestCase):
    def test_default_transport_disables_environment_proxies(self) -> None:
        with patch("cfopt.cloudflare_dns.urllib.request.build_opener") as build_opener:
            UrlLibTransport()
        proxy_handlers = [
            handler for handler in build_opener.call_args.args
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})

    def test_default_transport_does_not_follow_redirect_with_authorization(self) -> None:
        calls: list[tuple[str, str]] = []

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                calls.append((self.path, self.headers.get("Authorization", "")))
                if self.path == "/first":
                    self.send_response(302)
                    self.send_header("Location", "/must-not-be-requested")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")

        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            response = UrlLibTransport().request(
                "GET",
                f"http://127.0.0.1:{server.server_address[1]}/first",
                {"Authorization": f"Bearer {TOKEN}"},
                None,
                timeout_seconds=2,
                max_response_bytes=2048,
            )
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
        self.assertEqual(response.status, 302)
        self.assertEqual(calls, [("/first", f"Bearer {TOKEN}")])

    def test_auth_failure_requests_dns_pause_without_leaking_token(self) -> None:
        transport = OneShotTransport(HttpResponse(403, json.dumps({"error": TOKEN}).encode()))
        client = CloudflareDnsClient(TOKEN, transport=transport)
        with self.assertRaises(CloudflareDnsError) as raised:
            client.inspect_sync(zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1")
        error = raised.exception
        self.assertEqual(error.code, "auth_failed")
        self.assertTrue(error.pause_dns_automation)
        self.assertFalse(error.transient)
        self.assertNotIn(TOKEN, str(error))
        self.assertNotIn(TOKEN, json.dumps(error.to_dict()))
        self.assertEqual(transport.calls, 1)

    def test_rate_limit_is_not_retried(self) -> None:
        transport = OneShotTransport(HttpResponse(429, b"{}"))
        client = CloudflareDnsClient(TOKEN, transport=transport)
        with self.assertRaises(CloudflareDnsError) as raised:
            client.inspect_sync(zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1")
        self.assertEqual(raised.exception.code, "rate_limited")
        self.assertTrue(raised.exception.transient)
        self.assertEqual(transport.calls, 1)

    def test_transport_exception_text_and_oversized_body_are_sanitized(self) -> None:
        transport = OneShotTransport(TimeoutError(TOKEN))
        client = CloudflareDnsClient(TOKEN, transport=transport)
        with self.assertRaises(CloudflareDnsError) as raised:
            client.inspect_sync(zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1")
        self.assertNotIn(TOKEN, str(raised.exception))
        self.assertEqual(transport.calls, 1)

        oversized = OneShotTransport(HttpResponse(200, b"x" * 2049))
        client = CloudflareDnsClient(TOKEN, transport=oversized, max_response_bytes=2048)
        with self.assertRaises(CloudflareDnsError) as raised:
            client.inspect_sync(zone_id=ZONE_ID, record_name="edge.example.com", champion_ip="104.16.0.1")
        self.assertEqual(raised.exception.code, "response_too_large")


if __name__ == "__main__":
    unittest.main()
