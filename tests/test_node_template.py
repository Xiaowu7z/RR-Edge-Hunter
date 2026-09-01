import base64
import json
import unittest

from cfopt.node_template import parse_node_link, parse_node_profile


class NodeTemplateTest(unittest.TestCase):
    def test_vmess_public_route_summary_does_not_expose_uuid(self):
        encoded = base64.b64encode(json.dumps({
            "add": "104.16.0.1", "port": "2053", "id": "12345678-abcd-abcd-abcd-123456789abc", "net": "ws",
            "host": "route.trycloudflare.com", "path": "/argo?ed=2048", "tls": "tls",
            "sni": "route.trycloudflare.com",
        }).encode()).decode().rstrip("=")
        parsed = parse_node_link(f"vmess://{encoded}")
        self.assertEqual((parsed.protocol, parsed.port, parsed.sni, parsed.ws_path), ("VMess", 2053, "route.trycloudflare.com", "/argo?ed=2048"))
        self.assertNotIn("12345678", repr(parsed))

    def test_vless_preserves_distinct_sni_and_host(self):
        parsed = parse_node_link("vless://12345678-abcd-abcd-abcd-123456789abc@104.17.0.1:443?type=ws&security=tls&sni=tls.example.com&host=ws.example.com&path=%2Fvless%3Fed%3D2048#demo")
        self.assertEqual((parsed.sni, parsed.host_header, parsed.ws_path), ("tls.example.com", "ws.example.com", "/vless?ed=2048"))

    def test_rejects_non_ws_reality_and_bad_port(self):
        with self.assertRaisesRegex(ValueError, "WebSocket"):
            parse_node_link("vless://12345678-abcd-abcd-abcd-123456789abc@example.com:443?type=tcp&security=tls")
        with self.assertRaisesRegex(ValueError, "TLS"):
            parse_node_link("vless://12345678-abcd-abcd-abcd-123456789abc@example.com:443?type=ws&security=reality&host=example.com")
        with self.assertRaisesRegex(ValueError, "端口"):
            parse_node_link("vless://12345678-abcd-abcd-abcd-123456789abc@example.com:1234?type=ws&security=tls&host=example.com")

    def test_profile_keeps_credentials_private_and_replaces_only_address(self):
        profile = parse_node_profile(
            "vless://12345678-abcd-abcd-abcd-123456789abc@origin.example:8443"
            "?type=ws&security=tls&sni=tls.example.com&host=ws.example.com&path=%2Fargo&fp=chrome"
        )
        self.assertNotIn("12345678", repr(profile))
        outbound = profile.outbound_for("104.18.1.2")
        endpoint = outbound["settings"]["vnext"][0]
        self.assertEqual(endpoint["address"], "104.18.1.2")
        self.assertEqual(endpoint["port"], 8443)
        self.assertEqual(endpoint["users"][0]["id"], "12345678-abcd-abcd-abcd-123456789abc")
        self.assertEqual(outbound["streamSettings"]["tlsSettings"]["serverName"], "tls.example.com")
        self.assertEqual(outbound["streamSettings"]["wsSettings"]["headers"]["Host"], "ws.example.com")


if __name__ == "__main__":
    unittest.main()
