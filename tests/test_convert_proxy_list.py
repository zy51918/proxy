import base64
import contextlib
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

from scripts.convert_proxy_list import (
    ConversionError,
    main,
    parse_proxy_list,
    update_template,
    write_output,
)


TEST_UUID = "00000000-0000-4000-8000-000000000001"


def make_ss_uri(tag="测试 SS", server="ss.example.test", port=1443):
    credentials = base64.b64encode(b"chacha20-ietf-poly1305:test-password").decode("ascii")
    return f"ss://{credentials}@{server}:{port}#{quote(tag)}"


def make_vmess_uri(tag="测试 VMess", **overrides):
    config = {
        "add": "vmess.example.test",
        "port": "443",
        "id": TEST_UUID,
        "aid": 0,
        "scy": "auto",
        "net": "ws",
        "path": "/unit-test",
        "host": "ws.example.test",
        "tls": "tls",
        "sni": "sni.example.test",
        "skip-cert-verify": True,
        "ps": tag,
    }
    config.update(overrides)
    payload = base64.urlsafe_b64encode(json.dumps(config).encode("utf-8")).decode("ascii").rstrip("=")
    return f"vmess://{payload}"


def make_template():
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [{"tag": "dns-local", "address": "local"}]},
        "inbounds": [{"type": "mixed", "tag": "local-in"}],
        "route": {
            "rules": [{"outbound": "🐸 手动选择"}],
            "final": "♻️ 自动选择",
        },
        "experimental": {"cache_file": {"enabled": False}},
        "custom_extension": {"keep": ["unknown-config-field"]},
        "outbounds": [
            {
                "type": "urltest",
                "tag": "♻️ 自动选择",
                "outbounds": ["old-ss", "old-vmess"],
                "interval": "10m0s",
                "tolerance": 100,
            },
            {
                "type": "selector",
                "tag": "🐸 手动选择",
                "outbounds": ["old-ss", "old-vmess"],
                "default": "old-ss",
            },
            {"type": "shadowsocks", "tag": "old-ss", "server": "old.example.test"},
            {"type": "vless", "tag": "old-vmess", "server": "old.example.test"},
            {"type": "shadowsocks", "tag": "unrelated-ss", "server": "other.example.test"},
            {"type": "direct", "tag": "直连"},
        ],
    }


class ParseProxyListTests(unittest.TestCase):
    def test_parses_shadowsocks_uri(self):
        node = parse_proxy_list(make_ss_uri())[0]

        self.assertEqual(node["type"], "shadowsocks")
        self.assertEqual(node["tag"], "测试 SS")
        self.assertEqual(node["server"], "ss.example.test")
        self.assertEqual(node["server_port"], 1443)
        self.assertEqual(node["method"], "chacha20-ietf-poly1305")
        self.assertEqual(node["password"], "test-password")

    def test_parses_plain_credentials_and_ipv6_server(self):
        node = parse_proxy_list("ss://aes-128-gcm:test%3Apassword@[2001:db8::1]:1443#IPv6%20node")[0]

        self.assertEqual(node["server"], "2001:db8::1")
        self.assertEqual(node["server_port"], 1443)
        self.assertEqual(node["method"], "aes-128-gcm")
        self.assertEqual(node["password"], "test:password")
        self.assertEqual(node["tag"], "IPv6 node")

    def test_parses_vmess_tls_and_websocket(self):
        node = parse_proxy_list(make_vmess_uri())[0]

        self.assertEqual(node["type"], "vmess")
        self.assertEqual(node["tag"], "测试 VMess")
        self.assertEqual(node["server_port"], 443)
        self.assertEqual(node["uuid"], TEST_UUID)
        self.assertEqual(node["tls"], {
            "enabled": True,
            "server_name": "sni.example.test",
            "insecure": True,
        })
        self.assertEqual(node["transport"], {
            "type": "ws",
            "path": "/unit-test",
            "headers": {"Host": "ws.example.test"},
        })

    def test_supports_numbered_lines_and_default_tags(self):
        vmess = make_vmess_uri(ps="", net="tcp", tls="")
        nodes = parse_proxy_list(f"# 节点列表\n1 {make_ss_uri(tag='')}\n2 {vmess}\n")

        self.assertEqual(nodes[0]["tag"], "shadowsocks-ss.example.test:1443")
        self.assertEqual(nodes[1]["tag"], "vmess-vmess.example.test:443")
        self.assertNotIn("tls", nodes[1])
        self.assertNotIn("transport", nodes[1])

    def test_rejects_duplicate_tags(self):
        text = f"{make_ss_uri(tag='duplicate')}\n{make_ss_uri(tag='duplicate', port=1444)}"

        with self.assertRaisesRegex(ConversionError, "tag 重复"):
            parse_proxy_list(text)

    def test_rejects_invalid_input_without_echoing_uri(self):
        bad_uri = "vmess://private-test-value"

        with self.assertRaises(ConversionError) as raised:
            parse_proxy_list(bad_uri)

        self.assertNotIn(bad_uri, str(raised.exception))
        self.assertNotIn("private-test-value", str(raised.exception))

    def test_rejects_invalid_port(self):
        with self.assertRaisesRegex(ConversionError, "端口"):
            parse_proxy_list(make_ss_uri(port=0))

    def test_rejects_fractional_vmess_port_and_unsupported_transport(self):
        with self.assertRaisesRegex(ConversionError, "整数"):
            parse_proxy_list(make_vmess_uri(port=443.5))
        with self.assertRaisesRegex(ConversionError, "传输类型"):
            parse_proxy_list(make_vmess_uri(net="grpc"))


class TemplateTests(unittest.TestCase):
    def test_updates_groups_and_preserves_full_configuration(self):
        nodes = parse_proxy_list(f"{make_ss_uri()}\n{make_vmess_uri()}")
        template = make_template()
        original = deepcopy(template)
        result = update_template(template, nodes)
        outbounds = result["outbounds"]
        by_tag = {outbound["tag"]: outbound for outbound in outbounds}
        expected_tags = [node["tag"] for node in nodes]

        self.assertEqual(by_tag["♻️ 自动选择"]["outbounds"], expected_tags)
        self.assertEqual(by_tag["♻️ 自动选择"]["interval"], "10m0s")
        self.assertEqual(by_tag["🐸 手动选择"]["outbounds"], expected_tags)
        self.assertEqual(by_tag["🐸 手动选择"]["default"], expected_tags[0])
        self.assertIn("直连", by_tag)
        self.assertIn("unrelated-ss", by_tag)
        self.assertNotIn("old-ss", by_tag)
        self.assertNotIn("old-vmess", by_tag)
        self.assertEqual([item["type"] for item in outbounds[-2:]], ["shadowsocks", "vmess"])
        for field in ("log", "dns", "inbounds", "route", "experimental", "custom_extension"):
            self.assertEqual(result[field], original[field])
        self.assertEqual(template, original)

    def test_preserves_old_node_referenced_by_another_group(self):
        template = make_template()
        template["outbounds"].insert(
            -1,
            {"type": "selector", "tag": "其他选择", "outbounds": ["old-vmess"]},
        )
        nodes = parse_proxy_list(f"{make_ss_uri()}\n{make_vmess_uri()}")

        result = update_template(template, nodes)
        by_tag = {outbound["tag"]: outbound for outbound in result["outbounds"]}

        self.assertIn("old-vmess", by_tag)
        self.assertEqual(by_tag["其他选择"]["outbounds"], ["old-vmess"])
        self.assertEqual(by_tag["♻️ 自动选择"]["outbounds"], [node["tag"] for node in nodes])

    def test_requires_each_selector_once(self):
        with self.assertRaisesRegex(ConversionError, "自动选择"):
            update_template({"outbounds": []}, parse_proxy_list(make_ss_uri()))


class OutputTests(unittest.TestCase):
    def test_cli_requires_a_configuration_template(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main([])

        self.assertEqual(raised.exception.code, 2)

    def test_cli_refuses_to_overwrite_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.conf"
            template = root / "template.json"
            source_contents = make_ss_uri()
            source.write_text(source_contents, encoding="utf-8")
            template.write_text(json.dumps(make_template()), encoding="utf-8")

            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([
                    "--source", str(source),
                    "--template", str(template),
                    "--output", str(source),
                    "--force",
                ])

            self.assertEqual(source.read_text(encoding="utf-8"), source_contents)

    def test_cli_converts_source_and_template(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.conf"
            template = root / "template.json"
            output = root / "result.json"
            source.write_text(f"{make_ss_uri()}\n{make_vmess_uri()}\n", encoding="utf-8")
            template_config = make_template()
            template.write_text(json.dumps(template_config), encoding="utf-8")
            stdout = io.StringIO()

            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--input", str(source),
                    "--template", str(template),
                    "--output", str(output),
                ])

            converted = json.loads(output.read_text(encoding="utf-8"))
            outbound_by_tag = {outbound["tag"]: outbound for outbound in converted["outbounds"]}
            selected_tags = converted["outbounds"][0]["outbounds"]
            nodes = [outbound_by_tag[tag] for tag in selected_tags]
            self.assertEqual(result, 0)
            self.assertEqual(len(nodes), 2)
            self.assertEqual(converted["outbounds"][1]["outbounds"], selected_tags)
            for field in ("log", "dns", "inbounds", "route", "experimental", "custom_extension"):
                self.assertEqual(converted[field], template_config[field])
            self.assertNotIn("test-password", stdout.getvalue())

    def test_refuses_existing_output_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.json"
            output.write_text("original", encoding="utf-8")

            with self.assertRaisesRegex(ConversionError, "--force"):
                write_output(output, "replacement", force=False)

            self.assertEqual(output.read_text(encoding="utf-8"), "original")

    def test_force_replaces_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.json"
            output.write_text("original", encoding="utf-8")

            write_output(output, "replacement", force=True)

            self.assertEqual(output.read_text(encoding="utf-8"), "replacement")


if __name__ == "__main__":
    unittest.main()
