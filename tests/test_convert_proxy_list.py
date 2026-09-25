import base64
import contextlib
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote, urlencode

from scripts.convert_proxy_list import (
    ConversionError,
    main,
    parse_proxy_list,
    update_template,
    write_output,
)


TEST_UUID = "00000000-0000-4000-8000-000000000001"
TEST_UUID_2 = "00000000-0000-4000-8000-000000000002"


def make_ss_uri(tag="测试 SS", server="ss.example.test", port=1443):
    credentials = base64.b64encode(b"chacha20-ietf-poly1305:test-password").decode("ascii")
    return f"ss://{credentials}@{server}:{port}#{quote(tag)}"


def make_ssr_uri(tag="测试 SSR", server="ssr.example.test", port=1444, **overrides):
    parts = {
        "protocol": "auth_aes128_md5",
        "method": "aes-256-cfb",
        "obfs": "tls1.2_ticket_auth",
    }
    parts.update(overrides)
    password = base64.urlsafe_b64encode(b"test-password").decode("ascii").rstrip("=")
    body = ":".join([
        server,
        str(port),
        parts["protocol"],
        parts["method"],
        parts["obfs"],
        password,
    ])
    query = urlencode({
        "remarks": base64.urlsafe_b64encode(tag.encode("utf-8")).decode("ascii").rstrip("="),
        "protoparam": base64.urlsafe_b64encode(b"1:test-user").decode("ascii").rstrip("="),
        "obfsparam": base64.urlsafe_b64encode(b"obfs.example.test").decode("ascii").rstrip("="),
    })
    payload = base64.urlsafe_b64encode(f"{body}/?{query}".encode("utf-8")).decode("ascii").rstrip("=")
    return f"ssr://{payload}"


def make_vless_uri(tag="测试 VLESS", **overrides):
    params = {
        "encryption": "none",
        "security": "tls",
        "sni": "sni.example.test",
        "type": "ws",
        "path": "/unit-test",
        "host": "ws.example.test",
        "fp": "chrome",
    }
    params.update(overrides)
    query = urlencode({key: value for key, value in params.items() if value != ""})
    return f"vless://{TEST_UUID}@vless.example.test:443?{query}#{quote(tag)}"


def make_trojan_uri(tag="测试 Trojan", **overrides):
    params = {
        "security": "tls",
        "sni": "sni.example.test",
        "type": "tcp",
    }
    params.update(overrides)
    query = urlencode({key: value for key, value in params.items() if value != ""})
    return f"trojan://test-password@trojan.example.test:443?{query}#{quote(tag)}"


def make_hysteria2_uri(tag="测试 Hysteria2", **overrides):
    params = {
        "security": "tls",
        "sni": "sni.example.test",
    }
    params.update(overrides)
    query = urlencode({key: value for key, value in params.items() if value != ""})
    return f"hysteria2://test-password@hy2.example.test:443?{query}#{quote(tag)}"


def make_tuic_uri(tag="测试 TUIC", **overrides):
    params = {
        "congestion_control": "bbr",
    }
    params.update(overrides)
    query = urlencode({key: value for key, value in params.items() if value != ""})
    suffix = f"?{query}" if query else ""
    return f"tuic://{TEST_UUID_2}:test-password@tuic.example.test:443{suffix}#{quote(tag)}"


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


class ExtendedProtocolTests(unittest.TestCase):
    def test_parses_shadowsocksr_uri(self):
        node = parse_proxy_list(make_ssr_uri())[0]

        self.assertEqual(node["type"], "shadowsocksr")
        self.assertEqual(node["tag"], "测试 SSR")
        self.assertEqual(node["server"], "ssr.example.test")
        self.assertEqual(node["server_port"], 1444)
        self.assertEqual(node["method"], "aes-256-cfb")
        self.assertEqual(node["password"], "test-password")
        self.assertEqual(node["protocol"], "auth_aes128_md5")
        self.assertEqual(node["obfs"], "tls1.2_ticket_auth")
        self.assertEqual(node["protocol_param"], "1:test-user")
        self.assertEqual(node["obfs_param"], "obfs.example.test")

    def test_parses_shadowsocks_plugin(self):
        node = parse_proxy_list(
            "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.2.3.4:8388"
            "?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#plugin"
        )[0]

        self.assertEqual(node["plugin"], "obfs-local")
        self.assertEqual(node["plugin_opts"], "obfs=http;obfs-host=bing.com")
        self.assertNotIn("tls", node)

    def test_parses_vless_reality_and_transport(self):
        node = parse_proxy_list(make_vless_uri(
            security="reality",
            pbk="test-public-key",
            sid="abcd",
            fp="firefox",
            flow="xtls-rprx-vision",
            type="grpc",
            serviceName="unit-test",
        ))[0]

        self.assertEqual(node["type"], "vless")
        self.assertEqual(node["uuid"], TEST_UUID)
        self.assertEqual(node["flow"], "xtls-rprx-vision")
        self.assertEqual(node["tls"]["reality"], {"enabled": True, "public_key": "test-public-key", "short_id": "abcd"})
        self.assertTrue(node["tls"]["utls"]["enabled"])
        self.assertEqual(node["tls"]["utls"]["fingerprint"], "firefox")
        self.assertEqual(node["transport"], {"type": "grpc", "service_name": "unit-test"})

    def test_parses_vless_plain_with_packet_encoding(self):
        node = parse_proxy_list(make_vless_uri(
            security="",
            sni="",
            type="tcp",
            path="",
            host="",
            fp="",
            packetEncoding="xudp",
        ))[0]

        self.assertNotIn("tls", node)
        self.assertNotIn("transport", node)
        self.assertEqual(node["packet_encoding"], "xudp")

    def test_vless_rejects_missing_reality_public_key_and_bad_uuid(self):
        with self.assertRaisesRegex(ConversionError, "公钥"):
            parse_proxy_list(make_vless_uri(security="reality", fp="chrome"))
        with self.assertRaisesRegex(ConversionError, "UUID"):
            parse_proxy_list(f"vless://not-a-uuid@vless.example.test:443#bad")

    def test_implicit_tls_when_security_param_is_absent(self):
        trojan = parse_proxy_list("trojan://secret@trojan.example.test:443#no-security")[0]
        hysteria2 = parse_proxy_list("hysteria2://secret@hy2.example.test:443#no-security")[0]
        tuic = parse_proxy_list(f"tuic://{TEST_UUID_2}:secret@tuic.example.test:443#no-security")[0]

        self.assertEqual(trojan["tls"], {"enabled": True})
        self.assertEqual(hysteria2["tls"], {"enabled": True})
        self.assertEqual(tuic["tls"], {"enabled": True, "alpn": ["h3"]})

    def test_tuic_requires_password_and_tls(self):
        with self.assertRaisesRegex(ConversionError, "缺少密码"):
            parse_proxy_list(f"tuic://{TEST_UUID_2}@tuic.example.test:443#no-password")
        with self.assertRaisesRegex(ConversionError, "必须启用 TLS"):
            parse_proxy_list(make_trojan_uri(security="none"))

    def test_parses_trojan_with_websocket(self):
        node = parse_proxy_list(make_trojan_uri(
            type="ws",
            path="/trojan",
            host="ws.example.test",
        ))[0]

        self.assertEqual(node["type"], "trojan")
        self.assertEqual(node["password"], "test-password")
        self.assertEqual(node["tls"], {"enabled": True, "server_name": "sni.example.test"})
        self.assertEqual(node["transport"], {
            "type": "ws",
            "path": "/trojan",
            "headers": {"Host": "ws.example.test"},
        })

    def test_parses_hysteria2_with_obfs_and_bandwidth(self):
        node = parse_proxy_list(make_hysteria2_uri(
            obfs="salamander",
            **{"obfs-password": "obfs-secret"},
            upmbps="50",
            downmbps="100",
            insecure="1",
        ))[0]

        self.assertEqual(node["type"], "hysteria2")
        self.assertEqual(node["password"], "test-password")
        self.assertEqual(node["up_mbps"], 50)
        self.assertEqual(node["down_mbps"], 100)
        self.assertEqual(node["tls"], {"enabled": True, "server_name": "sni.example.test", "insecure": True})
        self.assertEqual(node["obfs"], {"type": "salamander", "password": "obfs-secret"})

    def test_hysteria2_requires_tls_and_obfs_password(self):
        with self.assertRaisesRegex(ConversionError, "密码"):
            parse_proxy_list(make_hysteria2_uri(obfs="salamander"))
        with self.assertRaisesRegex(ConversionError, "缺少密码"):
            parse_proxy_list("hysteria2://@hy2.example.test:443#empty")

    def test_parses_tuic_with_default_alpn(self):
        node = parse_proxy_list(make_tuic_uri())[0]

        self.assertEqual(node["type"], "tuic")
        self.assertEqual(node["uuid"], TEST_UUID_2)
        self.assertEqual(node["password"], "test-password")
        self.assertEqual(node["congestion_control"], "bbr")
        self.assertEqual(node["tls"], {"enabled": True, "alpn": ["h3"]})

    def test_supports_numbered_lines_for_new_protocols(self):
        nodes = parse_proxy_list(
            f"1 {make_ssr_uri()}\n2 {make_vless_uri()}\n3 {make_trojan_uri()}\n"
            f"4 {make_hysteria2_uri()}\n5 {make_tuic_uri()}\n"
        )

        self.assertEqual(
            [node["type"] for node in nodes],
            ["shadowsocksr", "vless", "trojan", "hysteria2", "tuic"],
        )

    def test_rejects_unsupported_scheme_and_invalid_options(self):
        with self.assertRaisesRegex(ConversionError, "仅支持"):
            parse_proxy_list("socks4://1.2.3.4:1080#socks4")
        with self.assertRaisesRegex(ConversionError, "拥塞控制"):
            parse_proxy_list(make_tuic_uri(congestion_control="vegas"))
        with self.assertRaisesRegex(ConversionError, "传输类型"):
            parse_proxy_list(make_vless_uri(type="kcp"))
        with self.assertRaisesRegex(ConversionError, "SSR 配置"):
            parse_proxy_list("ssr://" + base64.urlsafe_b64encode(b"only-one-field").decode("ascii"))


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


class SubscriptionTests(unittest.TestCase):
    def test_decodes_base64_subscription(self):
        payload = f"{make_vless_uri()}\n{make_hysteria2_uri()}\n"
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")

        nodes = parse_proxy_list(encoded)

        self.assertEqual([node["type"] for node in nodes], ["vless", "hysteria2"])

    def test_decodes_subscription_with_padding_and_newlines(self):
        payload = f"{make_vless_uri()}\n{make_trojan_uri()}\n"
        encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
        wrapped = "\n".join(encoded[index : index + 60] for index in range(0, len(encoded), 60))

        nodes = parse_proxy_list(wrapped)

        self.assertEqual(len(nodes), 2)

    def test_rejects_content_that_is_neither_list_nor_subscription(self):
        with self.assertRaisesRegex(ConversionError, "既不是代理列表也不是"):
            parse_proxy_list("这不是一个代理列表，也不是订阅")

    def test_plain_list_is_not_mistaken_for_subscription(self):
        nodes = parse_proxy_list(f"# 注释\n{make_ss_uri()}\n")

        self.assertEqual(len(nodes), 1)


class ExcludeTagTests(unittest.TestCase):
    def _run(self, extra_args, source_text, template):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.conf"
            output = root / "out.json"
            template_path = root / "template.json"
            source.write_text(source_text, encoding="utf-8")
            template_path.write_text(json.dumps(template), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                main([
                    "--source", str(source),
                    "--template", str(template_path),
                    "--output", str(output),
                    *extra_args,
                ])
            return json.loads(output.read_text(encoding="utf-8"))

    def test_excludes_matching_tags(self):
        source = f"{make_vless_uri(tag='剩余流量：1024 GB')}\n{make_vless_uri(tag='🇯🇵 日本 01')}\n"
        converted = self._run(["--exclude-tag", "剩余流量|套餐到期"], source, make_template())

        tags = converted["outbounds"][0]["outbounds"]
        self.assertEqual(tags, ["🇯🇵 日本 01"])

    def test_rejects_pattern_that_removes_everything(self):
        source = f"{make_vless_uri(tag='剩余流量：1024 GB')}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "source.conf"
            template_path = root / "template.json"
            source_path.write_text(source, encoding="utf-8")
            template_path.write_text(json.dumps(make_template()), encoding="utf-8")

            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([
                    "--source", str(source_path),
                    "--template", str(template_path),
                    "--output", str(root / "out.json"),
                    "--exclude-tag", ".",
                ])


class ProxyFallbackProtocolTests(unittest.TestCase):
    def test_parses_socks5_with_credentials(self):
        node = parse_proxy_list("socks5://user:secret@1.2.3.4:1080#socks")[0]

        self.assertEqual(node, {
            "type": "socks",
            "tag": "socks",
            "server": "1.2.3.4",
            "server_port": 1080,
            "version": "5",
            "username": "user",
            "password": "secret",
        })

    def test_parses_socks_without_credentials(self):
        node = parse_proxy_list("socks://1.2.3.4:1080#anonymous")[0]

        self.assertEqual(node["type"], "socks")
        self.assertNotIn("username", node)
        self.assertNotIn("password", node)

    def test_parses_http_and_https_proxies(self):
        http = parse_proxy_list("http://user:secret@1.2.3.4:8080#http-proxy")[0]
        https = parse_proxy_list("https://1.2.3.4:8443#https-proxy")[0]

        self.assertEqual(http["type"], "http")
        self.assertEqual(http["username"], "user")
        self.assertEqual(http["password"], "secret")
        self.assertEqual(https["type"], "http")
        self.assertEqual(https["tag"], "https-proxy")


if __name__ == "__main__":
    unittest.main()
