from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
import uuid
from collections import Counter
from copy import deepcopy
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "sing-box" / "config" / "proxy-list.example.conf"
DEFAULT_OUTPUT = ROOT / "sing-box" / "config" / "proxy-list.generated.json"
AUTO_TAG = "♻️ 自动选择"
MANUAL_TAG = "🐸 手动选择"
GROUP_TYPES = {AUTO_TAG: "urltest", MANUAL_TAG: "selector"}
NON_NODE_TYPES = {"block", "direct", "dns", "loadbalance", "loopback", "reject", "selector", "urltest"}

PROTOCOL_LABELS = {
    "ss": "SS",
    "ssr": "SSR",
    "vmess": "VMess",
    "vless": "VLESS",
    "trojan": "Trojan",
    "hysteria2": "Hysteria2",
    "hy2": "Hysteria2",
    "tuic": "TUIC",
    "socks": "SOCKS",
    "socks5": "SOCKS5",
    "http": "HTTP",
    "https": "HTTPS",
}
SUPPORTED_SUMMARY = "、".join(["SS", "SSR", "VMess", "VLESS", "Trojan", "Hysteria2", "TUIC", "SOCKS5", "HTTP"])

TLS_MODES = {"", "none", "tls", "xtls", "reality"}
VLESS_FLOWS = {"", "xtls-rprx-vision"}
CONGESTION_CONTROLS = {"cubic", "new_reno", "bbr"}
UDP_RELAY_MODES = {"native", "quic"}
PACKET_ENCODINGS = {"", "packetaddr", "xudp"}
TRANSPORT_ALIASES = {"": "tcp", "tcp": "tcp", "none": "tcp", "raw": "tcp"}
SUBSCRIPTION_MIN_LENGTH = 32
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/=_-]+")


class ConversionError(Exception):
    """表示输入代理列表或 sing-box 模板不符合预期。"""


def _decode_base64(value: str, line_number: int, field: str) -> bytes:
    try:
        encoded = unquote(value).encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ConversionError(f"第 {line_number} 行：{field} 不是有效的 Base64") from None


def _decode_base64_text(value: str, line_number: int, field: str) -> str:
    decoded = _decode_base64(value, line_number, field)
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        raise ConversionError(f"第 {line_number} 行：{field} 不是有效文本") from None


def _integer(value: object, line_number: int, field: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ConversionError(f"第 {line_number} 行：字段 {field} 必须是整数")
    if isinstance(value, str):
        value = value.strip()
        if not value.isdecimal():
            raise ConversionError(f"第 {line_number} 行：字段 {field} 必须是整数")
    elif not isinstance(value, int):
        raise ConversionError(f"第 {line_number} 行：字段 {field} 必须是整数")
    try:
        result = int(value)
    except (ValueError, OverflowError):
        raise ConversionError(f"第 {line_number} 行：字段 {field} 必须是整数") from None
    if result < minimum or (maximum is not None and result > maximum):
        if field == "port":
            raise ConversionError(f"第 {line_number} 行：端口必须是 1 到 65535 的整数")
        raise ConversionError(f"第 {line_number} 行：字段 {field} 超出允许范围")
    return result


def _port(value: object, line_number: int) -> int:
    return _integer(value, line_number, "port", 1, 65535)


def _tag(value: object, fallback: str, line_number: int) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        value = fallback
    if not isinstance(value, str):
        raise ConversionError(f"第 {line_number} 行：节点 tag 必须是字符串")
    result = " ".join(value.split())
    if not result:
        raise ConversionError(f"第 {line_number} 行：节点 tag 不能为空")
    return result


def _string_field(config: dict, name: str, line_number: int, *, required: bool = False) -> str:
    value = config.get(name)
    if not isinstance(value, str) or (required and not value.strip()):
        raise ConversionError(f"第 {line_number} 行：字段 {name} 必须是非空字符串")
    return value.strip()


def _boolean(value: object, line_number: int, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0", ""}:
            return False
    raise ConversionError(f"第 {line_number} 行：字段 {field} 必须是布尔值")


def _query_params(parsed, line_number: int) -> dict[str, str]:
    try:
        return dict(parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False))
    except ValueError:
        raise ConversionError(f"第 {line_number} 行：URI 查询参数格式无效") from None


def _query_value(params: dict[str, str], *names: str) -> str | None:
    for name in names:
        value = params.get(name)
        if value:
            return value
    return None


def _query_bool(params: dict[str, str], line_number: int, *names: str) -> bool:
    value = _query_value(params, *names)
    if value is None:
        return False
    return _boolean(value, line_number, names[0])


def _split_link(uri: str, scheme: str, line_number: int):
    label = PROTOCOL_LABELS[scheme]
    try:
        parsed = urlsplit(uri)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ConversionError(f"第 {line_number} 行：{label} URI 的服务器地址或端口无效") from None
    if not host or port is None:
        raise ConversionError(f"第 {line_number} 行：{label} URI 缺少服务器地址或端口")
    return parsed, host, _port(port, line_number)


def _credentials(parsed, line_number: int, label: str) -> tuple[str, str | None]:
    username = parsed.username
    if not username:
        raise ConversionError(f"第 {line_number} 行：{label} URI 缺少认证信息")
    if parsed.password is None:
        return unquote(username), None
    password = unquote(parsed.password)
    if not password:
        raise ConversionError(f"第 {line_number} 行：{label} URI 的认证信息不完整")
    return unquote(username), password


def _build_tls(
    params: dict[str, str],
    line_number: int,
    *,
    required: bool = False,
    implicit: bool = False,
    default_alpn: list[str] | None = None,
) -> dict | None:
    raw_mode = params.get("security")
    # 部分协议（Trojan/Hysteria2/TUIC）的 TLS 是隐含的，链接通常不带 security 参数
    if implicit and not raw_mode:
        mode = "tls"
    else:
        mode = (raw_mode or "").strip().lower()
    if mode not in TLS_MODES:
        raise ConversionError(f"第 {line_number} 行：不支持的 TLS 类型")
    reality = mode == "reality"
    enabled = mode in {"tls", "xtls", "reality"}
    if required and not enabled:
        raise ConversionError(f"第 {line_number} 行：该协议必须启用 TLS")
    if not enabled:
        return None

    tls: dict = {"enabled": True}
    server_name = _query_value(params, "sni", "peer")
    if server_name:
        tls["server_name"] = server_name
    if _query_bool(params, line_number, "insecure", "allowInsecure", "skip-cert-verify"):
        tls["insecure"] = True

    alpn = _query_value(params, "alpn")
    if alpn:
        tls["alpn"] = [item for item in (part.strip() for part in alpn.split(",")) if item]
    elif default_alpn:
        tls["alpn"] = list(default_alpn)

    fingerprint = _query_value(params, "fp")
    if reality:
        public_key = _query_value(params, "pbk", "publicKey")
        if not public_key:
            raise ConversionError(f"第 {line_number} 行：Reality 配置缺少公钥")
        tls["reality"] = {"enabled": True, "public_key": public_key}
        short_id = _query_value(params, "sid", "shortId")
        if short_id:
            tls["reality"]["short_id"] = short_id
    if fingerprint or reality:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint or "chrome"}
    return tls


def _build_transport(params: dict[str, str], line_number: int) -> dict | None:
    raw_type = _query_value(params, "type", "net") or "tcp"
    transport_type = TRANSPORT_ALIASES.get(raw_type.strip().lower(), raw_type.strip().lower())
    if transport_type == "tcp":
        return None

    host = _query_value(params, "host")
    path = _query_value(params, "path")
    if transport_type == "ws":
        transport: dict = {"type": "ws"}
        transport["path"] = path or "/"
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if transport_type == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if host:
            transport["host"] = host
        transport["path"] = path or "/"
        return transport
    if transport_type == "grpc":
        transport = {"type": "grpc"}
        service_name = _query_value(params, "serviceName", "servicename")
        if service_name:
            transport["service_name"] = service_name
        return transport
    if transport_type == "http":
        transport = {"type": "http"}
        if host:
            transport["host"] = [item for item in (part.strip() for part in host.split(",")) if item]
        transport["path"] = path or "/"
        return transport
    if transport_type == "quic":
        return {"type": "quic"}
    raise ConversionError(f"第 {line_number} 行：不支持的传输类型")


def _apply_packet_encoding(node: dict, params: dict[str, str], line_number: int) -> None:
    encoding = (_query_value(params, "packetEncoding", "packet_encoding") or "").strip().lower()
    if encoding not in PACKET_ENCODINGS:
        raise ConversionError(f"第 {line_number} 行：不支持的数据包编码")
    if encoding:
        node["packet_encoding"] = encoding


def _parse_shadowsocks(uri: str, line_number: int) -> dict:
    parsed, host, server_port = _split_link(uri, "ss", line_number)
    params = _query_params(parsed, line_number)

    username = parsed.username
    if username is None:
        raise ConversionError(f"第 {line_number} 行：SS URI 缺少认证信息")
    if parsed.password is not None:
        method = unquote(username)
        secret = unquote(parsed.password)
    else:
        credentials = _decode_base64_text(username, line_number, "SS 认证信息")
        method, separator, secret = credentials.partition(":")
        if not separator:
            raise ConversionError(f"第 {line_number} 行：SS 认证信息缺少加密方法或密码")

    if not method or not secret:
        raise ConversionError(f"第 {line_number} 行：SS 加密方法或密码不能为空")
    node = {
        "type": "shadowsocks",
        "tag": _tag(unquote(parsed.fragment), f"shadowsocks-{host}:{server_port}", line_number),
        "server": host,
        "server_port": server_port,
        "method": method,
        "password": secret,
    }
    plugin = _query_value(params, "plugin")
    if plugin:
        name, _, options = plugin.partition(";")
        name = name.strip()
        if not name:
            raise ConversionError(f"第 {line_number} 行：字段 plugin 不能为空")
        node["plugin"] = name
        if options.strip():
            node["plugin_opts"] = options.strip()
    return node


def _parse_shadowsocksr(uri: str, line_number: int) -> dict:
    payload = _decode_base64_text(uri[len("ssr://") :], line_number, "SSR 配置")
    stripped = "".join(payload.split())
    body, separator, raw_query = stripped.partition("/?")
    if not separator and "?" in stripped:
        body, _, raw_query = stripped.partition("?")

    fields = body.rsplit(":", 5)
    if len(fields) != 6:
        raise ConversionError(f"第 {line_number} 行：SSR 配置字段不完整")
    host, raw_port, protocol, method, obfs, encoded_password = fields
    if not host:
        raise ConversionError(f"第 {line_number} 行：SSR 服务器地址不能为空")
    server_port = _port(raw_port, line_number)

    protocol = protocol.strip()
    method = method.strip()
    obfs = obfs.strip()
    if not protocol or not method or not obfs:
        raise ConversionError(f"第 {line_number} 行：SSR 加密方法、协议或混淆方式不能为空")

    secret = _decode_base64_text(encoded_password, line_number, "SSR 密码")
    if not secret:
        raise ConversionError(f"第 {line_number} 行：SSR 密码不能为空")

    params = dict(parse_qsl(raw_query, keep_blank_values=True))
    remarks = _query_value(params, "remarks")
    if remarks:
        tag = _tag(_decode_base64_text(remarks, line_number, "SSR 备注"), f"shadowsocksr-{host}:{server_port}", line_number)
    else:
        tag = _tag(None, f"shadowsocksr-{host}:{server_port}", line_number)

    node = {
        "type": "shadowsocksr",
        "tag": tag,
        "server": host,
        "server_port": server_port,
        "method": method,
        "password": secret,
        "protocol": protocol,
        "obfs": obfs,
    }
    protocol_param = _query_value(params, "protoparam")
    if protocol_param:
        node["protocol_param"] = _decode_base64_text(protocol_param, line_number, "SSR 协议参数")
    obfs_param = _query_value(params, "obfsparam")
    if obfs_param:
        node["obfs_param"] = _decode_base64_text(obfs_param, line_number, "SSR 混淆参数")
    return node


def _parse_vmess(uri: str, line_number: int) -> dict:
    encoded = uri[len("vmess://") :]
    payload = _decode_base64(encoded, line_number, "VMess 配置")
    try:
        config = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ConversionError(f"第 {line_number} 行：VMess 配置不是有效的 JSON") from None
    if not isinstance(config, dict):
        raise ConversionError(f"第 {line_number} 行：VMess 配置必须是 JSON 对象")

    server = _string_field(config, "add", line_number, required=True)
    port = _port(config.get("port"), line_number)
    client_id = _string_field(config, "id", line_number, required=True)
    try:
        uuid.UUID(client_id)
    except (ValueError, AttributeError):
        raise ConversionError(f"第 {line_number} 行：字段 id 不是有效的 UUID") from None

    security = config.get("scy", "auto")
    if security is None or security == "":
        security = "auto"
    if not isinstance(security, str) or not security.strip():
        raise ConversionError(f"第 {line_number} 行：字段 scy 必须是非空字符串")
    alter_id = _integer(config.get("aid", 0), line_number, "aid", 0)

    node = {
        "type": "vmess",
        "tag": _tag(config.get("ps"), f"vmess-{server}:{port}", line_number),
        "server": server,
        "server_port": port,
        "uuid": client_id,
        "security": security.strip(),
        "alter_id": alter_id,
    }

    tls_value = config.get("tls", "")
    if isinstance(tls_value, bool):
        tls_enabled = tls_value
    elif isinstance(tls_value, str):
        normalized_tls = tls_value.strip().lower()
        if normalized_tls not in {"", "none", "false", "tls"}:
            raise ConversionError(f"第 {line_number} 行：不支持的 TLS 类型")
        tls_enabled = normalized_tls == "tls"
    else:
        raise ConversionError(f"第 {line_number} 行：TLS 配置无效")
    if tls_enabled:
        tls = {"enabled": True}
        server_name = config.get("sni")
        if server_name is not None and not isinstance(server_name, str):
            raise ConversionError(f"第 {line_number} 行：字段 sni 必须是字符串")
        if server_name and server_name.strip():
            tls["server_name"] = server_name.strip()
        if _boolean(config.get("skip-cert-verify", False), line_number, "skip-cert-verify"):
            tls["insecure"] = True
        node["tls"] = tls

    network = config.get("net") or "tcp"
    if not isinstance(network, str):
        raise ConversionError(f"第 {line_number} 行：字段 net 必须是字符串")
    network = network.strip().lower()
    if network == "ws":
        transport = {"type": "ws"}
        path = config.get("path")
        host = config.get("host")
        if path is not None and not isinstance(path, str):
            raise ConversionError(f"第 {line_number} 行：字段 path 必须是字符串")
        if host is not None and not isinstance(host, str):
            raise ConversionError(f"第 {line_number} 行：字段 host 必须是字符串")
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        node["transport"] = transport
    elif network not in {"tcp", ""}:
        raise ConversionError(f"第 {line_number} 行：不支持的传输类型")

    return node


def _parse_vless(uri: str, line_number: int) -> dict:
    parsed, host, server_port = _split_link(uri, "vless", line_number)
    params = _query_params(parsed, line_number)
    client_id, _ = _credentials(parsed, line_number, "VLESS")
    try:
        uuid.UUID(client_id)
    except (ValueError, AttributeError):
        raise ConversionError(f"第 {line_number} 行：VLESS 用户 ID 不是有效的 UUID") from None

    encryption = (_query_value(params, "encryption") or "none").strip().lower()
    if encryption not in {"", "none"}:
        raise ConversionError(f"第 {line_number} 行：不支持的 VLESS 加密方式")

    flow = (_query_value(params, "flow") or "").strip().lower()
    if flow not in VLESS_FLOWS:
        raise ConversionError(f"第 {line_number} 行：不支持的 VLESS flow")

    node = {
        "type": "vless",
        "tag": _tag(unquote(parsed.fragment), f"vless-{host}:{server_port}", line_number),
        "server": host,
        "server_port": server_port,
        "uuid": client_id,
    }
    tls = _build_tls(params, line_number, required=bool(flow))
    if tls:
        node["tls"] = tls
    if flow:
        node["flow"] = flow
    transport = _build_transport(params, line_number)
    if transport:
        node["transport"] = transport
    _apply_packet_encoding(node, params, line_number)
    return node


def _parse_trojan(uri: str, line_number: int) -> dict:
    parsed, host, server_port = _split_link(uri, "trojan", line_number)
    params = _query_params(parsed, line_number)
    secret, extra = _credentials(parsed, line_number, "Trojan")
    password = secret if extra is None else f"{secret}:{extra}"

    node = {
        "type": "trojan",
        "tag": _tag(unquote(parsed.fragment), f"trojan-{host}:{server_port}", line_number),
        "server": host,
        "server_port": server_port,
        "password": password,
        "tls": _build_tls(params, line_number, required=True, implicit=True),
    }
    transport = _build_transport(params, line_number)
    if transport:
        node["transport"] = transport
    return node


def _parse_hysteria2(uri: str, line_number: int) -> dict:
    parsed, host, server_port = _split_link(uri, "hysteria2", line_number)
    params = _query_params(parsed, line_number)

    username = parsed.username
    if parsed.password is None:
        password = unquote(username) if username else _query_value(params, "password")
    else:
        password = f"{unquote(username)}:{unquote(parsed.password)}"
    if not password:
        raise ConversionError(f"第 {line_number} 行：Hysteria2 URI 缺少密码")

    node = {
        "type": "hysteria2",
        "tag": _tag(unquote(parsed.fragment), f"hysteria2-{host}:{server_port}", line_number),
        "server": host,
        "server_port": server_port,
        "password": password,
        "tls": _build_tls(params, line_number, required=True, implicit=True),
    }

    for field, names in (("up_mbps", ("upmbps", "up")), ("down_mbps", ("downmbps", "down"))):
        raw_bandwidth = _query_value(params, *names)
        if raw_bandwidth:
            node[field] = _integer(raw_bandwidth, line_number, names[0], 1)
    if _query_bool(params, line_number, "fastopen"):
        node["tcp_fast_open"] = True

    obfs_type = (_query_value(params, "obfs") or "").strip().lower()
    if obfs_type and obfs_type != "none":
        if obfs_type != "salamander":
            raise ConversionError(f"第 {line_number} 行：不支持的 Hysteria2 混淆方式")
        obfs_password = _query_value(params, "obfs-password", "obfspassword")
        if not obfs_password:
            raise ConversionError(f"第 {line_number} 行：Hysteria2 混淆缺少密码")
        node["obfs"] = {"type": "salamander", "password": obfs_password}
    return node


def _parse_tuic(uri: str, line_number: int) -> dict:
    parsed, host, server_port = _split_link(uri, "tuic", line_number)
    params = _query_params(parsed, line_number)
    client_id, password = _credentials(parsed, line_number, "TUIC")
    if password is None:
        raise ConversionError(f"第 {line_number} 行：TUIC URI 缺少密码")
    try:
        uuid.UUID(client_id)
    except (ValueError, AttributeError):
        raise ConversionError(f"第 {line_number} 行：TUIC 用户 ID 不是有效的 UUID") from None

    node = {
        "type": "tuic",
        "tag": _tag(unquote(parsed.fragment), f"tuic-{host}:{server_port}", line_number),
        "server": host,
        "server_port": server_port,
        "uuid": client_id,
        "password": password,
        "tls": _build_tls(params, line_number, required=True, implicit=True, default_alpn=["h3"]),
    }

    congestion = (_query_value(params, "congestion_control", "congestion") or "").strip().lower()
    if congestion:
        if congestion not in CONGESTION_CONTROLS:
            raise ConversionError(f"第 {line_number} 行：不支持的拥塞控制算法")
        node["congestion_control"] = congestion
    relay_mode = (_query_value(params, "udp_relay_mode", "udp-relay-mode") or "").strip().lower()
    if relay_mode:
        if relay_mode not in UDP_RELAY_MODES:
            raise ConversionError(f"第 {line_number} 行：不支持的 UDP 转发模式")
        node["udp_relay_mode"] = relay_mode
    return node


def _parse_socks(uri: str, scheme: str, line_number: int) -> dict:
    parsed, host, server_port = _split_link(uri, scheme, line_number)
    node = {
        "type": "socks",
        "tag": _tag(unquote(parsed.fragment), f"socks-{host}:{server_port}", line_number),
        "server": host,
        "server_port": server_port,
        "version": "5",
    }
    username = parsed.username
    if username:
        node["username"] = unquote(username)
        if parsed.password is not None:
            node["password"] = unquote(parsed.password)
    return node


def _parse_http(uri: str, scheme: str, line_number: int) -> dict:
    parsed, host, server_port = _split_link(uri, scheme, line_number)
    node = {
        "type": "http",
        "tag": _tag(unquote(parsed.fragment), f"http-{host}:{server_port}", line_number),
        "server": host,
        "server_port": server_port,
    }
    username = parsed.username
    if username:
        node["username"] = unquote(username)
        node["password"] = unquote(parsed.password) if parsed.password is not None else ""
    return node


PROTOCOL_PARSERS = {
    "ss": _parse_shadowsocks,
    "ssr": _parse_shadowsocksr,
    "vmess": _parse_vmess,
    "vless": _parse_vless,
    "trojan": _parse_trojan,
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
    "socks": lambda uri, number: _parse_socks(uri, "socks", number),
    "socks5": lambda uri, number: _parse_socks(uri, "socks5", number),
    "http": lambda uri, number: _parse_http(uri, "http", number),
    "https": lambda uri, number: _parse_http(uri, "https", number),
}


def _iter_entries(text: str):
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        numbered_line = re.match(r"^\d+\s+([A-Za-z][A-Za-z0-9+.\-]*://\S+)$", line)
        if numbered_line:
            line = numbered_line.group(1)
        yield line_number, line


def _looks_like_proxy_list(text: str) -> bool:
    for _, line in _iter_entries(text):
        scheme, separator, _ = line.partition("://")
        if separator and scheme.lower() in PROTOCOL_PARSERS:
            return True
    return False


def _looks_like_subscription(text: str) -> bool:
    compact = "".join(text.split())
    if len(compact) < SUBSCRIPTION_MIN_LENGTH:
        return False
    if not BASE64_PATTERN.fullmatch(compact):
        return False
    try:
        decoded = _decode_subscription(compact)
    except ConversionError:
        return False
    return _looks_like_proxy_list(decoded)


def _decode_subscription(text: str) -> str:
    encoded = text.encode("ascii")
    encoded += b"=" * (-len(encoded) % 4)
    try:
        payload = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ConversionError("订阅内容不是有效的 Base64") from None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        raise ConversionError("订阅内容解码后不是有效文本") from None


def parse_proxy_list(text: str) -> list[dict]:
    if not _looks_like_proxy_list(text):
        if _looks_like_subscription(text):
            text = _decode_subscription("".join(text.split()))
        else:
            raise ConversionError(f"内容既不是代理列表也不是 Base64 订阅；仅支持 {SUPPORTED_SUMMARY} URI")

    nodes = []
    tags = set()
    for line_number, line in _iter_entries(text):
        scheme, separator, _ = line.partition("://")
        protocol = scheme.lower() if separator else ""
        parser = PROTOCOL_PARSERS.get(protocol)
        if parser is None:
            actual = f"检测到 {protocol}://" if protocol else "该行不是 xx:// 形式的分享链接"
            raise ConversionError(f"第 {line_number} 行：{actual}，仅支持 {SUPPORTED_SUMMARY} URI")
        node = parser(line, line_number)
        if node["tag"] in tags:
            raise ConversionError(f"第 {line_number} 行：节点 tag 重复")
        tags.add(node["tag"])
        nodes.append(node)

    if not nodes:
        raise ConversionError("代理列表中没有可转换的节点")
    return nodes


def _referenced_strings(value: object, target_group_tags: set[str]) -> set[str]:
    references = set()
    if isinstance(value, dict):
        tag = value.get("tag")
        is_target_group = isinstance(tag, str) and tag in target_group_tags
        for key, item in value.items():
            if key == "tag" or (is_target_group and key in {"outbounds", "default"}):
                continue
            references.update(_referenced_strings(item, target_group_tags))
    elif isinstance(value, list):
        for item in value:
            references.update(_referenced_strings(item, target_group_tags))
    elif isinstance(value, str):
        references.add(value)
    return references


def update_template(template: object, nodes: list[dict]) -> dict:
    if not isinstance(template, dict) or not isinstance(template.get("outbounds"), list):
        raise ConversionError("模板必须是包含 outbounds 数组的完整 JSON 对象")
    outbounds = template["outbounds"]
    if any(not isinstance(outbound, dict) for outbound in outbounds):
        raise ConversionError("模板 outbounds 中的每个节点都必须是 JSON 对象")

    outbound_by_tag = {}
    for outbound in outbounds:
        tag = outbound.get("tag")
        if tag is None:
            continue
        if not isinstance(tag, str) or not tag:
            raise ConversionError("模板出站的 tag 必须是非空字符串")
        if tag in outbound_by_tag:
            raise ConversionError("模板中存在重复的 outbound tag")
        outbound_by_tag[tag] = outbound

    groups = {}
    for tag, expected_type in GROUP_TYPES.items():
        group = outbound_by_tag.get(tag)
        if group is None or group.get("type") != expected_type:
            raise ConversionError(f"模板必须且只能包含一个 {tag} ({expected_type}) 出站")
        if not isinstance(group.get("outbounds"), list):
            raise ConversionError(f"模板中的 {tag} 必须包含 outbounds 数组")
        if any(not isinstance(item, str) for item in group["outbounds"]):
            raise ConversionError(f"模板中的 {tag} 节点引用必须是字符串")
        groups[tag] = group

    node_tags = [node.get("tag") for node in nodes if isinstance(node, dict)]
    if len(node_tags) != len(nodes) or any(not isinstance(tag, str) or not tag for tag in node_tags):
        raise ConversionError("生成的节点必须包含非空字符串 tag")
    if len(set(node_tags)) != len(node_tags):
        raise ConversionError("生成的节点 tag 重复")

    managed_old_tags = set()
    for group in groups.values():
        for reference in group["outbounds"]:
            outbound = outbound_by_tag.get(reference)
            if outbound is None:
                raise ConversionError("模板选择器引用了未定义的出站 tag")
            if outbound.get("type") not in NON_NODE_TYPES:
                managed_old_tags.add(reference)

    external_references = _referenced_strings(template, set(GROUP_TYPES))
    removable_tags = managed_old_tags - external_references
    preserved_tags = set(outbound_by_tag) - removable_tags
    if set(node_tags) & preserved_tags:
        raise ConversionError("生成的节点 tag 与模板中的其他出站冲突")

    result = deepcopy(template)
    new_outbounds = []
    for outbound in result["outbounds"]:
        tag = outbound.get("tag")
        if tag in GROUP_TYPES:
            outbound["outbounds"] = node_tags[:]
            if tag == MANUAL_TAG and "default" in outbound and outbound["default"] not in node_tags:
                outbound["default"] = node_tags[0]
            new_outbounds.append(outbound)
        elif tag in removable_tags:
            continue
        else:
            new_outbounds.append(outbound)
    new_outbounds.extend(deepcopy(nodes))
    result["outbounds"] = new_outbounds

    available_tags = {outbound.get("tag") for outbound in new_outbounds}
    for tag in GROUP_TYPES:
        group = next(outbound for outbound in new_outbounds if outbound.get("tag") == tag)
        refs = group["outbounds"]
        if refs != node_tags or any(ref not in available_tags for ref in refs):
            raise ConversionError(f"模板中的 {tag} 节点引用校验失败")
    return result


def write_output(path: Path, content: str, *, force: bool) -> None:
    if not path.parent.is_dir():
        raise ConversionError("输出目录不存在")
    try:
        with path.open("w" if force else "x", encoding="utf-8", newline="\n") as output_file:
            output_file.write(content)
    except FileExistsError:
        raise ConversionError("输出文件已存在；如需覆盖请指定 --force") from None
    except OSError:
        raise ConversionError("无法写入输出文件") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"根据 {SUPPORTED_SUMMARY} 代理列表或 Base64 订阅更新完整 sing-box JSON 配置",
    )
    parser.add_argument("-i", "--input", "--source", dest="source", type=Path, default=DEFAULT_SOURCE, help="代理 URI 列表，或整份 Base64 订阅")
    parser.add_argument("--template", type=Path, required=True, help="完整 sing-box JSON 配置模板，需包含两个目标选择器")
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT, help="生成的完整配置文件")
    parser.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    parser.add_argument(
        "--exclude-tag",
        action="append",
        default=[],
        metavar="正则",
        help="排除 tag 匹配该正则的节点（如订阅商注入的流量/到期信息节点），可重复",
    )
    return parser


def _select_nodes(nodes: list[dict], patterns: list[str], parser: argparse.ArgumentParser) -> list[dict]:
    if not patterns:
        return nodes
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error as error:
            parser.error(f"--exclude-tag 正则无效：{error}")
    kept = [node for node in nodes if not any(item.search(node["tag"]) for item in compiled)]
    if not kept:
        parser.error("按 --exclude-tag 排除后没有剩余节点")
    return kept


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    source_path = args.source.resolve()
    template_path = args.template.resolve()
    output_path = args.output.resolve()

    if output_path == source_path:
        parser.error("输出文件不能覆盖代理列表源文件")
    if output_path.exists() and not args.force:
        parser.error("输出文件已存在；如需覆盖请指定 --force")

    try:
        source_text = source_path.read_text(encoding="utf-8-sig")
        template = json.loads(template_path.read_text(encoding="utf-8-sig"))
    except OSError:
        parser.error("无法读取源文件或 JSON 模板")
    except UnicodeError:
        parser.error("源文件或 JSON 模板编码无效")
    except json.JSONDecodeError:
        parser.error("JSON 模板格式无效")

    try:
        nodes = parse_proxy_list(source_text)
        nodes = _select_nodes(nodes, args.exclude_tag, parser)
        config = update_template(template, nodes)
        serialized = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
        write_output(output_path, serialized, force=args.force)
    except ConversionError as error:
        parser.error(str(error))

    counts = Counter(node["type"] for node in nodes)
    summary = ", ".join(f"{protocol}={count}" for protocol, count in sorted(counts.items()))
    print(f"已生成 {len(nodes)} 个节点：{summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())