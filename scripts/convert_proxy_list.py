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
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "sing-box" / "config" / "proxy-list.example.conf"
DEFAULT_OUTPUT = ROOT / "sing-box" / "config" / "proxy-list.generated.json"
AUTO_TAG = "♻️ 自动选择"
MANUAL_TAG = "🐸 手动选择"
GROUP_TYPES = {AUTO_TAG: "urltest", MANUAL_TAG: "selector"}
NON_NODE_TYPES = {"block", "direct", "dns", "loadbalance", "loopback", "reject", "selector", "urltest"}


class ConversionError(Exception):
    """表示输入代理列表或 sing-box 模板不符合预期。"""


def _decode_base64(value: str, line_number: int, field: str) -> bytes:
    try:
        encoded = unquote(value).encode("ascii")
        encoded += b"=" * (-len(encoded) % 4)
        return base64.b64decode(encoded, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise ConversionError(f"第 {line_number} 行：{field} 不是有效的 Base64") from None


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


def _parse_shadowsocks(uri: str, line_number: int) -> dict:
    try:
        parsed = urlsplit(uri)
        host = parsed.hostname
        port = parsed.port
        username = parsed.username
        password_part = parsed.password
    except ValueError:
        raise ConversionError(f"第 {line_number} 行：SS URI 的服务器地址或端口无效") from None

    if parsed.scheme.lower() != "ss" or not host or port is None or username is None:
        raise ConversionError(f"第 {line_number} 行：SS URI 缺少认证信息、服务器或端口")
    if parsed.query:
        raise ConversionError(f"第 {line_number} 行：不支持带查询参数的 SS URI")

    if password_part is not None:
        method = unquote(username)
        secret = unquote(password_part)
    else:
        decoded = _decode_base64(username, line_number, "SS 认证信息")
        try:
            credentials = decoded.decode("utf-8")
        except UnicodeDecodeError:
            raise ConversionError(f"第 {line_number} 行：SS 认证信息不是有效文本") from None
        method, separator, secret = credentials.partition(":")
        if not separator:
            raise ConversionError(f"第 {line_number} 行：SS 认证信息缺少加密方法或密码")

    if not method or not secret:
        raise ConversionError(f"第 {line_number} 行：SS 加密方法或密码不能为空")
    server_port = _port(port, line_number)
    tag = _tag(unquote(parsed.fragment), f"shadowsocks-{host}:{server_port}", line_number)
    return {
        "type": "shadowsocks",
        "tag": tag,
        "server": host,
        "server_port": server_port,
        "method": method,
        "password": secret,
    }


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


def parse_proxy_list(text: str) -> list[dict]:
    nodes = []
    tags = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        numbered_line = re.match(r"^\d+\s+((?:ss|vmess)://\S+)$", line, re.IGNORECASE)
        if numbered_line:
            line = numbered_line.group(1)
        lowered = line.lower()
        if lowered.startswith("ss://"):
            node = _parse_shadowsocks(line, line_number)
        elif lowered.startswith("vmess://"):
            node = _parse_vmess(line, line_number)
        else:
            raise ConversionError(f"第 {line_number} 行：仅支持 SS 和 VMess URI")
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
    parser = argparse.ArgumentParser(description="根据 SS/VMess 代理列表更新完整 sing-box JSON 配置")
    parser.add_argument("-i", "--input", "--source", dest="source", type=Path, default=DEFAULT_SOURCE, help="代理 URI 列表")
    parser.add_argument("--template", type=Path, required=True, help="完整 sing-box JSON 配置模板，需包含两个目标选择器")
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT, help="生成的完整配置文件")
    parser.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    return parser


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
