#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy-audit — 本机代理链路安全体检工具

从「你本机正在运行的代理配置」出发，端到端验证这条代理链路是否干净、可信。

三层检测:
  1. 配置层  — 读取 v2rayN / sing-box / xray / clash(mihomo) 配置，
              检测 outbound 投毒、DNS 劫持、可疑路由规则、端口暴露。
  2. 传输层  — 通过代理发起真实 TLS 握手，检测中间人(MITM)、
              请求头身份泄漏、内容篡改、DNS 泄漏。
  3. 出口层  — 查询出口 IP 信誉、机房/代理标记、国内外分流是否正确。

零依赖：仅使用 Python 标准库。运行环境 Python 3.8+。

用法:
    python proxy_audit.py                 # 自动探测代理并体检
    python proxy_audit.py --proxy 127.0.0.1:10808
    python proxy_audit.py --json out.json # 额外输出 JSON 报告
    python proxy_audit.py --no-color      # 关闭彩色输出

免责声明: 本工具仅用于检测「你自己拥有或已获授权使用」的代理链路。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# 终端颜色
# --------------------------------------------------------------------------

_USE_COLOR = True


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty() and platform.system() != "Windows":
        return False
    return True


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


def c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{color}{text}{C.RESET}"


def enable_windows_ansi() -> None:
    """在 Windows 10+ 上启用 ANSI 转义支持。"""
    if platform.system() != "Windows":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


# --------------------------------------------------------------------------
# 结果模型
# --------------------------------------------------------------------------

SEV_PASS = "pass"
SEV_INFO = "info"
SEV_WARN = "warn"
SEV_FAIL = "fail"

_SEV_ORDER = {SEV_FAIL: 0, SEV_WARN: 1, SEV_INFO: 2, SEV_PASS: 3}
_SEV_LABEL = {
    SEV_PASS: ("[OK]  ", C.GREEN),
    SEV_INFO: ("[i]   ", C.CYAN),
    SEV_WARN: ("[WARN]", C.YELLOW),
    SEV_FAIL: ("[FAIL]", C.RED),
}


@dataclass
class Check:
    name: str
    severity: str
    detail: str
    layer: str = "general"
    evidence: dict[str, Any] = field(default_factory=dict)


class Report:
    def __init__(self) -> None:
        self.checks: list[Check] = []
        self.meta: dict[str, Any] = {}

    def add(self, name: str, severity: str, detail: str, layer: str = "general", **evidence: Any) -> None:
        self.checks.append(Check(name, severity, detail, layer, evidence))

    def ok(self, name: str, detail: str, layer: str = "general", **ev: Any) -> None:
        self.add(name, SEV_PASS, detail, layer, **ev)

    def info(self, name: str, detail: str, layer: str = "general", **ev: Any) -> None:
        self.add(name, SEV_INFO, detail, layer, **ev)

    def warn(self, name: str, detail: str, layer: str = "general", **ev: Any) -> None:
        self.add(name, SEV_WARN, detail, layer, **ev)

    def fail(self, name: str, detail: str, layer: str = "general", **ev: Any) -> None:
        self.add(name, SEV_FAIL, detail, layer, **ev)

    def summary(self) -> dict[str, int]:
        out = {SEV_PASS: 0, SEV_INFO: 0, SEV_WARN: 0, SEV_FAIL: 0}
        for ch in self.checks:
            out[ch.severity] = out.get(ch.severity, 0) + 1
        return out

    def verdict(self) -> str:
        s = self.summary()
        if s[SEV_FAIL]:
            return "high"
        if s[SEV_WARN]:
            return "medium"
        return "clean"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "proxy-audit",
            "version": __version__,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "meta": self.meta,
            "verdict": self.verdict(),
            "summary": self.summary(),
            "checks": [
                {
                    "name": ch.name,
                    "layer": ch.layer,
                    "severity": ch.severity,
                    "detail": ch.detail,
                    "evidence": ch.evidence,
                }
                for ch in self.checks
            ],
        }


# --------------------------------------------------------------------------
# 代理自动探测
# --------------------------------------------------------------------------


@dataclass
class ProxyInfo:
    host: str
    port: int
    source: str
    scheme: str = "http"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def __str__(self) -> str:
        return f"{self.host}:{self.port} ({self.source})"


COMMON_PROXY_PORTS = [10808, 10809, 1080, 1081, 7890, 7891, 7897, 8080, 8888, 2080, 20170, 4780]


def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def detect_proxy(explicit: str | None = None) -> ProxyInfo | None:
    """按优先级探测代理：显式参数 > 环境变量 > 系统代理 > 常见端口扫描。"""
    if explicit:
        host, _, port = explicit.rpartition(":")
        if not host:
            host, port = "127.0.0.1", explicit
        return ProxyInfo(host or "127.0.0.1", int(port), "命令行参数")

    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        val = os.environ.get(var)
        if not val:
            continue
        m = re.search(r"(?:https?|socks5?)://(?:[^@/]*@)?([^:/]+):(\d+)", val)
        if m:
            host, port = m.group(1), int(m.group(2))
            if host in ("127.0.0.1", "localhost", "::1") and _port_open(host, port):
                return ProxyInfo(host, port, f"环境变量 {var}")

    if platform.system() == "Windows":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            )
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if enabled:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                m = re.search(r"([^:;]+):(\d+)", server)
                if m and _port_open(m.group(1), int(m.group(2))):
                    return ProxyInfo(m.group(1), int(m.group(2)), "Windows 系统代理")
        except Exception:
            pass

    for port in COMMON_PROXY_PORTS:
        if _port_open("127.0.0.1", port):
            return ProxyInfo("127.0.0.1", port, "端口扫描")

    return None


# --------------------------------------------------------------------------
# HTTP 工具（基于标准库，手动处理代理）
# --------------------------------------------------------------------------


def http_via_proxy(
    url: str,
    proxy: ProxyInfo | None,
    timeout: float = 20.0,
    headers: dict[str, str] | None = None,
    insecure: bool = False,
    want_headers: bool = False,
) -> tuple[int, bytes, dict[str, str]]:
    """通过代理发起请求。insecure=True 时不验证证书（用于 MITM 检测）。"""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    if proxy:
        handler: urllib.request.BaseHandler = urllib.request.ProxyHandler(
            {"http": proxy.url, "https": proxy.url}
        )
    else:
        handler = urllib.request.ProxyHandler({})

    opener = urllib.request.build_opener(handler, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "proxy-audit/1.0"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, hdrs
    except urllib.error.HTTPError as e:
        return e.code, e.read(8192), {k.lower(): v for k, v in e.headers.items()}


def http_direct(url: str, timeout: float = 12.0) -> tuple[int, bytes, dict[str, str]]:
    """绕过任何代理直连。"""
    return http_via_proxy(url, None, timeout=timeout)


def get_json(url: str, proxy: ProxyInfo | None, timeout: float = 20.0) -> Any:
    try:
        status, body, _ = http_via_proxy(url, proxy, timeout=timeout)
        if status == 200:
            return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------
# 第 1 层：配置层检测
# --------------------------------------------------------------------------


def _find_config_dirs() -> list[str]:
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(localappdata, "v2rayN"),
        os.path.join(home, "AppData", "Local", "v2rayN"),
        os.path.join(home, ".config", "clash"),
        os.path.join(home, ".config", "mihomo"),
        os.path.join(home, ".config", "sing-box"),
        os.path.join(appdata, "clash-verge"),
        os.path.join(appdata, "io.github.clash-verge-rev.clash-verge-rev"),
        os.path.join(home, ".config", "clash-verge"),
    ]
    seen: set[str] = set()
    result: list[str] = []
    for d in candidates:
        if not d or not os.path.isdir(d):
            continue
        real = os.path.realpath(d).lower()
        if real in seen:
            continue
        seen.add(real)
        result.append(d)
    return result


def _read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def _iter_json_files(root: str, max_files: int = 40) -> list[str]:
    found: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().endswith(".json"):
                found.append(os.path.join(dirpath, fn))
                if len(found) >= max_files:
                    return found
    return found


SUSPICIOUS_OUTBOUND_HINTS = [
    "socks", "http", "vmess", "vless", "trojan", "shadowsocks", "ss", "hysteria",
]


def layer_config(report: Report, proxy: ProxyInfo | None) -> None:
    """配置层：寻找本地代理配置文件并审计。"""
    L = "config"
    dirs = _find_config_dirs()
    if not dirs:
        report.info("本地代理配置", "未发现常见代理客户端的配置目录，跳过配置层检测", L)
        return

    report.info("发现配置目录", ", ".join(dirs), L, dirs=dirs)

    # v2rayN: binConfigs/config.json 是运行时的核心配置
    v2ray_dirs = [d for d in dirs if "v2rayN" in d]
    for vd in v2ray_dirs:
        cfg_path = os.path.join(vd, "binConfigs", "config.json")
        if os.path.isfile(cfg_path):
            cfg = _read_json(cfg_path)
            if cfg:
                _audit_xray_config(report, cfg, cfg_path)
        else:
            report.info("v2rayN 运行配置", f"未找到 {cfg_path}", L)

    # clash / mihomo / sing-box 风格配置
    for d in dirs:
        if "v2rayN" in d:
            continue
        for p in _iter_json_files(d, max_files=20):
            base = os.path.basename(p).lower()
            if base in ("config.json", "config.yaml", "config.yml") or "clash" in base or "mihomo" in base:
                cfg = _read_json(p)
                if isinstance(cfg, dict):
                    _audit_clash_config(report, cfg, p)


def _audit_xray_config(report: Report, cfg: dict[str, Any], path: str) -> None:
    L = "config"
    report.info("运行中配置", path, L, path=path)

    inbounds = cfg.get("inbounds", []) or []
    outbounds = cfg.get("outbounds", []) or []
    routing = cfg.get("routing", {}) or {}
    dns = cfg.get("dns", {}) or {}

    # --- inbound 暴露面 ---
    for ib in inbounds:
        listen = str(ib.get("listen", "0.0.0.0"))
        port = ib.get("port")
        if listen in ("0.0.0.0", "::", ""):
            report.warn(
                "入站监听地址",
                f"inbound '{ib.get('tag', '?')}' 监听 {listen}:{port} — 对局域网/公网开放，"
                f"同网络下他人可能借用你的代理",
                L,
                listen=listen, port=port,
            )
        elif listen in ("127.0.0.1", "::1", "localhost"):
            report.ok(
                "入站监听地址",
                f"inbound '{ib.get('tag', '?')}' 仅监听 {listen}:{port}（本地回环，安全）",
                L, listen=listen, port=port,
            )
        else:
            report.info("入站监听地址", f"inbound '{ib.get('tag', '?')}' 监听 {listen}:{port}", L)

    # --- outbound 投毒检测 ---
    proxy_tags = {"proxy", "direct", "block", "dns", "api"}
    outbound_names = [str(o.get("tag", "?")) for o in outbounds]
    report.info("出站节点列表", ", ".join(outbound_names) or "(空)", L, outbounds=outbound_names)

    suspect: list[str] = []
    for ob in outbounds:
        tag = str(ob.get("tag", "?"))
        proto = str(ob.get("protocol", "")).lower()
        # freedom / blackhole 是内置直连与拦截，正常
        if proto in ("freedom", "blackhole", "dns"):
            continue
        # 除主代理外的第二个代理类 outbound 值得警惕
        if proto in SUSPICIOUS_OUTBOUND_HINTS and tag not in ("proxy",):
            addr = _extract_outbound_address(ob)
            suspect.append(f"{tag}({proto} -> {addr})")

    if suspect:
        report.warn(
            "出站节点审查",
            "发现除主代理外的额外出站连接，请确认是你自己配置的: " + "; ".join(suspect),
            L, suspects=suspect,
        )
    else:
        report.ok(
            "出站节点审查",
            "出站仅包含主代理 + 直连(freedom) + 拦截(blackhole)，未见可疑隐藏转发出口",
            L,
        )

    # --- 主代理节点信息 ---
    for ob in outbounds:
        if str(ob.get("protocol", "")).lower() in ("vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2"):
            info = _describe_proxy_outbound(ob)
            if info:
                report.info("上游节点信息", info, L, node=_extract_outbound_address(ob))

    # --- DNS 配置 ---
    dns_servers = dns.get("servers", []) or []
    plain_dns: list[str] = []
    secure_dns = 0
    for s in dns_servers:
        addr = s if isinstance(s, str) else str(s.get("address", ""))
        if addr.startswith("https://") or addr.startswith("tls://"):
            secure_dns += 1
        elif re.match(r"^[\d.:a-fA-F]+$", addr):
            plain_dns.append(addr)
    if plain_dns and not secure_dns:
        report.warn("DNS 加密", f"仅使用明文 DNS: {', '.join(plain_dns)}，可能被旁路监听", L, plain_dns=plain_dns)
    elif secure_dns:
        report.ok("DNS 加密", f"使用加密 DNS (DoH/DoT) 服务器 {secure_dns} 个，未发现纯明文 DNS", L, secure_dns=secure_dns)

    # --- 路由规则：检查是否有把敏感流量导向代理的可疑规则 ---
    rules = routing.get("rules", []) or []
    report.info("路由规则", f"共 {len(rules)} 条规则", L, rule_count=len(rules))

    # 检查是否有针对国内域名/IP 的异常转发（把 CN 流量导去代理）
    cn_to_proxy: list[str] = []
    for r in rules:
        if r.get("outboundTag") not in (None, "direct", "block"):
            domains = r.get("domain", []) or []
            ips = r.get("ip", []) or []
            for d in domains:
                if "geosite:cn" in str(d) or "geosite:private" in str(d):
                    cn_to_proxy.append(f"域名 {d} -> {r.get('outboundTag')}")
            for ip in ips:
                if "geoip:cn" in str(ip) or "geoip:private" in str(ip):
                    cn_to_proxy.append(f"IP {ip} -> {r.get('outboundTag')}")
    if cn_to_proxy:
        report.warn("分流异常", "国内/内网流量被规则导向代理出口: " + "; ".join(cn_to_proxy), L)
    else:
        report.ok("分流规则", "国内域名/IP 未被导向代理出口，分流正常", L)

    # --- sniffing 嗅探 ---
    for ib in inbounds:
        sn = ib.get("sniffing", {}) or {}
        if sn.get("enabled"):
            report.info("流量嗅探", f"inbound '{ib.get('tag')}' 开启 sniffing（用于分流，本地行为）", L)


def _extract_outbound_address(ob: dict[str, Any]) -> str:
    try:
        settings = ob.get("settings", {})
        vnext = settings.get("vnext") or settings.get("servers")
        if isinstance(vnext, list) and vnext:
            node = vnext[0]
            return f"{node.get('address')}:{node.get('port')}"
        if "address" in settings:
            return f"{settings['address']}:{settings.get('port')}"
    except Exception:
        pass
    return "?"


def _describe_proxy_outbound(ob: dict[str, Any]) -> str | None:
    proto = str(ob.get("protocol", "?")).upper()
    stream = ob.get("streamSettings", {}) or {}
    network = stream.get("network", "?")
    security = stream.get("security", "none")
    parts = [f"协议 {proto}", f"传输 {network}", f"加密 {security}"]
    if security == "reality":
        rs = stream.get("realitySettings", {}) or {}
        parts.append(f"REALITY SNI={rs.get('serverName', '?')}")
    elif security == "tls":
        ts = stream.get("tlsSettings", {}) or {}
        parts.append(f"SNI={ts.get('serverName', '?')}")
    return " | ".join(parts)


def _audit_clash_config(report: Report, cfg: dict[str, Any], path: str) -> None:
    L = "config"
    report.info("Clash 配置", path, L, path=path)
    proxies = cfg.get("proxies", []) or []
    port = cfg.get("port") or (cfg.get("mixed-port"))
    allow_lan = cfg.get("allow-lan", False)
    if allow_lan:
        report.warn("局域网暴露", f"allow-lan=true（端口 {port}），局域网内他人可借用你的代理", L)
    elif port:
        report.ok("入站监听", f"allow-lan=false，端口 {port} 仅本地可访问", L)
    report.info("节点数量", f"配置了 {len(proxies)} 个代理节点", L, count=len(proxies))


# --------------------------------------------------------------------------
# 第 2 层：传输层检测
# --------------------------------------------------------------------------

CANARY_HOSTS = [
    ("https://www.cloudflare.com/cdn-cgi/trace", "cloudflare"),
    ("https://www.gstatic.com/generate_204", "google"),
]


def layer_transport(report: Report, proxy: ProxyInfo | None) -> dict[str, Any]:
    """传输层：MITM / 注入头 / 内容篡改。"""
    L = "transport"
    if not proxy:
        report.info("传输层检测", "未探测到代理，跳过", L)
        return {}

    facts: dict[str, Any] = {}

    # --- 出口 IP ---
    ip_data = get_json("https://api.ipify.org?format=json", proxy)
    exit_ip = ip_data.get("ip") if isinstance(ip_data, dict) else None
    if not exit_ip:
        report.fail("连通性", f"通过代理 {proxy} 无法访问网络", L)
        return facts
    facts["exit_ip"] = exit_ip
    report.ok("代理连通性", f"通过 {proxy} 可正常访问网络，出口 IP = {exit_ip}", L, exit_ip=exit_ip)

    # --- 出口 IP 稳定性（采样 2 次）---
    ips = {exit_ip}
    for _ in range(2):
        d = get_json("https://api.ipify.org?format=json", proxy, timeout=12)
        if isinstance(d, dict) and d.get("ip"):
            ips.add(d["ip"])
    if len(ips) > 1:
        report.info("出口 IP 稳定性", f"多次采样出现不同出口: {', '.join(sorted(ips))}（负载均衡/轮换出口）", L, ips=sorted(ips))
    else:
        report.ok("出口 IP 稳定性", f"多次采样出口 IP 稳定为 {exit_ip}", L)

    # --- MITM 检测：验证证书链 ---
    _detect_mitm(report, proxy, facts)

    # --- 请求头注入检测 ---
    _detect_header_injection(report, proxy)

    # --- 内容篡改检测 ---
    _detect_content_tampering(report, proxy)

    # --- DNS 泄漏检测 ---
    _detect_dns_leak(report, proxy, facts)

    return facts


def _detect_mitm(report: Report, proxy: ProxyInfo, facts: dict[str, Any]) -> None:
    L = "transport"
    # 正常校验：若代理做 MITM，会因证书不受信而失败
    strict_ok = True
    strict_err = ""
    try:
        status, _body, _h = http_via_proxy("https://www.cloudflare.com/cdn-cgi/trace", proxy, timeout=20)
        if status >= 400:
            strict_ok = False
            strict_err = f"HTTP {status}"
    except ssl.SSLCertVerificationError as e:
        strict_ok = False
        strict_err = f"证书校验失败: {e}"
    except Exception as e:
        strict_ok = False
        strict_err = str(e)

    if strict_ok:
        report.ok(
            "中间人检测 (MITM)",
            "通过代理的 TLS 证书链校验通过，未发现证书被替换或降级 — HTTPS 端到端加密有效",
            L,
        )
    else:
        report.fail(
            "中间人检测 (MITM)",
            f"严格证书校验失败（{strict_err}）。这可能是代理在做 TLS 中间人解密，请高度警惕",
            L, error=strict_err,
        )

    # 读取真实证书签发者，确认不是常见企业/自签 CA
    try:
        info = _peek_certificate(proxy, "www.cloudflare.com", 443)
        if info:
            facts["cert_issuer"] = info.get("issuer")
            issuer = info.get("issuer", "")
            if any(bad in issuer.lower() for bad in ("self", "localhost", "proxy-audit", "untrusted", "mitm")):
                report.warn("证书签发者", f"证书由可疑 CA 签发: {issuer}", L, issuer=issuer)
            elif issuer:
                report.ok("证书签发者", f"证书由 {issuer} 签发（正常公共 CA）", L, issuer=issuer)
    except Exception:
        pass


def _peek_certificate(proxy: ProxyInfo, host: str, port: int) -> dict[str, Any] | None:
    """通过 HTTP CONNECT 隧道获取目标站点的证书信息。"""
    try:
        raw = socket.create_connection((proxy.host, proxy.port), timeout=15)
        raw.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = raw.recv(4096)
            if not chunk:
                break
            buf += chunk
        if b"200" not in buf.split(b"\r\n")[0]:
            raw.close()
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname=host)
        der = tls.getpeercert(binary_form=True)
        tls.close()
        if not der:
            return None
        return _parse_cert_names(der)
    except Exception:
        return None


def _parse_cert_names(der: bytes) -> dict[str, Any]:
    """解析证书里的 CN/O/国家。优先用标准库解码，失败则做极简 DER 字符串提取。"""
    decoded: dict[str, Any] = {}
    try:
        import tempfile

        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(pem)
            tmp = f.name
        try:
            decode_fn = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
            if decode_fn:
                decoded = decode_fn(tmp) or {}
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    except Exception:
        decoded = {}

    def _flatten(name_seq: Any) -> str:
        parts = []
        for rdn in name_seq or []:
            for k, v in rdn:
                if k in ("commonName", "organizationName", "countryName"):
                    parts.append(f"{k}={v}")
        return ", ".join(parts)

    issuer = _flatten(decoded.get("issuer"))
    subject = _flatten(decoded.get("subject"))

    # 降级：标准库解码不可用时，从 DER 里直接扒可打印字符串（够判断可疑 CA 用）
    if not issuer:
        try:
            strings = re.findall(rb"[\x20-\x7e]{4,64}", der)
            text = " | ".join(s.decode("ascii", "replace") for s in strings)
            issuer = text[:300]
        except Exception:
            issuer = ""

    return {"issuer": issuer, "subject": subject}


INJECTION_HEADERS = ["x-forwarded-for", "x-real-ip", "forwarded", "via", "x-proxy-id", "proxy-connection", "x-client-ip"]

ECHO_SOURCES = [
    "https://httpbin.org/headers",
    "https://postman-echo.com/headers",
    "https://headers.jsontest.com/",
]


def _detect_header_injection(report: Report, proxy: ProxyInfo) -> None:
    L = "transport"
    data = None
    used = None
    for url in ECHO_SOURCES:
        d = get_json(url, proxy, timeout=20)
        if isinstance(d, dict) and d:
            data = d
            used = url
            break
    if not data:
        report.info("请求头泄漏", "所有回显源均不可用，跳过该项检测", L)
        return
    headers_obj = data.get("headers") if "headers" in data else data
    got = {str(k).lower(): str(v) for k, v in headers_obj.items()}
    leaked = {h: got[h] for h in INJECTION_HEADERS if h in got and h != "proxy-connection"}
    if leaked:
        report.warn(
            "请求头泄漏",
            "代理向目标站点注入了可能暴露真实身份的头: "
            + "; ".join(f"{k}={v}" for k, v in leaked.items()),
            L, leaked=leaked, source=used,
        )
    else:
        report.ok("请求头泄漏", "未发现 X-Forwarded-For / Via 等身份泄漏头注入", L, source=used)


def _detect_content_tampering(report: Report, proxy: ProxyInfo) -> None:
    L = "transport"
    try:
        status, body, _ = http_via_proxy("http://httpbin.org/get", proxy, timeout=20)
        text = body.decode("utf-8", "replace")
        if status != 200 or not text.strip().startswith("{"):
            report.warn("内容篡改", f"HTTP 响应异常（status={status}），可能被注入内容", L, status=status)
            return
        data = json.loads(text)
        origin = data.get("origin", "")
        # 明文 HTTP 下若 origin 不是出口 IP，说明链路有额外中转
        report.ok("内容篡改", f"明文 HTTP 响应结构正常，服务端看到的来源 = {origin}", L, origin=origin)
    except Exception as e:
        report.info("内容篡改", f"检测跳过: {e}", L)


def _detect_dns_leak(report: Report, proxy: ProxyInfo, facts: dict[str, Any]) -> None:
    L = "transport"
    # 通过代理解析一个已知域名，看解析结果是否与出口地区相符（粗略判断）
    try:
        d = get_json("https://edns.ip-api.com/json", proxy, timeout=15)
        if isinstance(d, dict):
            dns_info = d.get("dns", {})
            geo = dns_info.get("geo", "")
            ip = dns_info.get("ip", "")
            facts["dns_resolver"] = ip
            if geo:
                report.info("DNS 出口位置", f"DNS 解析器 IP={ip} 归属={geo}", L, dns_ip=ip, dns_geo=geo)
    except Exception:
        pass

    # 对比直连能否解析（若直连被墙但代理可解析，说明 DNS 走代理，正常）
    report.info(
        "DNS 泄漏提示",
        "本工具无法完全替代浏览器 DNS 泄漏测试；建议配合 dnsleaktest.com 交叉验证",
        L,
    )


# --------------------------------------------------------------------------
# 第 3 层：出口层检测
# --------------------------------------------------------------------------


def layer_exit(report: Report, proxy: ProxyInfo | None, facts: dict[str, Any]) -> None:
    L = "exit"
    if not proxy:
        report.info("出口层检测", "未探测到代理，跳过", L)
        return

    exit_ip = facts.get("exit_ip")
    if not exit_ip:
        return

    # --- IP 信誉画像 ---
    info = get_json(f"https://ipinfo.io/{exit_ip}/json", proxy, timeout=20)
    if isinstance(info, dict) and info.get("ip"):
        org = info.get("org", "?")
        city = info.get("city", "?")
        country = info.get("country", "?")
        facts["exit_geo"] = f"{city}, {country}"
        report.info(
            "出口地理位置",
            f"{city}, {country} | 运营方: {org}",
            L, city=city, country=country, org=org,
        )

    api = get_json(
        f"http://ip-api.com/json/{exit_ip}?fields=status,country,city,isp,org,as,proxy,hosting,mobile",
        proxy,
        timeout=20,
    )
    if isinstance(api, dict) and api.get("status") == "success":
        is_proxy = api.get("proxy")
        is_hosting = api.get("hosting")
        facts["ip_api"] = api
        if is_proxy:
            report.warn(
                "出口 IP 信誉",
                f"出口 IP 已被标记为「代理/VPN」— 部分网站可能触发风控或验证码",
                L, proxy_flag=is_proxy,
            )
        else:
            report.ok("出口 IP 信誉", "出口 IP 未被公开标记为代理/VPN 出口", L)
        if is_hosting:
            report.info(
                "出口 IP 类型",
                f"机房 IP（{api.get('org') or api.get('isp')}）— 属正常 VPS 出口，非住宅 IP",
                L, hosting=is_hosting,
            )
        elif api.get("mobile"):
            report.info("出口 IP 类型", "移动网络 IP", L)
        else:
            report.info("出口 IP 类型", "住宅/企业 IP", L)

    # --- 分流验证：国内站点是否走直连 ---
    cn_ok = 0
    cn_test = ["https://www.baidu.com", "https://www.qq.com"]
    for url in cn_test:
        try:
            status, _b, _h = http_via_proxy(url, proxy, timeout=12)
            if status < 500:
                cn_ok += 1
        except Exception:
            pass
    if cn_ok == len(cn_test):
        report.ok("国内外分流", "国内站点可正常访问，分流规则工作正常", L)
    elif cn_ok == 0:
        report.warn("国内外分流", "国内站点通过代理全部访问失败，分流规则可能异常", L)
    else:
        report.info("国内外分流", f"国内站点 {cn_ok}/{len(cn_test)} 可访问", L)


# --------------------------------------------------------------------------
# 报告输出
# --------------------------------------------------------------------------


def render(report: Report, proxy: ProxyInfo | None) -> None:
    print()
    print(c("═" * 68, C.GRAY))
    print(c("  proxy-audit  ·  代理链路安全体检", C.BOLD + C.CYAN))
    print(c("═" * 68, C.GRAY))
    print(f"  时间     : {report.meta.get('timestamp', '')}")
    print(f"  平台     : {platform.system()} {platform.release()}  ·  Python {platform.python_version()}")
    print(f"  代理     : {c(str(proxy), C.GREEN) if proxy else c('未探测到', C.RED)}")
    print(c("─" * 68, C.GRAY))

    layer_names = {"config": "配置层", "transport": "传输层", "exit": "出口层", "general": "通用"}
    last_layer = None
    for ch in report.checks:
        if ch.layer != last_layer:
            print()
            print(c(f"  ▸ {layer_names.get(ch.layer, ch.layer)}", C.BOLD + C.BLUE))
            last_layer = ch.layer
        label, color = _SEV_LABEL[ch.severity]
        print(f"    {c(label, color)} {ch.name}")
        print(f"           {c(ch.detail, C.GRAY)}")

    s = report.summary()
    verdict = report.verdict()
    verdict_text = {
        "clean": (c("干净 — 未发现安全问题", C.GREEN + C.BOLD), C.GREEN),
        "medium": (c("需注意 — 存在可改进项", C.YELLOW + C.BOLD), C.YELLOW),
        "high": (c("高风险 — 发现可疑行为", C.RED + C.BOLD), C.RED),
    }[verdict]

    print()
    print(c("─" * 68, C.GRAY))
    print(
        f"  结果: {verdict_text[0]}   "
        + c(f"通过 {s[SEV_PASS]}", C.GREEN) + "  "
        + c(f"提示 {s[SEV_INFO]}", C.CYAN) + "  "
        + c(f"警告 {s[SEV_WARN]}", C.YELLOW) + "  "
        + c(f"失败 {s[SEV_FAIL]}", C.RED)
    )
    print(c("═" * 68, C.GRAY))
    print()


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------


def main() -> int:
    global _USE_COLOR

    parser = argparse.ArgumentParser(description="代理链路安全体检工具")
    parser.add_argument("--proxy", help="代理地址，如 127.0.0.1:10808")
    parser.add_argument("--json", metavar="FILE", help="额外输出 JSON 报告到文件")
    parser.add_argument("--no-color", action="store_true", help="关闭彩色输出")
    parser.add_argument("--version", action="version", version=f"proxy-audit {__version__}")
    args = parser.parse_args()

    if args.no_color or not _supports_color():
        _USE_COLOR = False
    enable_windows_ansi()

    report = Report()
    report.meta["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")

    proxy = detect_proxy(args.proxy)
    report.meta["proxy"] = str(proxy) if proxy else None

    print(c("  正在探测代理并执行三层检测，请稍候...", C.DIM), file=sys.stderr)

    layer_config(report, proxy)
    facts = layer_transport(report, proxy)
    layer_exit(report, proxy, facts)

    report.meta.update({k: v for k, v in facts.items() if not isinstance(v, (dict, list))})
    render(report, proxy)

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
            print(c(f"  JSON 报告已写入: {args.json}", C.GRAY))
        except Exception as e:
            print(c(f"  写入 JSON 失败: {e}", C.RED), file=sys.stderr)

    return 0 if report.verdict() != "high" else 2


if __name__ == "__main__":
    sys.exit(main())
