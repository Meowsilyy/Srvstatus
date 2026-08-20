import concurrent.futures
import datetime
import hashlib
import http.client
import ipaddress
import json
import mimetypes
import os
import re
import socket
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLIC_DIR = ROOT / "public"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "3000"))
ALLOWED_HTTP_PORTS = {80, 443, 8080, 8443}
USER_AGENT = "ServerStatus/4.0"
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=18)

SERVICE_PORTS_COMMON = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP submission",
    993: "IMAPS",
    995: "POP3S",
    25565: "Minecraft Java",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alt",
    8443: "HTTPS alt",
}
SERVICE_PORTS_EXTENDED = {
    **SERVICE_PORTS_COMMON,
    20: "FTP data",
    23: "Telnet",
    81: "HTTP alt",
    111: "RPC",
    135: "MS RPC",
    139: "NetBIOS",
    389: "LDAP",
    445: "SMB",
    636: "LDAPS",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    1883: "MQTT",
    2375: "Docker",
    2376: "Docker TLS",
    3000: "Web app",
    3001: "Web app alt",
    3389: "RDP",
    5000: "Web app",
    5672: "AMQP",
    5900: "VNC",
    8000: "HTTP alt",
    8008: "HTTP alt",
    8081: "HTTP alt",
    8888: "HTTP alt",
    9000: "App service",
    9090: "App service",
    9200: "Elasticsearch",
    10000: "Web admin",
    11211: "Memcached",
    27017: "MongoDB",
}


def now_ms():
    return int(time.time() * 1000)


def is_private_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or getattr(ip, "is_site_local", False)
    )


def is_blocked_hostname(hostname):
    h = hostname.lower().rstrip(".")
    if not h or h == "localhost":
        return True
    suffixes = (".localhost", ".local", ".internal", ".home", ".lan", ".test", ".invalid", ".example")
    if h.endswith(suffixes):
        return True
    return h in {"metadata.google.internal", "metadata.google"}


def resolve_public_host(hostname):
    if is_blocked_hostname(hostname):
        raise ValueError("Private or local hostnames are not allowed")
    try:
        ip = ipaddress.ip_address(hostname)
        if is_private_ip(str(ip)):
            raise ValueError("Private, local, reserved, and documentation IP ranges are not allowed")
        return [{"address": str(ip), "family": 6 if ip.version == 6 else 4}]
    except ValueError as exc:
        if "not allowed" in str(exc):
            raise
    entries = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    found = []
    seen = set()
    for entry in entries:
        family = 6 if entry[0] == socket.AF_INET6 else 4 if entry[0] == socket.AF_INET else 0
        address = entry[4][0]
        if family and address not in seen:
            found.append({"address": address, "family": family})
            seen.add(address)
    if not found:
        raise ValueError("Hostname did not resolve to an IP address")
    if any(is_private_ip(item["address"]) for item in found):
        raise ValueError("Hostname resolves to a private, local, or reserved address")
    return found


def normalize_target(value):
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Enter a hostname, IP address, or URL")
    if len(raw) > 300:
        raise ValueError("Target is too long")
    explicit_scheme = bool(re.match(r"^https?://", raw, re.I))
    parse_value = raw if explicit_scheme else f"https://{raw}"
    try:
        parsed = urllib.parse.urlsplit(parse_value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("That target is not a valid hostname, IP address, or HTTP(S) URL")
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValueError("That target is not a valid hostname, IP address, or HTTP(S) URL")
    hostname = hostname.lower().rstrip(".")
    if is_blocked_hostname(hostname):
        raise ValueError("Private or local targets are not allowed")
    final_port = port or (443 if parsed.scheme == "https" else 80)
    if explicit_scheme and final_port not in ALLOWED_HTTP_PORTS:
        raise ValueError("HTTP(S) lookups are limited to ports 80, 443, 8080, and 8443")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    netloc_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = netloc_host
    default_port = 443 if parsed.scheme == "https" else 80
    if port and port != default_port:
        netloc = f"{netloc_host}:{port}"
    normalized_url = urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))
    return {
        "raw": raw,
        "hostname": hostname,
        "port": final_port,
        "protocol": parsed.scheme,
        "path": path,
        "explicitScheme": explicit_scheme,
        "webPortAllowed": final_port in ALLOWED_HTTP_PORTS,
        "url": normalized_url,
    }


def scan_port(address, port, service, timeout_seconds):
    started = time.perf_counter()
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    try:
        result = sock.connect_ex((address, port))
        latency = round((time.perf_counter() - started) * 1000, 1)
        return {"port": port, "service": service, "open": result == 0, "latencyMs": latency if result == 0 else None}
    except Exception:
        return {"port": port, "service": service, "open": False, "latencyMs": None}
    finally:
        sock.close()


def scan_services(address, mode="common", timeout_ms=500):
    if mode not in {"off", "common", "extended"}:
        mode = "common"
    timeout_ms = max(100, min(int(timeout_ms or 500), 1500))
    if mode == "off" or not address:
        return {"mode": "off", "address": address, "checked": 0, "open": 0, "timeoutMs": timeout_ms, "durationMs": 0, "results": []}
    ports = SERVICE_PORTS_COMMON if mode == "common" else SERVICE_PORTS_EXTENDED
    started = now_ms()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(24, len(ports))) as pool:
        futures = [pool.submit(scan_port, address, port, service, timeout_ms / 1000) for port, service in ports.items()]
        results = [future.result() for future in futures]
    results.sort(key=lambda item: item["port"])
    return {
        "mode": mode,
        "address": address,
        "checked": len(results),
        "open": sum(1 for item in results if item["open"]),
        "timeoutMs": timeout_ms,
        "durationMs": now_ms() - started,
        "results": results,
    }


def minecraft_address(target):
    raw = re.sub(r"^https?://", "", target["raw"], flags=re.I).split("/", 1)[0]
    return raw or target["hostname"]


def fetch_json(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if response.status < 200 or response.status >= 300:
            raise ValueError(f"HTTP {response.status}")
        return json.loads(response.read().decode("utf-8", "replace"))


def doh_query(name, record_type, timeout=5):
    params = urllib.parse.urlencode({"name": name, "type": record_type, "do": "1"})
    data = fetch_json(f"https://dns.google/resolve?{params}", timeout)
    return data


def strip_dns_name(value):
    return value[:-1] if value.endswith(".") else value


def parse_txt(value):
    pieces = re.findall(r'"((?:\\.|[^"\\])*)"', value)
    if pieces:
        return "".join(piece.replace('\\"', '"').replace('\\\\', '\\') for piece in pieces)
    return value


def dns_answers(name, record_type):
    try:
        data = doh_query(name, record_type)
    except Exception:
        return []
    return [item.get("data", "") for item in data.get("Answer", []) if item.get("type") == record_type]


def parse_mx(value):
    parts = value.split(maxsplit=1)
    if len(parts) != 2:
        return None
    try:
        priority = int(parts[0])
    except ValueError:
        return None
    return {"priority": priority, "exchange": strip_dns_name(parts[1])}


def parse_srv(value):
    parts = value.split(maxsplit=3)
    if len(parts) != 4:
        return None
    try:
        priority, weight, port = map(int, parts[:3])
    except ValueError:
        return None
    return {"priority": priority, "weight": weight, "port": port, "name": strip_dns_name(parts[3])}


def parse_caa(value):
    match = re.match(r"(\d+)\s+(\S+)\s+\"?(.*?)\"?$", value)
    if not match:
        return {"raw": value}
    return {"critical": int(match.group(1)), "tag": match.group(2), "value": match.group(3).strip('"')}


def parse_soa(value):
    parts = value.split()
    keys = ["nsname", "hostmaster", "serial", "refresh", "retry", "expire", "minttl"]
    if len(parts) < 7:
        return {"raw": value}
    out = {}
    for key, item in zip(keys, parts[:7]):
        if key in {"serial", "refresh", "retry", "expire", "minttl"}:
            try:
                item = int(item)
            except ValueError:
                pass
        else:
            item = strip_dns_name(item)
        out[key] = item
    return out


def gather_dns(hostname):
    result = {"a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "txt": [], "caa": [], "soa": None, "naptr": [], "ptr": [], "services": {}}
    try:
        ip = ipaddress.ip_address(hostname)
        result["ptr"] = [strip_dns_name(item) for item in dns_answers(ip.reverse_pointer, 12)]
        return result
    except ValueError:
        pass
    tasks = {
        "a": EXECUTOR.submit(dns_answers, hostname, 1),
        "aaaa": EXECUTOR.submit(dns_answers, hostname, 28),
        "cname": EXECUTOR.submit(dns_answers, hostname, 5),
        "mx": EXECUTOR.submit(dns_answers, hostname, 15),
        "ns": EXECUTOR.submit(dns_answers, hostname, 2),
        "txt": EXECUTOR.submit(dns_answers, hostname, 16),
        "caa": EXECUTOR.submit(dns_answers, hostname, 257),
        "soa": EXECUTOR.submit(dns_answers, hostname, 6),
        "naptr": EXECUTOR.submit(dns_answers, hostname, 35),
    }
    raw = {key: future.result() for key, future in tasks.items()}
    result["a"] = raw["a"]
    result["aaaa"] = raw["aaaa"]
    result["cname"] = [strip_dns_name(item) for item in raw["cname"]]
    result["mx"] = sorted([item for item in (parse_mx(value) for value in raw["mx"]) if item], key=lambda item: item["priority"])
    result["ns"] = [strip_dns_name(item) for item in raw["ns"]]
    result["txt"] = [parse_txt(item) for item in raw["txt"]]
    result["caa"] = [parse_caa(item) for item in raw["caa"]]
    result["soa"] = parse_soa(raw["soa"][0]) if raw["soa"] else None
    result["naptr"] = [{"raw": item} for item in raw["naptr"]]
    service_names = ["_minecraft._tcp", "_minecraft._udp", "_sip._tcp", "_sip._udp", "_xmpp-server._tcp", "_xmpp-client._tcp"]
    service_tasks = {prefix: EXECUTOR.submit(dns_answers, f"{prefix}.{hostname}", 33) for prefix in service_names}
    for prefix, future in service_tasks.items():
        rows = [item for item in (parse_srv(value) for value in future.result()) if item]
        if rows:
            result["services"][prefix] = rows
    ips = result["a"] + result["aaaa"]
    if ips:
        try:
            reverse = ipaddress.ip_address(ips[0]).reverse_pointer
            result["ptr"] = [strip_dns_name(item) for item in dns_answers(reverse, 12)]
        except Exception:
            pass
    return result


def lookup_ip_geo(ip):
    try:
        data = fetch_json(f"https://ipwho.is/{urllib.parse.quote(ip)}", 5)
        if data.get("success") is False:
            return None
        return {
            "ip": data.get("ip"),
            "type": data.get("type"),
            "continent": data.get("continent"),
            "country": data.get("country"),
            "countryCode": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "connection": data.get("connection"),
            "flag": data.get("flag"),
        }
    except Exception:
        return None


def entity_name(entity):
    if not entity:
        return None
    cards = entity.get("vcardArray", [None, []])
    rows = cards[1] if isinstance(cards, list) and len(cards) > 1 and isinstance(cards[1], list) else []
    for row in rows:
        if isinstance(row, list) and len(row) > 3 and row[0] == "fn":
            return row[3]
    return entity.get("handle")


def rdap_events(data):
    out = {}
    for event in (data or {}).get("events", []):
        action = event.get("eventAction")
        date = event.get("eventDate")
        if action and date:
            out[action] = date
    return out


def parse_domain_rdap(data):
    if not data:
        return None
    registrar = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            registrar = entity
            break
    return {
        "handle": data.get("handle"),
        "ldhName": data.get("ldhName"),
        "unicodeName": data.get("unicodeName"),
        "status": data.get("status", []),
        "registrar": entity_name(registrar),
        "events": rdap_events(data),
        "nameservers": [item for item in [ns.get("ldhName") or ns.get("unicodeName") for ns in data.get("nameservers", [])] if item],
        "secureDns": data.get("secureDNS"),
        "notices": [{"title": item.get("title"), "description": item.get("description")} for item in data.get("notices", [])[:8]],
    }


def parse_ip_rdap(data):
    if not data:
        return None
    entities = []
    for entity in data.get("entities", []):
        name = entity_name(entity)
        if name:
            entities.append({"name": name, "roles": entity.get("roles", [])})
    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "startAddress": data.get("startAddress"),
        "endAddress": data.get("endAddress"),
        "ipVersion": data.get("ipVersion"),
        "country": data.get("country"),
        "parentHandle": data.get("parentHandle"),
        "status": data.get("status", []),
        "events": rdap_events(data),
        "entities": entities[:10],
    }


def find_domain_rdap(hostname):
    try:
        ipaddress.ip_address(hostname)
        return {"rootDomain": None, "data": None}
    except ValueError:
        pass
    labels = [item for item in hostname.split(".") if item]
    candidates = [".".join(labels[-count:]) for count in range(2, min(len(labels), 5) + 1)]
    for candidate in candidates:
        try:
            parsed = parse_domain_rdap(fetch_json(f"https://rdap.org/domain/{urllib.parse.quote(candidate)}", 6.5))
            if parsed and parsed.get("ldhName"):
                return {"rootDomain": parsed["ldhName"].lower(), "data": parsed}
        except Exception:
            pass
    return {"rootDomain": ".".join(labels[-2:]) if len(labels) >= 2 else hostname, "data": None}


def lookup_ip_rdap(ip):
    try:
        return parse_ip_rdap(fetch_json(f"https://rdap.org/ip/{urllib.parse.quote(ip)}", 6.5))
    except Exception:
        return None


def lookup_dnssec(domain):
    if not domain:
        return None
    try:
        data = doh_query(domain, 1)
        return {
            "status": data.get("Status"),
            "authenticatedData": bool(data.get("AD")),
            "checkingDisabled": bool(data.get("CD")),
            "truncated": bool(data.get("TC")),
            "comment": data.get("Comment"),
        }
    except Exception:
        return None


def combine_headers(items):
    out = {}
    cookies = []
    for key, value in items:
        lower = key.lower()
        if lower == "set-cookie":
            cookies.append(value)
        elif lower in out:
            out[lower] = f"{out[lower]}, {value}"
        else:
            out[lower] = value
    if cookies:
        out["set-cookie"] = cookies if len(cookies) > 1 else cookies[0]
    return out


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, address, port, timeout):
        super().__init__(hostname, port=port, timeout=timeout)
        self.address = address
        self.connect_ms = None
        self.tls_ms = None

    def connect(self):
        started = time.perf_counter()
        self.sock = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        self.connect_ms = int((time.perf_counter() - started) * 1000)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, address, port, timeout):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2", "http/1.1"])
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self.address = address
        self.connect_ms = None
        self.tls_ms = None

    def connect(self):
        started = time.perf_counter()
        raw = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        self.connect_ms = int((time.perf_counter() - started) * 1000)
        tls_started = time.perf_counter()
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        self.tls_ms = int((time.perf_counter() - tls_started) * 1000)


def request_once(url_string, timeout=8, max_body=650000):
    parsed = urllib.parse.urlsplit(url_string)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Unsupported URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_HTTP_PORTS:
        raise ValueError("Redirected to a disallowed port")
    dns_started = time.perf_counter()
    resolved = resolve_public_host(parsed.hostname)
    dns_ms = int((time.perf_counter() - dns_started) * 1000)
    chosen = resolved[0]
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    conn_class = PinnedHTTPSConnection if parsed.scheme == "https" else PinnedHTTPConnection
    conn = conn_class(parsed.hostname, chosen["address"], port, timeout)
    request_started = time.perf_counter()
    headers = {
        "Host": parsed.hostname if port in {80, 443} else f"{parsed.hostname}:{port}",
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        ttfb_ms = int((time.perf_counter() - request_started) * 1000)
        body = response.read(max_body)
        total_ms = int((time.perf_counter() - request_started) * 1000)
        response_headers = combine_headers(response.getheaders())
        http_version = {10: "1.0", 11: "1.1", 20: "2.0"}.get(response.version, str(response.version))
        alpn = conn.sock.selected_alpn_protocol() if parsed.scheme == "https" and conn.sock else None
        tls_version = conn.sock.version() if parsed.scheme == "https" and conn.sock else None
        remote = conn.sock.getpeername() if conn.sock else (chosen["address"], port)
        return {
            "url": urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")),
            "status": response.status,
            "statusMessage": response.reason,
            "httpVersion": http_version,
            "headers": response_headers,
            "body": body.decode("utf-8", "replace"),
            "bodyBytesRead": len(body),
            "remoteAddress": remote[0],
            "remotePort": remote[1],
            "alpnProtocol": alpn,
            "tlsProtocol": tls_version,
            "timings": {
                "dnsMs": dns_ms,
                "tcpMs": conn.connect_ms,
                "tlsMs": conn.tls_ms,
                "ttfbMs": ttfb_ms,
                "totalMs": total_ms,
            },
        }
    finally:
        conn.close()


def probe_http(target):
    host = f"[{target['hostname']}]" if ":" in target["hostname"] else target["hostname"]
    if target["webPortAllowed"] and target["port"] != 443:
        host = f"{host}:{target['port']}"
    candidates = [target["url"]] if target["explicitScheme"] else [f"https://{host}/", f"http://{host}/"]
    last_error = None
    for candidate in candidates:
        try:
            current = candidate
            chain = []
            final = None
            for _ in range(8):
                result = request_once(current)
                location = result["headers"].get("location")
                chain.append({"url": result["url"], "status": result["status"], "location": location, "ttfbMs": result["timings"]["ttfbMs"]})
                if result["status"] in {301, 302, 303, 307, 308} and location:
                    next_url = urllib.parse.urljoin(current, location)
                    next_parsed = urllib.parse.urlsplit(next_url)
                    if next_parsed.scheme not in {"http", "https"} or not next_parsed.hostname:
                        raise ValueError("Redirected to an unsupported destination")
                    next_port = next_parsed.port or (443 if next_parsed.scheme == "https" else 80)
                    if next_port not in ALLOWED_HTTP_PORTS:
                        raise ValueError("Redirected to an unsupported destination")
                    resolve_public_host(next_parsed.hostname)
                    current = next_url
                    continue
                final = result
                break
            if final is None:
                final = request_once(current)
            return {"available": True, "chain": chain, "final": final}
        except Exception as exc:
            last_error = exc
    return {"available": False, "error": str(last_error) if last_error else "HTTP probe failed"}


def cert_tuple_to_dict(rows):
    out = {}
    for group in rows or ():
        for key, value in group:
            out[key] = value
    return out


def cert_time_iso(value):
    if not value:
        return None
    try:
        stamp = ssl.cert_time_to_seconds(value)
        return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return value


def decode_certificate(binary):
    if not binary:
        return None
    pem = ssl.DER_cert_to_PEM_cert(binary)
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False, encoding="utf-8") as temp:
            temp.write(pem)
            path = temp.name
        decoded = ssl._ssl._test_decode_cert(path)
    except Exception:
        decoded = {}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    sans = []
    for kind, value in decoded.get("subjectAltName", ()):
        sans.append(f"{kind}:{value}")
    return {
        "subject": cert_tuple_to_dict(decoded.get("subject")),
        "issuer": cert_tuple_to_dict(decoded.get("issuer")),
        "subjectAltName": ", ".join(sans) or None,
        "validFrom": cert_time_iso(decoded.get("notBefore")),
        "validTo": cert_time_iso(decoded.get("notAfter")),
        "fingerprint": ":".join(f"{byte:02X}" for byte in hashlib.sha1(binary).digest()),
        "fingerprint256": ":".join(f"{byte:02X}" for byte in hashlib.sha256(binary).digest()),
        "serialNumber": decoded.get("serialNumber"),
        "bits": None,
        "pubkeyBits": None,
    }


def verified_tls(hostname, address, port):
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((address, port), timeout=7) as raw:
        with context.wrap_socket(raw, server_hostname=None if _is_ip(hostname) else hostname) as sock:
            return True, None


def _is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def probe_tls(hostname, port=443):
    if port not in {443, 8443}:
        return {"available": False, "reason": "TLS detail probe is limited to ports 443 and 8443"}
    try:
        resolved = resolve_public_host(hostname)
        address = resolved[0]["address"]
        authorization_error = None
        authorized = False
        try:
            authorized, authorization_error = verified_tls(hostname, address, port)
        except Exception as exc:
            authorization_error = str(exc)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((address, port), timeout=7) as raw:
            with context.wrap_socket(raw, server_hostname=None if _is_ip(hostname) else hostname) as sock:
                binary = sock.getpeercert(binary_form=True)
                cipher = sock.cipher()
                return {
                    "available": True,
                    "authorized": authorized,
                    "authorizationError": authorization_error,
                    "protocol": sock.version(),
                    "alpn": sock.selected_alpn_protocol(),
                    "cipher": {"name": cipher[0], "version": cipher[1], "bits": cipher[2]} if cipher else None,
                    "ephemeralKey": None,
                    "ocspStapled": False,
                    "certificate": decode_certificate(binary),
                }
    except Exception as exc:
        return {"available": False, "reason": str(exc)}


def extract_title(html):
    match = re.search(r"<title[^>]*>([\s\S]*?)</title>", html, re.I)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:240] if match else None


def extract_meta(html, name):
    escaped = re.escape(name)
    patterns = [
        rf'<meta[^>]+(?:name|property)=["\']{escaped}["\'][^>]+content=["\']([^"\']+)["\']',
        rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:name|property)=["\']{escaped}["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.I)
        if match:
            return match.group(1).strip()
    return None


def detect_tech(headers, html):
    hints = []

    def add(name, evidence, confidence="medium", category="software"):
        if name and not any(item["name"] == name for item in hints):
            hints.append({"name": name, "evidence": evidence, "confidence": confidence, "category": category})

    server = str(headers.get("server") or "")
    powered = str(headers.get("x-powered-by") or "")
    via = str(headers.get("via") or "")
    if server:
        add(server, "Server header", "high", "server")
    if powered:
        add(powered, "X-Powered-By header", "high", "runtime")
    if headers.get("x-vercel-id") or re.search("vercel", server, re.I):
        add("Vercel", "Vercel response headers", "high", "platform")
    if headers.get("x-nf-request-id") or re.search("netlify", server, re.I):
        add("Netlify", "Netlify response headers", "high", "platform")
    if headers.get("cf-ray") or re.search("cloudflare", server, re.I):
        add("Cloudflare", "Cloudflare edge headers", "high", "edge")
    if headers.get("x-amz-cf-pop") or re.search("cloudfront", via, re.I):
        add("Amazon CloudFront", "CloudFront response headers", "high", "edge")
    if headers.get("x-served-by") and headers.get("x-cache"):
        add("Fastly", "Cache and edge headers", "medium", "edge")
    if re.search(r"wp-content|wp-includes", html, re.I):
        add("WordPress", "WordPress asset paths", "high", "cms")
    if re.search(r"_next/static|__next_data__", html, re.I):
        add("Next.js", "Next.js page markers", "high", "framework")
    if re.search(r"/_nuxt/|__NUXT__", html, re.I):
        add("Nuxt", "Nuxt page markers", "high", "framework")
    if re.search(r"cdn\.shopify\.com|shopify-section", html, re.I):
        add("Shopify", "Shopify page markers", "high", "platform")
    if re.search(r"static\.wixstatic\.com|wix-code-sdk", html, re.I):
        add("Wix", "Wix page markers", "high", "platform")
    if re.search(r"webflow\.js|data-wf-page=", html, re.I):
        add("Webflow", "Webflow page markers", "high", "platform")
    if re.search(r"cdn\.squarespace\.com|static1\.squarespace\.com", html, re.I):
        add("Squarespace", "Squarespace asset hosts", "high", "platform")
    if re.search(r"drupalSettings|sites/default/files", html, re.I):
        add("Drupal", "Drupal page markers", "medium", "cms")
    if re.search(r"joomla|/media/system/js/", html, re.I):
        add("Joomla", "Joomla page markers", "medium", "cms")
    generator = extract_meta(html, "generator")
    if generator:
        add(generator, "Generator metadata", "high", "generator")
    if re.search(r"data-reactroot|__react|react-dom", html, re.I):
        add("React", "React page markers", "medium", "framework")
    if re.search(r"__vue__|data-v-[0-9a-f]{6,}|vue\.runtime", html, re.I):
        add("Vue", "Vue page markers", "medium", "framework")
    return hints[:28]


def detect_edge(headers, ip_geo, dns_data):
    evidence = []
    provider = None
    server = str(headers.get("server") or "")
    via = str(headers.get("via") or "")
    connection = (ip_geo or {}).get("connection") or {}
    asn = str(connection.get("asn") or "")
    isp = str(connection.get("isp") or "")
    org = str(connection.get("org") or "")

    def add(text):
        if text and text not in evidence:
            evidence.append(text)

    if headers.get("cf-ray") or headers.get("cf-cache-status") or re.search("cloudflare", server, re.I) or "13335" in asn:
        provider = "Cloudflare"
        if headers.get("cf-ray"):
            add(f"cf-ray: {headers['cf-ray']}")
        if headers.get("cf-cache-status"):
            add(f"cf-cache-status: {headers['cf-cache-status']}")
        if re.search("cloudflare", server, re.I):
            add(f"server: {server}")
        if "13335" in asn:
            add(f"ASN: {asn}")
    elif headers.get("x-vercel-id") or re.search("vercel", server + isp + org, re.I):
        provider = "Vercel"
        add(f"x-vercel-id: {headers['x-vercel-id']}" if headers.get("x-vercel-id") else "Vercel network fingerprint")
    elif headers.get("x-nf-request-id") or re.search("netlify", server + isp + org, re.I):
        provider = "Netlify"
        add(f"x-nf-request-id: {headers['x-nf-request-id']}" if headers.get("x-nf-request-id") else "Netlify network fingerprint")
    elif headers.get("x-amz-cf-pop") or re.search("cloudfront", via, re.I):
        provider = "Amazon CloudFront"
        add(f"x-amz-cf-pop: {headers['x-amz-cf-pop']}" if headers.get("x-amz-cf-pop") else f"via: {via}")
    elif (headers.get("x-served-by") and headers.get("x-cache")) or re.search("fastly", via + isp + org, re.I):
        provider = "Fastly"
        add("Fastly cache headers")
    elif re.search("akamai", server + via + isp + org, re.I) or any(key.startswith("x-akamai") for key in headers):
        provider = "Akamai"
        add("Akamai network fingerprint")
    elif headers.get("fly-request-id") or re.search(r"fly\.io", server + isp + org, re.I):
        provider = "Fly.io"
        add("Fly.io network fingerprint")
    cnames = dns_data.get("cname", [])
    if cnames:
        add("CNAME: " + ", ".join(cnames))
    edge_point = None
    if headers.get("cf-ray"):
        match = re.search(r"-([A-Z]{3})$", str(headers.get("cf-ray")), re.I)
        if match:
            edge_point = match.group(1).upper()
    if not edge_point and headers.get("x-amz-cf-pop"):
        edge_point = str(headers.get("x-amz-cf-pop"))
    if not edge_point and headers.get("x-vercel-id"):
        edge_point = str(headers.get("x-vercel-id")).split("::", 1)[0]
    return {
        "provider": provider,
        "detected": bool(provider),
        "evidence": evidence,
        "cloudflare": "detected" if provider == "Cloudflare" else "not detected",
        "edgePoint": edge_point,
        "requestPath": f"{provider} edge" if provider else "Direct or unidentified edge",
    }


def detect_network_provider(ip_geo, ip_rdap, edge, technologies):
    connection = (ip_geo or {}).get("connection") or {}
    parts = [
        connection.get("asn"),
        connection.get("isp"),
        connection.get("org"),
        connection.get("domain"),
        (ip_rdap or {}).get("name"),
        (ip_rdap or {}).get("handle"),
    ]
    for entity in (ip_rdap or {}).get("entities", []):
        parts.append(entity.get("name"))
    haystack = " | ".join(str(x) for x in parts if x).lower()
    patterns = [
        (("oracle cloud", "oracle corporation", "oracle"), "Oracle Cloud"),
        (("microsoft", "azure"), "Microsoft Azure"),
        (("amazon", "aws", "amazon technologies"), "Amazon Web Services"),
        (("google cloud", "google llc", "googleusercontent"), "Google Cloud"),
        (("digitalocean",), "DigitalOcean"),
        (("hetzner",), "Hetzner"),
        (("ovh",), "OVHcloud"),
        (("vultr", "choopa"), "Vultr"),
        (("linode", "akamai connected cloud"), "Akamai Connected Cloud"),
        (("cloudflare",), "Cloudflare"),
        (("fastly",), "Fastly"),
        (("fly.io", "flyio"), "Fly.io"),
        (("vercel",), "Vercel"),
        (("netlify",), "Netlify"),
        (("leaseweb",), "Leaseweb"),
        (("contabo",), "Contabo"),
        (("ionos", "1&1 internet"), "IONOS"),
        (("alibaba", "aliyun"), "Alibaba Cloud"),
        (("tencent",), "Tencent Cloud"),
        (("rackspace",), "Rackspace"),
        (("kamatera",), "Kamatera"),
        (("hostinger",), "Hostinger"),
    ]
    for needles, provider in patterns:
        if any(needle in haystack for needle in needles):
            return provider, [item for item in parts if item][:6]
    if edge.get("provider"):
        return edge["provider"], ["Edge/network fingerprint"]
    for tech in technologies:
        if tech.get("category") in {"platform", "edge"}:
            return tech.get("name"), [tech.get("evidence")]
    return connection.get("org") or connection.get("isp") or (ip_rdap or {}).get("name"), [item for item in parts if item][:4]


def detect_dns_provider(nameservers):
    joined = " ".join(nameservers or []).lower()
    mappings = [
        ("cloudflare.com", "Cloudflare DNS"),
        ("awsdns-", "Amazon Route 53"),
        ("azure-dns", "Azure DNS"),
        ("googledomains.com", "Google Cloud DNS"),
        ("ns-cloud-", "Google Cloud DNS"),
        ("digitalocean.com", "DigitalOcean DNS"),
        ("hetzner.com", "Hetzner DNS"),
        ("ovh.net", "OVH DNS"),
        ("registrar-servers.com", "Namecheap DNS"),
        ("domaincontrol.com", "GoDaddy DNS"),
        ("ui-dns", "IONOS DNS"),
        ("nsone.net", "NS1"),
        ("cloudns", "ClouDNS"),
    ]
    for needle, name in mappings:
        if needle in joined:
            return name
    return None


def detect_mail_provider(mail):
    hosts = " ".join(item.get("exchange", "") for item in (mail or {}).get("mx", [])).lower()
    mappings = [
        (("google.com", "googlemail.com"), "Google Workspace"),
        (("outlook.com", "protection.outlook.com"), "Microsoft 365"),
        (("protonmail", "proton.ch"), "Proton Mail"),
        (("zoho",), "Zoho Mail"),
        (("fastmail", "messagingengine.com"), "Fastmail"),
        (("icloud.com",), "iCloud Mail"),
        (("mimecast",), "Mimecast"),
        (("pphosted.com", "proofpoint"), "Proofpoint"),
        (("mxroute",), "MXroute"),
    ]
    for needles, name in mappings:
        if any(needle in hosts for needle in needles):
            return name
    return None


def build_infrastructure(ip_geo, ip_rdap, dns_data, mail, web, edge, technologies):
    connection = (ip_geo or {}).get("connection") or {}
    headers = (web or {}).get("headers") or {}
    provider, provider_evidence = detect_network_provider(ip_geo, ip_rdap, edge, technologies)
    return {
        "observedProvider": provider,
        "providerEvidence": provider_evidence,
        "networkOwner": connection.get("org") or (ip_rdap or {}).get("name"),
        "isp": connection.get("isp"),
        "asn": connection.get("asn"),
        "networkDomain": connection.get("domain"),
        "dnsProvider": detect_dns_provider(dns_data.get("ns", [])),
        "mailProvider": detect_mail_provider(mail),
        "serverSoftware": headers.get("server"),
        "poweredBy": headers.get("x-powered-by"),
        "via": headers.get("via"),
        "edgeProvider": edge.get("provider"),
        "edgePoint": edge.get("edgePoint"),
        "reverseDns": (dns_data.get("ptr") or [None])[0],
        "resolvedAddressCount": len(dns_data.get("a", [])) + len(dns_data.get("aaaa", [])),
    }

def security_analysis(headers):
    csp = str(headers.get("content-security-policy") or "")
    hsts = str(headers.get("strict-transport-security") or "")
    raw_cookies = headers.get("set-cookie")
    cookies = raw_cookies if isinstance(raw_cookies, list) else [raw_cookies] if raw_cookies else []
    checks = [
        ("Strict-Transport-Security", bool(hsts), 15),
        ("Content-Security-Policy", bool(csp), 20),
        ("X-Content-Type-Options", bool(re.search("nosniff", str(headers.get("x-content-type-options") or ""), re.I)), 10),
        ("Referrer-Policy", bool(headers.get("referrer-policy")), 10),
        ("Permissions-Policy", bool(headers.get("permissions-policy")), 10),
        ("Frame protection", bool(headers.get("x-frame-options")) or bool(re.search("frame-ancestors", csp, re.I)), 10),
        ("Cross-Origin-Opener-Policy", bool(headers.get("cross-origin-opener-policy")), 5),
        ("Cross-Origin-Embedder-Policy", bool(headers.get("cross-origin-embedder-policy")), 5),
        ("Cross-Origin-Resource-Policy", bool(headers.get("cross-origin-resource-policy")), 5),
        ("No X-Powered-By disclosure", not bool(headers.get("x-powered-by")), 5),
        ("Secure cookie posture", not cookies or all(re.search(r";\s*secure", cookie, re.I) for cookie in cookies), 5),
    ]
    score = sum(weight for _, passed, weight in checks if passed)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    cookie_details = []
    for cookie in cookies:
        match = re.search(r";\s*samesite=(strict|lax|none)", cookie, re.I)
        cookie_details.append({
            "name": cookie.split("=", 1)[0].strip() or "cookie",
            "secure": bool(re.search(r";\s*secure", cookie, re.I)),
            "httpOnly": bool(re.search(r";\s*httponly", cookie, re.I)),
            "sameSite": match.group(1) if match else None,
        })
    return {
        "score": score,
        "grade": grade,
        "note": "Weighted from common response headers and cookie flags.",
        "checks": [{"name": name, "pass": passed, "weight": weight} for name, passed, weight in checks],
        "details": {
            "hsts": hsts,
            "csp": csp,
            "cspUnsafeInline": bool(re.search("'unsafe-inline'", csp, re.I)),
            "cspUnsafeEval": bool(re.search("'unsafe-eval'", csp, re.I)),
            "corsAllowOrigin": headers.get("access-control-allow-origin"),
            "xFrameOptions": headers.get("x-frame-options"),
            "xContentTypeOptions": headers.get("x-content-type-options"),
            "referrerPolicy": headers.get("referrer-policy"),
            "permissionsPolicy": headers.get("permissions-policy"),
            "coop": headers.get("cross-origin-opener-policy"),
            "coep": headers.get("cross-origin-embedder-policy"),
            "corp": headers.get("cross-origin-resource-policy"),
            "cookies": cookie_details,
        },
    }


def same_host_resource(base_url, pathname):
    try:
        base = urllib.parse.urlsplit(base_url)
        url = urllib.parse.urljoin(base_url, pathname)
        parsed = urllib.parse.urlsplit(url)
        if parsed.hostname != base.hostname:
            return None
        result = request_once(url, 5.5, 120000)
        content_type = result["headers"].get("content-type")
        preview = result["body"][:1600] if content_type and (content_type.lower().startswith("text/") or re.search(r"json|xml", content_type, re.I)) else None
        return {"url": url, "status": result["status"], "contentType": content_type, "bytesRead": result["bodyBytesRead"], "preview": preview}
    except Exception:
        return None


def email_dns(root_domain):
    if not root_domain:
        return None
    tasks = {
        "mx": EXECUTOR.submit(dns_answers, root_domain, 15),
        "txt": EXECUTOR.submit(dns_answers, root_domain, 16),
        "dmarc": EXECUTOR.submit(dns_answers, f"_dmarc.{root_domain}", 16),
        "mta": EXECUTOR.submit(dns_answers, f"_mta-sts.{root_domain}", 16),
        "bimi": EXECUTOR.submit(dns_answers, f"default._bimi.{root_domain}", 16),
    }
    mx = sorted([item for item in (parse_mx(value) for value in tasks["mx"].result()) if item], key=lambda item: item["priority"])
    root_txt = [parse_txt(item) for item in tasks["txt"].result()]
    return {
        "mx": mx,
        "spf": [item for item in root_txt if re.match(r"^v=spf1", item, re.I)],
        "dmarc": [parse_txt(item) for item in tasks["dmarc"].result()],
        "mtaSts": [parse_txt(item) for item in tasks["mta"].result()],
        "bimi": [parse_txt(item) for item in tasks["bimi"].result()],
    }


def minecraft_lookup(address):
    encoded = urllib.parse.quote(address, safe="")
    java_future = EXECUTOR.submit(_safe_fetch_json, f"https://api.mcsrvstat.us/3/{encoded}", 7)
    bedrock_future = EXECUTOR.submit(_safe_fetch_json, f"https://api.mcsrvstat.us/bedrock/3/{encoded}", 7)
    return {"address": address, "java": java_future.result(), "bedrock": bedrock_future.result(), "cacheNote": "mcsrvstat.us status data is cached by the upstream API for about 5 minutes."}


def _safe_fetch_json(url, timeout):
    try:
        return fetch_json(url, timeout)
    except Exception:
        return None


def parse_date(value):
    if not value:
        return None
    normalized = str(value).replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(normalized)
    except ValueError:
        try:
            return datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(value), datetime.timezone.utc)
        except Exception:
            return None


def domain_age(events):
    created = parse_date((events or {}).get("registration"))
    if not created:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=datetime.timezone.utc)
    days = max(0, (datetime.datetime.now(datetime.timezone.utc) - created).days)
    return {"days": days, "years": round(days / 365.2425, 2)}


def header_clock_skew(value):
    if not value:
        return None
    try:
        parsed = email_date_to_datetime(value)
        return round((parsed - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    except Exception:
        return None


def email_date_to_datetime(value):
    import email.utils
    parsed = email.utils.parsedate_to_datetime(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def lookup(value, options=None):
    started = now_ms()
    options = options if isinstance(options, dict) else {}
    scan_mode = str(options.get("scanMode") or "common").lower()
    if scan_mode not in {"off", "common", "extended"}:
        scan_mode = "common"
    try:
        scan_timeout = int(options.get("scanTimeout") or 500)
    except Exception:
        scan_timeout = 500
    scan_timeout = max(100, min(scan_timeout, 1500))
    minecraft_enabled = options.get("minecraft") is not False
    target = normalize_target(value)
    resolved = resolve_public_host(target["hostname"])
    dns_future = EXECUTOR.submit(gather_dns, target["hostname"])
    rdap_future = EXECUTOR.submit(find_domain_rdap, target["hostname"])
    http_future = EXECUTOR.submit(probe_http, target)
    tls_port = target["port"] if target["explicitScheme"] else 8443 if target["webPortAllowed"] and target["port"] == 8443 else 443
    tls_future = EXECUTOR.submit(probe_tls, target["hostname"], tls_port)
    dns_data = dns_future.result()
    rdap = rdap_future.result()
    http_data = http_future.result()
    tls_data = tls_future.result()
    root_domain = rdap["rootDomain"]
    primary_ip = http_data["final"]["remoteAddress"] if http_data.get("available") else resolved[0]["address"] if resolved else None
    geo_future = EXECUTOR.submit(lookup_ip_geo, primary_ip) if primary_ip else None
    ip_rdap_future = EXECUTOR.submit(lookup_ip_rdap, primary_ip) if primary_ip else None
    dnssec_future = EXECUTOR.submit(lookup_dnssec, root_domain) if root_domain else None
    mail_future = EXECUTOR.submit(email_dns, root_domain) if root_domain else None
    scan_future = EXECUTOR.submit(scan_services, primary_ip, scan_mode, scan_timeout) if primary_ip else None
    mc_future = EXECUTOR.submit(minecraft_lookup, minecraft_address(target)) if minecraft_enabled else None
    ip_geo = geo_future.result() if geo_future else None
    ip_rdap = ip_rdap_future.result() if ip_rdap_future else None
    dnssec = dnssec_future.result() if dnssec_future else None
    mail = mail_future.result() if mail_future else None
    service_scan = scan_future.result() if scan_future else {"mode": scan_mode, "address": primary_ip, "checked": 0, "open": 0, "timeoutMs": scan_timeout, "durationMs": 0, "results": []}
    minecraft = mc_future.result() if mc_future else {"address": minecraft_address(target), "skipped": True, "java": None, "bedrock": None, "cacheNote": "Disabled"}
    web = None
    edge = {"provider": None, "detected": False, "evidence": [], "cloudflare": "not detected", "requestPath": "HTTP unavailable"}
    security = None
    technologies = []
    resources = None
    if http_data.get("available"):
        final = http_data["final"]
        headers = final["headers"]
        html = final["body"] or ""
        technologies = detect_tech(headers, html)
        edge = detect_edge(headers, ip_geo, dns_data)
        security = security_analysis(headers)
        resource_futures = [
            EXECUTOR.submit(same_host_resource, final["url"], "/robots.txt"),
            EXECUTOR.submit(same_host_resource, final["url"], "/sitemap.xml"),
            EXECUTOR.submit(same_host_resource, final["url"], "/.well-known/security.txt"),
            EXECUTOR.submit(same_host_resource, final["url"], "/favicon.ico"),
        ]
        resource_results = [future.result() for future in resource_futures]
        resources = {"robots": resource_results[0], "sitemap": resource_results[1], "securityTxt": resource_results[2], "favicon": resource_results[3]}
        content_type = str(headers.get("content-type") or "")
        lang_match = re.search(r'<html[^>]+lang=["\']([^"\']+)', html, re.I)
        charset_match = re.search(r'<meta[^>]+charset=["\']?([^\s"\'/>]+)', html, re.I)
        if not charset_match:
            charset_match = re.search(r"charset=([^;\s]+)", content_type, re.I)
        web = {
            "finalUrl": final["url"],
            "status": final["status"],
            "statusMessage": final["statusMessage"],
            "httpVersion": final["httpVersion"],
            "remoteAddress": final["remoteAddress"],
            "remotePort": final["remotePort"],
            "alpnProtocol": final["alpnProtocol"],
            "tlsProtocol": final["tlsProtocol"],
            "timings": final["timings"],
            "redirects": http_data["chain"],
            "headers": headers,
            "page": {
                "title": extract_title(html),
                "description": extract_meta(html, "description"),
                "generator": extract_meta(html, "generator"),
                "contentType": headers.get("content-type"),
                "contentLengthHeader": headers.get("content-length"),
                "bytesSampled": final["bodyBytesRead"],
                "language": lang_match.group(1) if lang_match else None,
                "charset": charset_match.group(1) if charset_match else None,
                "clockSkewSeconds": header_clock_skew(headers.get("date")),
                "http3Advertised": bool(re.search(r"\bh3(?:-|=|\b)", str(headers.get("alt-svc") or ""), re.I)),
                "compression": headers.get("content-encoding") or "none/identity",
                "cacheControl": headers.get("cache-control"),
                "age": headers.get("age"),
                "etag": headers.get("etag"),
                "lastModified": headers.get("last-modified"),
                "serverTiming": headers.get("server-timing"),
                "sampleSha256": hashlib.sha256(html.encode("utf-8", "replace")).hexdigest() if html else None,
                "headersSha256": hashlib.sha256(json.dumps(headers, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
            },
        }
    registration = None
    if rdap.get("data"):
        registration = dict(rdap["data"])
        registration["domainAge"] = domain_age(registration.get("events"))
    infrastructure = build_infrastructure(ip_geo, ip_rdap, dns_data, mail, web, edge, technologies)
    summary = {
        "target": target["hostname"],
        "online": bool(http_data.get("available")),
        "httpStatus": web.get("status") if web else None,
        "primaryIp": primary_ip,
        "ipv4Count": len(dns_data["a"]),
        "ipv6Count": len(dns_data["aaaa"]),
        "ipv6Supported": len(dns_data["aaaa"]) > 0,
        "edgeProvider": edge.get("provider"),
        "edgePoint": edge.get("edgePoint"),
        "cloudflare": edge.get("cloudflare"),
        "networkProvider": infrastructure.get("observedProvider"),
        "networkOwner": infrastructure.get("networkOwner"),
        "asn": infrastructure.get("asn"),
        "dnsProvider": infrastructure.get("dnsProvider"),
        "mailProvider": infrastructure.get("mailProvider"),
        "server": infrastructure.get("serverSoftware"),
        "poweredBy": infrastructure.get("poweredBy"),
        "openPortCount": service_scan.get("open"),
        "country": (ip_geo or {}).get("country"),
        "region": (ip_geo or {}).get("region"),
        "httpVersion": web.get("httpVersion") if web else None,
        "tlsVersion": tls_data.get("protocol") if tls_data else None,
        "alpn": tls_data.get("alpn") if tls_data else web.get("alpnProtocol") if web else None,
        "dnssec": dnssec.get("authenticatedData") if dnssec else None,
        "registrar": registration.get("registrar") if registration else None,
        "domainAgeYears": registration.get("domainAge", {}).get("years") if registration and registration.get("domainAge") else None,
        "minecraftJavaOnline": minecraft.get("java", {}).get("online") if minecraft.get("java") else None,
        "minecraftBedrockOnline": minecraft.get("bedrock", {}).get("online") if minecraft.get("bedrock") else None,
    }
    return {
        "meta": {
            "product": "ServerStatus",
            "requestedTarget": value,
            "normalizedHost": target["hostname"],
            "rootDomain": root_domain,
            "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "durationMs": now_ms() - started,
            "engine": "HTTP + DNS + TLS + RDAP + TCP services + Minecraft",
        },
        "summary": summary,
        "web": web,
        "edge": edge,
        "tls": tls_data,
        "dns": dns_data,
        "dnssec": dnssec,
        "network": {"resolvedAddresses": resolved, "primaryIp": primary_ip, "geolocation": ip_geo, "registration": ip_rdap},
        "infrastructure": infrastructure,
        "serviceScan": service_scan,
        "registration": registration,
        "email": mail,
        "security": security,
        "technologies": technologies,
        "resources": resources,
        "minecraft": minecraft,
    }


class ServerStatusHandler(BaseHTTPRequestHandler):
    server_version = "ServerStatus"

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

    def send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/lookup":
            self.send_json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 12000:
                raise ValueError("Request body is too large")
            payload = json.loads(self.rfile.read(length or 0).decode("utf-8") or "{}")
            result = lookup(payload.get("target"), payload.get("options"))
            self.send_json(200, result)
        except Exception as exc:
            self.send_json(400, {"error": str(exc) or "Lookup failed"})

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        pathname = urllib.parse.unquote(parsed.path)
        requested = "index.html" if pathname == "/" else pathname.lstrip("/")
        candidate = (PUBLIC_DIR / requested).resolve()
        if PUBLIC_DIR.resolve() not in candidate.parents and candidate != PUBLIC_DIR.resolve():
            self.send_json(404, {"error": "Not found"})
            return
        if not candidate.is_file():
            self.send_json(404, {"error": "Not found"})
            return
        mime = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") or mime in {"application/javascript", "application/json"} else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def open_browser():
    if os.environ.get("NO_BROWSER") == "1":
        return
    webbrowser.open(f"http://127.0.0.1:{PORT}")


def main():
    server = ThreadingHTTPServer((HOST, PORT), ServerStatusHandler)
    print()
    print("ServerStatus")
    print(f"Local URL: http://127.0.0.1:{PORT}")
    print("Close this window or press Ctrl+C to stop it.")
    print()
    threading.Timer(0.7, open_browser).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        EXECUTOR.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
