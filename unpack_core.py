import datetime
import hashlib
import html
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser

USER_AGENT = "Unpack/1.0"
ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_HTML_BYTES = 1_500_000
MAX_SOURCE_CHARS = 900_000


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
    host = (hostname or "").lower().rstrip(".")
    if not host or host == "localhost":
        return True
    if host in {"metadata.google.internal", "metadata.google"}:
        return True
    return host.endswith((".localhost", ".local", ".internal", ".home", ".lan", ".test", ".invalid", ".example"))


def resolve_public_host(hostname):
    if is_blocked_hostname(hostname):
        raise ValueError("Local and private addresses are not supported")
    try:
        ip = ipaddress.ip_address(hostname)
        address = str(ip)
        if is_private_ip(address):
            raise ValueError("Local, private and reserved IP ranges are not supported")
        return [{"address": address, "family": 6 if ip.version == 6 else 4}]
    except ValueError as exc:
        if "not supported" in str(exc):
            raise
    try:
        entries = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The hostname did not resolve")
    seen = set()
    found = []
    for entry in entries:
        family = 6 if entry[0] == socket.AF_INET6 else 4 if entry[0] == socket.AF_INET else 0
        address = entry[4][0]
        if family and address not in seen:
            if is_private_ip(address):
                raise ValueError("The hostname resolves to a local, private or reserved address")
            found.append({"address": address, "family": family})
            seen.add(address)
    if not found:
        raise ValueError("The hostname did not resolve")
    return found


def normalize_url(value):
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Enter a website address")
    if len(raw) > 500:
        raise ValueError("That address is too long")
    supplied_scheme = bool(re.match(r"^https?://", raw, re.I))
    parsed = urllib.parse.urlsplit(raw if supplied_scheme else f"https://{raw}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS address")
    hostname = parsed.hostname.lower().rstrip(".")
    if is_blocked_hostname(hostname):
        raise ValueError("Local and private addresses are not supported")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError("Website checks are limited to ports 80, 443, 8080 and 8443")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, address, port, timeout):
        super().__init__(hostname, port=port, timeout=timeout)
        self.address = address
        self.connect_ms = None

    def connect(self):
        started = time.perf_counter()
        self.sock = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        self.connect_ms = round((time.perf_counter() - started) * 1000, 1)


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
        self.connect_ms = round((time.perf_counter() - started) * 1000, 1)
        tls_started = time.perf_counter()
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        self.tls_ms = round((time.perf_counter() - tls_started) * 1000, 1)


def combine_headers(items):
    result = {}
    cookies = []
    for key, value in items:
        lower = key.lower()
        if lower == "set-cookie":
            cookies.append(value)
        elif lower in result:
            result[lower] = f"{result[lower]}, {value}"
        else:
            result[lower] = value
    if cookies:
        result["set-cookie"] = cookies
    return result


def request_once(url, timeout=7.0, max_bytes=MAX_HTML_BYTES, method="GET"):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Unsupported URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError("Redirected to an unsupported port")
    resolved = resolve_public_host(parsed.hostname)
    chosen = resolved[0]
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    conn_cls = PinnedHTTPSConnection if parsed.scheme == "https" else PinnedHTTPConnection
    conn = conn_cls(parsed.hostname, chosen["address"], port, timeout)
    headers = {
        "Host": parsed.hostname if port in {80, 443} else f"{parsed.hostname}:{port}",
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    started = time.perf_counter()
    try:
        conn.request(method, path, headers=headers)
        response = conn.getresponse()
        ttfb = round((time.perf_counter() - started) * 1000, 1)
        body = b"" if method == "HEAD" else response.read(max_bytes)
        total = round((time.perf_counter() - started) * 1000, 1)
        response_headers = combine_headers(response.getheaders())
        remote = conn.sock.getpeername() if conn.sock else (chosen["address"], port)
        return {
            "url": urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")),
            "status": response.status,
            "reason": response.reason,
            "headers": response_headers,
            "body": body,
            "remoteAddress": remote[0],
            "remotePort": remote[1],
            "resolved": resolved,
            "timings": {
                "connectMs": conn.connect_ms,
                "tlsMs": getattr(conn, "tls_ms", None),
                "ttfbMs": ttfb,
                "totalMs": total,
            },
            "tlsProtocol": conn.sock.version() if parsed.scheme == "https" and conn.sock else None,
            "alpn": conn.sock.selected_alpn_protocol() if parsed.scheme == "https" and conn.sock else None,
        }
    finally:
        conn.close()


def fetch_with_redirects(value, timeout=7.0):
    current = normalize_url(value)
    chain = []
    for _ in range(7):
        result = request_once(current, timeout=timeout)
        location = result["headers"].get("location")
        chain.append({"url": result["url"], "status": result["status"], "location": location})
        if result["status"] in {301, 302, 303, 307, 308} and location:
            current = normalize_url(urllib.parse.urljoin(current, location))
            continue
        return result, chain
    raise ValueError("Too many redirects")


def body_charset(headers):
    content_type = str(headers.get("content-type") or "")
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    if match:
        return match.group(1).strip('"\'')
    return "utf-8"


class PageParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts = []
        self.in_title = False
        self.meta = []
        self.assets = []
        self.links = []
        self.forms = []
        self.lang = None

    def absolute(self, value):
        if not value or value.startswith(("data:", "javascript:", "mailto:", "tel:")):
            return None
        return urllib.parse.urljoin(self.base_url, value)

    def add_asset(self, kind, value, attrs=None):
        url = self.absolute(value)
        if url and len(self.assets) < 300:
            self.assets.append({"type": kind, "url": url, "attrs": attrs or {}})

    def handle_starttag(self, tag, attrs):
        data = {str(k).lower(): v for k, v in attrs if k}
        if tag == "html" and not self.lang:
            self.lang = data.get("lang")
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            key = data.get("name") or data.get("property") or data.get("http-equiv")
            value = data.get("content")
            if key and value and len(self.meta) < 100:
                self.meta.append({"name": key, "content": value})
        elif tag == "script" and data.get("src"):
            self.add_asset("script", data.get("src"), {"type": data.get("type"), "async": "async" in data, "defer": "defer" in data})
        elif tag == "link" and data.get("href"):
            rel = str(data.get("rel") or "").lower()
            kind = "stylesheet" if "stylesheet" in rel else "icon" if "icon" in rel else "manifest" if "manifest" in rel else "preload" if "preload" in rel else "link"
            self.add_asset(kind, data.get("href"), {"rel": rel, "as": data.get("as")})
        elif tag in {"img", "source", "video", "audio"} and data.get("src"):
            self.add_asset(tag, data.get("src"))
        elif tag == "iframe" and data.get("src"):
            self.add_asset("iframe", data.get("src"))
        elif tag == "a" and data.get("href"):
            url = self.absolute(data.get("href"))
            if url and len(self.links) < 500:
                self.links.append(url)
        elif tag == "form":
            action = self.absolute(data.get("action") or self.base_url)
            if len(self.forms) < 50:
                self.forms.append({"method": str(data.get("method") or "GET").upper(), "action": action})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def parse_page(source, final_url):
    parser = PageParser(final_url)
    try:
        parser.feed(source)
    except Exception:
        pass
    title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip()[:300] or None
    meta_map = {}
    for item in parser.meta:
        key = str(item["name"]).lower()
        meta_map.setdefault(key, item["content"])
    host = urllib.parse.urlsplit(final_url).hostname
    internal = 0
    external = 0
    for link in parser.links:
        parsed = urllib.parse.urlsplit(link)
        if parsed.hostname == host:
            internal += 1
        elif parsed.hostname:
            external += 1
    return {
        "title": title,
        "description": meta_map.get("description") or meta_map.get("og:description"),
        "language": parser.lang,
        "generator": meta_map.get("generator"),
        "canonical": next((a["url"] for a in parser.assets if a["type"] == "link" and "canonical" in str(a.get("attrs", {}).get("rel", ""))), None),
        "meta": parser.meta,
        "assets": dedupe_rows(parser.assets, "url"),
        "forms": parser.forms,
        "links": {"total": len(parser.links), "internal": internal, "external": external},
    }


def dedupe_rows(rows, key):
    seen = set()
    result = []
    for row in rows:
        value = row.get(key)
        if value and value not in seen:
            seen.add(value)
            result.append(row)
    return result


def detect_technology(headers, source):
    found = []

    def add(name, evidence):
        if not any(item["name"] == name for item in found):
            found.append({"name": name, "evidence": evidence})

    server = str(headers.get("server") or "")
    powered = str(headers.get("x-powered-by") or "")
    if server:
        add(server, "Server header")
    if powered:
        add(powered, "X-Powered-By")
    hay = source[:500000]
    tests = [
        ("Cloudflare", bool(headers.get("cf-ray") or re.search("cloudflare", server, re.I)), "Edge headers"),
        ("Vercel", bool(headers.get("x-vercel-id") or re.search(r"/_next/|__NEXT_DATA__", hay, re.I)), "Headers or page markers"),
        ("Netlify", bool(headers.get("x-nf-request-id")), "Response headers"),
        ("WordPress", bool(re.search(r"wp-content|wp-includes", hay, re.I)), "Asset paths"),
        ("Next.js", bool(re.search(r"/_next/static|__NEXT_DATA__", hay, re.I)), "Page markers"),
        ("Nuxt", bool(re.search(r"/_nuxt/|__NUXT__", hay, re.I)), "Page markers"),
        ("React", bool(re.search(r"react-dom|data-reactroot|__react", hay, re.I)), "Page markers"),
        ("Vue", bool(re.search(r"data-v-[0-9a-f]{6,}|vue\.runtime|__vue__", hay, re.I)), "Page markers"),
        ("Shopify", bool(re.search(r"cdn\.shopify\.com|shopify-section", hay, re.I)), "Page markers"),
        ("Webflow", bool(re.search(r"data-wf-page=|webflow\.js", hay, re.I)), "Page markers"),
        ("Squarespace", bool(re.search(r"static1\.squarespace\.com|cdn\.squarespace\.com", hay, re.I)), "Asset hosts"),
        ("Wix", bool(re.search(r"static\.wixstatic\.com|wix-code-sdk", hay, re.I)), "Asset hosts"),
    ]
    for name, yes, evidence in tests:
        if yes:
            add(name, evidence)
    return found[:30]


def security_headers(headers):
    checks = {
        "hsts": bool(headers.get("strict-transport-security")),
        "csp": bool(headers.get("content-security-policy")),
        "nosniff": "nosniff" in str(headers.get("x-content-type-options") or "").lower(),
        "frameProtection": bool(headers.get("x-frame-options")) or "frame-ancestors" in str(headers.get("content-security-policy") or "").lower(),
        "referrerPolicy": bool(headers.get("referrer-policy")),
        "permissionsPolicy": bool(headers.get("permissions-policy")),
        "coop": bool(headers.get("cross-origin-opener-policy")),
    }
    score = round(sum(1 for value in checks.values() if value) / len(checks) * 100)
    return {"score": score, "checks": checks}


def detect_edge(headers, address):
    server = str(headers.get("server") or "")
    if headers.get("cf-ray") or "cloudflare" in server.lower():
        return {"provider": "Cloudflare", "proxied": True, "note": "Observed address belongs to the public edge and may not be the origin server."}
    if headers.get("x-vercel-id"):
        return {"provider": "Vercel", "proxied": True, "note": "Observed address is the public serving edge."}
    if headers.get("x-nf-request-id"):
        return {"provider": "Netlify", "proxied": True, "note": "Observed address is the public serving edge."}
    if headers.get("x-amz-cf-pop"):
        return {"provider": "Amazon CloudFront", "proxied": True, "note": "Observed address is the public serving edge."}
    return {"provider": None, "proxied": False, "note": "Public address observed for this request."}


def certificate_info(hostname, address, port):
    if port not in {443, 8443}:
        return None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((address, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=None if _looks_like_ip(hostname) else hostname) as sock:
                cert = sock.getpeercert(binary_form=True)
                cipher = sock.cipher()
                return {
                    "protocol": sock.version(),
                    "alpn": sock.selected_alpn_protocol(),
                    "cipher": cipher[0] if cipher else None,
                    "sha256": hashlib.sha256(cert).hexdigest() if cert else None,
                }
    except Exception as exc:
        return {"error": str(exc)}


def _looks_like_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def fetch_json(url, timeout=5):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def doh(name, record_type):
    try:
        query = urllib.parse.urlencode({"name": name, "type": record_type})
        data = fetch_json(f"https://dns.google/resolve?{query}", 4.5)
        return [item.get("data") for item in data.get("Answer", []) if item.get("data")]
    except Exception:
        return []


def dns_snapshot(hostname, resolved):
    try:
        ipaddress.ip_address(hostname)
        ptr = []
        try:
            ptr = [socket.gethostbyaddr(hostname)[0]]
        except Exception:
            pass
        return {"a": [hostname] if ":" not in hostname else [], "aaaa": [hostname] if ":" in hostname else [], "cname": [], "mx": [], "ns": [], "txt": [], "ptr": ptr}
    except ValueError:
        pass
    return {
        "a": [item["address"] for item in resolved if item["family"] == 4],
        "aaaa": [item["address"] for item in resolved if item["family"] == 6],
        "cname": doh(hostname, 5),
        "mx": doh(hostname, 15),
        "ns": doh(hostname, 2),
        "txt": doh(hostname, 16)[:30],
        "ptr": _ptr_for(resolved[0]["address"]) if resolved else [],
    }


def _ptr_for(address):
    try:
        return [socket.gethostbyaddr(address)[0]]
    except Exception:
        return []


def public_files(base_url, timeout=4.0):
    files = []
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/manifest.json", "/site.webmanifest"]:
        try:
            url = urllib.parse.urljoin(base_url, path)
            result = request_once(url, timeout=timeout, max_bytes=120000)
            if result["status"] < 400:
                files.append({"path": path, "status": result["status"], "contentType": result["headers"].get("content-type"), "bytes": len(result["body"])})
        except Exception:
            pass
    return files


def build_web_report(value, profile="standard"):
    started = now_ms()
    timeouts = {"quick": 3.2, "fast": 4.5, "standard": 6.5, "full": 8.0}
    profile = profile if profile in timeouts else "standard"
    result, redirects = fetch_with_redirects(value, timeout=timeouts[profile])
    charset = body_charset(result["headers"])
    try:
        source = result["body"].decode(charset, "replace")
    except LookupError:
        source = result["body"].decode("utf-8", "replace")
    parsed_url = urllib.parse.urlsplit(result["url"])
    page = parse_page(source, result["url"])
    dns = dns_snapshot(parsed_url.hostname, result["resolved"]) if profile != "quick" else {
        "a": [item["address"] for item in result["resolved"] if item["family"] == 4],
        "aaaa": [item["address"] for item in result["resolved"] if item["family"] == 6],
        "cname": [], "mx": [], "ns": [], "txt": [], "ptr": []
    }
    tls = certificate_info(parsed_url.hostname, result["remoteAddress"], result["remotePort"]) if parsed_url.scheme == "https" and profile != "quick" else None
    files = public_files(result["url"], timeout=3.5 if profile == "fast" else 4.5) if profile in {"standard", "full"} else []
    technologies = detect_technology(result["headers"], source)
    edge = detect_edge(result["headers"], result["remoteAddress"])
    pack_links = []
    for row in page["assets"]:
        lower = row["url"].lower()
        if lower.endswith(".zip") or "resourcepack" in lower or "resource-pack" in lower or "pack.mcmeta" in lower:
            pack_links.append(row["url"])
    source_truncated = len(source) > MAX_SOURCE_CHARS
    source_out = source[:MAX_SOURCE_CHARS]
    return {
        "kind": "website",
        "profile": profile,
        "overview": {
            "requested": value,
            "finalUrl": result["url"],
            "status": result["status"],
            "statusText": result["reason"],
            "title": page["title"],
            "description": page["description"],
            "contentType": result["headers"].get("content-type"),
            "bytesRead": len(result["body"]),
            "sourceSha256": hashlib.sha256(result["body"]).hexdigest(),
            "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "durationMs": now_ms() - started,
        },
        "network": {
            "hostname": parsed_url.hostname,
            "address": result["remoteAddress"],
            "port": result["remotePort"],
            "scheme": parsed_url.scheme,
            "resolved": result["resolved"],
            "dns": dns,
            "edge": edge,
            "timings": result["timings"],
            "tls": tls,
        },
        "page": page,
        "headers": result["headers"],
        "security": security_headers(result["headers"]),
        "technologies": technologies,
        "publicFiles": files,
        "redirects": redirects,
        "packCandidates": list(dict.fromkeys(pack_links))[:20],
        "source": source_out,
        "sourceTruncated": source_truncated,
    }
