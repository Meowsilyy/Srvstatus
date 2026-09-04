import concurrent.futures
import datetime
import gzip
import hashlib
import http.client
import io
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
import zipfile
import zlib
from html.parser import HTMLParser

USER_AGENT = "Unpack/2.0"
ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_HTML_BYTES = 4_000_000
MAX_SOURCE_CHARS = 1_500_000
MAX_ARCHIVE_ASSETS = 90
MAX_ARCHIVE_ASSET_BYTES = 2_500_000
MAX_ARCHIVE_TOTAL_BYTES = 40_000_000


def now_ms():
    return int(time.time() * 1000)


def is_private_ip(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified or getattr(ip, "is_site_local", False))


def is_blocked_hostname(hostname):
    host = (hostname or "").lower().rstrip(".")
    if not host or host == "localhost":
        return True
    if host in {"metadata.google.internal", "metadata.google", "169.254.169.254"}:
        return True
    return host.endswith((".localhost", ".local", ".internal", ".home", ".lan", ".test", ".invalid", ".example"))


def resolve_public_host(hostname):
    if is_blocked_hostname(hostname):
        raise ValueError("Private and local addresses are blocked")
    try:
        ip = ipaddress.ip_address(hostname)
        address = str(ip)
        if is_private_ip(address):
            raise ValueError("Private and local addresses are blocked")
        return [{"address": address, "family": 6 if ip.version == 6 else 4}]
    except ValueError as exc:
        if "blocked" in str(exc):
            raise
    try:
        entries = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Hostname did not resolve")
    found = []
    seen = set()
    for entry in entries:
        family = 6 if entry[0] == socket.AF_INET6 else 4 if entry[0] == socket.AF_INET else 0
        address = entry[4][0]
        if not family or address in seen:
            continue
        if is_private_ip(address):
            raise ValueError("Hostname resolves to a private or local address")
        seen.add(address)
        found.append({"address": address, "family": family})
    if not found:
        raise ValueError("Hostname did not resolve")
    return found


def normalize_url(value):
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Enter a website address")
    if len(raw) > 800:
        raise ValueError("Address is too long")
    parsed = urllib.parse.urlsplit(raw if re.match(r"^https?://", raw, re.I) else f"https://{raw}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS address")
    if is_blocked_hostname(parsed.hostname):
        raise ValueError("Private and local addresses are blocked")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError("Only ports 80, 443, 8080 and 8443 are supported")
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
        context.set_alpn_protocols(["http/1.1"])
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


def decode_transfer(body, headers):
    encoding = str(headers.get("content-encoding") or "").lower().strip()
    if not body or not encoding or encoding == "identity":
        return body
    if "gzip" in encoding:
        return gzip.decompress(body)
    if "deflate" in encoding:
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    if "br" in encoding:
        try:
            import brotli
            return brotli.decompress(body)
        except Exception:
            raise ValueError("Site returned Brotli data that this worker cannot decode")
    return body


def request_once(url, timeout=7.0, max_bytes=MAX_HTML_BYTES, method="GET", accept="*/*"):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Unsupported URL")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError("Redirected to an unsupported port")
    resolved = resolve_public_host(parsed.hostname)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    last_error = None
    for chosen in resolved[:4]:
        conn_cls = PinnedHTTPSConnection if parsed.scheme == "https" else PinnedHTTPConnection
        conn = conn_cls(parsed.hostname, chosen["address"], port, timeout)
        headers = {
            "Host": parsed.hostname if port in {80, 443} else f"{parsed.hostname}:{port}",
            "User-Agent": USER_AGENT,
            "Accept": accept,
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        started = time.perf_counter()
        try:
            conn.request(method, path, headers=headers)
            response = conn.getresponse()
            ttfb = round((time.perf_counter() - started) * 1000, 1)
            response_headers = combine_headers(response.getheaders())
            raw = b"" if method == "HEAD" else response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError("Response is too large")
            body = decode_transfer(raw, response_headers)
            if len(body) > max_bytes * 4:
                raise ValueError("Decoded response is too large")
            total = round((time.perf_counter() - started) * 1000, 1)
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
        except Exception as exc:
            last_error = exc
        finally:
            try:
                conn.close()
            except Exception:
                pass
    if isinstance(last_error, ValueError):
        raise last_error
    raise ValueError(str(last_error) if last_error else "Request failed")


def fetch_public_url(url, timeout=7.0, max_bytes=MAX_HTML_BYTES, accept="*/*", redirects=6):
    current = normalize_url(url)
    chain = []
    for _ in range(redirects + 1):
        result = request_once(current, timeout=timeout, max_bytes=max_bytes, accept=accept)
        location = result["headers"].get("location")
        chain.append({"url": result["url"], "status": result["status"], "location": location})
        if result["status"] in {301, 302, 303, 307, 308} and location:
            current = normalize_url(urllib.parse.urljoin(current, location))
            continue
        result["redirects"] = chain
        return result
    raise ValueError("Too many redirects")


def body_charset(headers):
    content_type = str(headers.get("content-type") or "")
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    return match.group(1).strip('"\'') if match else "utf-8"


def decode_text(body, headers):
    charset = body_charset(headers)
    try:
        return body.decode(charset, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


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
        if not value or str(value).startswith(("data:", "javascript:", "mailto:", "tel:")):
            return None
        url = urllib.parse.urljoin(self.base_url, str(value))
        parsed = urllib.parse.urlsplit(url)
        return url if parsed.scheme in {"http", "https"} else None

    def add_asset(self, kind, value, attrs=None):
        url = self.absolute(value)
        if url and len(self.assets) < 500:
            self.assets.append({"type": kind, "url": url, "source": str(value), "attrs": attrs or {}})

    def add_srcset(self, kind, value):
        for item in str(value or "").split(","):
            source = item.strip().split(" ", 1)[0]
            if source:
                self.add_asset(kind, source)

    def handle_starttag(self, tag, attrs):
        data = {str(k).lower(): v for k, v in attrs if k}
        if tag == "html" and not self.lang:
            self.lang = data.get("lang")
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            key = data.get("name") or data.get("property") or data.get("http-equiv")
            value = data.get("content")
            if key and value and len(self.meta) < 120:
                self.meta.append({"name": key, "content": value})
        elif tag == "script" and data.get("src"):
            self.add_asset("script", data.get("src"), {"type": data.get("type")})
        elif tag == "link" and data.get("href"):
            rel = str(data.get("rel") or "").lower()
            kind = "stylesheet" if "stylesheet" in rel else "icon" if "icon" in rel else "manifest" if "manifest" in rel else "preload" if "preload" in rel else "link"
            self.add_asset(kind, data.get("href"), {"rel": rel, "as": data.get("as")})
        elif tag in {"img", "source", "video", "audio"}:
            if data.get("src"):
                self.add_asset(tag, data.get("src"))
            if data.get("srcset"):
                self.add_srcset(tag, data.get("srcset"))
            if tag == "video" and data.get("poster"):
                self.add_asset("poster", data.get("poster"))
        elif tag == "iframe" and data.get("src"):
            self.add_asset("iframe", data.get("src"))
        elif tag == "a" and data.get("href"):
            url = self.absolute(data.get("href"))
            if url and len(self.links) < 800:
                self.links.append(url)
        elif tag == "form":
            action = self.absolute(data.get("action") or self.base_url)
            if len(self.forms) < 80:
                self.forms.append({"method": str(data.get("method") or "GET").upper(), "action": action})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def dedupe_rows(rows, key):
    seen = set()
    result = []
    for row in rows:
        value = row.get(key)
        if value and value not in seen:
            seen.add(value)
            result.append(row)
    return result


def parse_page(source, final_url):
    parser = PageParser(final_url)
    try:
        parser.feed(source)
    except Exception:
        pass
    title = re.sub(r"\s+", " ", "".join(parser.title_parts)).strip()[:300] or None
    meta_map = {}
    for item in parser.meta:
        meta_map.setdefault(str(item["name"]).lower(), item["content"])
    host = urllib.parse.urlsplit(final_url).hostname
    internal = 0
    external = 0
    for link in parser.links:
        parsed = urllib.parse.urlsplit(link)
        if parsed.hostname == host:
            internal += 1
        elif parsed.hostname:
            external += 1
    assets = dedupe_rows(parser.assets, "url")
    canonical = None
    for asset in assets:
        if asset["type"] == "link" and "canonical" in str(asset.get("attrs", {}).get("rel", "")):
            canonical = asset["url"]
            break
    return {
        "title": title,
        "description": meta_map.get("description") or meta_map.get("og:description"),
        "language": parser.lang,
        "generator": meta_map.get("generator"),
        "canonical": canonical,
        "meta": parser.meta,
        "assets": assets,
        "forms": parser.forms,
        "links": {"total": len(parser.links), "internal": internal, "external": external},
    }


def detect_technology(headers, source):
    found = []

    def add(name, evidence):
        if name and not any(item["name"] == name for item in found):
            found.append({"name": name, "evidence": evidence})

    server = str(headers.get("server") or "").strip()
    powered = str(headers.get("x-powered-by") or "").strip()
    if server:
        add(server, "server header")
    if powered:
        add(powered, "x-powered-by")
    hay = source[:700000]
    tests = [
        ("Cloudflare", bool(headers.get("cf-ray") or re.search("cloudflare", server, re.I))),
        ("Vercel", bool(headers.get("x-vercel-id"))),
        ("Netlify", bool(headers.get("x-nf-request-id"))),
        ("WordPress", bool(re.search(r"wp-content|wp-includes", hay, re.I))),
        ("Next.js", bool(re.search(r"/_next/static|__NEXT_DATA__", hay, re.I))),
        ("Nuxt", bool(re.search(r"/_nuxt/|__NUXT__", hay, re.I))),
        ("React", bool(re.search(r"react-dom|data-reactroot|__react", hay, re.I))),
        ("Vue", bool(re.search(r"data-v-[0-9a-f]{6,}|vue\.runtime|__vue__", hay, re.I))),
        ("Shopify", bool(re.search(r"cdn\.shopify\.com|shopify-section", hay, re.I))),
        ("Webflow", bool(re.search(r"data-wf-page=|webflow\.js", hay, re.I))),
        ("Squarespace", bool(re.search(r"static1\.squarespace\.com|cdn\.squarespace\.com", hay, re.I))),
        ("Wix", bool(re.search(r"static\.wixstatic\.com|wix-code-sdk", hay, re.I))),
    ]
    for name, yes in tests:
        if yes:
            add(name, "page or response marker")
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
    return {"score": round(sum(1 for value in checks.values() if value) / len(checks) * 100), "checks": checks}


def detect_edge(headers):
    server = str(headers.get("server") or "").lower()
    if headers.get("cf-ray") or "cloudflare" in server:
        return {"provider": "Cloudflare", "proxied": True, "note": "This is the public Cloudflare edge, not a hidden origin."}
    if headers.get("x-vercel-id"):
        return {"provider": "Vercel", "proxied": True, "note": "This is the public Vercel edge."}
    if headers.get("x-nf-request-id"):
        return {"provider": "Netlify", "proxied": True, "note": "This is the public Netlify edge."}
    if headers.get("x-amz-cf-pop"):
        return {"provider": "CloudFront", "proxied": True, "note": "This is the public CloudFront edge."}
    return {"provider": None, "proxied": False, "note": "Public address used for this request."}


def fetch_json(url, timeout=4.5):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def doh(name, record_type):
    try:
        query = urllib.parse.urlencode({"name": name, "type": record_type})
        data = fetch_json(f"https://dns.google/resolve?{query}")
        return [item.get("data") for item in data.get("Answer", []) if item.get("data")]
    except Exception:
        return []


def ptr_for(address):
    try:
        return [socket.gethostbyaddr(address)[0]]
    except Exception:
        return []


def dns_snapshot(hostname, resolved, full=True):
    try:
        ipaddress.ip_address(hostname)
        return {
            "a": [hostname] if ":" not in hostname else [],
            "aaaa": [hostname] if ":" in hostname else [],
            "cname": [], "mx": [], "ns": [], "txt": [], "ptr": ptr_for(hostname),
        }
    except ValueError:
        pass
    base = {
        "a": [item["address"] for item in resolved if item["family"] == 4],
        "aaaa": [item["address"] for item in resolved if item["family"] == 6],
        "cname": [], "mx": [], "ns": [], "txt": [], "ptr": ptr_for(resolved[0]["address"]) if resolved else [],
    }
    if full:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            future_map = {
                "cname": pool.submit(doh, hostname, 5),
                "mx": pool.submit(doh, hostname, 15),
                "ns": pool.submit(doh, hostname, 2),
                "txt": pool.submit(doh, hostname, 16),
            }
            for key, future in future_map.items():
                try:
                    base[key] = future.result()[:40]
                except Exception:
                    base[key] = []
    return base


def certificate_info(hostname, address, port):
    if port not in {443, 8443}:
        return None
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["http/1.1"])
        with socket.create_connection((address, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as sock:
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


def public_files(base_url, timeout=4.0):
    files = []
    for path in ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/manifest.json", "/site.webmanifest"]:
        try:
            url = urllib.parse.urljoin(base_url, path)
            result = fetch_public_url(url, timeout=timeout, max_bytes=250000)
            if result["status"] < 400:
                files.append({"path": path, "url": result["url"], "status": result["status"], "contentType": result["headers"].get("content-type"), "bytes": len(result["body"])})
        except Exception:
            pass
    return files


def build_web_report(value, profile="standard"):
    started = now_ms()
    timeouts = {"quick": 3.0, "fast": 4.0, "standard": 5.5, "full": 7.0}
    profile = profile if profile in timeouts else "standard"
    result = fetch_public_url(value, timeout=timeouts[profile], max_bytes=MAX_HTML_BYTES, accept="text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5")
    source = decode_text(result["body"], result["headers"])
    parsed_url = urllib.parse.urlsplit(result["url"])
    page = parse_page(source, result["url"])
    dns = dns_snapshot(parsed_url.hostname, result["resolved"], full=profile != "quick")
    tls = certificate_info(parsed_url.hostname, result["remoteAddress"], result["remotePort"]) if parsed_url.scheme == "https" and profile != "quick" else None
    files = public_files(result["url"], timeout=3.5 if profile in {"fast", "standard"} else 4.5) if profile in {"standard", "full"} else []
    technologies = detect_technology(result["headers"], source)
    edge = detect_edge(result["headers"])
    pack_links = []
    for row in page["assets"]:
        lower = row["url"].lower()
        if lower.endswith(".zip") or "resourcepack" in lower or "resource-pack" in lower or "pack.mcmeta" in lower:
            pack_links.append(row["url"])
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
            "dns": dns,
            "tls": tls,
            "timings": result["timings"],
            "edge": edge,
            "resolved": result["resolved"],
        },
        "redirects": result["redirects"],
        "headers": result["headers"],
        "page": page,
        "technologies": technologies,
        "security": security_headers(result["headers"]),
        "publicFiles": files,
        "packCandidates": list(dict.fromkeys(pack_links))[:20],
        "source": source[:MAX_SOURCE_CHARS],
        "sourceTruncated": len(source) > MAX_SOURCE_CHARS,
        "meta": {"version": "2.0", "httpMode": "http/1.1"},
    }


def safe_segment(value):
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._")
    return cleaned[:100] or "file"


def asset_path(url):
    parsed = urllib.parse.urlsplit(url)
    host = safe_segment(parsed.hostname or "host")
    raw_parts = [part for part in urllib.parse.unquote(parsed.path or "/").split("/") if part not in {"", ".", ".."}]
    parts = [safe_segment(part) for part in raw_parts]
    if not parts or (parsed.path or "/").endswith("/"):
        parts.append("index")
    if parsed.query:
        base = parts[-1]
        stem, dot, ext = base.rpartition(".")
        suffix = hashlib.sha1(parsed.query.encode("utf-8", "ignore")).hexdigest()[:8]
        parts[-1] = f"{stem}_{suffix}.{ext}" if dot else f"{base}_{suffix}"
    return "/".join(["assets", host] + parts)


def download_asset(row, timeout):
    try:
        result = fetch_public_url(row["url"], timeout=timeout, max_bytes=MAX_ARCHIVE_ASSET_BYTES, accept="*/*", redirects=4)
        if result["status"] >= 400:
            return {"url": row["url"], "type": row.get("type"), "error": f"HTTP {result['status']}"}
        return {
            "url": row["url"],
            "finalUrl": result["url"],
            "type": row.get("type"),
            "path": asset_path(row["url"]),
            "contentType": result["headers"].get("content-type"),
            "sha256": hashlib.sha256(result["body"]).hexdigest(),
            "bytes": len(result["body"]),
            "data": result["body"],
        }
    except Exception as exc:
        return {"url": row.get("url"), "type": row.get("type"), "error": str(exc)}


def build_site_archive(value, profile="standard"):
    report = build_web_report(value, profile)
    main_host = report["network"]["hostname"]
    assets = list(report["page"].get("assets") or [])
    for row in report.get("publicFiles") or []:
        assets.append({"type": "public-file", "url": row["url"], "source": row["path"]})
    unique = []
    seen = set()
    for row in assets:
        url = row.get("url")
        if not url or url in seen:
            continue
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            continue
        seen.add(url)
        row = dict(row)
        row["sameOrigin"] = parsed.hostname == main_host
        unique.append(row)
    unique.sort(key=lambda row: (not row["sameOrigin"], row.get("type") not in {"stylesheet", "script", "img", "icon", "manifest", "public-file"}))
    unique = unique[:MAX_ARCHIVE_ASSETS]
    downloaded = []
    failed = []
    total = 0
    timeout = 4.0 if profile in {"quick", "fast"} else 5.5
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = [pool.submit(download_asset, row, timeout) for row in unique]
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            data = item.pop("data", None)
            if data is None:
                failed.append(item)
                continue
            if total + len(data) > MAX_ARCHIVE_TOTAL_BYTES:
                item["error"] = "archive size limit reached"
                failed.append(item)
                continue
            item["data"] = data
            downloaded.append(item)
            total += len(data)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("index.html", report.get("source") or "")
        clean_report = dict(report)
        clean_report.pop("source", None)
        archive.writestr("report.json", json.dumps(clean_report, indent=2, ensure_ascii=False))
        manifest = {
            "source": report["overview"]["finalUrl"],
            "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "assetsSaved": len(downloaded),
            "assetsFailed": len(failed),
            "bytesSaved": total,
            "files": [{k: v for k, v in item.items() if k != "data"} for item in downloaded],
            "failed": failed,
        }
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        archive.writestr("README.txt", f"Unpack export\n{report['overview']['finalUrl']}\nAssets saved: {len(downloaded)}\nAssets skipped: {len(failed)}\n")
        used_paths = set()
        for item in downloaded:
            path = item["path"]
            if path in used_paths:
                stem, dot, ext = path.rpartition(".")
                suffix = item["sha256"][:8]
                path = f"{stem}_{suffix}.{ext}" if dot else f"{path}_{suffix}"
            used_paths.add(path)
            archive.writestr(path, item["data"])
    host = safe_segment(main_host)
    return buffer.getvalue(), f"{host}-source.zip", {"assetsSaved": len(downloaded), "assetsFailed": len(failed), "bytesSaved": total}
