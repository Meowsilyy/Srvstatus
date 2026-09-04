import concurrent.futures
import datetime
import io
import json
import posixpath
import re
import urllib.parse
import zipfile

import unpack_core_v2 as base

CHALLENGE_MARKERS = (
    "just a moment",
    "cf-chl-",
    "/cdn-cgi/challenge-platform/",
    "challenge-platform",
    "checking your browser",
    "enable javascript and cookies to continue",
    "attention required! | cloudflare",
)


def detect_challenge(report):
    source = str(report.get("source") or "")[:250000]
    title = str((report.get("overview") or {}).get("title") or "")
    headers = report.get("headers") if isinstance(report.get("headers"), dict) else {}
    hay = f"{title}\n{source}".lower()
    marker = next((item for item in CHALLENGE_MARKERS if item in hay), None)
    cf_mitigated = str(headers.get("cf-mitigated") or "").lower() == "challenge"
    if not marker and not cf_mitigated:
        return None
    provider = "Cloudflare" if headers.get("cf-ray") or "cloudflare" in hay or cf_mitigated else "Site protection"
    return {
        "detected": True,
        "provider": provider,
        "reason": "challenge page",
        "message": f"{provider} returned a challenge page instead of the website.",
    }


def build_web_report(value, profile="standard"):
    report = base.build_web_report(value, profile)
    challenge = detect_challenge(report)
    report["access"] = {
        "challenge": bool(challenge),
        "provider": challenge.get("provider") if challenge else None,
        "message": challenge.get("message") if challenge else None,
    }
    return report


def _unique_assets(report):
    rows = []
    seen = set()
    main_host = str((report.get("network") or {}).get("hostname") or "").lower()
    for row in list((report.get("page") or {}).get("assets") or []):
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        rows.append(dict(row))
    for row in report.get("publicFiles") or []:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        rows.append({"type": "public-file", "url": url, "source": row.get("path")})
    rows.sort(key=lambda row: 0 if (urllib.parse.urlsplit(str(row.get("url") or "")).hostname or "").lower() == main_host else 1)
    return rows[: base.MAX_ARCHIVE_ASSETS]


def _download_many(rows, timeout):
    if not rows:
        return []
    results = []
    workers = min(12, len(rows))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(base.download_asset, row, timeout): row for row in rows}
        for future in concurrent.futures.as_completed(future_map):
            try:
                results.append(future.result())
            except Exception as exc:
                row = future_map[future]
                results.append({"url": row.get("url"), "type": row.get("type"), "error": str(exc)})
    return results


def _dedupe_paths(downloaded):
    used = set()
    for item in downloaded:
        path = str(item.get("path") or "assets/file")
        original = path
        count = 1
        while path in used:
            stem, dot, ext = original.rpartition(".")
            suffix = str(item.get("sha256") or "")[:8] or str(count)
            path = f"{stem}_{suffix}.{ext}" if dot else f"{original}_{suffix}"
            count += 1
        used.add(path)
        item["path"] = path
    return downloaded


def _css_refs(text, base_url):
    found = []
    patterns = [
        r"url\(\s*(['\"]?)(.*?)\1\s*\)",
        r"@import\s+(?:url\()?\s*(['\"])(.*?)\1",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.I):
            value = match.group(2).strip()
            if not value or value.startswith(("data:", "blob:", "#")):
                continue
            url = urllib.parse.urljoin(base_url, value)
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme in {"http", "https"}:
                found.append(url)
    return list(dict.fromkeys(found))


def _secondary_css_assets(downloaded, known_urls, timeout, remaining):
    if remaining <= 0:
        return []
    rows = []
    for item in downloaded:
        content_type = str(item.get("contentType") or "").lower()
        path = str(item.get("path") or "").lower()
        if "text/css" not in content_type and not path.endswith(".css"):
            continue
        try:
            text = item.get("data", b"").decode("utf-8", "replace")
        except Exception:
            continue
        base_url = str(item.get("finalUrl") or item.get("url") or "")
        for url in _css_refs(text, base_url):
            if url in known_urls:
                continue
            known_urls.add(url)
            rows.append({"type": "css-asset", "url": url, "source": url})
            if len(rows) >= remaining:
                return rows
    return rows


def _rewrite_html(source, final_url, mapping):
    attr_pattern = re.compile(r"\b(src|href|poster)\s*=\s*(['\"])(.*?)\2", re.I | re.S)
    srcset_pattern = re.compile(r"\bsrcset\s*=\s*(['\"])(.*?)\1", re.I | re.S)

    def repl_attr(match):
        attr, quote, value = match.group(1), match.group(2), match.group(3)
        if value.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
            return match.group(0)
        absolute = urllib.parse.urljoin(final_url, value)
        target = mapping.get(absolute)
        if not target:
            return match.group(0)
        return f"{attr}={quote}{target}{quote}"

    def repl_srcset(match):
        quote, value = match.group(1), match.group(2)
        parts = []
        changed = False
        for chunk in value.split(","):
            bit = chunk.strip()
            if not bit:
                continue
            pieces = bit.split()
            absolute = urllib.parse.urljoin(final_url, pieces[0])
            target = mapping.get(absolute)
            if target:
                pieces[0] = target
                changed = True
            parts.append(" ".join(pieces))
        return f"srcset={quote}{', '.join(parts)}{quote}" if changed else match.group(0)

    rewritten = attr_pattern.sub(repl_attr, source)
    rewritten = srcset_pattern.sub(repl_srcset, rewritten)
    rewritten = re.sub(r"<base\b[^>]*>", "", rewritten, flags=re.I)
    return rewritten


def _rewrite_css(data, item, mapping):
    text = data.decode("utf-8", "replace")
    base_url = str(item.get("finalUrl") or item.get("url") or "")
    current_dir = posixpath.dirname(str(item.get("path") or "")) or "."

    def repl_url(match):
        quote = match.group(1) or ""
        value = match.group(2).strip()
        if not value or value.startswith(("data:", "blob:", "#")):
            return match.group(0)
        absolute = urllib.parse.urljoin(base_url, value)
        target = mapping.get(absolute)
        if not target:
            return match.group(0)
        relative = posixpath.relpath(target, current_dir)
        return f"url({quote}{relative}{quote})"

    return re.sub(r"url\(\s*(['\"]?)(.*?)\1\s*\)", repl_url, text, flags=re.I).encode("utf-8")


def _rewrite_js(data, item, mapping):
    text = data.decode("utf-8", "replace")
    current_dir = posixpath.dirname(str(item.get("path") or "")) or "."
    for url, target in sorted(mapping.items(), key=lambda pair: len(pair[0]), reverse=True):
        if url in text:
            text = text.replace(url, posixpath.relpath(target, current_dir))
    return text.encode("utf-8")


def _start_files(source_url):
    bat = "@echo off\r\ncd /d %~dp0\r\nstart http://127.0.0.1:8000/\r\npy -m http.server 8000 2>nul || python -m http.server 8000\r\n"
    sh = "#!/bin/sh\ncd \"$(dirname \"$0\")\"\npython3 -m http.server 8000\n"
    readme = (
        "Unpack website export\n\n"
        f"Source: {source_url}\n\n"
        "Open index.html directly for simple static sites.\n"
        "For modern sites, run START.bat on Windows or START.sh on macOS/Linux, then open http://127.0.0.1:8000/.\n"
        "This archive contains files the public page exposed. Server-side code and protected content are not included.\n"
    )
    return bat, sh, readme


def build_site_archive(value, profile="standard"):
    report = build_web_report(value, profile)
    challenge = detect_challenge(report)
    if challenge:
        raise ValueError(f"{challenge['provider']} returned a challenge page, not the website. ZIP export stopped.")
    final_url = str((report.get("overview") or {}).get("finalUrl") or "")
    if not final_url:
        raise ValueError("No page was returned")
    timeout = {"quick": 3.5, "fast": 4.5, "standard": 6.0, "full": 7.5}.get(profile, 6.0)
    initial_rows = _unique_assets(report)
    results = _download_many(initial_rows, timeout)
    downloaded = [item for item in results if isinstance(item, dict) and item.get("data") is not None and not item.get("error")]
    failed = [item for item in results if not isinstance(item, dict) or item.get("error") or item.get("data") is None]
    downloaded = _dedupe_paths(downloaded)
    known_urls = {str(row.get("url") or "") for row in initial_rows}
    remaining = max(0, base.MAX_ARCHIVE_ASSETS - len(downloaded) - len(failed))
    extra_rows = _secondary_css_assets(downloaded, known_urls, timeout, remaining)
    if extra_rows:
        extra_results = _download_many(extra_rows, timeout)
        extra_downloaded = [item for item in extra_results if isinstance(item, dict) and item.get("data") is not None and not item.get("error")]
        failed.extend(item for item in extra_results if not isinstance(item, dict) or item.get("error") or item.get("data") is None)
        downloaded.extend(extra_downloaded)
        downloaded = _dedupe_paths(downloaded)
    total = 0
    kept = []
    for item in downloaded:
        size = len(item.get("data") or b"")
        if total + size > base.MAX_ARCHIVE_TOTAL_BYTES:
            failed.append({"url": item.get("url"), "type": item.get("type"), "error": "archive size limit reached"})
            continue
        total += size
        kept.append(item)
    downloaded = kept
    mapping = {}
    for item in downloaded:
        for key in (item.get("url"), item.get("finalUrl")):
            if key:
                mapping[str(key)] = str(item.get("path"))
    html = _rewrite_html(str(report.get("source") or ""), final_url, mapping)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("index.html", html)
        clean_report = dict(report)
        clean_report.pop("source", None)
        archive.writestr("report.json", json.dumps(clean_report, indent=2, ensure_ascii=False))
        manifest_files = []
        for item in downloaded:
            data = item.get("data") or b""
            content_type = str(item.get("contentType") or "").lower()
            path = str(item.get("path") or "assets/file")
            if "text/css" in content_type or path.lower().endswith(".css"):
                data = _rewrite_css(data, item, mapping)
            elif "javascript" in content_type or path.lower().endswith((".js", ".mjs")):
                data = _rewrite_js(data, item, mapping)
            archive.writestr(path, data)
            manifest_files.append({k: v for k, v in item.items() if k != "data"})
        manifest = {
            "source": final_url,
            "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "assetsSaved": len(downloaded),
            "assetsFailed": len(failed),
            "bytesSaved": total,
            "files": manifest_files,
            "failed": failed,
            "offlineRewrite": True,
        }
        archive.writestr("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        bat, sh, readme = _start_files(final_url)
        archive.writestr("START.bat", bat)
        archive.writestr("START.sh", sh)
        archive.writestr("README.txt", readme)
    host = base.safe_segment((report.get("network") or {}).get("hostname") or "site")
    return buffer.getvalue(), f"{host}-source.zip", {"assetsSaved": len(downloaded), "assetsFailed": len(failed), "bytesSaved": total}
