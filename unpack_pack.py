import hashlib
import io
import json
import os
import re
import urllib.parse
import zipfile

from unpack_core_v2 import fetch_public_url

MAX_PACK_BYTES = 64_000_000
MAX_UNCOMPRESSED_BYTES = 512_000_000
MAX_ENTRIES = 5000


def normalize_pack_url(value):
    url = str(value or "").strip()
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("Paste the full resource-pack URL")
    return url


def fetch_pack(value):
    url = normalize_pack_url(value)
    result = fetch_public_url(url, timeout=12.0, max_bytes=MAX_PACK_BYTES, accept="application/zip,application/octet-stream,*/*", redirects=6)
    if result["status"] >= 400:
        raise ValueError(f"Pack server returned HTTP {result['status']}")
    data = result["body"]
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ValueError("That URL did not return a ZIP resource pack")
    return result, data


def inspect_pack_url(value):
    result, data = fetch_pack(value)
    entries = []
    pack_meta = None
    total_uncompressed = 0
    warnings = []
    with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise ValueError("Pack has too many files")
        for info in infos:
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or "../" in name.split("/"):
                warnings.append(f"Unsafe path skipped: {name}")
                continue
            total_uncompressed += info.file_size
            if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Pack expands past the safety limit")
            ratio = round(info.file_size / max(info.compress_size, 1), 1)
            if ratio > 250 and info.file_size > 2_000_000:
                warnings.append(f"High compression ratio: {name}")
            entries.append({
                "name": name,
                "bytes": info.file_size,
                "compressedBytes": info.compress_size,
                "directory": info.is_dir(),
            })
        if "pack.mcmeta" in archive.namelist():
            try:
                raw = archive.read("pack.mcmeta")
                if len(raw) <= 250000:
                    pack_meta = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                pack_meta = None
    folders = []
    seen = set()
    for row in entries:
        first = row["name"].split("/", 1)[0]
        if first and first not in seen:
            seen.add(first)
            folders.append(first)
    parsed = urllib.parse.urlsplit(result["url"])
    filename = os.path.basename(parsed.path) or "resource-pack.zip"
    if not filename.lower().endswith(".zip"):
        filename += ".zip"
    return {
        "kind": "pack",
        "url": result["url"],
        "filename": filename,
        "downloadBytes": len(data),
        "uncompressedBytes": total_uncompressed,
        "sha256": hashlib.sha256(data).hexdigest(),
        "fileCount": len(entries),
        "folders": folders[:100],
        "packMeta": pack_meta,
        "entries": entries[:1800],
        "entriesTruncated": len(entries) > 1800,
        "warnings": list(dict.fromkeys(warnings))[:50],
    }


def download_pack_url(value):
    result, data = fetch_pack(value)
    parsed = urllib.parse.urlsplit(result["url"])
    filename = os.path.basename(parsed.path) or "resource-pack.zip"
    filename = re.sub(r"[^A-Za-z0-9._-]+", "_", filename)
    if not filename.lower().endswith(".zip"):
        filename += ".zip"
    return data, filename
