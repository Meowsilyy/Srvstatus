import copy
import json
import re
import threading
import time

from unpack_core_v3 import build_site_archive, build_web_report
from unpack_minecraft import build_minecraft_report
from unpack_pack import download_pack_url, inspect_pack_url

_CACHE = {}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 20


def cache_key(kind, value, profile):
    return f"{kind}|{profile}|{str(value).strip().lower()}"


def cached_get(key):
    with _CACHE_LOCK:
        row = _CACHE.get(key)
        if not row:
            return None
        if time.time() - row[0] > _CACHE_TTL:
            _CACHE.pop(key, None)
            return None
        result = copy.deepcopy(row[1])
        result.setdefault("meta", {})["cached"] = True
        return result


def cached_set(key, value):
    with _CACHE_LOCK:
        _CACHE[key] = (time.time(), copy.deepcopy(value))
        if len(_CACHE) > 80:
            oldest = sorted(_CACHE.items(), key=lambda item: item[1][0])[:20]
            for old_key, _ in oldest:
                _CACHE.pop(old_key, None)


def read_payload(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0 or length > 16000:
        raise ValueError("Invalid request")
    return json.loads(handler.rfile.read(length).decode("utf-8") or "{}")


def safe_filename(value, fallback):
    filename = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or ""))[:140].strip("._")
    return filename or fallback


def send_binary(handler, data, filename, content_type):
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Content-Disposition", f'attachment; filename="{safe_filename(filename, "download.bin")}"')
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def handle_unpack(handler):
    try:
        payload = read_payload(handler)
        kind = str(payload.get("kind") or "website").lower()
        value = payload.get("value") or payload.get("url") or payload.get("address")
        profile = str(payload.get("profile") or "standard").lower()
        if profile not in {"quick", "fast", "standard", "full"}:
            profile = "standard"
        if kind not in {"website", "minecraft", "pack"}:
            raise ValueError("Unknown lookup type")
        key = cache_key(kind, value, profile)
        cached = cached_get(key)
        if cached is not None:
            handler.send_json(200, cached)
            return
        if kind == "minecraft":
            result = build_minecraft_report(value)
        elif kind == "pack":
            result = inspect_pack_url(value)
        else:
            result = build_web_report(value, profile)
        result.setdefault("meta", {})["cached"] = False
        cached_set(key, result)
        handler.send_json(200, result)
    except ValueError as exc:
        handler.send_json(400, {"error": str(exc) or "Could not load that"})
    except Exception as exc:
        handler.send_json(502, {"error": str(exc) or "Request failed"})


def handle_export(handler):
    try:
        payload = read_payload(handler)
        value = payload.get("value") or payload.get("url") or payload.get("address")
        profile = str(payload.get("profile") or "standard").lower()
        if profile not in {"quick", "fast", "standard", "full"}:
            profile = "standard"
        data, filename, _ = build_site_archive(value, profile)
        send_binary(handler, data, filename, "application/zip")
    except ValueError as exc:
        handler.send_json(400, {"error": str(exc) or "Export failed"})
    except Exception as exc:
        handler.send_json(502, {"error": str(exc) or "Export failed"})


def handle_pack_download(handler):
    try:
        payload = read_payload(handler)
        value = payload.get("value") or payload.get("url")
        data, filename = download_pack_url(value)
        send_binary(handler, data, filename, "application/zip")
    except ValueError as exc:
        handler.send_json(400, {"error": str(exc) or "Pack download failed"})
    except Exception as exc:
        handler.send_json(502, {"error": str(exc) or "Pack download failed"})
