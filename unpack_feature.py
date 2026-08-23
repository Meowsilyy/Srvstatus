import copy
import json
import threading
import time

from unpack_core import build_web_report
from unpack_minecraft import build_minecraft_report

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


def handle_unpack(handler):
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if length <= 0 or length > 12000:
            raise ValueError("Invalid request")
        payload = json.loads(handler.rfile.read(length).decode("utf-8") or "{}")
        kind = str(payload.get("kind") or "website").lower()
        value = payload.get("value") or payload.get("url") or payload.get("address")
        profile = str(payload.get("profile") or "standard").lower()
        if profile not in {"quick", "fast", "standard", "full"}:
            profile = "standard"
        if kind not in {"website", "minecraft"}:
            raise ValueError("Unknown lookup type")
        key = cache_key(kind, value, profile)
        cached = cached_get(key)
        if cached is not None:
            handler.send_json(200, cached)
            return
        result = build_minecraft_report(value) if kind == "minecraft" else build_web_report(value, profile)
        result.setdefault("meta", {})["cached"] = False
        cached_set(key, result)
        handler.send_json(200, result)
    except ValueError as exc:
        handler.send_json(400, {"error": str(exc) or "Could not unpack that address"})
    except Exception as exc:
        handler.send_json(502, {"error": str(exc) or "The request failed"})
