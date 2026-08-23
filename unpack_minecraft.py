import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request

USER_AGENT = "Unpack/1.0"


def _is_private(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified
    except ValueError:
        return False


def normalize_address(value):
    raw = str(value or "").strip()
    raw = re.sub(r"^minecraft://", "", raw, flags=re.I)
    raw = re.sub(r"^https?://", "", raw, flags=re.I).split("/", 1)[0]
    if not raw or len(raw) > 255:
        raise ValueError("Enter a Minecraft server address")
    host = raw
    if raw.startswith("[") and "]" in raw:
        host = raw[1:raw.index("]")]
    elif raw.count(":") == 1:
        host = raw.rsplit(":", 1)[0]
    if host.lower() == "localhost" or host.lower().endswith((".local", ".lan", ".internal")):
        raise ValueError("Local and private addresses are not supported")
    if _is_private(host):
        raise ValueError("Local and private addresses are not supported")
    try:
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            if _is_private(item[4][0]):
                raise ValueError("The server resolves to a local or private address")
    except socket.gaierror:
        pass
    return raw


def fetch_json(url, timeout=6):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def safe_fetch(url):
    try:
        return fetch_json(url)
    except Exception as exc:
        return {"online": False, "_error": str(exc)}


def pack_candidates(payload):
    found = []

    def walk(value, key=""):
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, str(child_key))
        elif isinstance(value, list):
            for child in value:
                walk(child, key)
        elif isinstance(value, str):
            lower = value.lower()
            key_lower = key.lower()
            if value.startswith(("http://", "https://")) and (lower.endswith(".zip") or "resourcepack" in lower or "resource-pack" in lower or "pack" in key_lower):
                found.append(value)

    walk(payload)
    return list(dict.fromkeys(found))[:10]


def clean_motd(value):
    if not isinstance(value, dict):
        return []
    clean = value.get("clean")
    if isinstance(clean, list):
        return [str(item) for item in clean]
    if isinstance(clean, str):
        return [clean]
    raw = value.get("raw")
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return []


def summarize(payload):
    if not isinstance(payload, dict):
        return {"online": False}
    players = payload.get("players") if isinstance(payload.get("players"), dict) else {}
    version = payload.get("version")
    if isinstance(version, dict):
        version_name = version.get("name") or version.get("raw")
    else:
        version_name = version
    return {
        "online": bool(payload.get("online")),
        "ip": payload.get("ip"),
        "port": payload.get("port"),
        "hostname": payload.get("hostname"),
        "version": version_name,
        "protocol": payload.get("protocol"),
        "software": payload.get("software"),
        "playersOnline": players.get("online"),
        "playersMax": players.get("max"),
        "playersList": players.get("list") if isinstance(players.get("list"), list) else [],
        "motd": clean_motd(payload.get("motd")),
        "icon": payload.get("icon"),
        "map": payload.get("map"),
        "gamemode": payload.get("gamemode"),
        "eulaBlocked": payload.get("eula_blocked"),
        "mods": payload.get("mods") if isinstance(payload.get("mods"), list) else [],
        "plugins": payload.get("plugins") if isinstance(payload.get("plugins"), list) else [],
        "debug": payload.get("debug") if isinstance(payload.get("debug"), dict) else {},
        "raw": payload,
    }


def build_minecraft_report(value):
    address = normalize_address(value)
    encoded = urllib.parse.quote(address, safe="")
    java = safe_fetch(f"https://api.mcsrvstat.us/3/{encoded}")
    bedrock = safe_fetch(f"https://api.mcsrvstat.us/bedrock/3/{encoded}")
    packs = pack_candidates(java) + pack_candidates(bedrock)
    return {
        "kind": "minecraft",
        "address": address,
        "java": summarize(java),
        "bedrock": summarize(bedrock),
        "packCandidates": list(dict.fromkeys(packs))[:10],
        "packNote": "A server-list ping normally does not expose the resource-pack URL. Download is shown only when a public pack URL is actually present in returned metadata.",
        "source": "mcsrvstat.us API v3",
    }
