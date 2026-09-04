import io
import json
import zipfile

import unpack_core_v2 as base
import unpack_core_v3 as v3

build_web_report = v3.build_web_report


def _challenge_from_response(result, source):
    report = {
        "source": source,
        "overview": {"title": ""},
        "headers": result.get("headers") if isinstance(result, dict) else {},
    }
    return v3.detect_challenge(report)


def build_site_archive(value, profile="standard"):
    data, filename, meta = v3.build_site_archive(value, profile)
    with zipfile.ZipFile(io.BytesIO(data), "r") as source_zip:
        manifest = json.loads(source_zip.read("manifest.json").decode("utf-8", "replace"))
        final_url = str(manifest.get("source") or "")
        if not final_url:
            return data, filename, meta
        result = base.fetch_public_url(final_url, timeout=7.5, max_bytes=base.MAX_HTML_BYTES, accept="text/html,application/xhtml+xml,*/*;q=0.5", redirects=4)
        full_source = base.decode_text(result.get("body") or b"", result.get("headers") or {})
        challenge = _challenge_from_response(result, full_source)
        if challenge:
            raise ValueError(f"{challenge['provider']} returned a challenge page, not the website. ZIP export stopped.")
        mapping = {}
        for item in manifest.get("files") or []:
            if not isinstance(item, dict) or not item.get("path"):
                continue
            for key in (item.get("url"), item.get("finalUrl")):
                if key:
                    mapping[str(key)] = str(item.get("path"))
        rewritten = v3._rewrite_html(full_source, final_url, mapping)
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target_zip:
            for info in source_zip.infolist():
                if info.filename == "index.html":
                    continue
                target_zip.writestr(info, source_zip.read(info.filename))
            target_zip.writestr("index.html", rewritten)
            target_zip.writestr("original-page.html", full_source)
        meta = dict(meta or {})
        meta["htmlBytes"] = len(result.get("body") or b"")
        meta["fullHtml"] = True
        return out.getvalue(), filename, meta
