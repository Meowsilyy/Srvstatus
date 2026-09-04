import os
import sys
import threading
from pathlib import Path

os.environ["NO_BROWSER"] = "1"

FROZEN = bool(getattr(sys, "frozen", False))
BUNDLE_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
SOURCE_ROOT = BUNDLE_ROOT if FROZEN else Path(__file__).resolve().parents[1]

if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

import server as server_core
import webview

APP_NAME = "SRVSTATUS"
DEFAULT_PORT = 17844


def storage_path():
    base = os.environ.get("APPDATA")
    root = Path(base) if base else Path.home()
    path = root / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_server():
    preferred = int(os.environ.get("SRVSTATUS_DESKTOP_PORT", str(DEFAULT_PORT)))
    try:
        return server_core.ThreadingHTTPServer(("127.0.0.1", preferred), server_core.ServerStatusHandler)
    except OSError:
        return server_core.ThreadingHTTPServer(("127.0.0.1", 0), server_core.ServerStatusHandler)


def main():
    server_core.PUBLIC_DIR = BUNDLE_ROOT / "public"
    httpd = create_server()
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, name="SRVSTATUS-LocalServer", daemon=True)
    thread.start()

    webview.create_window(
        APP_NAME,
        f"http://127.0.0.1:{port}/",
        width=1480,
        height=920,
        min_size=(960, 640),
        resizable=True,
        fullscreen=False,
        frameless=False,
        easy_drag=False,
        confirm_close=False,
        background_color="#090a0c",
        text_select=True,
        zoomable=True,
    )

    try:
        webview.start(
            gui="edgechromium",
            debug=False,
            private_mode=False,
            storage_path=str(storage_path()),
            user_agent="SRVSTATUS Desktop/1.0",
        )
    finally:
        httpd.shutdown()
        httpd.server_close()
        server_core.EXECUTOR.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    main()
