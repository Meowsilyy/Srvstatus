from pathlib import Path

root = Path(__file__).resolve().parent
server_path = root / "server.py"
index_path = root / "public" / "index.html"

server = server_path.read_text(encoding="utf-8")
if "import unpack_feature" not in server:
    server = "import unpack_feature\n" + server
post_needle = "    def do_POST(self):\n"
post_insert = "    def do_POST(self):\n        if self.path == \"/api/unpack\":\n            return unpack_feature.handle_unpack(self)\n"
if post_insert not in server:
    if post_needle not in server:
        raise SystemExit("Could not find ServerStatusHandler.do_POST")
    server = server.replace(post_needle, post_insert, 1)
get_needle = "    def do_GET(self):\n"
get_insert = "    def do_GET(self):\n        if self.path.split(\"?\", 1)[0] in {\"/unpack\", \"/unpack/\"}:\n            self.send_response(302)\n            self.send_header(\"Location\", \"/unpack.html\")\n            self.send_header(\"Cache-Control\", \"no-store\")\n            self.end_headers()\n            return\n"
if get_insert not in server:
    if get_needle not in server:
        raise SystemExit("Could not find ServerStatusHandler.do_GET")
    server = server.replace(get_needle, get_insert, 1)
server_path.write_text(server, encoding="utf-8")

if index_path.exists():
    index = index_path.read_text(encoding="utf-8")
    tag = '<script src="/unpack-link.js"></script>'
    if tag not in index:
        if "</body>" in index:
            index = index.replace("</body>", f"  {tag}\n</body>", 1)
        else:
            index += f"\n{tag}\n"
        index_path.write_text(index, encoding="utf-8")
