from pathlib import Path

root = Path(__file__).resolve().parent
server_path = root / "server.py"
index_path = root / "public" / "index.html"

server = server_path.read_text(encoding="utf-8")
if "import unpack_feature" not in server:
    server = "import unpack_feature\n" + server
needle = "    def do_POST(self):\n"
insert = "    def do_POST(self):\n        if self.path == \"/api/unpack\":\n            return unpack_feature.handle_unpack(self)\n"
if insert not in server:
    if needle not in server:
        raise SystemExit("Could not find ServerStatusHandler.do_POST")
    server = server.replace(needle, insert, 1)
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
