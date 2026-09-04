import base64
import hashlib
import io
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHUNK_DIR = ROOT / ".release" / "v10"
EXPECTED_SHA256 = "acd5ca8a90112013920c08b839305e152fded8671252cf663f799d0cd514abf3"


def main():
    encoded = "".join((CHUNK_DIR / f"chunk0{i}").read_text(encoding="utf-8") for i in range(4))
    payload = base64.b64decode(encoded)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"Release archive checksum mismatch: {digest}")

    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        for member in archive.getmembers():
            destination = (ROOT / member.name).resolve()
            if destination != ROOT and ROOT not in destination.parents:
                raise SystemExit(f"Unsafe archive path: {member.name}")
        archive.extractall(ROOT)

    source = (ROOT / "integrate_unpack.py").read_text(encoding="utf-8")
    exec(compile(source, str(ROOT / "integrate_unpack.py"), "exec"), {"__name__": "__main__", "__file__": str(ROOT / "integrate_unpack.py")})


if __name__ == "__main__":
    main()
