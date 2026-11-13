"""Stage the reviewed synthetic protocol vectors required by frozen source tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path

EXPECTED = {
    "test-vectors/authenticated-enrollment-v1.json",
    "test-vectors/registration-operation-read-v1.json",
    "spec/testdata/token-payment-review-v1.json",
    "vectors/presence-device-proof-v1.json",
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", default="source/tden-spec")
    args = parser.parse_args()
    fixture_root = Path(__file__).resolve().parent / "fixtures" / "shared-spec"
    manifest = json.loads((fixture_root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("protocol") != "tden:ci-shared-spec-fixtures:v1":
        raise SystemExit("unexpected shared fixture manifest")
    rows = manifest.get("files", [])
    if len(rows) != len(EXPECTED) or {r.get("path") for r in rows} != EXPECTED:
        raise SystemExit("unexpected shared fixture file set")
    validated = []
    for row in rows:
        relative = Path(row["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("unsafe fixture path")
        source = fixture_root / relative
        if source.is_symlink() or source.resolve() != source.absolute():
            raise SystemExit("fixture symlink is forbidden")
        data = source.read_bytes()
        if len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise SystemExit("shared fixture digest/length mismatch: " + row["path"])
        json.loads(data)
        validated.append((row, data))
    destination = Path(args.destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise SystemExit("shared fixture destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.resolve() != destination.parent:
        raise SystemExit("shared fixture destination parent is a symlink")
    destination.mkdir()
    copied = []
    for row, data in validated:
        path = destination / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.read_bytes() != data:
            raise SystemExit("fixture copy readback mismatch")
        copied.append({key: row[key] for key in ("path", "bytes", "sha256")})
    print(json.dumps({"protocol": manifest["protocol"], "files": copied,
                      "scope": "Synthetic protocol tests only; no real authority or presence acceptance"}))

if __name__ == "__main__":
    main()
