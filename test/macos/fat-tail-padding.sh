#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/main.c" <<'EOF'
int main(void) {
    return 0;
}
EOF

# An unsigned watchOS executable has no reserved signature space, which makes
# zsign reallocate both slices and rebuild the fat container.
for arch in arm64_32 arm64; do
    xcrun --sdk watchos clang \
        -arch "$arch" \
        -Wl,-no_adhoc_codesign \
        "$tmp/main.c" \
        -o "$tmp/main-$arch"
done
xcrun lipo -create "$tmp/main-arm64_32" "$tmp/main-arm64" -output "$tmp/main-fat"

"$repo_root/bin/zsign" -q -a "$tmp/main-fat"
/usr/bin/codesign --verify --strict "$tmp/main-fat"

python3 - "$tmp/main-fat" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
data = path.read_bytes()
magic, count = struct.unpack_from(">II", data)
if magic != 0xCAFEBABE:
    raise SystemExit(f"unexpected fat magic: 0x{magic:08x}")

arches = [
    struct.unpack_from(">IIIII", data, 8 + index * 20)
    for index in range(count)
]
for _, _, offset, _, align in arches:
    if offset % (1 << align):
        raise SystemExit(f"slice offset {offset} is not aligned to 2^{align}")

expected_size = max(offset + size for _, _, offset, size, _ in arches)
if len(data) != expected_size:
    raise SystemExit(
        f"fat binary has {len(data) - expected_size} trailing bytes "
        f"(file size {len(data)}, final slice end {expected_size})"
    )
PY
