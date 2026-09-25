#!/usr/bin/env bash
# Build the Phase 4 BPF LSM probes.
#
# vmlinux.h is generated from the running kernel's BTF rather than from kernel
# headers, so the build depends only on clang, llvm-strip and a readable
# /sys/kernel/btf/vmlinux.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PROBES="$HERE/probes"
OUT="$HERE/out"

mkdir -p "$OUT"

if [[ ! -f "$PROBES/vmlinux.h" ]]; then
    echo "generating vmlinux.h from BTF..."
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$PROBES/vmlinux.h"
fi

ARCH="$(uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')"

built=0
for src in "$PROBES"/*.bpf.c; do
    [[ -e "$src" ]] || continue
    name="$(basename "$src" .bpf.c)"
    obj="$OUT/$name.bpf.o"

    echo "compiling $name..."
    # -Wno-missing-declarations: vmlinux.h, being generated from BTF, contains
    # forward declarations of anonymous types that clang warns about. The warnings
    # are a property of the generator, not of the probe source.
    clang -g -O2 -target bpf \
        -D__TARGET_ARCH_"$ARCH" \
        -Wall -Wno-missing-declarations \
        -I"$PROBES" \
        -c "$src" -o "$obj"

    llvm-strip -g "$obj"
    built=$((built + 1))
    echo "  -> $obj"
done

echo
echo "built $built probe(s) into $OUT"
