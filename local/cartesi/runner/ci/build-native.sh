#!/bin/sh
# Builds run-cartesi-worker natively on the machine it runs on (Windows under MSYS2/MINGW64, or macOS), from the
# emulator's own sources: libcartesi.a with the emulator's Makefile, then the C runner linked against it.
# Used by .github/workflows/cartesi-runner-native.yml. UNATTESTED, DEV ONLY (virtio-net via libslirp).
#
# usage: build-native.sh UARCH_DIR OUTDIR
#   UARCH_DIR  holds uarch-pristine-ram.c, uarch-pristine-hash.c, cm-version.h and interpret-jump-table.hpp, generated
#              once on Linux (they need the riscv64 toolchain and lua5.4, which the other runners do not have)
#   OUTDIR     receives run-cartesi-worker[.exe] and a short report
# env: EMULATOR_TAG (default v0.22.0), FLASH_X=yes to also make the flash drive executable (needed for a DAX root;
#      see local/cartesi/README.md), THREADS (default yes on Windows, no on macOS: no libomp to bundle)
set -eu
UARCH_DIR="$(cd "$1" && pwd)"; OUT="$2"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${EMULATOR_TAG:-v0.22.0}"
OS="$(uname -s)"
case "$OS" in
  Darwin) THREADS="${THREADS:-no}"; EXT=""; JOBS="$(sysctl -n hw.ncpu)" ;;
  MINGW*|MSYS*) THREADS="${THREADS:-yes}"; EXT=".exe"; JOBS="$(nproc)" ;;
  *) echo "unsupported host $OS (Linux uses build-static.sh)"; exit 2 ;;
esac

W="$(mktemp -d)"; cd "$W"
git clone -q --depth 1 --branch "$TAG" https://github.com/cartesi/machine-emulator.git emu
cd emu
cp "$UARCH_DIR"/uarch-pristine-ram.c "$UARCH_DIR"/uarch-pristine-hash.c uarch/
cp "$UARCH_DIR"/cm-version.h "$UARCH_DIR"/interpret-jump-table.hpp src/ # generated on Linux (they need lua5.4)
if [ "${FLASH_X:-no}" = yes ]; then
  sed -i.bak "/const pmem_flags flash_flags{/,/};/ s/\.X = false,/.X = true,/; /const pmas_flags flash_flags{/,/};/ s/\.X = false,/.X = true,/" src/machine-address-ranges.cpp
  grep -q "\.X = true" src/machine-address-ranges.cpp || { echo "flash patch did not apply"; exit 1; }
fi

make -C src -j"$JOBS" release=yes threads="$THREADS" libcartesi.a
S="$PWD/src"
ls -la "$S/libcartesi.a"

# Link the runner. libslirp and what it needs: static where a static archive exists.
case "$OS" in
  Darwin)
    PFX="$(brew --prefix)"
    LIBS=""
    for flag in $(pkg-config --static --libs slirp); do
      case "$flag" in
        -L*) LIBS="$LIBS $flag" ;;
        -l*) n="${flag#-l}"; found=""
             for d in $(pkg-config --static --libs-only-L slirp | sed 's/-L//g') "$PFX/lib"; do
               [ -f "$d/lib$n.a" ] && { found="$d/lib$n.a"; break; }; done
             LIBS="$LIBS ${found:-$flag}" ;;
        *) LIBS="$LIBS $flag" ;;
      esac
    done
    clang++ -O2 -x c -I"$S" -I"$PFX/include" "$HERE/run-cartesi-worker.c" -x none -o "$OUT/run-cartesi-worker" \
      "$S/libcartesi.a" $LIBS -lc++ -framework CoreFoundation -framework Foundation -liconv -lresolv ;;
  *)
    g++ -O2 -x c -I"$S" "$HERE/run-cartesi-worker.c" -x none -o "$OUT/run-cartesi-worker.exe" \
      "$S/libcartesi.a" $(pkg-config --static --libs slirp) -static -fopenmp -lws2_32 -liphlpapi ;;
esac
strip "$OUT/run-cartesi-worker$EXT" 2>/dev/null || true
{
  echo "host: $OS $(uname -m)   emulator: $TAG   threads: $THREADS   flash executable: ${FLASH_X:-no}"
  ls -la "$OUT/run-cartesi-worker$EXT"
  if [ "$OS" = Darwin ]; then otool -L "$OUT/run-cartesi-worker"; else ldd "$OUT/run-cartesi-worker.exe" 2>/dev/null || true; fi
} | tee "$OUT/report.txt"
