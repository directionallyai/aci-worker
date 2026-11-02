#!/bin/sh
# Builds run-cartesi-worker natively on the machine it runs on (Windows under MSYS2/UCRT64, or macOS), from the
# emulator's own sources: libcartesi.a with the emulator's Makefile, then the C runner linked against it.
# Used by .github/workflows/cartesi-runner-native.yml. UNATTESTED, DEV ONLY (virtio-net via libslirp).
#
# usage: build-native.sh OUTDIR
#   OUTDIR     receives run-cartesi-worker[.exe] and a short report
# env: EMULATOR_TAG (default v0.22.0), FLASH_X=yes to also make the flash drive executable (needed for a DAX root;
#      see local/cartesi/README.md), THREADS (default no: OpenMP only speeds up hashing, and MSYS2 has no static libgomp nor macOS a libomp to bundle)
set -eu
OUT="$1"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${EMULATOR_TAG:-v0.22.0}"
OS="$(uname -s)"
case "$OS" in
  Darwin) THREADS="${THREADS:-no}"; export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"; # the Makefile would use the runner's own OS version
          EXT=""; JOBS="$(sysctl -n hw.ncpu)" ;;
  MINGW*|MSYS*) THREADS="${THREADS:-no}"; EXT=".exe"; JOBS="$(nproc)" ;;
  *) echo "unsupported host $OS (Linux uses build-static.sh)"; exit 2 ;;
esac

W="$(mktemp -d)"; cd "$W"
git clone -q --depth 1 --branch "$TAG" https://github.com/cartesi/machine-emulator.git emu
cd emu
# The runner never steps the microarchitecture, so its pristine RAM image and hash are stand-ins instead of the real
# generated files (which need the riscv64 toolchain). Checked on Linux: a runner built this way boots the guest.
printf '#include <stddef.h>\nunsigned char uarch_pristine_ram[] = {0};\nunsigned int uarch_pristine_ram_len = 1;\n' > uarch/uarch-pristine-ram.c
printf 'const unsigned char uarch_pristine_hash[32] = {0};\nconst unsigned int uarch_pristine_hash_len = 32;\n' > uarch/uarch-pristine-hash.c
# The emulator generates interpret-jump-table.hpp with a script whose shebang is `lua5.4`.
command -v lua5.4 >/dev/null 2>&1 || { l="$(command -v lua)"; mkdir -p "$W/bin"; ln -s "$l" "$W/bin/lua5.4"; export PATH="$W/bin:$PATH"; }
# Windows: upstream's slirp network device includes POSIX-only headers (arpa/inet.h, sys/select.h) although it only uses
# select() and libslirp, which Winsock provides. Swap the two includes under _WIN32; nothing else in the file changes.
case "$OS" in MINGW*|MSYS*)
  sed -i -e 's|^#include <arpa/inet.h>.*$|#ifdef _WIN32\n#include <winsock2.h>\n#include <ws2tcpip.h>\n#else\n#include <arpa/inet.h>\n#endif|' \
         -e 's|^#include <sys/select.h>$|#ifndef _WIN32\n#include <sys/select.h>\n#endif|' src/virtio-net-user-address-range.cpp
  grep -q "winsock2.h" src/virtio-net-user-address-range.cpp || { echo "windows slirp patch did not apply"; exit 1; } ;;
esac
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
    OMP=""; [ "$THREADS" = yes ] && OMP="-fopenmp"
    g++ -O2 -x c -I"$S" "$HERE/run-cartesi-worker.c" -x none -o "$OUT/run-cartesi-worker.exe" \
      "$S/libcartesi.a" $(pkg-config --static --libs slirp) -static $OMP -lws2_32 -liphlpapi ;;
esac
strip "$OUT/run-cartesi-worker$EXT" 2>/dev/null || true
{
  echo "host: $OS $(uname -m)   emulator: $TAG   threads: $THREADS   flash executable: ${FLASH_X:-no}"
  ls -la "$OUT/run-cartesi-worker$EXT"
  if [ "$OS" = Darwin ]; then otool -l "$OUT/run-cartesi-worker" | grep -A4 LC_BUILD_VERSION; otool -L "$OUT/run-cartesi-worker"; else ldd "$OUT/run-cartesi-worker.exe" 2>/dev/null || true; fi
} | tee "$OUT/report.txt"
