#!/usr/bin/env bash
set -euo pipefail

src_root="${HIBR2BIN_SRC:-/home/lee/tools/Hibr2Bin-src/Hibr2Bin}"
out_dir="${HIBR2BIN_LINUX_OUT:-/home/lee/tools/Hibr2Bin-linux}"
mkdir -p "$out_dir"

g++ -std=gnu++17 -O2 -DNDEBUG -D_CONSOLE \
  -I"$(dirname "$0")/include" \
  -I"$src_root" \
  -I"$src_root/CommonLibLight" \
  "$(dirname "$0")/src/linux_main.cpp" \
  "$src_root/Hiberfil.cpp" \
  "$src_root/MemoryBlocks.cpp" \
  "$src_root/Disk.cpp" \
  "$(dirname "$0")/src/FileContextPosix.cpp" \
  "$(dirname "$0")/src/MiscPosix.cpp" \
  -o "$out_dir/hibr2bin-linux"

echo "$out_dir/hibr2bin-linux"
