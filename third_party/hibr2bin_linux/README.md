# Hibr2Bin Linux Wrapper

This directory contains a small POSIX compatibility layer for building the
local Magnet Forensics Hibr2Bin source checkout as a native Linux executable.
It does not vendor the Hibr2Bin source; by default the build script expects it
at `/home/lee/tools/Hibr2Bin-src/Hibr2Bin`.

Build:

```bash
third_party/hibr2bin_linux/build.sh
```

Overrides:

```bash
HIBR2BIN_SRC=/path/to/Hibr2Bin/Hibr2Bin \
HIBR2BIN_LINUX_OUT=/home/lee/tools/Hibr2Bin-linux \
third_party/hibr2bin_linux/build.sh
```

The forensic orchestrator memory string workflow auto-detects the resulting
`/home/lee/tools/Hibr2Bin-linux/hibr2bin-linux` binary.
