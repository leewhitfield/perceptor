# Perceptor Dependencies

Perceptor relies on a combination of system packages and Python libraries.

## System Dependencies (Ubuntu 24.04)
These packages are required for parsing forensic artifacts and extracting data:
- **sleuthkit**: Filesystem parsing (NTFS, EXT4, etc.)
- **ewf-tools**: Reading E01 forensic images
- **qemu-utils**: Mounting VM disk images
- **ntfs-3g**: NTFS mounting
- **cryptsetup & dislocker & libbde-utils**: BitLocker and encrypted volume unlocking
- **libesedb-utils**: ESE database parsing (Windows Search, WebCache)
- **libvshadow-utils**: Volume Shadow Copy parsing
- **libfsntfs-utils & python3-libfsntfs**: Advanced NTFS parsing
- **poppler-utils & tesseract-ocr**: PDF extraction and OCR
- **exiftool**: Metadata extraction

## Python Dependencies
Python dependencies are managed via `uv` in `pyproject.toml`.
Run `uv sync` to install all required libraries in an isolated virtual environment.

## Managed Third-Party Tools
Perceptor can automatically download and install additional tools (like Zimmerman's EZ Tools) via:
```bash
perceptor standalone install-third-party
```
