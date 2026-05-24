from __future__ import annotations

import csv
import os
import hashlib
import re
import shutil
import subprocess
from pathlib import Path


DEFAULT_TERMS: dict[str, tuple[str, ...]] = {
    "credentials": ("password", "passwd", "pwd=", "token", "bearer ", "refresh_token", "credential"),
    "remote_access": ("mstsc", "rdp", "teamviewer", "anydesk", "logmein", "screenconnect", "splashtop"),
    "cloud": ("sharepoint", "onedrive", "google drive", "dropbox", "box.com", "teams.microsoft.com"),
    "browser": ("cookies", "login data", "places.sqlite", "history", "sessionstorage", "localstorage"),
    "search": ("windows.edb", "windows.db", "searchindexer", "systemindex", "aesgcm1"),
    "email": (".ost", ".pst", "smtp", "imap", "exchange", "outlook"),
    "paths": ("c:\\users\\", "\\users\\", "\\appdata\\", "\\desktop\\", "\\downloads\\"),
}


def scan_memory_strings_to_csv(
    source: Path,
    output_dir: Path,
    *,
    terms: dict[str, tuple[str, ...]] | None = None,
    min_length: int = 6,
    context_limit: int = 500,
    decompress_hiberfil: bool = True,
) -> tuple[Path, dict[str, str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    terms = terms or DEFAULT_TERMS
    source = source.resolve()
    scanned_path = source
    decompressed_path = ""
    decompress_status = "not_applicable"
    if decompress_hiberfil and source.name.lower() == "hiberfil.sys":
        target = output_dir / "hiberfil.decompressed.bin"
        decompressed = decompress_hiberfil_candidate(source, target)
        decompress_status = decompressed["status"]
        if decompressed.get("path"):
            scanned_path = Path(decompressed["path"])
            decompressed_path = str(scanned_path)
    output = output_dir / "MemoryStringScanner.csv"
    scanner = "bstrings" if _bstrings_command() else "strings"
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "source_artifact_type",
                "source_path",
                "scanned_path",
                "decompressed_path",
                "scanner",
                "encoding",
                "hit_category",
                "matched_term",
                "string_value",
                "string_sha256",
                "string_length",
                "offset",
                "context_hint",
            ],
        )
        writer.writeheader()
        for row in iter_string_hits(scanned_path, scanner=scanner, terms=terms, min_length=min_length, context_limit=context_limit):
            row.update(
                {
                    "source_artifact_type": memory_artifact_type(source),
                    "source_path": str(source),
                    "scanned_path": str(scanned_path),
                    "decompressed_path": decompressed_path,
                    "scanner": scanner,
                }
            )
            writer.writerow(row)
    return output, {"scanner": scanner, "decompress_status": decompress_status, "scanned_path": str(scanned_path)}


def decompress_hiberfil_candidate(source: Path, target: Path) -> dict[str, str]:
    target.parent.mkdir(parents=True, exist_ok=True)
    commands = []
    hibr2bin = _hibr2bin_command()
    if hibr2bin:
        commands.append([*hibr2bin, "/PLATFORM", "X64", "/MAJOR", "10", "/MINOR", "0", "/INPUT", str(source), "/OUTPUT", str(target)])
    if shutil.which("HibernationRecon"):
        commands.append(["HibernationRecon", "-f", str(source), "-o", str(target.parent)])
    if shutil.which("HibernationRecon.exe"):
        commands.append(["HibernationRecon.exe", "-f", str(source), "-o", str(target.parent)])
    for command in commands:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=3600)
        except (OSError, subprocess.TimeoutExpired) as exc:
            last_error = str(exc)
            continue
        if completed.returncode == 0:
            if target.exists() and target.stat().st_size > 0:
                return {"status": "decompressed", "path": str(target), "command": " ".join(command)}
            candidates = sorted(target.parent.glob("*"), key=lambda path: path.stat().st_size if path.is_file() else 0, reverse=True)
            for candidate in candidates:
                if candidate.is_file() and candidate.stat().st_size > 0 and candidate != source:
                    return {"status": "decompressed", "path": str(candidate), "command": " ".join(command)}
        last_error = (completed.stderr or completed.stdout or "").strip()
    return {"status": "decompressor_unavailable_or_failed", "error": locals().get("last_error", "no supported hiberfil decompressor found")}


def _hibr2bin_command() -> list[str] | None:
    explicit = os.environ.get("HIBR2BIN_BIN")
    candidates = [explicit] if explicit else []
    for name in ("hibr2bin", "Hibr2Bin", "HIBR2BIN", "Hibr2Bin.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in (
        "/home/lee/tools/Hibr2Bin-build/Hibr2Bin.exe",
        "/home/lee/tools/Hibr2Bin/Hibr2Bin.exe",
    ):
        if Path(candidate).exists():
            candidates.append(candidate)
    wine = shutil.which("wine64") or shutil.which("wine")
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.suffix.lower() == ".exe" and not _is_linux_executable(path):
            if wine:
                return [wine, str(path)]
            continue
        if path.exists() or shutil.which(candidate):
            return [str(path)]
    return None


def _is_linux_executable(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def iter_string_hits(
    source: Path,
    *,
    scanner: str,
    terms: dict[str, tuple[str, ...]],
    min_length: int,
    context_limit: int,
) -> list[dict[str, str]]:
    outputs = []
    if scanner == "bstrings":
        command = _bstrings_command()
        if command:
            with source.open("rb") as handle:
                completed = subprocess.run(
                    [*command, "-m", str(min_length), "--off", "-q"],
                    stdin=handle,
                    capture_output=True,
                    text=True,
                    errors="replace",
                    check=False,
                )
            outputs.append(completed.stdout)
    else:
        for command in _scanner_commands(scanner, source, min_length):
            completed = subprocess.run(command, capture_output=True, text=True, errors="replace", check=False)
            outputs.append(completed.stdout)
    hits = []
    seen: set[tuple[str, str, str]] = set()
    for line in "\n".join(outputs).splitlines():
        offset, text = _split_offset(line, scanner)
        lowered = text.lower()
        for category, needles in terms.items():
            for term in needles:
                if term.lower() not in lowered:
                    continue
                value = text[:context_limit]
                key = (category, term.lower(), hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest())
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    {
                        "encoding": "utf-8/utf-16le",
                        "hit_category": category,
                        "matched_term": term,
                        "string_value": value,
                        "string_sha256": key[2],
                        "string_length": str(len(text)),
                        "offset": offset,
                        "context_hint": _context_hint(text),
                    }
                )
    return hits


def memory_artifact_type(source: Path) -> str:
    name = source.name.lower()
    if name == "hiberfil.sys":
        return "hiberfil"
    if name == "pagefile.sys":
        return "pagefile"
    if name == "swapfile.sys":
        return "swapfile"
    return "memory"


def _scanner_commands(scanner: str, source: Path, min_length: int) -> list[list[str]]:
    return [
        ["strings", "-a", "-td", "-n", str(min_length), str(source)],
        ["strings", "-a", "-td", "-n", str(min_length), "-el", str(source)],
    ]


def _split_offset(line: str, scanner: str) -> tuple[str, str]:
    if scanner == "bstrings":
        match = re.match(r"^(?P<text>.*?)\t0x(?P<offset>[0-9A-Fa-f]+)\s+\((?P<encoding>[^)]*)\)$", line)
        if match:
            return str(int(match.group("offset"), 16)), match.group("text")
    match = re.match(r"^\s*(\d+)\s+(.+)$", line)
    if match:
        return match.group(1), match.group(2)
    return "", line


def _bstrings_command() -> list[str] | None:
    explicit = os.environ.get("BSTRINGS_BIN")
    candidates = [explicit] if explicit else []
    found = shutil.which("bstrings")
    if found:
        candidates.append(found)
    for candidate in (
        "/home/lee/tools/bstrings/bstrings.dll",
        "/home/lee/tools/eztools/bstrings/bstrings.dll",
    ):
        if Path(candidate).exists():
            candidates.append(candidate)
    dotnet = shutil.which("dotnet") or "/home/lee/.dotnet/dotnet"
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.suffix.lower() == ".dll":
            if Path(dotnet).exists():
                return [dotnet, str(path)]
        elif path.exists() or shutil.which(candidate):
            return [str(path)]
    return None


def _context_hint(text: str) -> str:
    if re.search(r"https?://", text, re.I):
        return "url"
    if re.search(r"[A-Za-z]:\\|\\\\|/Users/|/home/", text):
        return "path"
    if "@" in text:
        return "email_or_account"
    return ""
