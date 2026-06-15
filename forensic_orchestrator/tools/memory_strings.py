from __future__ import annotations

import csv
import os
import hashlib
import re
import shlex
import shutil
import subprocess
from collections.abc import Iterator
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
    source_artifact_type: str | None = None,
) -> tuple[Path, dict[str, str]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    terms = terms or DEFAULT_TERMS
    source = source.resolve()
    scanned_path = source
    decompressed_path = ""
    decompress_status = "not_applicable"
    decompress_error = ""
    decompress_command = ""
    decompress_attempts = "0"
    hiberfil_status = "not_applicable"
    hiberfil_note = ""
    if decompress_hiberfil and source.name.lower() == "hiberfil.sys":
        hiberfil_status, hiberfil_note = assess_hiberfil_source(source)
        target = output_dir / "hiberfil.decompressed.bin"
        decompressed = decompress_hiberfil_candidate(source, target)
        decompress_status = decompressed["status"]
        decompress_error = decompressed.get("error", "")
        decompress_command = decompressed.get("command", "")
        decompress_attempts = decompressed.get("attempt_count", "0")
        if decompressed.get("path"):
            scanned_path = Path(decompressed["path"])
            decompressed_path = str(scanned_path)
        elif hiberfil_status == "zeroed_or_inactive":
            scanned_path = None
    output = output_dir / "MemoryStringScanner.csv"
    scanner = "bstrings" if _bstrings_command() else "strings"
    term_file = _write_bstrings_terms(output_dir, terms) if scanner == "bstrings" else None
    artifact_type = source_artifact_type or memory_artifact_type(source)
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
        if scanned_path is not None:
            for row in iter_string_hits(
                scanned_path,
                scanner=scanner,
                terms=terms,
                min_length=min_length,
                context_limit=context_limit,
                term_file=term_file,
            ):
                row.update(
                    {
                        "source_artifact_type": artifact_type,
                        "source_path": str(source),
                        "scanned_path": str(scanned_path),
                        "decompressed_path": decompressed_path,
                        "scanner": scanner,
                    }
                )
                writer.writerow(row)
    return output, {
        "source_path": str(source),
        "source_artifact_type": artifact_type,
        "scanner": scanner,
        "decompress_status": decompress_status,
        "decompress_error": decompress_error,
        "decompress_command": decompress_command,
        "decompress_attempt_count": str(decompress_attempts),
        "hiberfil_status": hiberfil_status,
        "hiberfil_note": hiberfil_note,
        "scanned_path": str(scanned_path or source),
        "source_size_bytes": str(_path_size(source)),
        "scanned_size_bytes": str(_path_size(scanned_path) if scanned_path else 0),
    }


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
    if not commands:
        return {"status": "decompressor_unavailable", "error": "no supported hiberfil decompressor found", "attempt_count": "0"}
    last_error = ""
    for attempt_index, command in enumerate(commands, 1):
        command_text = shlex.join(command)
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=3600)
        except subprocess.TimeoutExpired as exc:
            last_error = f"{command_text}: timed out after {exc.timeout} seconds"
            continue
        except OSError as exc:
            last_error = f"{command_text}: {exc}"
            continue
        if completed.returncode == 0:
            if target.exists() and target.stat().st_size > 0:
                return {"status": "decompressed", "path": str(target), "command": command_text, "attempt_count": str(attempt_index)}
            candidates = sorted(target.parent.glob("*"), key=lambda path: path.stat().st_size if path.is_file() else 0, reverse=True)
            for candidate in candidates:
                if candidate.is_file() and candidate.stat().st_size > 0 and candidate != source:
                    return {"status": "decompressed", "path": str(candidate), "command": command_text, "attempt_count": str(attempt_index)}
        last_error = f"{command_text}: {(completed.stderr or completed.stdout or '').strip()}"
    return {"status": "decompress_failed", "error": last_error, "attempt_count": str(len(commands))}


def assess_hiberfil_source(source: Path, *, sample_size: int = 4096) -> tuple[str, str]:
    try:
        size = source.stat().st_size
    except OSError as exc:
        return "unreadable", str(exc)
    if size == 0:
        return "empty", "hiberfil.sys is zero bytes."
    offsets = [0, min(0x1000, max(size - sample_size, 0))]
    if size > sample_size:
        offsets.extend([size // 4, size // 2, (size * 3) // 4, max(size - sample_size, 0)])
    nonzero_samples = 0
    first = b""
    try:
        with source.open("rb") as handle:
            for offset in dict.fromkeys(offsets):
                handle.seek(offset)
                data = handle.read(sample_size)
                if offset == 0:
                    first = data
                if any(data):
                    nonzero_samples += 1
    except OSError as exc:
        return "unreadable", str(exc)
    header = first[:16]
    if header.startswith((b"hibr", b"HIBR", b"wake", b"WAKE", b"RSTR")):
        return "active_hibernation_header", f"hiberfil.sys has a recognized hibernation signature: {header[:4]!r}."
    if nonzero_samples == 0:
        return "zeroed_or_inactive", "Sampled hiberfil.sys regions are all zeroed; no active hibernation payload was detected."
    return "unknown_or_compressed", "hiberfil.sys has non-zero data but no recognized active hibernation header in sampled regions."


def _hibr2bin_command() -> list[str] | None:
    explicit = os.environ.get("HIBR2BIN_BIN")
    candidates = [explicit] if explicit else []
    for name in ("hibr2bin", "Hibr2Bin", "HIBR2BIN", "Hibr2Bin.exe"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in _tool_root_candidates(
        "Hibr2Bin-linux/hibr2bin-linux",
        "Hibr2Bin-build/Hibr2Bin.exe",
        "Hibr2Bin/Hibr2Bin.exe",
        "hibr2bin-linux/hibr2bin-linux",
        "hibr2bin/hibr2bin",
        "hibr2bin/Hibr2Bin.exe",
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
    term_file: Path | None = None,
) -> Iterator[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    for line in _iter_scanner_lines(source, scanner=scanner, min_length=min_length, term_file=term_file):
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
                yield {
                    "encoding": "utf-8/utf-16le",
                    "hit_category": category,
                    "matched_term": term,
                    "string_value": value,
                    "string_sha256": key[2],
                    "string_length": str(len(text)),
                    "offset": offset,
                    "context_hint": _context_hint(text),
                }


def _iter_scanner_lines(source: Path, *, scanner: str, min_length: int, term_file: Path | None = None) -> Iterator[str]:
    if scanner == "bstrings":
        command = _bstrings_command()
        if not command:
            return
        bstrings_args = [*command, "-m", str(min_length), "-b", "64", "--off", "-q"]
        if term_file:
            bstrings_args.extend(["--fs", str(term_file)])
        with source.open("rb") as handle:
            process = subprocess.Popen(
                bstrings_args,
                stdin=handle,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                errors="replace",
            )
            assert process.stdout is not None
            for line in process.stdout:
                yield line.rstrip("\n")
            process.wait()
        return
    for command in _scanner_commands(scanner, source, min_length):
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
        assert process.stdout is not None
        for line in process.stdout:
            yield line.rstrip("\n")
        process.wait()


def _write_bstrings_terms(output_dir: Path, terms: dict[str, tuple[str, ...]]) -> Path:
    term_file = output_dir / "MemoryStringTerms.txt"
    all_terms = {term for needles in terms.values() for term in needles}
    unique_terms = sorted(all_terms | {term.lower() for term in all_terms})
    term_file.write_text("\n".join(unique_terms) + "\n", encoding="utf-8")
    return term_file


def memory_artifact_type(source: Path) -> str:
    name = source.name.lower()
    lowered_path = str(source).replace("\\", "/").lower()
    if name == "hiberfil.sys":
        return "hiberfil"
    if name == "pagefile.sys":
        return "pagefile"
    if name == "swapfile.sys":
        return "swapfile"
    if name.endswith((".dmp", ".dump", ".mdmp")):
        if "/crashdumps/" in lowered_path or "/wer/" in lowered_path or "/minidump/" in lowered_path or name == "memory.dmp":
            return "crash_dump"
        return "process_dump"
    if name.endswith((".raw", ".vmem", ".mem")):
        return "full_memory_dump"
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
    for candidate in _tool_root_candidates(
        "bstrings/bstrings",
        "bstrings/bstrings.dll",
        "eztools/bstrings/bstrings.dll",
        "EZTools/bstrings/bstrings.dll",
    ):
        if Path(candidate).exists():
            candidates.append(candidate)
    dotnet = os.environ.get("PERCEPTOR_DOTNET") or os.environ.get("FORENSIC_ORCHESTRATOR_DOTNET") or shutil.which("dotnet")
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.suffix.lower() == ".dll":
            if dotnet and (Path(dotnet).exists() or shutil.which(dotnet)):
                return [dotnet, str(path)]
        elif path.exists() or shutil.which(candidate):
            return [str(path)]
    return None


def _tool_root_candidates(*relative_paths: str) -> list[str]:
    roots: list[Path] = []
    explicit = os.environ.get("PERCEPTOR_TOOLS_ROOT") or os.environ.get("FORENSIC_ORCHESTRATOR_TOOLS_ROOT")
    if explicit:
        roots.append(Path(explicit).expanduser())
    roots.extend([Path("/opt/perceptor-tools"), Path.home() / "tools"])
    output: list[str] = []
    seen: set[str] = set()
    for root in roots:
        for relative_path in relative_paths:
            candidate = str(root / relative_path)
            if candidate not in seen:
                seen.add(candidate)
                output.append(candidate)
    return output


def _path_size(path: Path | None) -> int:
    if path is None:
        return 0
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _context_hint(text: str) -> str:
    if re.search(r"https?://", text, re.I):
        return "url"
    if re.search(r"[A-Za-z]:\\|\\\\|/Users/|/home/", text):
        return "path"
    if "@" in text:
        return "email_or_account"
    return ""
