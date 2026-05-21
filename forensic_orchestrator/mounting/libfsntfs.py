from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from forensic_orchestrator.safety import ToolError


EVTX_SIGNATURE = b"ElfFile\x00"


def pyfsntfs_available() -> bool:
    try:
        importlib.import_module("pyfsntfs")
    except ImportError:
        return False
    return True


@dataclass(frozen=True)
class LibfsntfsSalvageResult:
    source_path: str
    destination: Path
    logical_size: int
    recovered_size: int
    readable_bytes: int
    failed_offsets: tuple[int, ...]
    block_size: int
    header_valid: bool

    @property
    def failed_block_count(self) -> int:
        return len(self.failed_offsets)


class OffsetFile:
    def __init__(self, path: Path, offset: int) -> None:
        self._file: BinaryIO = path.open("rb")
        self._offset = offset
        self._file.seek(0, 2)
        self._size = max(0, self._file.tell() - offset)
        self._file.seek(offset)

    def read(self, size: int = -1) -> bytes:
        return self._file.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            target = self._offset + offset
        elif whence == 1:
            target = self._file.tell() + offset
        elif whence == 2:
            target = self._offset + self._size + offset
        else:
            raise ValueError(f"Unsupported seek mode: {whence}")
        self._file.seek(target)
        return self.tell()

    def tell(self) -> int:
        return self._file.tell() - self._offset

    def close(self) -> None:
        self._file.close()


def evtx_header_valid(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(EVTX_SIGNATURE)) == EVTX_SIGNATURE
    except OSError:
        return False


def salvage_ntfs_file(
    *,
    raw_image: Path,
    offset_bytes: int,
    ntfs_path: str,
    destination: Path,
    block_size: int = 64 * 1024,
) -> LibfsntfsSalvageResult:
    try:
        pyfsntfs = importlib.import_module("pyfsntfs")
    except ImportError as exc:
        raise ToolError("python3-libfsntfs/pyfsntfs is not available") from exc

    normalized_path = ntfs_path.replace("/", "\\").lstrip("\\")
    destination.parent.mkdir(parents=True, exist_ok=True)

    volume = pyfsntfs.volume()
    file_object: OffsetFile | None = None
    try:
        if offset_bytes:
            file_object = OffsetFile(raw_image, offset_bytes)
            volume.open_file_object(file_object)
        else:
            volume.open(str(raw_image))

        file_entry = volume.get_file_entry_by_path(normalized_path)
        if file_entry is None:
            raise ToolError(f"libfsntfs could not find file: {ntfs_path}")

        logical_size = int(file_entry.get_size())
        failed_offsets: list[int] = []
        readable_bytes = 0

        with destination.open("wb") as output:
            for offset in range(0, logical_size, block_size):
                requested = min(block_size, logical_size - offset)
                try:
                    data = file_entry.read_buffer_at_offset(requested, offset)
                    if len(data) < requested:
                        data = data + (b"\x00" * (requested - len(data)))
                    readable_bytes += requested
                except Exception:
                    data = b"\x00" * requested
                    failed_offsets.append(offset)
                output.write(data)
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"libfsntfs salvage failed for {ntfs_path}: {exc}") from exc
    finally:
        try:
            volume.close()
        except Exception:
            pass
        if file_object is not None:
            file_object.close()

    return LibfsntfsSalvageResult(
        source_path=ntfs_path,
        destination=destination,
        logical_size=logical_size,
        recovered_size=destination.stat().st_size,
        readable_bytes=readable_bytes,
        failed_offsets=tuple(failed_offsets),
        block_size=block_size,
        header_valid=evtx_header_valid(destination),
    )
