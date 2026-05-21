from __future__ import annotations

import re
from pathlib import Path

from forensic_orchestrator.models import Partition
from forensic_orchestrator.safety import PartitionError, require_dependency


def build_mmls_command(raw_image: Path) -> list[str]:
    return ["mmls", str(raw_image)]


def validate_mmls_available() -> None:
    require_dependency("mmls")


def parse_mmls_output(output: str, sector_size: int = 512) -> list[Partition]:
    partitions: list[Partition] = []
    pattern = re.compile(
        r"^\s*(?P<slot>\d{3}:\s+\S+)\s+"
        r"(?P<start>\d+)\s+"
        r"(?P<end>\d+)\s+"
        r"(?P<length>\d+)\s+"
        r"(?P<desc>.+?)\s*$"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        desc = match.group("desc")
        if "unallocated" in desc.lower() or "metadata" in desc.lower():
            continue
        slot = re.sub(r"_+", "_", match.group("slot").replace(" ", "_").replace(":", "")).strip("_")
        partitions.append(
            Partition(
                id=f"part-{slot}",
                slot=match.group("slot"),
                start_sector=int(match.group("start")),
                end_sector=int(match.group("end")),
                length=int(match.group("length")),
                description=desc,
                sector_size=sector_size,
            )
        )
    return partitions


def select_windows_partition(partitions: list[Partition]) -> Partition:
    if not partitions:
        raise PartitionError("No partitions detected by mmls")
    ntfs = [partition for partition in partitions if partition.likely_ntfs]
    if ntfs:
        return max(ntfs, key=lambda partition: partition.length)
    return max(partitions, key=lambda partition: partition.length)
