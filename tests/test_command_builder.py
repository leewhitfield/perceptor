from pathlib import Path
from shutil import which

from forensic_orchestrator.models import Partition
from forensic_orchestrator.mounting.ewf import build_ewfmount_command
from forensic_orchestrator.mounting.partitions import build_mmls_command, parse_mmls_output, select_windows_partition
from forensic_orchestrator.mounting.volume_mount import build_ntfs_mount_command


def test_mount_commands_are_arrays_and_read_only():
    image = Path("/evidence/disk.E01")
    ewf_dir = Path("/case/mounts/ewf")
    raw = ewf_dir / "ewf1"
    volume = Path("/case/mounts/volumes/part-002")
    partition = Partition(
        id="part-002",
        slot="002: 000",
        start_sector=2048,
        end_sector=4095,
        length=2048,
        description="NTFS / exFAT (0x07)",
    )

    assert build_ewfmount_command(image, ewf_dir) == ["ewfmount", str(image), str(ewf_dir)]
    assert build_ewfmount_command(image, ewf_dir, allow_other=True) == [
        "ewfmount",
        "-X",
        "allow_other",
        str(image),
        str(ewf_dir),
    ]
    assert build_ewfmount_command(image, ewf_dir, use_sudo=True) == [
        "sudo",
        "-n",
        which("ewfmount") or "ewfmount",
        str(image),
        str(ewf_dir),
    ]
    assert build_mmls_command(raw) == ["mmls", str(raw)]
    assert build_ntfs_mount_command(raw, volume, partition) == [
        "ntfs-3g",
        "-o",
        "ro,show_sys_files,streams_interface=windows,offset=1048576",
        str(raw),
        str(volume),
    ]
    assert build_ntfs_mount_command(raw, volume, partition, use_sudo=True, norecover=True) == [
        "sudo",
        "-n",
        which("ntfs-3g") or "ntfs-3g",
        "-o",
        "ro,show_sys_files,streams_interface=windows,norecover,offset=1048576",
        str(raw),
        str(volume),
    ]


def test_mmls_parser_selects_likely_windows_ntfs_partition():
    output = """
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
003:  000:001   0001026048   0002047999   0001021952   Linux (0x83)
"""
    partitions = parse_mmls_output(output)
    selected = select_windows_partition(partitions)

    assert selected.id == "part-002_000000"
    assert selected.offset_bytes == 2048 * 512
    assert selected.likely_ntfs is True
