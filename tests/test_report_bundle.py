from __future__ import annotations

import csv

from forensic_orchestrator.report_bundle import infer_report_candidate


def test_report_bundle_detects_vsc_named_mft_by_header(tmp_path):
    csv_path = tmp_path / "Replaced1-A00521_E_ShadowCopy52_$MFT.csv"
    csv_path.write_text(
        "EntryNumber,SequenceNumber,ParentPath,FileName,Created0x10\n"
        "42,3,C:/Users/test,thing.txt,2023-01-01 00:00:00\n",
        encoding="utf-8",
    )

    candidate = infer_report_candidate(csv_path)

    assert candidate is not None
    assert candidate.tool_name == "MFTECmd"
    assert candidate.transform is None


def test_report_bundle_detects_and_transforms_tzworks_lnk(tmp_path):
    csv_path = tmp_path / "Replaced1_output.csv"
    csv_path.write_text(
        "lp (lnk parser)\n"
        "\n"
        "source path/filename,source type,file mdate, time-UTC,file adate, time-UTC,file cdate, time-UTC,"
        "tgt mdate, time-UTC,tgt adate, time-UTC,tgt cdate, time-UTC,ObjID date, time-UTC,tgt attrib,"
        "target inode,target seq#,file size,target name,IDList extra info,vol type,vol serial,vol label,"
        "local path,common path,network/device info,extra info,netbios name\n"
        "C:/Recent/a.lnk,file,2023-01-02,01:02:03,2023-01-03,02:03:04,2023-01-04,03:04:05,"
        "2023-01-05,04:05:06,2023-01-06,05:06:07,2023-01-07,06:07:08,,,,123,1,4096,"
        "target.exe,,fixed,ABCD-1234,DATA,C:/target.exe,,,/safe,HOST01\n",
        encoding="utf-8",
    )

    candidate = infer_report_candidate(csv_path)
    assert candidate is not None
    assert candidate.tool_name == "LECmd"
    transformed = candidate.transform(csv_path, tmp_path / "lnk.normalized.csv")

    with transformed.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["SourceFile"] == "C:/Recent/a.lnk"
    assert rows[0]["TargetModified"] == "2023-01-05 04:05:06"
    assert rows[0]["VolumeSerialNumber"] == "ABCD-1234"
    assert rows[0]["LocalPath"] == "C:/target.exe"
    assert rows[0]["MachineID"] == "HOST01"


def test_report_bundle_detects_and_transforms_tzworks_usp(tmp_path):
    csv_path = tmp_path / "usp_output.csv"
    csv_path.write_text(
        "usp (usb storage parser)\n"
        "\n"
        "device name,vid/pid, time-UTC,install, time-local,disk dev, time-UTC,vol dev, time-UTC,type,"
        "vid,pid,hub,port,vendor,product,rev,volume guid,vol name/details,users [ date/time-UTC],"
        "instance/serial#,Other dates defined by explicit property keys,Readyboost\n"
        "SanDisk Ultra,2020-12-12,03:37:00,2020-12-12,03:38:00,2020-12-12,03:39:00,"
        "2020-12-12,03:40:00,disk [usbstor],#0781,#5581,hub1,1,SanDisk,Ultra,1.00,"
        "{11111111-2222-3333-4444-555555555555},E: DATA,user1,SERIAL123,,\n",
        encoding="utf-8",
    )

    candidate = infer_report_candidate(csv_path)
    assert candidate is not None
    assert candidate.tool_name == "USPParser"
    transformed = candidate.transform(csv_path, tmp_path / "usp.normalized.csv")

    with transformed.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["device_name"] == "SanDisk Ultra"
    assert rows[0]["vendor_id"] == "0781"
    assert rows[0]["product_id"] == "5581"
    assert rows[0]["serial"] == "SERIAL123"
    assert rows[0]["volume_device_utc"] == "2020-12-12 03:40:00"
