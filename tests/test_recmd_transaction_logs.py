from pathlib import Path

from forensic_orchestrator.tools.runner import prepare_recmd_transaction_logs


def test_prepare_recmd_transaction_logs_matches_hive_case(tmp_path):
    user_dir = tmp_path / "Users" / "fredr"
    user_dir.mkdir(parents=True)
    hive = user_dir / "NTUSER.DAT"
    log1 = user_dir / "ntuser.dat.LOG1"
    log2 = user_dir / "ntuser.dat.LOG2"
    hive.write_bytes(b"hive")
    log1.write_bytes(b"log1")
    log2.write_bytes(b"log2")

    prepared = prepare_recmd_transaction_logs({"registry_ntuser": tmp_path / "Users"})

    assert prepared == [user_dir / "NTUSER.DAT.LOG1", user_dir / "NTUSER.DAT.LOG2"]
    assert (user_dir / "NTUSER.DAT.LOG1").read_bytes() == b"log1"
    assert (user_dir / "NTUSER.DAT.LOG2").read_bytes() == b"log2"
    assert log1.exists()
    assert log2.exists()


def test_prepare_recmd_transaction_logs_keeps_existing_case_match(tmp_path):
    hive = tmp_path / "UsrClass.dat"
    existing = tmp_path / "UsrClass.dat.LOG1"
    hive.write_bytes(b"hive")
    existing.write_bytes(b"log1")

    prepared = prepare_recmd_transaction_logs({"registry_usrclass": tmp_path})

    assert prepared == []
    assert existing.read_bytes() == b"log1"
