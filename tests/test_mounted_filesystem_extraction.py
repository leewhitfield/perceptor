from pathlib import Path

from forensic_orchestrator.db import Database
from forensic_orchestrator.models import ArtifactDefinition
from forensic_orchestrator.mounting.filesystem import extract_artifact_from_mount


def _case_db(tmp_path: Path) -> tuple[Database, str]:
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    db.add_image("image-1", case.id, Path("/evidence/desktop.E01"), computer_id="computer-1")
    return db, case.id


def test_mounted_recursive_extraction_preserves_sqlite_sidecars(tmp_path):
    db, case_id = _case_db(tmp_path)
    mount = tmp_path / "mount"
    package = mount / "Users" / "Jane" / "AppData" / "Local" / "Packages" / "AppleInc.iCloud" / "LocalCache"
    package.mkdir(parents=True)
    database = package / "client.db"
    database.write_text("db")
    database.with_name("client.db-wal").write_text("wal")
    database.with_name("client.db-shm").write_text("shm")
    database.with_name("client.db-journal").write_text("journal")

    extract_artifact_from_mount(
        db=db,
        case_id=case_id,
        image_id="image-1",
        computer_id="computer-1",
        mount_path=mount,
        artifact=ArtifactDefinition(
            name="package_databases",
            source="Users",
            destination="packages",
            recursive=True,
            patterns=("*.db",),
            include_path_patterns=("Users/*/AppData/Local/Packages/*",),
        ),
        artifacts_root=tmp_path / "artifacts",
        dry_run=False,
        mounted_files=[database],
    )

    copied = (
        tmp_path
        / "artifacts"
        / "packages"
        / "Jane"
        / "AppData"
        / "Local"
        / "Packages"
        / "AppleInc.iCloud"
        / "LocalCache"
        / "client.db"
    )
    assert copied.read_text() == "db"
    assert copied.with_name("client.db-wal").read_text() == "wal"
    assert copied.with_name("client.db-shm").read_text() == "shm"
    assert copied.with_name("client.db-journal").read_text() == "journal"
