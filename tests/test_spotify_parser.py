import csv

from forensic_orchestrator.analytics_query import query_one
from forensic_orchestrator.db import Database
from forensic_orchestrator.tools.ingest import ingest_csv_output
from forensic_orchestrator.tools.spotify import parse_spotify_artifacts_to_csv


def test_spotify_parser_extracts_account_and_cached_profile(tmp_path):
    package = (
        tmp_path
        / "Users"
        / "mayas"
        / "AppData"
        / "Local"
        / "Packages"
        / "SpotifyAB.SpotifyMusic_zpdnekdrzrea0"
    )
    prefs = package / "LocalState" / "Spotify" / "prefs"
    prefs.parent.mkdir(parents=True)
    prefs.write_text(
        'autologin.username="31m6roeqt4zfvqqzcbjt6aonxdfy"\n'
        'autologin.canonical_username="31m6roeqt4zfvqqzcbjt6aonxdfy"\n'
    )
    leveldb_file = (
        package
        / "LocalState"
        / "Spotify"
        / "Users"
        / "31m6roeqt4zfvqqzcbjt6aonxdfy-user"
        / "primary.ldb"
        / "000001.ldb"
    )
    leveldb_file.parent.mkdir(parents=True)
    leveldb_file.write_bytes(
        b"!xmeta#cache#"
        b"/#)spotify:user:31m6roeqt4zfvqqzcbjt6aonxdfy#"
        b"3type.googleapis.com/"
        b"Mx.identity.v3.UserProfile"
        b"3je\x00MayaSCyberGrl\"\x000#$"
    )

    csv_path = parse_spotify_artifacts_to_csv(tmp_path / "Users", tmp_path / "out")
    rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))

    prefs_rows = [row for row in rows if row["artifact_type"] == "spotify_account_pref"]
    profile_rows = [row for row in rows if row["artifact_type"] == "spotify_user_profile"]

    assert {row["key_name"] for row in prefs_rows} == {"autologin.username", "autologin.canonical_username"}
    assert profile_rows[0]["spotify_user_id"] == "31m6roeqt4zfvqqzcbjt6aonxdfy"
    assert profile_rows[0]["display_name"] == "MayaSCyberGrl"
    assert profile_rows[0]["user_profile"] == "mayas"


def test_spotify_ingest_populates_duckdb(tmp_path):
    db = Database(tmp_path / "orchestrator.sqlite3")
    case = db.create_case("case-1", tmp_path / "cases" / "case-1")
    computer = db.create_computer(computer_id="computer-1", case_id=case.id, label="Desktop")
    image = db.add_image("image-1", case.id, tmp_path / "evidence.E01", computer_id=computer.id)
    csv_path = tmp_path / "SpotifyArtifacts.csv"
    csv_path.write_text(
        "artifact_type,user_profile,source_path,source_name,source_file,file_size,modified_utc,"
        "account_user_id,spotify_user_id,spotify_user_uri,display_name,key_name,value,evidence,error\n"
        "spotify_user_profile,mayas,Users/mayas/profile.ldb,primary.ldb,/mnt/profile.ldb,10,"
        "2025-12-06T08:08:06Z,,31m6roeqt4zfvqqzcbjt6aonxdfy,"
        "spotify:user:31m6roeqt4zfvqqzcbjt6aonxdfy,MayaSCyberGrl,,,cached identity.v3.UserProfile,\n",
        encoding="utf-8",
    )

    ingest_csv_output(
        db=db,
        case_id=case.id,
        computer_id=computer.id,
        image_id=image.id,
        tool_output_id="output-spotify",
        tool_name="SpotifyParser",
        path=csv_path,
    )

    row = query_one(db, "spotify_artifacts", "SELECT * FROM spotify_artifacts")
    assert row["display_name"] == "MayaSCyberGrl"
    assert row["spotify_user_uri"] == "spotify:user:31m6roeqt4zfvqqzcbjt6aonxdfy"
