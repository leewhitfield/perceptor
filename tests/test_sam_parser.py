import struct
from datetime import datetime, timezone

from forensic_orchestrator.tools.sam import (
    FILETIME_EPOCH,
    RegistryKeyRecord,
    accounts_from_registry_keys,
    decode_account_flags,
    unknown_account_flags,
    unknown_account_flags_hex,
)


def test_sam_accounts_are_extracted_from_users_names_keys():
    records = {
        1: RegistryKeyRecord(1, "SAM", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Domains", 1, {}),
        3: RegistryKeyRecord(3, "Account", 2, {}),
        4: RegistryKeyRecord(4, "Users", 3, {}),
        5: RegistryKeyRecord(5, "Names", 4, {}),
        6: RegistryKeyRecord(6, "Administrator", 5, {"": 500}),
        7: RegistryKeyRecord(7, "Jean", 5, {"": 1004}),
        8: RegistryKeyRecord(8, "Devon", 5, {"": 1007}),
        9: RegistryKeyRecord(
            9,
            "000003EC",
            4,
            {},
            {"F": create_sam_f_value(1004, "2026-05-12T13:14:15Z", 80, 2)},
        ),
    }

    accounts = accounts_from_registry_keys(records)

    assert [(account.username, account.rid, account.account_category, account.logon_count) for account in accounts] == [
        ("Administrator", 500, "builtin", None),
        ("Jean", 1004, "local", 80),
        ("Devon", 1007, "local", None),
    ]
    assert accounts[1].last_login_utc == "2026-05-12T13:14:15Z"
    assert accounts[1].bad_password_count == 2
    assert accounts[1].as_row("/tmp/SAM")["account_flags"] == "normal_account;password_does_not_expire"
    assert accounts[1].as_row("/tmp/SAM")["account_flags_unknown_hex"] == ""


def test_sam_accounts_ignore_unrelated_names_keys():
    records = {
        1: RegistryKeyRecord(1, "SAM", 0xFFFFFFFF, {}),
        2: RegistryKeyRecord(2, "Other", 1, {}),
        3: RegistryKeyRecord(3, "Names", 2, {}),
        4: RegistryKeyRecord(4, "NotAUser", 3, {"": 1000}),
    }

    assert accounts_from_registry_keys(records) == []


def test_decode_account_flags():
    assert decode_account_flags(0x00000210) == ["normal_account", "password_does_not_expire"]
    assert decode_account_flags(0x00000411) == [
        "account_disabled",
        "normal_account",
        "account_auto_locked",
    ]
    assert decode_account_flags(None) == []


def test_unknown_account_flags_are_preserved():
    assert unknown_account_flags(0x00008210) == 0x00008000
    assert unknown_account_flags_hex(0x00008210) == "0x00008000"
    assert unknown_account_flags_hex(0x00000210) == ""
    assert unknown_account_flags_hex(None) is None


def create_sam_f_value(rid: int, last_login: str, logon_count: int, bad_password_count: int) -> bytes:
    value = bytearray(80)
    struct.pack_into("<Q", value, 0x08, filetime(datetime.fromisoformat(last_login.replace("Z", "+00:00"))))
    struct.pack_into("<I", value, 0x30, rid)
    struct.pack_into("<I", value, 0x38, 0x00000210)
    struct.pack_into("<H", value, 0x40, bad_password_count)
    struct.pack_into("<H", value, 0x42, logon_count)
    return bytes(value)


def filetime(dt: datetime) -> int:
    return int((dt.astimezone(timezone.utc) - FILETIME_EPOCH).total_seconds() * 10_000_000)
