import base64
import csv
import hashlib
import io
import json
from unittest.mock import patch

import pytest
from Crypto.Cipher import AES

from authy_migrate import (
    build_aegis,
    build_otpauth,
    decrypt_seed,
    main,
    split_name,
    write_secret_file,
)

# ---------------------------------------------------------------------------
# Shared test vectors
# ---------------------------------------------------------------------------

_PASSWORD = "hunter2"
_SALT = "somesalt"
_IV_HEX = "deadbeefdeadbeefdeadbeefdeadbeef"
_SECRET = "JBSWY3DPEHPK3PXP"


def _encrypt(
    secret: str, password: str = _PASSWORD, salt: str = _SALT, iv_hex: str = _IV_HEX
) -> str:
    """Encrypt a secret the same way Authy does, for use in test fixtures."""
    key = hashlib.pbkdf2_hmac(
        "sha1", password.encode(), salt.encode(), 100_000, dklen=32
    )
    plain = secret.encode("utf-8")
    pad_len = 16 - (len(plain) % 16)
    padded = plain + bytes([pad_len] * pad_len)
    ciphertext = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv_hex)).encrypt(padded)
    return base64.b64encode(ciphertext).decode()


_ENCRYPTED = _encrypt(_SECRET)


def _make_csv(rows: list[dict], wrap: bool = False) -> str:
    """Build an Authy-formatted CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["name", "encrypted_seed", "salt", "iv"])
    writer.writeheader()
    writer.writerows(rows)
    content = buf.getvalue()
    return f'"{content}"' if wrap else content


def _token_row(name: str = "GitHub:user@example.com") -> dict:
    return {"name": name, "encrypted_seed": _ENCRYPTED, "salt": _SALT, "iv": _IV_HEX}


# ---------------------------------------------------------------------------
# decrypt_seed
# ---------------------------------------------------------------------------


class TestDecryptSeed:
    def test_correct_password_returns_secret(self):
        assert decrypt_seed(_ENCRYPTED, _SALT, _IV_HEX, _PASSWORD) == _SECRET

    def test_result_is_uppercase(self):
        enc = _encrypt(_SECRET.lower())
        assert decrypt_seed(enc, _SALT, _IV_HEX, _PASSWORD) == _SECRET.upper()

    def test_wrong_password_raises(self):
        with pytest.raises((ValueError, UnicodeDecodeError)):
            decrypt_seed(_ENCRYPTED, _SALT, _IV_HEX, "wrong")

    def test_wrong_salt_raises(self):
        with pytest.raises((ValueError, UnicodeDecodeError)):
            decrypt_seed(_ENCRYPTED, "badsalt", _IV_HEX, _PASSWORD)

    def test_wrong_iv_does_not_yield_original_secret(self):
        # With wrong IV the first plaintext block is garbled, so the result either
        # fails to decode or differs from the original — never matches.
        bad_iv = "00" * 16
        try:
            result = decrypt_seed(_ENCRYPTED, _SALT, bad_iv, _PASSWORD)
        except (ValueError, UnicodeDecodeError):
            return
        assert result != _SECRET


# ---------------------------------------------------------------------------
# split_name
# ---------------------------------------------------------------------------


class TestSplitName:
    def test_service_and_account(self):
        assert split_name("GitHub:user@example.com") == ("GitHub", "user@example.com")

    def test_no_colon_gives_empty_account(self):
        assert split_name("GitHub") == ("GitHub", "")

    def test_strips_whitespace(self):
        assert split_name("  GitHub : user  ") == ("GitHub", "user")

    def test_only_first_colon_is_split(self):
        assert split_name("Service:user:extra") == ("Service", "user:extra")


# ---------------------------------------------------------------------------
# build_otpauth
# ---------------------------------------------------------------------------


class TestBuildOtpauth:
    def test_with_account(self):
        uri = build_otpauth("GitHub", "user@example.com", "ABCDEF")
        # '@' is a reserved URI char and must be percent-encoded
        assert uri.startswith("otpauth://totp/GitHub:user%40example.com?")
        assert "secret=ABCDEF" in uri
        assert "issuer=GitHub" in uri

    def test_without_account_omits_colon(self):
        uri = build_otpauth("GitHub", "", "ABCDEF")
        assert "otpauth://totp/GitHub?" in uri
        assert "GitHub:?" not in uri

    def test_fixed_parameters(self):
        uri = build_otpauth("X", "y", "Z")
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_special_characters_are_url_encoded(self):
        uri = build_otpauth("Acme & Co", "user?id=1", "ABCDEF")
        # raw '&' and '?' must not appear inside the label or issuer
        assert "Acme & Co" not in uri
        assert "user?id=1" not in uri
        assert "Acme%20%26%20Co" in uri
        assert "user%3Fid%3D1" in uri
        # secret stays unencoded so importers can read it
        assert "secret=ABCDEF" in uri

    def test_slash_in_issuer_is_encoded(self):
        uri = build_otpauth("Mail/Cloud", "a", "S")
        assert "Mail/Cloud" not in uri
        assert "Mail%2FCloud" in uri


# ---------------------------------------------------------------------------
# build_aegis
# ---------------------------------------------------------------------------


class TestBuildAegis:
    def test_top_level_structure(self):
        result = build_aegis([{"issuer": "X", "account": "a", "secret": "S"}])
        assert result["version"] == 1
        assert result["db"]["version"] == 2

    def test_entry_fields(self):
        entry = build_aegis(
            [{"issuer": "GitHub", "account": "user", "secret": "ABCDEF"}]
        )["db"]["entries"][0]
        assert entry["type"] == "totp"
        assert entry["issuer"] == "GitHub"
        assert entry["name"] == "user"
        assert entry["info"] == {
            "secret": "ABCDEF",
            "algo": "SHA1",
            "digits": 6,
            "period": 30,
        }

    def test_name_falls_back_to_issuer_when_no_account(self):
        entry = build_aegis([{"issuer": "GitHub", "account": "", "secret": "X"}])["db"][
            "entries"
        ][0]
        assert entry["name"] == "GitHub"

    def test_entry_count_matches_input(self):
        tokens = [
            {"issuer": "A", "account": "a", "secret": "X"},
            {"issuer": "B", "account": "b", "secret": "Y"},
        ]
        entries = build_aegis(tokens)["db"]["entries"]
        assert len(entries) == 2

    def test_each_entry_has_unique_uuid(self):
        tokens = [
            {"issuer": "A", "account": "a", "secret": "X"},
            {"issuer": "B", "account": "b", "secret": "Y"},
        ]
        uuids = [e["uuid"] for e in build_aegis(tokens)["db"]["entries"]]
        assert len(set(uuids)) == 2


# ---------------------------------------------------------------------------
# write_secret_file
# ---------------------------------------------------------------------------


class TestWriteSecretFile:
    def test_content_is_written(self, tmp_path):
        path = tmp_path / "out.txt"
        write_secret_file(path, "hello")
        assert path.read_text() == "hello"

    def test_new_file_has_0600_permissions(self, tmp_path):
        path = tmp_path / "out.txt"
        write_secret_file(path, "secret")
        assert (path.stat().st_mode & 0o777) == 0o600

    def test_preexisting_loose_permissions_are_tightened(self, tmp_path):
        path = tmp_path / "out.txt"
        path.write_text("old")
        path.chmod(0o644)
        write_secret_file(path, "new")
        assert path.read_text() == "new"
        assert (path.stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------------------
# Integration: main()
# ---------------------------------------------------------------------------


def _run(args: list[str], password: str = _PASSWORD):
    """Call main() with patched argv and getpass."""
    with patch("sys.argv", ["authy_migrate.py"] + args), patch(
        "getpass.getpass", return_value=password
    ):
        main()


class TestMain:
    def test_decrypts_token_to_both_formats(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()]))
        _run([str(csv_file)])

        aegis = json.loads((tmp_path / "tokens_aegis.json").read_text())
        assert aegis["db"]["entries"][0]["info"]["secret"] == _SECRET

        uris = (tmp_path / "otpauth_uris.txt").read_text()
        assert f"secret={_SECRET}" in uris

    def test_handles_authy_quoted_csv_wrapping(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()], wrap=True))
        _run([str(csv_file)])
        assert (tmp_path / "tokens_aegis.json").exists()

    def test_output_files_have_0600_permissions(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()]))
        _run([str(csv_file)])
        for name in ("tokens_aegis.json", "otpauth_uris.txt"):
            assert (tmp_path / name).stat().st_mode & 0o777 == 0o600

    def test_output_dir_option(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()]))
        out = tmp_path / "out"
        out.mkdir()
        _run([str(csv_file), "-o", str(out)])
        assert (out / "tokens_aegis.json").exists()

    def test_format_aegis_only(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()]))
        _run([str(csv_file), "--format", "aegis"])
        assert (tmp_path / "tokens_aegis.json").exists()
        assert not (tmp_path / "otpauth_uris.txt").exists()

    def test_format_uris_only(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()]))
        _run([str(csv_file), "--format", "uris"])
        assert not (tmp_path / "tokens_aegis.json").exists()
        assert (tmp_path / "otpauth_uris.txt").exists()

    def test_exits_1_on_missing_input_file(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            _run([str(tmp_path / "ghost.csv")])
        assert exc.value.code == 1

    def test_exits_1_on_missing_csv_columns(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text("wrong,columns\nfoo,bar\n")
        with pytest.raises(SystemExit) as exc:
            _run([str(csv_file)])
        assert exc.value.code == 1

    def test_exits_1_on_empty_csv(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([]))
        with pytest.raises(SystemExit) as exc:
            _run([str(csv_file)])
        assert exc.value.code == 1

    def test_exits_1_on_wrong_password(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()]))
        with pytest.raises(SystemExit) as exc:
            _run([str(csv_file)], password="wrong")
        assert exc.value.code == 1

    def test_exits_1_on_nonexistent_output_dir(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(_make_csv([_token_row()]))
        with pytest.raises(SystemExit) as exc:
            _run([str(csv_file), "-o", str(tmp_path / "ghost")])
        assert exc.value.code == 1

    def test_skips_rows_with_empty_name(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(
            _make_csv(
                [
                    {
                        "name": "",
                        "encrypted_seed": _ENCRYPTED,
                        "salt": _SALT,
                        "iv": _IV_HEX,
                    },
                    _token_row("Valid:user"),
                ]
            )
        )
        _run([str(csv_file)])
        aegis = json.loads((tmp_path / "tokens_aegis.json").read_text())
        assert len(aegis["db"]["entries"]) == 1
