# authy-migrate

Twilio provides no way to export your Authy tokens. This leaves you either locked into the
app or forced to manually reset 2FA on every account. However, the GDPR's data portability
right (Article 20) legally requires Twilio to hand over your data on request.

That data arrives as a CSV in which every token is encrypted with your backup password.
**authy-migrate** is a Python command-line utility that unlocks each one and rewrites them
as an [Aegis](https://github.com/beemdevelopment/Aegis) vault or plain `otpauth://` URIs.
So you can migrate your codes over to any standard authenticator app.

## Getting Started

### 1. Request your Authy GDPR export

Authy provides no direct export, so you must submit a data portability request to Twilio:

1. Submit a GDPR data request by email to privacy@twilio.com or support@twilio.zendesk.com.
2. Verify your identity when they reply. You will need access to the email address and
   phone number linked to your Authy account.
3. Once verified, they send a download link by email. This can take up to 30 days.
4. Download the archive and locate the `.csv` file containing your tokens.

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the migration script

```bash
python authy_migrate.py [options] <tokens.csv>
```

You will be prompted for your Authy backup password, and the output files are written next
to the input CSV by default.

## Usage

### Options

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir PATH` | Same directory as input | Directory for output files |
| `-p, --password TEXT` | Prompted | Backup password |
| `--format {aegis,uris,both}` | `both` | Output format |
| `--aegis-file NAME` | `tokens_aegis.json` | Filename for the Aegis JSON export |
| `--uris-file NAME` | `otpauth_uris.txt` | Filename for the otpauth URI list |

> [!WARNING]
> Avoid passing `--password` on the command line. It is visible to other users on the same
> system via `ps` and is recorded in your shell history. Let the script prompt you instead.

### Examples

```bash
# Prompt for the password; write both formats next to the CSV
python authy_migrate.py "Authy Personal Information Request - Tokens.csv"

# Write only the Aegis JSON to a custom directory
python authy_migrate.py tokens.csv -o ~/exports --format aegis
```

### Output formats

| File | Compatible with |
|---|---|
| `tokens_aegis.json` | Aegis (Android) natively; 2FAS and others that support Aegis import |
| `otpauth_uris.txt` | Plain-text URIs accepted by most open-source authenticators; some apps (e.g. Google Authenticator, iOS Passwords) only import URIs via QR code |

> [!IMPORTANT]
> **Delete the output files immediately after importing** - they contain plaintext TOTP
> secrets. The export CSV holds encrypted secrets but should still be treated as sensitive.

## How it works

Your one backup password re-derives the key that unlocks every token,
and the script uses it to turn each encrypted row back into a secret any authenticator
understands. It runs in three moves:

1. **Read the export.** The CSV is parsed and checked for the four columns it needs
   (`name`, `encrypted_seed`, `salt`, and `iv`). Authy wraps the whole file in one extra
   pair of quotes, so the script strips those first or the parser would read the entire
   file as a single field.
2. **Unlock each token.** For every row, your password plus that row's `salt` are stretched
   into a 32-byte key (PBKDF2), which then decrypts the `encrypted_seed` with AES. The result
   is the base32 TOTP secret - the short string that actually generates your 6-digit codes.
3. **Write the output.** The recovered secrets are saved as an Aegis vault and/or a list of
   `otpauth://` URIs, each written owner-only (`0600`).

A wrong backup password produces garbage that fails a final validity check, so every row
fails together. The script notices that nothing decrypted and stops telling you the password was likely wrong.

Under the hood, Authy encrypts each backup seed with the scheme below, which this tool reverses:

```
Key  = PBKDF2-HMAC-SHA1(password, salt_utf8, iterations=100000, dklen=32)
Data = AES-256-CBC(key, iv_hex, base64(encrypted_seed))
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Authy is a trademark of Twilio Inc. This project is independent and has no affiliation with,
or endorsement by, Twilio Inc.
