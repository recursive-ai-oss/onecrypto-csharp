# Windows-made ECDH EnvelopedData messages

`windows-*.eml` are `EnvelopedData` messages (`application/pkcs7-mime`, `smime-type=enveloped-data`) written by Windows' own CMS encoder (the `CryptMsgOpenToEncode` call that Outlook's S/MIME goes through) for the P-256 recipient in `cert.pem` / `key.pem`. The key is a throw-away test key generated on Windows for this purpose. The content is a `text/plain` entity whose text is `windows made body` (`expected.txt`).

| File | Key-agreement scheme | Key wrap | Recipient identifier | UKM |
|---|---|---|---|---|
| `windows-sha1-a256` | dhSinglePass-stdDH-sha1kdf | AES-256 | issuer and serial | no |
| `windows-sha256-a256` | dhSinglePass-stdDH-sha256kdf | AES-256 | issuer and serial | no |
| `windows-sha1-a256-ukm` | dhSinglePass-stdDH-sha1kdf | AES-256 | issuer and serial | 32 bytes |
| `windows-sha1-a256-ski` | dhSinglePass-stdDH-sha1kdf | AES-256 | subject key identifier | no |

Windows writes the originator key's algorithm identifier and the key-wrap algorithm identifier with `NULL` parameters.
