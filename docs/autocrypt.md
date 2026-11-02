# Autocrypt (Level 1)

Normative behaviour of the Autocrypt types in `RecursiveAI.OneCrypto.OpenPgp` (`AutocryptHeader`, `AutocryptPeer`, `AutocryptRecommender`, `AutocryptSetupMessage`), written to the Autocrypt Level 1 specification (<https://autocrypt.org/level1.html>, revision 1.1, CC0). Everything here is format and state logic over header values, dates and keys. **Mail parsing stays with the caller**: the library takes the text of the `Autocrypt` and `Autocrypt-Gossip` headers, the From address, the `Date` and the time received. There is no MIME code, no storage and no clock: every function that depends on a time takes it as an argument.

## The header value

`AutocryptHeader.TryParse(value, out header, out error)` reads the text after `Autocrypt:` (folding allowed). A header is valid when:

- it is at most 10 KiB with its name, colon and folding (`TooLarge` otherwise; Level 1 says to treat larger ones as invalid);
- it is a list of `name=value` attributes separated by `;`, and no attribute appears twice;
- `addr` is present and is a single address (no white space, comma, semicolon or angle brackets);
- `keydata` is present, is the last attribute (it takes everything after it), is Base64 once white space is removed, and decodes to binary OpenPGP packets, not armor;
- the key data is **exactly one transferable public key**: more than one key, or any secret key material, is `KeyNotSinglePublicCertificate`;
- every attribute whose name does not start with `_` is one this level knows (`addr`, `prefer-encrypt`, `keydata`). An unknown critical attribute makes the whole header invalid (`UnsupportedCriticalAttribute`); an unknown `_name` attribute is ignored.

`prefer-encrypt` is `mutual` (any case) or nothing: any other value means no preference. The key is not otherwise judged: whether it is bound, unexpired or capable of encryption is decided at the reference time of whoever uses it (`AutocryptRecommender.CanEncrypt`). The five-packet shape the specification asks of senders is not required of receivers, which "MAY support other OpenPGP key formats".

`TryParse` never throws; `Parse` raises `AutocryptFormatException` with the same `Error`. `ToHeaderValue()` writes `addr`, `prefer-encrypt=mutual` only when mutual, then `keydata=` folded at 76 Base64 characters with CR LF and one space; `ToHeaderField(name)` adds the field name. `AsGossip()` drops the preference, because gossip headers must not state one. `IsValidFor(from)` compares the `addr` with the message's From address ASCII case-insensitively.

## Peer state

`AutocryptPeer` is an immutable record of the specification's per-peer state: `last_seen`, `autocrypt_timestamp`, `public_key`, `prefer_encrypt`, `gossip_timestamp`, `gossip_key`. Addresses are kept in lower case (`NormalizeAddress`). Storage is the caller's.

`AutocryptPeer.Apply(previous, message)` (Level 1, "Updating Autocrypt Peer State"):

1. A message is ignored (the previous state is returned unchanged) when it is a `multipart/report`, has more than one From address, or is believed to be spam; the caller states these in `AutocryptMessage`.
2. The **effective date** is the `Date` header if present and not after the time received, otherwise the time received.
3. If the effective date is older than `autocrypt_timestamp`, nothing changes.
4. `last_seen` moves forward to the effective date if it is later.
5. Every `Autocrypt` header is examined, not only the first. A header counts if it is valid and its `addr` equals the From address. **If there is not exactly one such header, none is used** (two valid headers are an error and are all discarded). Rejected headers are listed with their reasons in `AutocryptUpdate.HeaderErrors`.
6. With one valid header, `autocrypt_timestamp`, `public_key` and `prefer_encrypt` are set from it.

`AutocryptPeer.ApplyGossip(previous, headerValue, context)` (Level 1, "Updating Autocrypt Peer State from Key Gossip"): the header is ignored if it is invalid, if its address is not among the message's To, Cc and Reply-To addresses, or if the held `gossip_timestamp` is newer than the message; otherwise `gossip_timestamp` and `gossip_key` are set. Gossip must come from the encrypted payload of a message; the caller decides what counts as such.

## The recommendation

`AutocryptRecommender.ForPeer` and `Recommend` implement "Provide a recommendation for message encryption" and are pure functions of the peer states, the context and the time.

- No peer record: `Disable`. A key that is revoked, expired or unable to encrypt at `Now` counts as absent (`CanEncrypt` parses the key and asks `PgpKey.StateAt`; `AutocryptComposeContext.IsKeyUsable` overrides it). Neither key usable: `Disable`.
- Only the gossip key is usable: it is the target key and the preliminary recommendation is `Discourage`.
- Otherwise `public_key` is the target. If `autocrypt_timestamp` is **more than 35 days** older than `last_seen` the preliminary recommendation is `Discourage`, else `Available`. Exactly 35 days is still `Available`.
- Then: a reply to an encrypted message turns `Available` and `Discourage` into `Encrypt`; and `Available` becomes `Encrypt` when both the peer and the sender have `mutual`.
- For several recipients: any `Disable` gives `Disable`; all `Encrypt` gives `Encrypt`; else any `Discourage` gives `Discourage`; else `Available`. An empty recipient list is `Disable`. `TargetKeys` is the merge of the recipients' target keys.

What the sender then does (encrypt as PGP/MIME to each target key and its own key, sign) is OpenPGP message writing and mail construction, not this class.

## The setup message

`AutocryptSetupMessage` makes and opens the armored `-----BEGIN PGP MESSAGE-----` block that is the content of the `application/autocrypt-setup` part. The e-mail around it (`Autocrypt-Setup-Message: v1`, the MIME structure, the human-readable first part) is the caller's.

- **Code.** `GenerateSetupCode()` returns 36 decimal digits from `RandomNumberGenerator` in nine blocks of four separated by dashes (about 119 bits). `NormalizeSetupCode` turns a typed code of digits, spaces and dashes with exactly 36 digits into that form; anything else is used as typed (other clients may use free-form passphrases).
- **Create.** The payload is the account's transferable secret key as ASCII armor (`PGP PRIVATE KEY BLOCK`) with an `Autocrypt-Prefer-Encrypt: mutual` header when mutual. It is encrypted to the code **as a password only**: one symmetric-key encrypted session key packet (version 4, iterated and salted S2K) followed by one SEIPD version 1 packet, with AES-256. The outer armor carries `Passphrase-Format: numeric9x4` and `Passphrase-Begin: <first two digits>` when the code has the standard form. A key that is protected by its own passphrase stays protected inside the payload. The certificate must hold secret key material.
- **Open.** Text around the armored block (an HTML wrapper) is ignored. The code is the only way in: no other key or password is tried. The message must authenticate (SEIPD v1 MDC checked over the whole body before any plaintext is used); a wrong code and an altered message give the same `WrongCodeOrCorrupt`. The payload is limited to 2 MiB and the message to 4 MiB. After the decrypted payload's first armor tail line, trailing data is dropped; a binary payload is accepted as well. The result must hold a certificate with secret key material (`NoSecretKey` otherwise).
- `ReadHints` returns the `Passphrase-Format` and `Passphrase-Begin` headers so a caller can show the nine-by-four input form and prefill the first digits.

## Checked against

- The examples of the specification itself, extracted by `tools/extract-autocrypt-vectors.py` into `testdata/openpgp/autocrypt/`: the example `Autocrypt` header (key `EB85BB5FA33A75E15E944E63F231550C4F47E38E`), and the example setup message, opened with the example code `1742-0185-6197-1303-7016-8412-3581-4441-0597` to the example secret key.
- GnuPG 2.4.8 as a black box in both directions (`SetupMessagesGoBothWaysWithGnuPG`, when `ONECRYPTO_GPG` names a `gpg`): it decrypts the specification's message and ours with their codes, and a message it makes with `--symmetric --s2k-mode 3` opens with our code. No Autocrypt client (a mail user agent) was available as an oracle, so header handling and the peer-state rules are tested against the specification's text and our own round trips only.
- A fuzz target `autocrypt` (headers with write-back identity, peer updates and gossip, the recommendation, setup messages).
