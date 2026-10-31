# Key containers: PKCS#8, PKCS#12 and OpenSSH keys

Normative behaviour of `RecursiveAI.OneCrypto.Pkcs` and `RecursiveAI.OneCrypto.Wire.Ssh`. Clause numbers are those of the RFC or document named.

## What is read and written

| Container | Reads | Writes |
|---|---|---|
| `PrivateKeyInfo` (RFC 5208, RFC 5958 `OneAsymmetricKey`) | v1 and v2 (public key, attributes) for any algorithm; typed access for RSA, EC, Ed25519/Ed448, X25519/X448, ML-DSA, ML-KEM | the same, from platform keys or this library's key types |
| `EncryptedPrivateKeyInfo` | PBES2 (RFC 8018 §6.2) with PBKDF2 (HMAC-SHA-1/224/256/384/512) or scrypt (RFC 7914 §7), AES-128/192/256-CBC, AES-128/192/256-GCM (RFC 5084), 3DES-CBC; the PKCS#12 PBEs with 3DES (2- and 3-key) and RC2-40/128 | PBES2 only: AES-CBC or AES-GCM with PBKDF2 (SHA-1/256/384/512) or scrypt |
| PEM private keys | `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, the last two also with `Proc-Type`/`DEK-Info` (AES-128/192/256-CBC, DES-EDE3-CBC) | `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` |
| PKCS#12 (RFC 7292) | password-integrity MAC (HMAC with the Appendix B derivation over SHA-1/224/256/384/512) and PBMAC1 (RFC 9579); data and encryptedData safes; key, shrouded key, cert, CRL, secret and nested safe-contents bags; friendlyName and localKeyId | key and secret bags in a data safe, certificates and CRLs in an encrypted safe (PBES2), MAC of either kind |
| OpenSSH `openssh-key-v1` (PROTOCOL.key) | RSA, ECDSA P-256/384/521, Ed25519, FIDO `sk-` keys; ciphers `none`, `aes{128,192,256}-ctr`, `aes{128,192,256}-cbc`, `aes{128,256}-gcm@openssh.com`; KDF `none` and `bcrypt` | RSA, ECDSA, Ed25519 with `none`, `aes{128,192,256}-ctr` or `aes{128,256}-gcm@openssh.com` |
| OpenSSH public keys and certificates | blob, `authorized_keys` line (with options), RFC 4716 file, `*-cert-v01@openssh.com` (RSA, ECDSA, Ed25519) | blob, line, RFC 4716 |

Not read, with a typed answer (`PkcsStatus.UnsupportedAlgorithm`, `SshError.Unsupported`): the RC4 PKCS#12 PBEs and the PKCS#5 v1.5 password schemes (obsolete; the platform has no RC4), PKCS#12 public-key integrity and privacy modes (signedData, envelopedData), `chacha20-poly1305@openssh.com` and `3des-cbc` private key files, files with more than one OpenSSH key, SLH-DSA private keys, `ssh-dss`.

## Losslessness

A `PrivateKeyInfo` keeps its encoding as received in a pinned buffer and returns it unchanged. Certificates inside a PKCS#12 file keep their bytes. OpenSSH blobs and certificates keep the received bytes; the signed part of a certificate is a slice of them.

## Secrets

Keys live in pinned buffers (`PrivateKeyInfo`, secret bags, decrypted safes, OpenSSH private sections) that are zeroed on `Dispose` or when parsing ends. Every decryption writes into such a buffer and releases it only when the padding, tag, MAC or check integers have verified. A wrong password and damaged data cannot be told apart and give `PkcsStatus.WrongPasswordOrCorrupt` with no plaintext. The RSA CRT exponents that OpenSSH files omit are recomputed with constant-time shift-and-subtract reduction (`SecretMod`), not `BigInteger`. A garbage-collected runtime cannot promise that no other copy of a secret exists.

## Passwords

PBES2 and PBMAC1 use the password as UTF-8 (RFC 8018 §3, RFC 9579 §3). The PKCS#12 derivations use a BMPString: UTF-16BE with a terminating zero character (RFC 7292 Appendix B.1). An empty PKCS#12 password has two encodings in the wild (the terminator alone, or no bytes); when the password is empty both are tried, MAC first. Writers always use the terminator form. PEM legacy encryption derives the key with EVP_BytesToKey over MD5 with one iteration and the first eight IV bytes as salt (the `EVP_BytesToKey(3)` manual page); it is read-only.

## Limits (`PkcsLimits`, on by default)

| Limit | Default | Applies to |
|---|---|---|
| `MaxEncodedSize` | 64 MiB | any container |
| `MaxIterations` | 5,000,000 | PBKDF2 and PKCS#12-derivation iteration counts read from a file, checked before any derivation |
| `MaxSaltLength` | 1024 bytes | salts read from a file |
| `MaxSafes`, `MaxBags`, `MaxSafeNesting` | 256, 4096, 4 | PKCS#12 structure |
| `Kdf` (`KdfLimits`) | memory 2 GiB, scrypt work 2^26, bcrypt rounds 4096 | scrypt parameters in PBES2, bcrypt rounds in OpenSSH keys |
| ASN.1 | depth 24 | outer structure |

An OpenSSH private key file is limited to 1 MiB (OpenSSH itself stops at 256 KiB). A parameter above its limit gives `LimitExceeded` before the expensive step runs.

## Integrity of PKCS#12

`Pkcs12File.TryOpen` verifies the MAC before decrypting anything and refuses a file with no MAC (`PkcsStatus.IntegrityMissing`) unless `requireMac` is false. A file that opens has every safe decrypted and every bag read; there is no partial result.

## Write defaults

PBKDF2-HMAC-SHA-256, 600,000 iterations, AES-256-CBC, a 16-byte random salt, for shrouded keys, the certificate safe and the MAC. The MAC is the classic HMAC-SHA-256 with the PKCS#12 derivation because every reader supports it; PBMAC1 is one option away. OpenSSH keys use `aes256-ctr` and 16 bcrypt rounds, the `ssh-keygen` defaults. Triple DES and RC2 are never written.

## Experiments that settled behaviour the specifications leave open

* `aes*-gcm@openssh.com` private key files authenticate the encrypted section with an empty additional-data string and a 16-byte tag directly after the section (checked against files `ssh-keygen -Z aes256-gcm@openssh.com` writes, both directions).
* OpenSSL's `pkey -traditional` and `-<cipher>` write the `DEK-Info` form; `rsa`/`ec` write PKCS#8 in OpenSSL 3.
* `ssh-keygen -s` writes `rsa-sha2-512` signatures for RSA CAs; `ssh-rsa` (SHA-1) certificate signatures are reported `UnsupportedAlgorithm`, never `Valid`.

## Preview parts

ML-DSA and ML-KEM private keys go through the platform's PKCS#8 calls, which the platform marks experimental. They are confined to one file (`PqKeys.cs`) behind one suppression, and the methods say so. SLH-DSA private keys are not handled.
