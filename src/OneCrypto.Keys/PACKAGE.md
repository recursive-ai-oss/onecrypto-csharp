# RecursiveAI.OneCrypto.Keys

Key backends for OneCrypto, the cryptography (not cryptocurrency) library for .NET: private keys that stay in a PKCS #11 token or HSM, in gpg-agent (over Assuan) or in ssh-agent, used through the same signing, decryption and key-agreement interfaces as in-memory keys. Signing can be two-phase: prepare in one process, sign against the token or agent later or elsewhere, complete in another. Keys plug into CMS, X.509 and OpenPGP (including decrypting OpenPGP messages with an agent-held key). It is unaffiliated with other products named OneCrypto.

The library has no key store or agent of its own. Every token and agent signature is checked against the public key before it is released. PKCS #11 works on 64-bit Linux and macOS; Windows is refused. It has been tested against SoftHSM2, GnuPG 2.4 and 2.5 and OpenSSH agents, not against a hardware token.

This is an early preview. The key-backend glue had an internal review (`docs/key-backend-review.md` in the repository); it has not been independently audited.

- Guide: <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/docs/keys.md>
- Source, issues and the full package list: <https://github.com/recursive-ai-oss/onecrypto-csharp>
- Changelog: <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/CHANGELOG.md>
- Licence: MIT OR Apache-2.0, <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/LICENSE-MIT> and <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/LICENSE-APACHE>
