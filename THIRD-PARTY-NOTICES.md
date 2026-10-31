# Third-party notices

OneCrypto's own code is licensed `MIT OR Apache-2.0`. Test vectors and other material from other projects that ship with the repository or its packages are listed here, each with its source, licence and the notice it requires.

| Material | Source | Licence | SHA-256 | Notice |
|---|---|---|---|---|
| EdDSA test vectors (`tests/OneCrypto.Tests/Primitives/Data/rfc8032.json`) | RFC 8032 section 7 (RFC text sha256 ed63657f…c4c3), extracted by `tools/extract-rfc-curve-vectors.py` | IETF Trust legal provisions (RFC text; code components BSD-3-Clause) | 94b80aebf57c838b3518f7d0f68f2d6974b2e5fbf1a1a5f6857c8bd55e945732 | Copyright (c) 2017 IETF Trust and the persons identified as the document authors. |
| OCB sample results and iterated-test outputs (`testdata/vectors/rfc7253-ocb.txt`) | RFC 7253, Appendix A, https://www.rfc-editor.org/rfc/rfc7253 | IETF Trust Legal Provisions: short data extracted from an RFC, used with attribution | `1df966c3d07c9a7502976d8b68cfc2d2ef6af6815623e353b1fba57698691ee2` | Test vectors from RFC 7253, Copyright (c) 2014 IETF Trust and the persons identified as the document authors. |
| EAX-AES128 test vectors (`testdata/vectors/eax-bellare-rogaway-wagner.txt`) | M. Bellare, P. Rogaway, D. Wagner, "The EAX Mode of Operation", 2004, Appendix G (vectors by Jack Lloyd, verified by Brian Gladman) | Public domain: "Our work for this note is hereby placed in the public domain." (section 4) | `72fa979f17d370db8d8640674cbd70c76d824e9e4c8f4745dc7c925cf6a83914` | None required; credited here. |
| AES key wrap test vectors (inline in `tests/OneCrypto.Tests/Primitives/AesKeyWrapTests.cs`) | RFC 3394, section 4, https://www.rfc-editor.org/rfc/rfc3394 | IETF Trust Legal Provisions: short data extracted from an RFC, used with attribution | n/a (inline) | Test vectors from RFC 3394, Copyright (c) 2002 The Internet Society. |
