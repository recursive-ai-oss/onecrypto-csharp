# Samples

Each file is a complete program: `dotnet run samples/<file>.cs -- <arguments>`.

| File | Task |
|---|---|
| `09-load-any-file.cs` | Load any key or certificate file (PEM, DER, PKCS#8, PKCS#12, OpenSSH, ...) in one call: `Crypto.Load(path, _ => password)` |
