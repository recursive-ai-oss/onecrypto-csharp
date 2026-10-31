#:project ../src/OneCrypto/OneCrypto.csproj

// Task 9: load any key or certificate file. Usage: dotnet run samples/09-load-any-file.cs -- <file> [password]
using RecursiveAI.OneCrypto;

using LoadedItems file = Crypto.Load(args[0], _ => args.Length > 1 ? args[1] : null);

Console.WriteLine($"{file.Format}: {file.Certificates.Count} certificates, {file.PrivateKeys.Count} private keys, {file.PublicKeys.Count} public keys");
