using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OneCrypto.Tests.Support;
using RecursiveAI.OneCrypto;
using RecursiveAI.OneCrypto.Issuance;
using RecursiveAI.OneCrypto.Keys;
using RecursiveAI.OneCrypto.Policy;
using RecursiveAI.OneCrypto.X509;

namespace OneCrypto.Tests.Issuance;

/// <summary>The certificate authority: profiles, refusals, serial numbers, CRLs and delta CRLs, two-phase signing, checked against the openssl command-line program.</summary>
public class CertificateAuthorityTests
{
    private static readonly DateTimeOffset T0 = IssuanceKit.T0;
    private static readonly DateTimeOffset Later = IssuanceKit.T0.AddHours(2);

    private static IssuanceKit Kit => IssuanceKit.Get();

    private static DistinguishedName Name(string cn) => DistinguishedName.Create((KnownOids.Organization, "OneCrypto Tests"), (KnownOids.CommonName, cn));

    private static IReadOnlyList<GeneralName> SanFor(CertificateProfile p) =>
        p.Name == "smime" ? [GeneralName.Email("alice@example.test")]
        : p.Name is "tls-server" or "tls-client" ? [GeneralName.Dns("www.example.test")]
        : [];

    private static Certificate Leaf(CertificateProfile p, SigKind kind = SigKind.Rsa, CertificateAuthority? ca = null) =>
        (ca ?? Kit.Intermediate).Issue(CmsKeys.Get(kind).Signer.PublicKey, Name(p.Name + " leaf"), new CertificateIssueOptions { Profile = p, NotBefore = T0, SubjectAlternativeNames = SanFor(p) });

    public static TheoryData<string, SigKind> ProfileMatrix()
    {
        var d = new TheoryData<string, SigKind>();
        foreach (string p in new[] { "tls-server", "tls-client", "smime", "code-signing", "ocsp-signing", "time-stamping" })
        {
            foreach (SigKind k in new[] { SigKind.Rsa, SigKind.P256, SigKind.Ed25519 })
            {
                d.Add(p, k);
            }
        }

        return d;
    }

    private static CertificateProfile ByName(string n) => n switch
    {
        "tls-server" => CertificateProfile.TlsServer,
        "tls-client" => CertificateProfile.TlsClient,
        "smime" => CertificateProfile.SMime,
        "code-signing" => CertificateProfile.CodeSigning,
        "ocsp-signing" => CertificateProfile.OcspSigning,
        _ => CertificateProfile.TimeStamping,
    };

    [Theory]
    [MemberData(nameof(ProfileMatrix))]
    public void EveryProfileGivesAChainOpenSslVerifies(string profile, SigKind kind)
    {
        CertificateProfile p = ByName(profile);
        Certificate leaf = Leaf(p, kind);

        // What the profile promises is what the certificate says.
        Assert.False(leaf.BasicConstraints!.IsCA);
        Assert.True(leaf.Extensions.Find(KnownOids.BasicConstraints)!.Critical);
        Assert.Equal(p.ExtendedKeyUsages, leaf.ExtendedKeyUsage?.Purposes ?? []);
        Assert.Equal(p.ExtendedKeyUsageCritical, leaf.Extensions.Find(KnownOids.ExtendedKeyUsage)?.Critical ?? false);
        Assert.Equal(p.OcspNoCheck, leaf.Extensions.Contains(KnownOids.OcspNoCheck));
        Assert.NotNull(leaf.AuthorityKeyIdentifier);
        Assert.Equal(Kit.Intermediate.Certificate.SubjectKeyIdentifier!.KeyIdentifier.ToArray(), leaf.AuthorityKeyIdentifier!.KeyIdentifier.ToArray());
        Assert.Equal(p.KeyUsages | (kind == SigKind.Rsa ? p.RsaAdditionalKeyUsages : 0), leaf.KeyUsage!.Usages);
        Assert.True(leaf.VerifySignature(Kit.Intermediate.Certificate).IsValid);

        OpenSslTool.RequireOrSkip();
        string dir = IssuanceKit.Dir($"ca-{profile}-{kind}");
        IssuanceKit.Write(dir, "root.pem", Kit.Root.Certificate.ToPem());
        IssuanceKit.Write(dir, "inter.pem", Kit.Intermediate.Certificate.ToPem());
        string leafFile = IssuanceKit.Write(dir, "leaf.pem", leaf.ToPem());
        var args = new List<string> { "verify", "-x509_strict", "-CAfile", Path.Combine(dir, "root.pem"), "-untrusted", Path.Combine(dir, "inter.pem"), "-attime", IssuanceKit.Epoch(Later).ToString() };
        string? purpose = profile switch
        {
            "tls-server" => "sslserver",
            "tls-client" => "sslclient",
            "smime" => "smimesign",
            "ocsp-signing" => "ocsphelper",
            "time-stamping" => "timestampsign",
            _ => null,
        };
        if (purpose is not null)
        {
            args.AddRange(["-purpose", purpose]);
        }

        args.Add(leafFile);
        (int code, string output) = OpenSslTool.Run([.. args]);
        Assert.True(code == 0, "openssl verify: " + output);
        Assert.Contains("OK", output);
    }

    [Fact]
    public void RootAndIntermediateAreSelfConsistent()
    {
        Certificate root = Kit.Root.Certificate;
        Assert.True(root.IsSelfSigned);
        Assert.True(root.BasicConstraints!.IsCA);
        Assert.Equal(KeyUsages.KeyCertSign | KeyUsages.CrlSign, root.KeyUsage!.Usages);
        Assert.True(Kit.Intermediate.Certificate.VerifySignature(root).IsValid);
        Assert.Equal(root.SubjectKeyIdentifier!.KeyIdentifier.ToArray(), Kit.Intermediate.Certificate.AuthorityKeyIdentifier!.KeyIdentifier.ToArray());
        OpenSslTool.RequireOrSkip();
        string dir = IssuanceKit.Dir("ca-chain");
        IssuanceKit.Write(dir, "root.pem", root.ToPem());
        string inter = IssuanceKit.Write(dir, "inter.pem", Kit.Intermediate.Certificate.ToPem());
        IssuanceKit.Ok(OpenSslTool.Run("verify", "-x509_strict", "-CAfile", Path.Combine(dir, "root.pem"), "-attime", IssuanceKit.Epoch(Later).ToString(), "-purpose", "crlsign", inter), "intermediate");
    }

    [Fact]
    public void IssuedCertificatesRoundTripThroughX509Certificate2()
    {
        Certificate leaf = Leaf(CertificateProfile.TlsServer);
        using X509Certificate2 platform = leaf.ToX509Certificate2();
        Assert.Equal(leaf.Encoded.ToArray(), platform.RawData);
        Assert.Equal(leaf.Encoded.ToArray(), Certificate.FromX509Certificate2(platform).Encoded.ToArray());
        Assert.Equal("www.example.test", platform.GetNameInfo(X509NameType.DnsName, false));
    }

    [Fact]
    public void SerialsAreRandomLongAndPositive()
    {
        var seen = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            Certificate c = Leaf(CertificateProfile.CodeSigning, SigKind.P256);
            ReadOnlySpan<byte> s = c.SerialNumber.Span;
            Assert.True(s.Length >= 9 && s.Length <= 20);
            Assert.True(s[0] < 0x80 && s[0] != 0);
            Assert.True(seen.Add(Convert.ToHexString(s)));
        }
    }

    [Fact]
    public void ACsrIsCheckedAndOnlyItsSubjectKeyAndNamesAreTaken()
    {
        SignerKit kit = CmsKeys.Get(SigKind.P256);
        CertificateSigningRequest csr = CertificateSigningRequestBuilder.Create(new CertificateSigningRequestOptions
        {
            Subject = Name("csr subject"),
            Extensions =
            [
                Extension.Create(new SubjectAlternativeName([GeneralName.Dns("csr.example.test")]), false),
                Extension.Create(new BasicConstraints(true, null), true),
                Extension.Create(new ExtendedKeyUsage([KnownOids.CodeSigning]), false),
            ],
        }, kit.Signer);
        Certificate c = Kit.Intermediate.Issue(csr, new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = T0 });
        Assert.Equal("csr.example.test", Assert.Single(c.SubjectAlternativeName!.Names).Value);
        Assert.False(c.BasicConstraints!.IsCA);
        Assert.Equal([KnownOids.ServerAuth], c.ExtendedKeyUsage!.Purposes);
        Assert.Equal(kit.Signer.PublicKey, c.PublicKey);

        // A request whose signature is wrong proves nothing about the key.
        byte[] bad = csr.Encoded.ToArray();
        bad[^2] ^= 0x55;
        CertificateSigningRequest forged = CertificateSigningRequest.Parse(bad);
        IssuanceException e = Assert.Throws<IssuanceException>(() => Kit.Intermediate.Issue(forged, new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = T0 }));
        Assert.Equal("csr-signature", e.Rule);
    }

    [Fact]
    public void RefusalsNameTheRule()
    {
        PublicKeyInfo key = CmsKeys.Get(SigKind.P256).Signer.PublicKey;
        CertificateAuthority ca = Kit.Intermediate;
        static IssuanceException Refused(Func<Certificate> f) => Assert.Throws<IssuanceException>(f);

        Assert.Equal("san", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = T0 })).Rule);
        Assert.Equal("san", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions { Profile = CertificateProfile.SMime, NotBefore = T0, SubjectAlternativeNames = [GeneralName.Dns("a.example.test")] })).Rule);
        Assert.Equal("san", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = T0, SubjectAlternativeNames = [GeneralName.Dns("a.example.test")] })).Rule);
        Assert.Equal("validity", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = T0, Validity = TimeSpan.FromDays(399), SubjectAlternativeNames = SanFor(CertificateProfile.TlsServer) })).Rule);
        Assert.Equal("issuer-validity", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = T0.AddYears(20) })).Rule);
        Assert.Equal("issuer-validity", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = T0.AddDays(-400) })).Rule);
        Assert.Equal("path-length", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = T0, PathLength = 1, SubjectAlternativeNames = SanFor(CertificateProfile.TlsServer) })).Rule);
        Assert.Equal("subject", Refused(() => ca.Issue(key, DistinguishedName.Empty, new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = T0 })).Rule);

        // The profile writes basicConstraints and key usage itself; a caller cannot add a second copy.
        Assert.Equal("extensions", Refused(() => ca.Issue(key, Name("x"), new CertificateIssueOptions
        {
            Profile = CertificateProfile.CodeSigning, NotBefore = T0, AdditionalExtensions = [Extension.Create(new BasicConstraints(true, null), true)],
        })).Rule);

        // A short-lived key is refused by the policy, not by a profile rule.
        using var weak = RSA.Create(1024);
        Assert.Throws<PolicyViolationException>(() => ca.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(weak), Name("weak"), new CertificateIssueOptions { Profile = CertificateProfile.CodeSigning, NotBefore = T0 }));
    }

    [Fact]
    public void PathLengthOfTheIssuerCapsWhatItIssues()
    {
        // Root issues an intermediate with pathLen 0; that intermediate can issue leaves but no further CA.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Certificate capped = Kit.Root.Issue(PublicKeyInfo.FromAsymmetricAlgorithm(key), Name("capped"), new CertificateIssueOptions { Profile = CertificateProfile.Intermediate, NotBefore = T0.AddDays(-5), PathLength = 0 });
        Assert.Equal(0, capped.BasicConstraints!.PathLengthConstraint);
        var cappedCa = new CertificateAuthority(capped, X509Signer.FromECDsa(key));
        IssuanceException e = Assert.Throws<IssuanceException>(() => cappedCa.Issue(CmsKeys.Get(SigKind.P256).Signer.PublicKey, Name("sub"), new CertificateIssueOptions { Profile = CertificateProfile.Intermediate, NotBefore = T0 }));
        Assert.Equal("path-length", e.Rule);
        Assert.NotNull(Leaf(CertificateProfile.CodeSigning, SigKind.P256, cappedCa));

        // A CA certificate that cannot sign certificates cannot become a CA object.
        Assert.Throws<ArgumentException>(() => new CertificateAuthority(Leaf(CertificateProfile.CodeSigning), CmsKeys.Get(SigKind.Rsa).Signer));
    }

    [Fact]
    public void AnIssuerFromAKeyInterfaceSignsTheSame()
    {
        using var rsa = RSA.Create(3072);
        using ISigningKey key = PrivateKey.FromRsa(rsa);
        CertificateAuthority root = CertificateAuthority.CreateRoot(Name("iface root"), X509Signer.FromKey(key, SignatureSpec.RsaPss(HashAlgorithmName.SHA256)), T0, TimeSpan.FromDays(365));
        Assert.True(root.Certificate.IsSelfSigned);
        Assert.Equal(KnownOids.RsaPss, root.Certificate.SignatureAlgorithm.Oid);
    }

    // -------------------------------------------------------------------- CRLs

    private static string Hex(Certificate c) => Convert.ToHexString(c.SerialNumber.Span);

    [Fact]
    public void ACrlCarriesNumbersReasonsDatesAndTheDistributionPoint()
    {
        Certificate revoked = Leaf(CertificateProfile.CodeSigning, SigKind.P256);
        CertificateRevocationList crl = Kit.Intermediate.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = Later,
            NextUpdate = Later.AddDays(7),
            Number = 5,
            Revoked = [new RevokedCertificateInfo(revoked.SerialNumberValue, Later.AddHours(-1), RevocationReason.KeyCompromise, T0)],
            DistributionPointUrl = "http://pki.example.test/ca.crl",
            OnlyUserCertificates = true,
            DeltaCrlUrl = "http://pki.example.test/delta.crl",
        });
        Assert.True(crl.VerifySignature(Kit.Intermediate.Certificate).IsValid);
        Assert.Equal(new BigInteger(5), crl.Number);
        Assert.False(crl.IsDelta);
        Assert.Equal(Later.ToUnixTimeSeconds(), crl.ThisUpdate.ToUnixTimeSeconds());
        Assert.Equal("http://pki.example.test/ca.crl", crl.IssuingDistributionPoint!.DistributionPoint!.FullName![0].Value);
        Assert.True(crl.IssuingDistributionPoint.OnlyContainsUserCerts);
        RevokedCertificate entry = Assert.Single(crl.Entries);
        Assert.Equal(RevocationReason.KeyCompromise, entry.Reason);
        Assert.Equal(T0.ToUnixTimeSeconds(), entry.InvalidityDate!.Value.ToUnixTimeSeconds());
        Assert.Equal(revoked.SerialNumberValue, entry.SerialNumberValue);
        Assert.NotNull(crl.Extensions.Find(KnownOids.FreshestCrl));
        Assert.Equal(Kit.Intermediate.Certificate.SubjectKeyIdentifier!.KeyIdentifier.ToArray(), crl.AuthorityKeyIdentifier!.KeyIdentifier.ToArray());
    }

    [Fact]
    public void CrlRulesAreEnforced()
    {
        static CrlIssueOptions O(Action<List<string>>? _ = null, BigInteger? delta = null, BigInteger? number = null, TimeSpan? next = null, string? deltaUrl = null) =>
            new() { ThisUpdate = Later, NextUpdate = Later + (next ?? TimeSpan.FromDays(1)), Number = number ?? 3, DeltaBaseNumber = delta, DeltaCrlUrl = deltaUrl };
        CertificateAuthority ca = Kit.Intermediate;
        Assert.Equal("next-update", Assert.Throws<IssuanceException>(() => ca.IssueCrl(O(next: TimeSpan.Zero))).Rule);
        Assert.Equal("delta-base", Assert.Throws<IssuanceException>(() => ca.IssueCrl(O(delta: 3))).Rule);
        Assert.Equal("delta-url", Assert.Throws<IssuanceException>(() => ca.IssueCrl(O(delta: 2, deltaUrl: "http://x.example.test/d"))).Rule);
        Assert.Equal("crl-number", Assert.Throws<IssuanceException>(() => ca.IssueCrl(O(number: -1))).Rule);
        Assert.Equal("issuer-validity", Assert.Throws<IssuanceException>(() => ca.IssueCrl(new CrlIssueOptions { ThisUpdate = T0.AddYears(30), NextUpdate = T0.AddYears(31), Number = 1 })).Rule);
        Assert.Equal("reason", Assert.Throws<IssuanceException>(() => ca.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = Later, NextUpdate = Later.AddDays(1), Number = 1, Revoked = [new RevokedCertificateInfo(7, Later, RevocationReason.RemoveFromCrl)],
        })).Rule);
    }

    [Fact]
    public void OpenSslAcceptsOurCrlAndDeltaCrlAndEnforcesThem()
    {
        OpenSslTool.RequireOrSkip();
        Certificate good = Leaf(CertificateProfile.CodeSigning, SigKind.P256);
        Certificate revokedInBase = Leaf(CertificateProfile.CodeSigning, SigKind.P256);
        Certificate revokedInDelta = Leaf(CertificateProfile.CodeSigning, SigKind.P256);
        CertificateAuthority ca = Kit.Intermediate;
        CertificateRevocationList baseCrl = ca.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = T0.AddHours(1), NextUpdate = T0.AddDays(7), Number = 10,
            Revoked = [new RevokedCertificateInfo(revokedInBase.SerialNumberValue, T0.AddMinutes(30), RevocationReason.Superseded, T0.AddMinutes(10))],
            DeltaCrlUrl = "http://pki.example.test/delta.crl",
        });
        CertificateRevocationList delta = ca.IssueCrl(new CrlIssueOptions
        {
            ThisUpdate = T0.AddHours(2), NextUpdate = T0.AddDays(1), Number = 11, DeltaBaseNumber = 10,
            Revoked = [new RevokedCertificateInfo(revokedInDelta.SerialNumberValue, T0.AddMinutes(90), RevocationReason.CessationOfOperation)],
        });
        Assert.True(delta.IsDelta);
        Assert.Equal(new BigInteger(10), delta.BaseNumber);

        string dir = IssuanceKit.Dir("ca-crl");
        string root = IssuanceKit.Write(dir, "root.pem", Kit.Root.Certificate.ToPem());
        string inter = IssuanceKit.Write(dir, "inter.pem", ca.Certificate.ToPem());
        string baseFile = IssuanceKit.Write(dir, "base.crl", baseCrl.ToPem());
        string deltaFile = IssuanceKit.Write(dir, "delta.crl", delta.ToPem());
        string both = IssuanceKit.Write(dir, "both.crl", baseCrl.ToPem() + delta.ToPem());
        string at = IssuanceKit.Epoch(T0.AddHours(3)).ToString();

        IssuanceKit.Ok(OpenSslTool.Run("crl", "-in", baseFile, "-CAfile", inter, "-noout", "-verify"), "crl -verify base");
        IssuanceKit.Ok(OpenSslTool.Run("crl", "-in", deltaFile, "-CAfile", inter, "-noout", "-verify"), "crl -verify delta");
        (int c, string text) = OpenSslTool.Run("crl", "-in", deltaFile, "-noout", "-text");
        Assert.Equal(0, c);
        Assert.Contains("Delta CRL Indicator", text);
        Assert.Contains("CRL Number", text);

        string Verify(Certificate leaf, string crls, bool deltas, out int code)
        {
            string f = IssuanceKit.Write(dir, "leaf-" + Hex(leaf) + ".pem", leaf.ToPem());
            var args = new List<string> { "verify", "-CAfile", root, "-untrusted", inter, "-attime", at, "-crl_check", "-CRLfile", crls };
            if (deltas)
            {
                // openssl only reads a delta CRL (whose indicator is critical) with the extended CRL support switched on.
                args.AddRange(["-extended_crl", "-use_deltas"]);
            }

            args.Add(f);
            (code, string o) = OpenSslTool.Run([.. args]);
            return o;
        }

        string o1 = Verify(good, both, true, out int code1);
        Assert.True(code1 == 0, o1);
        string o2 = Verify(revokedInBase, both, true, out int code2);
        Assert.NotEqual(0, code2);
        Assert.Contains("certificate revoked", o2);
        string o3 = Verify(revokedInDelta, both, true, out int code3);
        Assert.NotEqual(0, code3);
        Assert.Contains("certificate revoked", o3);
        // Without the delta the base list alone does not know the second revocation.
        string o4 = Verify(revokedInDelta, baseFile, false, out int code4);
        Assert.True(code4 == 0, o4);
    }

    // ---------------------------------------------------------------- two phase

    [Fact]
    public void ACertificateAndACrlAreSignedInAnotherProcess()
    {
        string dir = IssuanceKit.Dir("ca-two-phase");
        byte[] pkcs8 = Kit.InterKey.ExportPkcs8PrivateKey();
        SignatureSpec spec = SignatureSpec.Ecdsa(HashAlgorithmName.SHA384);
        CertificateAuthority ca = Kit.Intermediate;
        PublicKeyInfo subject = CmsKeys.Get(SigKind.Rsa).Signer.PublicKey;
        var o = new CertificateIssueOptions { Profile = CertificateProfile.TlsServer, NotBefore = T0, SubjectAlternativeNames = SanFor(CertificateProfile.TlsServer) };

        PreparedSignature prepared = ca.PrepareIssue(subject, Name("two-phase"), o, spec);
        byte[] state = prepared.Encode();
        byte[] sig = IssuanceKit.SignInOtherProcess(dir, "ecdsa", pkcs8, state);
        Certificate cert = CertificateAuthority.CompleteIssue(PreparedSignature.Decode(state), sig);
        Assert.True(cert.VerifySignature(ca.Certificate).IsValid);
        Assert.Equal(subject, cert.PublicKey);
        byte[] wrong = sig.ToArray();
        wrong[10] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => CertificateAuthority.CompleteIssue(prepared, wrong));

        PreparedSignature crlState = ca.PrepareCrl(new CrlIssueOptions { ThisUpdate = Later, NextUpdate = Later.AddDays(1), Number = 77, Revoked = [new RevokedCertificateInfo(cert.SerialNumberValue, Later, RevocationReason.Unspecified)] }, spec);
        byte[] crlSig = IssuanceKit.SignInOtherProcess(dir, "ecdsa", pkcs8, crlState.Encode());
        CertificateRevocationList crl = CertificateAuthority.CompleteCrl(PreparedSignature.Decode(crlState.Encode()), crlSig);
        Assert.True(crl.VerifySignature(ca.Certificate).IsValid);
        Assert.Equal(new BigInteger(77), crl.Number);
        Assert.Throws<ArgumentException>(() => CertificateAuthority.CompleteIssue(crlState, crlSig)); // a CRL state cannot complete a certificate

        OpenSslTool.RequireOrSkip();
        string r = IssuanceKit.Write(dir, "root.pem", Kit.Root.Certificate.ToPem());
        string i = IssuanceKit.Write(dir, "inter.pem", ca.Certificate.ToPem());
        string l = IssuanceKit.Write(dir, "leaf.pem", cert.ToPem());
        IssuanceKit.Ok(OpenSslTool.Run("verify", "-CAfile", r, "-untrusted", i, "-attime", IssuanceKit.Epoch(Later).ToString(), "-purpose", "sslserver", l), "verify two-phase leaf");
        IssuanceKit.Ok(OpenSslTool.Run("crl", "-in", IssuanceKit.Write(dir, "c.crl", crl.ToPem()), "-CAfile", i, "-noout", "-verify"), "crl -verify two-phase");
        Assert.NotEmpty(Hex(cert));
    }
}
