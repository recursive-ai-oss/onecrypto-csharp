using System.Text;
using RecursiveAI.OneCrypto.OpenPgp;

namespace RecursiveAI.OneCrypto;

/// <summary>
/// The happy path for OpenPGP keys: one call each, no algorithm choices (the key version and algorithms come from the library's policy). Drop to
/// <see cref="PgpKeyGenerator"/> and <see cref="PgpKeyEditor"/> to choose a profile, a reference time or a policy.
/// </summary>
public static partial class Pgp
{
    /// <summary>
    /// Generates a key for one User ID: a version 6 Ed25519 key that certifies and signs, with an X25519 subkey for encryption, protected by
    /// <paramref name="password"/> when it is given.
    /// </summary>
    /// <param name="userId">The User ID, for example <c>Alice &lt;alice@example.org&gt;</c>.</param>
    /// <param name="password">The password, or null to leave the key unprotected.</param>
    /// <param name="time">The clock for the creation time. <see cref="TimeProvider.System"/> when null.</param>
    public static PgpCertificate GenerateKey(string userId, string? password = null, TimeProvider? time = null) =>
        PgpKeyGenerator.Generate(new PgpKeyGenerationOptions
        {
            Now = (time ?? TimeProvider.System).GetUtcNow(),
            UserIds = [userId],
            Password = password is null ? null : Encoding.UTF8.GetBytes(password),
        });

    /// <summary>Changes the password of every secret key in <paramref name="key"/>; a null <paramref name="newPassword"/> removes the protection.</summary>
    /// <exception cref="PgpException">The old password does not open the key (<see cref="PgpFailure.KeyIsProtected"/>).</exception>
    public static PgpCertificate ChangePassword(PgpCertificate key, string? oldPassword, string? newPassword) =>
        PgpKeyEditor.SetPassword(key, oldPassword is null ? [] : [Encoding.UTF8.GetBytes(oldPassword)], newPassword is null ? null : Encoding.UTF8.GetBytes(newPassword));

    /// <summary>Revokes a key: the returned certificate carries a hard key revocation (reason "no reason given") and can be published.</summary>
    /// <exception cref="PgpException">The password does not open the key.</exception>
    public static PgpCertificate Revoke(PgpCertificate key, string? password = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        using PgpSecretKey primary = PgpSecretKey.Unlock(key.Primary, password is null ? [] : [Encoding.UTF8.GetBytes(password)]);
        return PgpKeyEditor.RevokeKey(key.ToPublicCertificate(), primary, PgpRevocationReason.None, string.Empty, (time ?? TimeProvider.System).GetUtcNow());
    }

    /// <summary>Certifies a User ID of <paramref name="target"/> with <paramref name="certifierKey"/> and returns the certificate with the certification added.</summary>
    /// <exception cref="PgpException">The User ID is not on the certificate, or the password does not open the certifier's key.</exception>
    public static PgpCertificate Certify(PgpCertificate target, string userId, PgpCertificate certifierKey, string? password = null, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(certifierKey);
        using PgpSecretKey primary = PgpSecretKey.Unlock(certifierKey.Primary, password is null ? [] : [Encoding.UTF8.GetBytes(password)]);
        return PgpKeyEditor.Certify(target, userId, primary, (time ?? TimeProvider.System).GetUtcNow());
    }
}
