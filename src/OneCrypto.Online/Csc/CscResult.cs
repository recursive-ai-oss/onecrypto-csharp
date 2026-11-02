namespace RecursiveAI.OneCrypto.Online.Csc;

/// <summary>How a call to a remote signing service ended.</summary>
public enum CscOutcome
{
    /// <summary>The service answered and the answer was understood.</summary>
    Ok = 0,

    /// <summary>The request did not complete: the network failed, a limit or guard stopped it, or the service answered with a redirect (never followed, because requests carry credentials). <see cref="CscResult{T}.Fetch"/> has the details.</summary>
    TransportFailed = 1,

    /// <summary>The service answered with an error object (<c>error</c> and <c>error_description</c>, CSC API §10). <see cref="CscResult{T}.Error"/> is its code.</summary>
    ServiceError = 2,

    /// <summary>The service refused the access token: HTTP 401, <c>invalid_token</c> or <c>expired_token</c>. A fresh token was already asked for once before this was reported.</summary>
    TokenRejected = 3,

    /// <summary>The token source gave no token, or one that has already expired.</summary>
    TokenUnavailable = 4,

    /// <summary>The answer is not what the API describes (not JSON, a missing or mistyped member, an undecodable certificate).</summary>
    MalformedResponse = 5,

    /// <summary>The authorization is still being given out of band (HTTP 202). <see cref="CscAuthorization.PendingHandle"/> names it.</summary>
    AuthorizationPending = 6,

    /// <summary>The credential cannot be used for what was asked: its key is disabled, or its authorization mode is one this client cannot drive.</summary>
    CredentialUnusable = 7,

    /// <summary>The signature the service returned does not verify against the credential's certificate key, or the service returned the wrong number of signatures.</summary>
    BadSignature = 8,
}

/// <summary>
/// What a remote-signing call produced. A failure is an <see cref="Outcome"/> with a <see cref="Reason"/>, not an exception. No reason, error text or
/// property of this object contains an access token, a Signature Activation Data value or an authentication value.
/// </summary>
/// <typeparam name="T">The value of a successful call.</typeparam>
public sealed class CscResult<T>
{
    internal CscResult(CscOutcome outcome, string reason, T? value, FetchResult? fetch, string? error, int? statusCode)
    {
        Outcome = outcome;
        Reason = reason;
        Value = value;
        Fetch = fetch;
        Error = error;
        StatusCode = statusCode;
    }

    /// <summary>How the call ended.</summary>
    public CscOutcome Outcome { get; }

    /// <summary>True when <see cref="Outcome"/> is <see cref="CscOutcome.Ok"/>.</summary>
    public bool IsSuccess => Outcome == CscOutcome.Ok;

    /// <summary>A sentence saying why, empty on success.</summary>
    public string Reason { get; }

    /// <summary>The value; null unless the call succeeded (or, for <see cref="CscOutcome.AuthorizationPending"/>, the pending authorization).</summary>
    public T? Value { get; }

    /// <summary>The HTTP exchange of the last request, null when none was made.</summary>
    public FetchResult? Fetch { get; }

    /// <summary>The service's <c>error</c> code (for example <c>invalid_request</c>), when it sent one.</summary>
    public string? Error { get; }

    /// <summary>The HTTP status of the last answer, when there was one.</summary>
    public int? StatusCode { get; }

    internal static CscResult<T> Ok(T value, FetchResult? fetch) => new(CscOutcome.Ok, string.Empty, value, fetch, null, fetch?.StatusCode);

    internal static CscResult<T> Fail(CscOutcome outcome, string reason, FetchResult? fetch = null, string? error = null) =>
        new(outcome, reason, default, fetch, error, fetch?.StatusCode);

    internal CscResult<TOther> As<TOther>() => new(Outcome, Reason, default, Fetch, Error, StatusCode);
}

/// <summary>
/// Thrown by <see cref="CscSigningKey"/>, whose interface has no result type. It carries the same outcome and reason a <see cref="CscResult{T}"/> would, and
/// never any credential.
/// </summary>
public sealed class CscSigningException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="outcome">How the call ended.</param>
    /// <param name="message">The reason.</param>
    /// <param name="error">The service's error code, if any.</param>
    public CscSigningException(CscOutcome outcome, string message, string? error = null)
        : base(message)
    {
        Outcome = outcome;
        Error = error;
    }

    /// <summary>Creates the exception.</summary>
    public CscSigningException()
        : this(CscOutcome.TransportFailed, "remote signing failed")
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">The reason.</param>
    public CscSigningException(string message)
        : this(CscOutcome.TransportFailed, message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">The reason.</param>
    /// <param name="inner">The underlying exception.</param>
    public CscSigningException(string message, Exception inner)
        : base(message, inner)
    {
        Outcome = CscOutcome.TransportFailed;
    }

    /// <summary>How the call ended.</summary>
    public CscOutcome Outcome { get; }

    /// <summary>The service's <c>error</c> code, if it sent one.</summary>
    public string? Error { get; }
}
