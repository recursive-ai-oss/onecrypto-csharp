namespace RecursiveAI.OneCrypto.Keys.Agents;

/// <summary>
/// An agent could not do what was asked. The subclasses say why: <see cref="AgentUnavailableException"/> (nothing to talk to),
/// <see cref="AgentKeyNotFoundException"/>, <see cref="AgentRefusedException"/> (the agent, or the user at its prompt, said no),
/// <see cref="AgentProtocolException"/> (the reply was not what the protocol allows) and <see cref="AgentLimitException"/>.
/// </summary>
public abstract class AgentException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What went wrong.</param>
    protected AgentException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with the failure that caused it.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The underlying failure.</param>
    protected AgentException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>There is no agent to talk to: no socket path could be found, the socket does not exist, the connection was refused or timed out, or the platform has no local sockets.</summary>
public sealed class AgentUnavailableException : AgentException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="socketPath">The socket that was tried, or null when none could be worked out.</param>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The socket failure, if any.</param>
    public AgentUnavailableException(string? socketPath, string message, Exception? innerException = null)
        : base(message, innerException!)
    {
        SocketPath = socketPath;
    }

    /// <summary>The socket that was tried, or null.</summary>
    public string? SocketPath { get; }
}

/// <summary>The agent does not hold the key that was asked for.</summary>
public sealed class AgentKeyNotFoundException : AgentException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What was looked for.</param>
    public AgentKeyNotFoundException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// The agent answered with an error or a failure. For gpg-agent that is an Assuan <c>ERR</c> reply: <see cref="Code"/> is the GnuPG error code (the low 16 bits of the
/// number the agent sent), <see cref="ErrorSource"/> the error source (the high byte) and <see cref="IsCancelled"/> is true when the user cancelled at the prompt. For ssh-agent
/// it is an <c>SSH_AGENT_FAILURE</c> reply, with <see cref="Code"/> 0.
/// </summary>
public sealed class AgentRefusedException : AgentException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="rawCode">The error number as the agent sent it (source in the high byte, code in the low 16 bits).</param>
    /// <param name="description">The agent's description text, which may be empty.</param>
    public AgentRefusedException(uint rawCode, string description)
        : base(Describe(rawCode, description))
    {
        RawCode = rawCode;
        Description = description;
    }

    /// <summary>The error number as the agent sent it.</summary>
    public uint RawCode { get; }

    /// <summary>The GnuPG error code (low 16 bits; the system-error flag, bit 15, included when set).</summary>
    public int Code => (int)(RawCode & 0xFFFF);

    /// <summary>The GnuPG error source (the high byte): 4 is gpg-agent itself, 5 is the pinentry.</summary>
    public int ErrorSource => (int)((RawCode >> 24) & 0x7F);

    /// <summary>The agent's description text.</summary>
    public string Description { get; }

    /// <summary>True when the user cancelled at the agent's prompt (GnuPG's "canceled" and "fully canceled", codes 99 and 198).</summary>
    public bool IsCancelled => Code is 99 or 198;

    /// <summary>True when the agent says the passphrase was wrong (GnuPG's "bad passphrase", code 11).</summary>
    public bool IsBadPassphrase => Code == 11;

    private static string Describe(uint rawCode, string description) =>
        rawCode == 0 ? "The agent refused the request" + (description.Length > 0 ? ": " + description : ".")
        : $"The agent refused the request (error {rawCode & 0xFFFF}, source {(rawCode >> 24) & 0x7F})" + (description.Length > 0 ? ": " + description : ".");
}

/// <summary>The agent sent something the protocol does not allow: a line or reply over the size limits, a malformed line or S-expression, a reply of the wrong kind, a signature that does not verify, or a closed connection mid-reply.</summary>
public sealed class AgentProtocolException : AgentException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What was wrong with the reply.</param>
    /// <param name="innerException">The underlying failure, if any.</param>
    public AgentProtocolException(string message, Exception? innerException = null)
        : base(message, innerException!)
    {
    }
}

/// <summary>The request is bigger than the agent accepts, for example the message of a pure EdDSA signature that exceeds what gpg-agent takes in one inquiry.</summary>
public sealed class AgentLimitException : AgentException
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What was too big, and the limit.</param>
    public AgentLimitException(string message)
        : base(message)
    {
    }
}
