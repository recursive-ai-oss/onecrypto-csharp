using Microsoft.Win32.SafeHandles;

namespace RecursiveAI.OneCrypto.Cli.Sop;

/// <summary>The process surroundings a sop command works with: standard streams and the environment. Tests supply their own.</summary>
internal sealed class SopIo
{
    public SopIo(Stream stdin, Stream stdout, TextWriter stderr, Func<string, string?> getEnvironmentVariable)
    {
        Stdin = stdin;
        Stdout = stdout;
        Stderr = stderr;
        GetEnvironmentVariable = getEnvironmentVariable;
    }

    public Stream Stdin { get; }

    public Stream Stdout { get; }

    public TextWriter Stderr { get; }

    public Func<string, string?> GetEnvironmentVariable { get; }

    /// <summary>
    /// Opens an indirect output (draft-dkg-openpgp-stateless-cli §7.1): <c>@FD:n</c> writes to descriptor n, any other <c>@</c> prefix is refused, and a
    /// plain name is created new (an existing file is OUTPUT_EXISTS) and never matched against the special forms.
    /// </summary>
    public static Stream OpenOutput(string designator)
    {
        if (designator.StartsWith('@'))
        {
            if (designator.StartsWith("@FD:", StringComparison.Ordinal))
            {
                if (!int.TryParse(designator.AsSpan(4), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int fd) || OperatingSystem.IsWindows())
                {
                    throw new SopException(SopExit.UnsupportedSpecialPrefix, "cannot use " + designator + " as an output");
                }

                // The descriptor stays open for the caller that passed it; only the handle object is ours.
                return new FileStream(new SafeFileHandle((IntPtr)fd, ownsHandle: false), FileAccess.Write);
            }

            throw new SopException(SopExit.UnsupportedSpecialPrefix, "unsupported special designator for output: " + designator);
        }

        try
        {
            return new FileStream(designator, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        }
        catch (IOException) when (File.Exists(designator))
        {
            throw new SopException(SopExit.OutputExists, "the output already exists: " + designator);
        }
    }

    /// <summary>
    /// Opens an indirect input: <c>@ENV:name</c> reads the environment variable, <c>@FD:n</c> descriptor n, other <c>@</c> prefixes are refused, and a plain
    /// name is a file (missing is MISSING_INPUT).
    /// </summary>
    public Stream OpenInput(string designator)
    {
        if (designator.StartsWith('@'))
        {
            if (designator.StartsWith("@ENV:", StringComparison.Ordinal))
            {
                string? value = GetEnvironmentVariable(designator[5..]);
                return value is null
                    ? throw new SopException(SopExit.MissingInput, "the environment variable is not set: " + designator[5..])
                    : new MemoryStream(System.Text.Encoding.UTF8.GetBytes(value));
            }

            if (designator.StartsWith("@FD:", StringComparison.Ordinal))
            {
                if (!int.TryParse(designator.AsSpan(4), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int fd) || OperatingSystem.IsWindows())
                {
                    throw new SopException(SopExit.UnsupportedSpecialPrefix, "cannot use " + designator + " as an input");
                }

                return new FileStream(new SafeFileHandle((IntPtr)fd, ownsHandle: false), FileAccess.Read);
            }

            throw new SopException(SopExit.UnsupportedSpecialPrefix, "unsupported special designator for input: " + designator);
        }

        try
        {
            return new FileStream(designator, FileMode.Open, FileAccess.Read, FileShare.Read);
        }
        catch (FileNotFoundException)
        {
            throw new SopException(SopExit.MissingInput, "no such file: " + designator);
        }
        catch (DirectoryNotFoundException)
        {
            throw new SopException(SopExit.MissingInput, "no such file: " + designator);
        }
    }
}
