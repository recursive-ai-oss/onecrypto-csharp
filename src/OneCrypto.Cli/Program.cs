namespace RecursiveAI.OneCrypto.Cli;

/// <summary>The <c>onecrypto</c> tool. The <c>sop</c> and <c>inspect</c> verbs are added as the libraries they sit on arrive.</summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        Console.Error.WriteLine(args.Length == 0
            ? "onecrypto: no command given. Commands (sop, inspect) are not available in this preview."
            : $"onecrypto: unknown command '{args[0]}'. Commands (sop, inspect) are not available in this preview.");
        return 2;
    }
}
