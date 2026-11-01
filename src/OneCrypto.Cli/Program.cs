using RecursiveAI.OneCrypto.Cli.Sop;

namespace RecursiveAI.OneCrypto.Cli;

/// <summary>The <c>onecrypto</c> tool. <c>onecrypto sop ...</c> is the Stateless OpenPGP interface; the <c>inspect</c> and convenience verbs are added as the libraries they sit on arrive.</summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] is "sop" or "sopv")
        {
            using Stream stdin = Console.OpenStandardInput();
            using Stream stdout = Console.OpenStandardOutput();
            var io = new SopIo(stdin, stdout, Console.Error, Environment.GetEnvironmentVariable);
            return SopApp.Run(args[1..], io, sopvOnly: args[0] == "sopv");
        }

        Console.Error.WriteLine(args.Length == 0
            ? "onecrypto: no command given. Available: sop, sopv."
            : $"onecrypto: unknown command '{args[0]}'. Available: sop, sopv.");
        return 2;
    }
}
