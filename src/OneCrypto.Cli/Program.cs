using RecursiveAI.OneCrypto.Cli.Sop;

namespace RecursiveAI.OneCrypto.Cli;

/// <summary>The <c>onecrypto</c> tool. <c>onecrypto sop ...</c> is the Stateless OpenPGP interface; <c>onecrypto pgp authenticate</c> runs the web of trust; the <c>inspect</c> and convenience verbs are added as the libraries they sit on arrive.</summary>
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

        if (args.Length > 1 && args[0] == "pgp" && args[1] == "authenticate")
        {
            return PgpAuthenticate.Run(args[2..], Console.Out, Console.Error);
        }

        Console.Error.WriteLine(args.Length == 0
            ? "onecrypto: no command given. Available: sop, sopv, pgp authenticate."
            : $"onecrypto: unknown command '{args[0]}'. Available: sop, sopv, pgp authenticate.");
        return 2;
    }
}
