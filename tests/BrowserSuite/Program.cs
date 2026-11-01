using OneCrypto.Smoke;

// Arguments: an optional comma-separated list of areas ("all" or none runs everything), then optionally "force-fallbacks", which makes a native
// run use the managed verifiers the browser uses.
string? only = args.Length > 0 && args[0] != "all" ? args[0] : null;
return BrowserSuite.Run(only, args.Length > 1 && args[1] == "force-fallbacks");
