// Runs the same published app under Node, for the case-by-case comparison with the browser. Run from the published wwwroot.
import { dotnet } from './_framework/dotnet.js';

const { runMain } = await dotnet.withApplicationArguments(...process.argv.slice(2)).create();
process.exitCode = await runMain();
