import { dotnet } from './_framework/dotnet.js'

const { runMain } = await dotnet
    .withApplicationArguments(...process.argv.slice(2))
    .create();

await runMain();
