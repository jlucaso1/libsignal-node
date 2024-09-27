import {$} from "bun";

await $`bun tsc`;

// copy all d.ts files to lib

await $`cp ./src/*.d.ts ./lib`;