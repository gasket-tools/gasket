import yargz from "yargs/yargs";
import { hideBin } from "yargs/helpers";

export default function parseArgs() {
  const yargs = yargz(hideBin(process.argv));
  if (process.argv.length <= 2) {
    yargs.showHelp();
    process.exit(0);
  }
  return yargs
    .option("root", {
      alias: "r",
      type: "string",
      description: "Package root",
      demandOption: false,
    })
    .option("module", {
      alias: "m",
      type: "string",
      description: "Module to analyze",
      demandOption: false,
    })
    .option("internal", {
      type: "boolean",
      description:
        "Whether the analyzed module is an internal binding (to be used with -m)",
      default: false,
    })
    .option("output", {
      alias: "o",
      type: "string",
      description: "output file",
    })
    .option("profile-heap", {
      alias: "p",
      type: "boolean",
      describe: "Profile the V8 Heap for unexported objects",
      default: false,
    })
    .option("native-only", {
      type: "boolean",
      describe: "Detect only JS-to-Native bridges",
    })
    .option("wasm-only", {
      type: "boolean",
      describe: "Detect only JS-to-Wasm bridges",
    })
    .option("force-export", {
      type: "boolean",
      describe: "Force export top-level declarations in analyzed modules",
    })
    .conflicts("module", "root")
    .conflicts("wasm-only", "native-only")
    .check((argv) => {
      if (argv.internal && !argv.module) {
        throw new Error("--internal can only be used with --module");
      }
      return true;
    })
    .strict()
    .showHelpOnFail(true)
    .help().argv;
}
