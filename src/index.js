if (typeof Deno !== "undefined") {
	import nodeGypBuild from 'npm:node-gyp-build';
} else {
  import nodeGypBuild from 'node-gyp-build';
}
import nodeGypBuild from 'npm:node-gyp-build';
import { fileURLToPath  } from "node:url";
import { dirname, resolve } from "node:path";

const native = nodeGypBuild(resolve(dirname(fileURLToPath(import.meta.url)), ".."));

export const addon = native;

export * from './ffdir.js';
