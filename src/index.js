import nodeGypBuild from 'npm:node-gyp-build';
import { fileURLToPath  } from "node:url";
import { dirname, resolve } from "node:path";

const native = nodeGypBuild(resolve(dirname(fileURLToPath(import.meta.url)), ".."));

export const jid = native;

export * from './ffdir.js';
