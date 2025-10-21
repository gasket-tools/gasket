let nodeGypBuild;
if (typeof Deno !== "undefined" && Deno.version?.deno) {
  nodeGypBuild = (await import("npm:node-gyp-build")).default;
} else {
  nodeGypBuild = (await import("node-gyp-build")).default;
}
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const native = nodeGypBuild(
  resolve(dirname(fileURLToPath(import.meta.url)), ".."),
);

export const addon = native;

// export * from './ffdir.js';
