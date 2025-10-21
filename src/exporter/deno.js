import * as fs from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

export const __filename = fileURLToPath(import.meta.url);
export const __dirname = dirname(__filename);

import parser from "npm:@babel/parser";
import traverseMod from "npm:@babel/traverse";
import * as t from "npm:@babel/types";
import generateMod from "npm:@babel/generator";

export { parser, traverseMod, generateMod, t, fs };
