import * as fs from 'fs'
import { fileURLToPath  } from "url";
import { dirname  } from "path";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

import parser from "@babel/parser";
import traverseMod from "@babel/traverse";
import * as t from "@babel/types";
import generateMod from "@babel/generator";

export { parser, traverseMod, generateMod, t, fs };
