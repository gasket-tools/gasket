#! /usr/bin/env -S deno --node-modules-dir=auto --allow-all

import yargz from "npm:yargs@^18.0.0/yargs";
import { hideBin } from "npm:yargs@^18.0.0/helpers";

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { execSync, spawnSync } from "node:child_process";

// Resolve the real path of this file (follow symlinks)
const selfUrl = new URL(import.meta.url);
const selfPath =
  selfUrl.protocol === "file:" ? selfUrl.pathname : selfUrl.toString();
const realSelf = await Deno.realPath(selfPath);

const ffdirPath = path.join(path.dirname(realSelf), "..", "src", "ffdir.js");
const addonPath = path.join(path.dirname(realSelf), "..", "src", "index.js");
const transformPath = path.join(
  path.dirname(realSelf),
  "..",
  "src",
  "transformer.js",
);

const { SimplePropertyRetriever } = await import(pathToFileURL(ffdirPath).href);
const { addon } = await import(pathToFileURL(addonPath).href);
const { default: transform } = await import(pathToFileURL(transformPath).href);

const yargs = yargz(hideBin(process.argv));

if (process.env.GASKET_ROOT) {
  globalThis.RESOLVE_SCRIPT_PATH = path.join(
    process.env.GASKET_ROOT,
    "scripts/resolve_syms.py",
  );
  globalThis.GET_LOADED_LIBS_SCRIPT_PATH = path.join(
    process.env.GASKET_ROOT,
    "scripts/get_loaded_libs.py",
  );
} else {
  globalThis.RESOLVE_SCRIPT_PATH = 'resolve-syms'
  globalThis.GET_LOADED_LIBS_SCRIPT_PATH = 'get-loaded-libs'
}

self.mod = addon;

self.objects_examined = 0;
self.callable_objects = 0;
self.foreign_callable_objects = 0;

self.cur_file = "foo";

self.fqn2failed = {};
self.fqn2mod = {};
self.fqn2obj = {};
self.fqn2overloadsaddr = {};
self.fqn2overloads = {};
self.fqn2cbaddr = {};
self.fqn2cbaddr2 = {};
self.fqn2cb = {};
self.fqn2cb2 = {};
self.fqn2cfunc = {};
self.fqn2cfuncaddr = {};
self.self.fqn2type = {};
self.addr2sym = {};
self.cbs_set = new Set();
self.cbs = [];

self.use_heap = false;
self.seen = new Set();

self.heap_jsfuncs = [];
self.heap_jsfuncs_before = [];
self.heap_jsfuncs_before_addresses = [];
self.heap_jsfuncs_after = [];
self.heap_jsfuncs_after_addresses = [];

self.heap_accessorPair_addresses = [];

self.heap_ids_before = [];
self.heap_ids_after = [];

self.loaded_libs_before = [];
self.loaded_libs_after = [];

self.sym2lib = {};

self.final_result = {
  objects_examined: 0,
  callable_objects: 0,
  foreign_callable_objects: 0,
  duration_sec: 0,
  count: 0,
  modules: [],
  jump_libs: [],
  bridges: [],
};

function parse_args() {
  return yargs
    .option("root", {
      alias: "r",
      type: "string",
      description: "Package root",
      demandOption: true,
    })
    .option("output", {
      alias: "o",
      type: "string",
      description: "output file",
    })
    .option("profile-heap", {
      alias: "p",
      type: "boolean",
      describe: "Enable verbose mode",
      default: false,
    })
    .help().argv;
}

function get_library_symbols(path) {
  const proc = new Deno.Command("nm", {
    args: ["-D", "--defined-only", path],
    stdout: "piped",
    stderr: "piped",
  }).outputSync();

  if (proc.code !== 0) {
    throw new Error(new TextDecoder().decode(proc.stderr));
  }

  const text = new TextDecoder().decode(proc.stdout);
  return text
    .split("\n")
    .map((line) => line.trim().split(/\s+/).pop())
    .filter((sym) => sym && !sym.startsWith("("));
}

function populate_sym2lib() {
  for (const lib of self.loaded_libs_after) {
    const syms = get_library_symbols(lib);
    for (const sym of syms) {
      sym2lib[sym] = lib;
    }
  }
}

/*
 * Deduplicate file paths by basename,
 * prefer real files that do not contain 'build' or 'tmp'.
 */
function deduplicate_paths(paths) {
  const grouped = new Map();

  for (const p of paths) {
    const base = path.basename(p);
    if (!grouped.has(base)) {
      grouped.set(base, []);
    }
    grouped.get(base).push(p);
  }

  const result = [];

  for (const [, pathList] of grouped) {
    // Prefer non-build/tmp paths that exist
    const preferred = pathList.find(
      (p) =>
        !p.includes("darwin") &&
        !p.includes("build") &&
        !p.includes("tmp") &&
        fs.existsSync(p),
    );

    // If not found, fallback to any existing file
    const fallback = pathList.find((p) => fs.existsSync(p));

    if (preferred) {
      result.push(path.resolve(preferred));
    } else if (fallback) {
      result.push(path.resolve(fallback));
    }
  }
  return result;
}

function demangle_cpp(mangled) {
  const cmd = `c++filt '${mangled}'`;
  try {
    const out = execSync(cmd, { encoding: "utf-8", shell: true });
    return out.trim();
  } catch (err) {
    console.error(err);
    throw err;
  }
}

function dir(obj) {
  // console.log(`dir(): ${obj}`)
  return SimplePropertyRetriever.getOwnAndPrototypeEnumAndNonEnumProps(obj);
}

function gdb_resolve(addresses) {
  const tmp_dir = os.tmpdir();
  const addr_file = path.join(tmp_dir, `addr_${randomUUID()}.json`);
  const res_file = path.join(tmp_dir, `res_${randomUUID()}.json`);

  var pid = process.pid;

  fs.writeFileSync(addr_file, JSON.stringify(addresses, null, 2));

  var args = [
    "-p",
    String(pid),
    "-i",
    addr_file,
    "-o",
    res_file,
  ];

  var result = spawnSync(RESOLVE_SCRIPT_PATH, args, { encoding: "utf-8" });
  const out = result.stdout;
  // console.log('OUT:')
  // console.log(out)
  const err = result.stderr;
  // console.log('ERR:')
  // console.log(err)

  const raw = fs.readFileSync(res_file, "utf-8");
  result = JSON.parse(raw);
  console.log("GDB RESULT:");
  console.log(result);

  return result;
}

function get_loaded_libs() {
  const tmp_dir = os.tmpdir();
  const res_file = path.join(tmp_dir, `res_${randomUUID()}.json`);

  var pid = process.pid;

  var args = ["-p", String(pid), "-o", res_file];

  var result = spawnSync(GET_LOADED_LIBS_SCRIPT_PATH, args, { encoding: "utf-8" });
  const out = result.stdout;
  console.log("OUT:");
  console.log(out);
  const err = result.stderr;
  console.log("ERR:");
  console.log(err);

  const raw = fs.readFileSync(res_file, "utf-8");
  result = JSON.parse(raw);
  return result;
}

function extract_fcb_invoke(fqn) {
  var obj = fqn2obj[fqn];
  var res = mod.extract_fcb_invoke(obj);
  if (res == "NONE") {
    fqn2failed[fqn] = "EXTRACT_FCB_INOKE";
  } else {
    /* res = address of cb2 */
    fqn2type[fqn] = "fcb";
    fqn2cbaddr2[fqn] = res;
  }
}

function extract_napi(fqn) {
  console.log(`Extract napi called: ${fqn}`);
  var obj = fqn2obj[fqn];
  var res = mod.extract_napi(obj);
  if (res == "NONE") {
    fqn2failed[fqn] = "EXTRACT_NAPI";
  } else {
    fqn2type[fqn] = "napi";
    fqn2cfuncaddr[fqn] = res;
  }
}

function extract_nan(fqn) {
  var obj = fqn2obj[fqn];
  var res = mod.extract_nan(obj);
  if (res == "NONE") {
    fqn2failed[fqn] = "EXTRACT_NAN";
  } else {
    fqn2type[fqn] = "nan";
    fqn2cfuncaddr[fqn] = res;
  }
}

function extract_cfunc(fqn) {
  var cb = fqn2cb[fqn];

  if (cb.includes("mod.mpl") && cb.includes("FunctionCallbackWrapper6Invoke")) {
    extract_fcb_invoke(fqn);
  } else if (cb.includes("Nan") && cb.includes("imp")) {
    extract_nan(fqn);
  } else {
    fqn2cfuncaddr[fqn] = fqn2cbaddr[fqn];
  }
}

function extract_cfunc_2(fqn) {
  var cb = fqn2cb2[fqn];
  var b;

  // Napi::ObjectWrap::ConstructorCallbackWrapper
  if (
    cb.includes("Napi") &&
    cb.includes("ObjectWrap") &&
    cb.includes("ConstructorCallbackWrapper")
  ) {
    var dem = demangle_cpp(cb);
    var cls = dem.match(/<([^>]*)>/)[1];
    var fn = cls + "::" + cls.split("::").pop();
    console.log(`fn = ${fn}`);
    // XXX: Spaghettoni
    var lib = addr2sym[fqn2cbaddr2[fqn]].library;
    b = {
      jsname: fqn,
      cfunc: fn,
      library: lib,
    };

    console.log(b);
    final_result["bridges"].push(b);
    if (!final_result["jump_libs"].includes(lib))
      final_result["jump_libs"].push(lib);
  }

  // Generic Napi
  else if (
    (cb.includes("Napi") &&
      cb.includes("CallbackData") &&
      cb.includes("Wrapper")) ||
    (cb.includes("Napi") && cb.includes("InstanceWrap")) ||
    (cb.includes("Napi") && cb.includes("ObjectWrap"))
  ) {
    extract_napi(fqn);
  } else if (cb.includes("neon") && cb.includes("sys")) {
    var name = mod.extract_neon(fqn2obj[fqn]);
    if (name !== "NONE") {
      const match = name.match(/#([^>]+)>/);
      if (match) {
        fn = match[1];
      } else {
        /* failed regex */
        fqn2failed[fqn] = "NEON_FAIL";
        return;
      }
      lib = cur_file;
      b = {
        jsname: fqn,
        cfunc: fn,
        library: lib,
      };
      final_result["bridges"].push(b);
      if (!final_result["jump_libs"].includes(lib))
        final_result["jump_libs"].push(lib);
    }
  }
  // napi-rs
  else if (cb.includes("_napi_internal_register")) {
    var fn = demangle_cpp(cb);
    console.log(`fn = ${fn}`);
    var lib = addr2sym[fqn2cbaddr2[fqn]].library;
    b = {
      jsname: fqn,
      cfunc: fn,
      library: lib,
    };

    console.log(b);
    final_result["bridges"].push(b);
    if (!final_result["jump_libs"].includes(lib))
      final_result["jump_libs"].push(lib);
  }

  // node-bindgen
  else if (cb.includes("napi_")) {
    var fn = demangle_cpp(cb);
    console.log(`fn = ${fn}`);
    var lib = addr2sym[fqn2cbaddr2[fqn]].library;
    b = {
      jsname: fqn,
      cfunc: fn,
      library: lib,
    };

    console.log(b);
    final_result["bridges"].push(b);
    if (!final_result["jump_libs"].includes(lib))
      final_result["jump_libs"].push(lib);
  } else {
    fqn2cfuncaddr[fqn] = fqn2cbaddr2[fqn];
  }
}

function clear_dicts() {
  fqn2mod = {};
  fqn2obj = {};
  fqn2overloadsaddr = {};
  fqn2overloads = {};
  fqn2cbaddr = {};
  fqn2cbaddr2 = {};
  fqn2cb = {};
  fqn2cb2 = {};
  fqn2cfunc = {};
  fqn2cfuncaddr = {};

  fqn2type = {};

  addr2sym = {};

  cbs_set = new Set();
  cbs = [];
}

function recursive_inspect(obj, jsname) {
  var pending = [[obj, jsname, {}]];
  // console.log(`len pending = ${pending.length}`)
  // var seen = new Set()
  var desc_names;
  var desc;
  var descname;
  var getter;
  var setter;
  var v;

  // XXX: BFS. Use queue: insert using .push(),
  //      get head using .shift
  while (pending.length > 0) {
    [obj, jsname] = pending.shift();
    // console.log(`jsname = ${jsname}`)

    if (!(obj instanceof Object) && typeof obj != "object") {
      continue;
    }
    // desc_names = Object.getOwnPropertyNames(obj)
    // console.log(`NAMES: ${desc_names}`)
    // for (const name of Object.getOwnPropertyNames(obj)) {
    //   desc = Object.getOwnPropertyDescriptor(obj, name);
    //   descname = jsname + '.' + name
    //   console.log(`DESC: ${descname}`)
    //   getter = desc['get']
    //   setter = desc['set']
    //   if (typeof(getter) == 'function') {
    //       check_bingo(getter, descname + '.' + 'GET', obj)
    //   }
    //   if (typeof(setter) == 'function') {
    //       check_bingo(setter, descname + '.' + 'SET', obj)
    //   }
    // }
    if (typeof obj == "function") {
      check_bingo(mod.jid(obj), jsname);
    }
    // console.log(`dir(obj)`)
    // console.log(`${dir(obj)}`)
    for (const k of dir(obj)) {
      // console.log(`getattr(${jsname}, ${k})`)
      try {
        v = obj[k];
      } catch (error) {
        // console.log(error)
        continue;
      }
      objects_examined += 1;
      if (typeof v == "undefined" || !(v instanceof Object)) {
        continue;
      }

      if (typeof obj == "function") callable_objects += 1;

      var ident = mod.jid(v);
      if (seen.has(ident)) {
        // console.log('ALREADY SEEN')
        continue;
      } else {
        seen.add(ident);
      }

      pending.push([v, jsname + "." + k]);
    }
    seen.add(mod.jid(obj));
  }
}

function extractJSFunctions(input) {
  const regexAddrFirst = /(0x[0-9a-fA-F]+)\s*<JSFunction\s+([^\s<(]+)/g;
  const regexNameFirst = /([a-zA-Z0-9_]+):\s*(0x[0-9a-fA-F]+)\s*<JSFunction/g;

  let match;

  // Address-first pattern
  while ((match = regexAddrFirst.exec(input)) !== null) {
    callable_objects += 1;
    objects_examined += 1;

    const addr = parseInt(match[1]).toString();
    const ob = { address: addr, name: match[2] };

    if (!heap_jsfuncs_after_addresses.includes(addr)) {
      if (!heap_jsfuncs_before_addresses.includes(addr)) {
        heap_jsfuncs_after.push(ob);
        heap_jsfuncs_after_addresses.push(addr);
      }
    }
  }

  // Name-first pattern
  while ((match = regexNameFirst.exec(input)) !== null) {
    callable_objects += 1;
    objects_examined += 1;

    const addr = parseInt(match[2]).toString();
    const ob = { address: addr, name: match[1] };

    if (!heap_jsfuncs_after_addresses.includes(addr)) {
      if (!heap_jsfuncs_before_addresses.includes(addr)) {
        heap_jsfuncs_after.push(ob);
        heap_jsfuncs_after_addresses.push(addr);
      }
    }
  }
}

function analyze_heap_before() {
  var object_addresses = JSON.parse(mod.get_objects());
  var addr;
  var raw;
  for (const addr of object_addresses) {
    objects_examined += 1;
    if (!heap_ids_before.includes(addr)) {
      heap_ids_before.push(addr);
    }
  }
}

function analyze_heap() {
  var object_addresses = JSON.parse(mod.get_objects());
  var raw;
  for (const addr of object_addresses) {
    if (!heap_ids_before.includes(addr) && !heap_ids_after.includes(addr)) {
      heap_ids_after.push(addr);
    }
  }
  for (const addr of heap_ids_after) {
    raw = mod.job_addr(parseInt(addr));
    console.log(raw);
    extractJSFunctions(raw);
    // extractGetSetters(raw)
  }
  // console.log(`HEAP FUNCS BEFORE: ${heap_jsfuncs_before.length}`)
  // console.log(JSON.stringify(heap_jsfuncs_before, null, 2))
  console.log(`HEAP FUNCS AFTER: ${heap_jsfuncs_after.length}`);
  console.log(JSON.stringify(heap_jsfuncs_after, null, 2));

  heap_jsfuncs = heap_jsfuncs_after;
  for (const func of heap_jsfuncs) {
    var addr = func.address;
    var name = func.name;
    console.log(`HEAP FUNC: ${addr} NAME=${name}`);
    // check_bingo(addr, name)
    if (!seen.has(addr)) {
      check_bingo(parseInt(addr), name);
    }
  }
}

function locate_js_modules(packagePath) {
  const soFiles = [];

  function walkDir(dir) {
    const files = fs.readdirSync(dir);
    files.forEach((file) => {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory()) {
        walkDir(fullPath); // Recursive call for directories
      } else if (file.endsWith("ts")) {
        soFiles.push(path.resolve(fullPath)); // Add .so files to the list
      }
    });
  }

  walkDir(packagePath);
  return soFiles;
}

async function analyze_single(mod_file, pkg_root) {
  var addr;
  var lib;
  var obj;
  var cb;
  var b;
  clear_dicts();
  cur_file = mod_file;
  try {
    obj = await import(mod_file);
    // console.log(dir(obj))
  } catch (error) {
    console.log(error);
    return;
  }
  var jsname = get_mod_fqn(mod_file, pkg_root);
  fqn2mod[jsname] = obj;
  console.log(`${mod_file}: jsname = ${jsname}`);
  recursive_inspect(obj, jsname);

  return;

  var cbs = Array.from(cbs_set);
  // XXX: Initialize Set with CBS!
  var resolve_addresses = new Set(cbs);

  // for (let key in fqn2overloadsaddr) {
  //     new_addrs = []
  //     for (let addr of fqn2overloadsaddr[key]) {
  //         console.log(addr)
  //         dec_addr = String(Number(addr))
  //         console.log(dec_addr)
  //         new_addrs.push(dec_addr)
  //     }
  //     fqn2overloadsaddr[key] = new_addrs
  // }

  for (let key in fqn2overloadsaddr) {
    fqn2overloadsaddr[key].forEach((item) => resolve_addresses.add(item));
  }

  console.log(
    `FQN2OVERLOADSADDR = ${JSON.stringify(fqn2overloadsaddr, null, 2)}`,
  );

  console.log(`RESOLVE_ADDRESSES = ${Array.from(resolve_addresses)}`);
  var res1 = gdb_resolve(Array.from(resolve_addresses));
  for (let addr in res1) {
    addr2sym[addr] = res1[addr];
  }

  for (let fqn in fqn2overloadsaddr) {
    for (let addr of fqn2overloadsaddr[fqn]) {
      try {
        var lib = addr2sym[addr].library;
      } catch (error) {
        console.log(`Error: ${error}`);
        fqn2failed[fqn] = "OVERLOAD_RESOLUTION";
        continue;
      }
      b = {
        jsname: fqn,
        cfunc: addr2sym[addr].cfunc,
        library: lib,
      };
      final_result["bridges"].push(b);
      if (!final_result["jump_libs"].includes(lib))
        final_result["jump_libs"].push(lib);
    }
  }

  for (let fqn in fqn2cbaddr) {
    addr = fqn2cbaddr[fqn];
    cb = addr2sym[addr].cfunc;
    fqn2cb[fqn] = cb;
  }

  // console.log(`FQN2CB = ${JSON.stringify(fqn2cb, null, 2)}`)
  // console.log(`FQN2OVERLOADS = ${JSON.stringify(fqn2overloads, null, 2)}`)
  // console.log('FQN2OBJ: (next line)')
  // console.log(fqn2obj)

  for (let fqn in fqn2cbaddr) {
    extract_cfunc(fqn);
  }

  console.log(`FQN2CBADDR2 = ${JSON.stringify(fqn2cbaddr2, null, 2)}`);

  // sleepSync(1000)

  resolve_addresses.clear();
  for (let fqn in fqn2cbaddr2) {
    addr = fqn2cbaddr2[fqn];
    resolve_addresses.add(addr);
  }
  var res2 = gdb_resolve(Array.from(resolve_addresses));
  console.log("RES2:");
  console.log(res2);
  for (let addr in res2) {
    addr_dec = String(Number(addr));
    addr2sym[addr_dec] = res2[addr];
  }

  console.log(addr2sym);

  for (let fqn in fqn2cbaddr2) {
    addr = fqn2cbaddr2[fqn];
    try {
      cb = addr2sym[addr].cfunc;
    } catch (error) {
      console.log(`fqn = ${fqn}, fqn2cbaddr2 resolve ${error}`);
    }
    fqn2cb2[fqn] = cb;
  }

  for (let fqn in fqn2cb2) {
    extract_cfunc_2(fqn);
  }

  console.log("FQN2CFUNCADDR");
  console.log(fqn2cfuncaddr);
  var addr_dec;
  resolve_addresses.clear();
  for (let fqn in fqn2cfuncaddr) {
    addr_dec = String(Number(fqn2cfuncaddr[fqn]));
    fqn2cfuncaddr[fqn] = addr_dec;
    resolve_addresses.add(addr_dec);
  }
  console.log("RESOLVE_ADDRESSES FOR FINAL CFUNCS");
  console.log(resolve_addresses);
  var res3 = gdb_resolve(Array.from(resolve_addresses));
  for (let addr in res3) {
    addr_dec = String(Number(addr));
    addr2sym[addr_dec] = res3[addr];
  }

  console.log("ADDR2SYM");
  console.log(addr2sym);

  console.log("FQN2CFUNCADDR");
  console.log(fqn2cfuncaddr);

  for (let fqn in fqn2cfuncaddr) {
    addr = fqn2cfuncaddr[fqn];
    try {
      lib = addr2sym[addr].library;
    } catch (error) {
      console.log(`Key = ${addr} not found`);
      fqn2failed[fqn] = "CFUNC_ADDRESS_RESOLUTION";
      continue;
    }
    b = {
      jsname: fqn,
      cfunc: demangle_cpp(addr2sym[addr].cfunc),
      library: lib,
    };
    final_result["bridges"].push(b);
    if (!final_result["jump_libs"].includes(lib))
      final_result["jump_libs"].push(lib);
  }
}

function get_mod_fqn(fullPath, packageRoot) {
  const packageName = path.basename(packageRoot);
  const relativePath = path.relative(packageRoot, fullPath);
  const noExt = relativePath.replace(/\.[^/.]+$/, ""); // strip extension
  // const dottedPath = noExt.split(path.sep).join('.');
  // return `${packageName}.${dottedPath}`;
  return `${packageName}/${noExt}`;
  // const relativePath = path.relative(packageRoot, fullPath);
  // const noExt = relativePath.replace(/\.node$/, ''); // remove .node
}

function check_bingo(addr, jsname) {
  var jres;
  var lib;
  var cb;
  var overloads;
  var b;
  var cfunc;
  // console.log(`dir(par) = ${dir(par)}`)
  var res = mod.getcb(parseInt(addr));
  if (res == "NONE") {
    // fqn2failed[jsname] = 'FAILED_GETCB'
    return;
  } else {
    // console.log('IN HERE')
    foreign_callable_objects += 1;
    jres = JSON.parse(res);
    cb = jres["callback"];
    overloads = jres["overloads"];
    if (overloads.length > 0) {
      // console.log('IN HERE')
      cfunc = jsname.split(".").pop();
      b = {
        jsname: jsname,
        cfunc: cfunc,
        library: null,
        DENO_FFI: true,
      };

      console.log(b);
      final_result["bridges"].push(b);
      // if (!(final_result['jump_libs'].includes(lib)))
      //     final_result['jump_libs'].push(lib)
      return;
    }
    console.log(`FQN = ${jsname}`);
    console.log(`cb = ${cb}`);
    if (cb == "0") {
      fqn2failed[jsname] = "NULL_CB";
      return;
    }
    cbs_set.add(cb);
    // console.log('CBS = (next line)')
    // console.log(cbs_set)
    // fqn2cbaddr[jsname] = cb
    // fqn2overloadsaddr[jsname] = overloads
    // fqn2obj[jsname] = addr
  }
}

async function foo() {
  console.log("started!");
  var start = Date.now();
  const args = parse_args();
  self.loaded_libs_before = get_loaded_libs();
  var output_file = args.output;
  if (args.profileHeap) {
    analyze_heap_before();
  }

  console.log(`Package root = ${args.root}`);
  console.log(`Output file = ${args.output}`);

  var so_files = locate_js_modules(args.root);

  console.log(`FILES = ${so_files}`);
  for (const so_file of so_files) {
    transform(so_file);
  }

  for (const so_file of so_files) {
    try {
      await analyze_single(so_file, args.root);
      self.final_result["modules"].push(so_file);
    } catch (error) {
      console.log(`ERROR WHILE INSPECTING ${so_file}: ${error}`);
    }
  }

  self.loaded_libs_after = get_loaded_libs();
  const libs_diff = loaded_libs_after.filter(
    (v) => !self.loaded_libs_before.includes(v),
  );
  populate_sym2lib();
  // console.log(JSON.stringify(self.sym2lib, null, 2))
  // console.log(`libs_diff = ${libs_diff}`)

  if (args.profileHeap) {
    analyze_heap();
  }
  for (var b of self.final_result["bridges"]) {
    if (b["DENO_FFI"] === true) {
      var cfunc = b["cfunc"];

      if (cfunc in sym2lib) {
        var lib = sym2lib[cfunc];
        b["library"] = lib;
      } else {
        console.error("symbol not found:", cfunc);
        lib = null;
      }

      if (!final_result["jump_libs"].includes(lib)) {
        final_result["jump_libs"].push(lib);
      }
    }
  }

  var end = Date.now();

  var duration_sec = Math.round((end - start) / 1000);
  self.final_result["duration_sec"] = duration_sec;
  self.final_result["objects_examined"] = objects_examined;
  self.final_result["callable_objects"] = callable_objects;
  self.final_result["foreign_callable_objects"] = foreign_callable_objects;
  self.final_result["count"] = self.final_result["bridges"].length;

  if (output_file !== undefined) {
    if (!path.isAbsolute(output_file)) {
      output_file = path.join(Deno.env.get("PWD"), output_file);
    }
    Deno.writeTextFileSync(
      output_file,
      JSON.stringify(self.final_result, null, 2),
    );
    console.log(`Wrote bridges to ${output_file}`);
  } else {
    console.log(JSON.stringify(self.final_result, null, 2));
  }
}

await foo();
