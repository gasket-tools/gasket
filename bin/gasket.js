#! /usr/bin/env node

import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { execSync, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

import v8 from "v8"

import * as utils from 'gasket-tools/utils';
import parseArgs from 'gasket-tools/args';
import dir from 'gasket-tools/ffdir';
import * as rawmod from 'gasket-tools';
globalThis.mod = rawmod.addon

import transform, {revertChanges} from 'gasket-tools/transformer';


const require = createRequire(import.meta.url);


class NativeState {
  constructor() {
    this.reset();
  }
  reset() {
    this.fqn2addr = {};
    this.fqn2overloadsaddr = {};
    this.fqn2overloads = {};
    this.fqn2cbaddr = {};
    this.fqn2cfuncaddr = {};
    this.fqn2cbaddr2 = {};
    this.fqn2cb = {};
    this.fqn2cb2 = {};
    this.fqn2type = {};
    this.addr2sym = {};
    this.fqn2failed = {};
    this.cbs_set = new Set();
    this.cbs = [];
  }
}


class WasmState {
  constructor() {
    this.reset();
    this.wasm_file_idx2jsnames = {}
    this.wasm_file_idx2cfunc = {}
    this.wasm_file_jsnames = {}
  }

  reset() {
    this.fqn2mod = {}
    this.fqn2obj = {}
    this.fqn2idx = {}
    this.fqn2wasminstance = {}
    this.wasminstance2jsnames = {}
    this.fqn2wasmfunc = {};
    this.fqn2wasmfile = {};
    this.fqn2failed = {};
  }
}

const BridgeType = Object.freeze({
  NATIVE: 'js-to-native',
  WASM: 'js-to-wasm'
})


class OLAAnalysis {
  constructor(args) {
    this.args = args;
    this.stats = {
      objects_examined: 0,
      callable_objects: 0,
      foreign_callable_objects: 0,
      duration_sec: 0,
      count: 0,
      modules: [],
      jump_libs: [],
      bridges: [],
    };
    this.state = new NativeState();
    this.wasm_state = new WasmState();
    this.seenObjects = new Set();
    this.currentFile = "none";
    this.heap_jsfuncs = []
    this.heap_jsfuncs_after = []
    this.heap_jsfuncs_after_addresses = []

    this.heap_ids_before = []
    this.heap_ids_after = []
    this.heap_AccessorPair_addresses = [];
  }

  prepare() {
    if (this.args.forceExport && !this.args.nativeOnly) {
      const jsFiles = utils.locateJSModules(this.args.root);
      for (const jsfile of jsFiles) {
        transform(jsfile);
      }
    }
    if (this.args.profileHeap) {
      this.analyzeHeapBefore();
    }

    if (!this.args.nativeOnly && !this.args.internal) {
      const wasmModules = utils.locateWasmModules(this.args.root);
      for (const mod of wasmModules) {
        this.analyze_wasm(mod);
      }
    }
  }

  tearDown() {
    if (this.args.forceExport && !this.args.nativeOnly) {
      const jsFiles = utils.locateJSModules(this.args.root);
      for (const jsfile of jsFiles) {
        revertChanges(jsfile);
      }
    }
  }

  addBridge(fqn, fn, lib, type) {
    const cb = utils.demangleCpp(fn)
    console.log(`Adding bridge ${fqn} to ${cb}(${lib})`)
    const b = {
      'type': type,
      'jsname': fqn,
      'cfunc': cb,
      'library': lib
    };
    this.stats['bridges'].push(b)
    if (!(this.stats['jump_libs'].includes(lib))) {
      this.stats['jump_libs'].push(lib)
    }
  }

  visitObjectNative(addr, jsname) {
    // This function checks if the given object contains a bridge to a native
    // function.
    const res = mod.getcb(parseInt(addr))
    if (res == 'NONE') {
      return;
    } else {
      this.stats.foreign_callable_objects += 1
      const jres = JSON.parse(res)
      const cb = jres['callback']
      const overloads = jres['overloads']
      console.log(`FQN = ${jsname}`)
      console.log(`cb = ${cb}`)
      if (cb == '0') {
        this.state.fqn2failed[jsname] = 'NULL_CB'
        return
      }
      this.state.cbs_set.add(cb)
      this.state.fqn2cbaddr[jsname] = cb
      this.state.fqn2overloadsaddr[jsname] = overloads
      this.state.fqn2addr[jsname] = addr
    }
  }

  visitObjectWasm(idxstr, jsname, jobRes) {
    const idx = parseInt(idxstr);
	this.wasm_state.fqn2idx[jsname] = idx;
    const wasm_instance_address = parseInt(extract_wasm_instance_address(
        jobRes));
    this.wasm_state.fqn2wasminstance[jsname] = wasm_instance_address;
    let raw = mod.job_addr(wasm_instance_address);
    const exports_addr = parseInt(extract_exports_addr(raw))
    raw = mod.job_addr(exports_addr)
    const jsnames = extract_jsnames_from_export(raw)
    this.wasm_state.wasminstance2jsnames[wasm_instance_address] = jsnames
  }

  visitObject(addr, jsname) {
    let raw = mod.job_addr(parseInt(addr))
    // First check if the object contains an index to a Wasm function.
    const idxstr = extract_wasm_idx(raw)
    if (idxstr === null) {
      // If not, fallback to visitObjectNative
      return this.visitObjectNative(addr, jsname);
    } else {
      return this.visitObjectWasm(idxstr, jsname, raw);
    }
  }

  extract_fcb_invoke(fqn) {
    const addr = this.state.fqn2addr[fqn];
    const res = mod.extract_fcb_invoke(parseInt(addr))
    if (res == 'NONE') {
      this.state.fqn2failed[fqn] = 'EXTRACT_FCB_INOKE'
    } else { /* res = address of cb2 */
      this.state.fqn2type[fqn] = 'fcb';
      this.state.fqn2cbaddr2[fqn] = res;
    }
  }

  extract_napi(fqn) {
    console.log(`Extract napi called: ${fqn}`)
    const addr = this.state.fqn2addr[fqn];
    const res = mod.extract_napi(parseInt(addr));
    if (res == 'NONE') {
      this.state.fqn2failed[fqn] = 'EXTRACT_NAPI';
    } else {
      this.state.fqn2type[fqn] = 'napi';
      this.state.fqn2cfuncaddr[fqn] = res;
    }
  }

  extract_nan(fqn) {
    const addr = this.state.fqn2addr[fqn];
    const res = mod.extract_nan(parseInt(addr));
    if (res == 'NONE') {
      this.state.fqn2failed[fqn] = 'EXTRACT_NAN';
    } else {
      this.state.fqn2type[fqn] = 'nan';
      this.state.fqn2cfuncaddr[fqn] = res;
    }
  }

  extract_cfunc(fqn) {
    const cb = this.state.fqn2cb[fqn];
    if (cb.includes('v8impl') && cb.includes('FunctionCallbackWrapper6Invoke')) {
      this.extract_fcb_invoke(fqn);
    } else if (cb.includes('Nan') && cb.includes('imp')) {
      this.extract_nan(fqn);
    } else {
      this.state.fqn2cfuncaddr[fqn] = this.state.fqn2cbaddr[fqn]
    }
  }

  extract_cfunc_2(fqn) {
    const cb = this.state.fqn2cb2[fqn]

    // Napi::ObjectWrap::ConstructorCallbackWrapper
    if (cb.includes('Napi') && cb.includes('ObjectWrap')
        && cb.includes('ConstructorCallbackWrapper')) {
      const dem = utils.demangleCpp(cb)
      const cls = dem.match(/<([^>]*)>/)[1];
      let fn = cls + "::" + cls.split("::").pop();
      console.log(`fn = ${fn}`)
      let lib = this.state.addr2sym[this.state.fqn2cbaddr2[fqn]].library;
      this.addBridge(fqn, fn, lib, BridgeType.NATIVE);
    } else if (
      (
        cb.includes('Napi') && cb.includes('CallbackData') && cb.includes('Wrapper')
      )
      || ((cb.includes('Napi') && cb.includes('InstanceWrap')))
      || ((cb.includes('Napi') && cb.includes('ObjectWrap')))
    ) {
      this.extract_napi(fqn);
    } else if (cb.includes('neon') && cb.includes('sys')) {
      const addr = this.state.fqn2addr[fqn]
      const name = mod.extract_neon(parseInt(addr))
      let fn;
      if (name !== 'NONE') {
        const match = name.match(/#([^>]+)>/);
        if (match) {
          fn = match[1];
        } else { /* failed regex */
          fqn2failed[fqn] = 'NEON_FAIL'
          return;
        }
        this.addBridge(fqn, fn, this.currentFile, BridgeType.NATIVE);
      }
    }
    // napi-rs
    else if (cb.includes('_napi_internal_register')) {
      const lib = this.state.addr2sym[this.state.fqn2cbaddr2[fqn]].library;
      this.addBridge(fqn, cb, lib, BridgeType.NATIVE);
    }

    // node-bindgen
    else if (cb.includes('napi_')) {
      const lib = this.state.addr2sym[this.state.fqn2cbaddr2[fqn]].library;
      this.addBridge(fqn, cb, lib, BridgeType.NATIVE);
    } else {
      this.state.fqn2cfuncaddr[fqn] = this.state.fqn2cbaddr2[fqn]
    }
  }

  introspect(obj, jsname) {
    const pending = [[obj, jsname]]
    this.seenObjects = new Set()

    // XXX: BFS. Use queue: insert using .push(),
    //      get head using .shift
    while (pending.length > 0) {
      [obj, jsname] = pending.shift()

      if (!(obj instanceof(Object)) && (typeof obj != "object")) {
          continue
      }
      if (obj === null) {
        continue;
      }
      const desc_names = Object.getOwnPropertyNames(obj)
      for (const name of Object.getOwnPropertyNames(obj)) {
        const desc = Object.getOwnPropertyDescriptor(obj, name);
        const descname = jsname + '.' + name;
        const getter = desc['get'];
        const setter = desc['set'];
        if (typeof(getter) == 'function') {
          this.visitObject(mod.jid(getter), descname + '.' + 'GET');
        }
        if (typeof(setter) == 'function') {
          this.visitObject(mod.jid(setter), descname + '.' + 'SET');
        }
      }
      if (typeof(obj) == 'function') {
        this.visitObject(mod.jid(obj), jsname);
      }

      for (const k of dir(obj)) {
        let v;
        try {
          v = obj[k]
        } catch(error) {
          continue;
        }
        this.stats.objects_examined += 1

        if (typeof(obj) == 'function') {
          this.stats.callable_objects += 1;
        }
        const ident = mod.jid(v)
        const jobstr = mod.job_addr(parseInt(ident))
		    if (this.seenObjects.has(ident) && !((jobstr ?? '').includes('wasm'))) {
          // skip object; already seen.
          continue;
        } else {
          this.seenObjects.add(ident)
        }
        pending.push([v, jsname + '.' + k]);
      }
      this.seenObjects.add(mod.jid(obj));
    }
  }

  analyze_wasm(wasm_file) {
    const {idx2cfunc, idx2jsnames, allJsNames} = parseWasmFuncExports(wasm_file);
    this.wasm_state.wasm_file_idx2cfunc[wasm_file] = idx2cfunc
    this.wasm_state.wasm_file_idx2jsnames[wasm_file] = idx2jsnames
    this.wasm_state.wasm_file_jsnames[wasm_file] = allJsNames
  }

  resolve_wasm() {
    const fileToNameSet = {};
    for (const [file, names] of Object.entries(this.wasm_state.wasm_file_jsnames)) {
      fileToNameSet[file] = new Set(names);
    }

    const unresolved = [];
    const ambiguous = [];

    for (const fqn of Object.keys(this.wasm_state.fqn2idx)) {
      const idx = this.wasm_state.fqn2idx[fqn];
      const inst = this.wasm_state.fqn2wasminstance[fqn];
      const jsnames = this.wasm_state.wasminstance2jsnames[inst] || [];

      // find files whose name set is a superset of jsnames
      const candidates = [];
      for (const [file, nameSet] of Object.entries(fileToNameSet)) {
        const ok = jsnames.every(n => nameSet.has(n));
        if (ok) candidates.push(file);
      }

      if (candidates.length === 0) {
        unresolved.push({ fqn, idx, jsnames });
        continue;
      }

      // choose file
      let chosen = null;
      const exact = candidates.filter(
        f => fileToNameSet[f].size === jsnames.length);
      if (exact.length === 1) {
        chosen = exact[0];
      } else if (candidates.length === 1) {
        chosen = candidates[0];
      } else {
        ambiguous.push({ fqn, idx, jsnames, candidates });
        continue;
      }
      const idx2cfunc = this.wasm_state.wasm_file_idx2cfunc[chosen] || {};
      const cfunc = idx2cfunc[idx];
      if (cfunc !== undefined) {
        this.wasm_state.fqn2wasmfunc[fqn] = cfunc;
        this.wasm_state.fqn2wasmfile[fqn] = chosen;
      } else {
        unresolved.push({ fqn, idx, jsnames, file: chosen, reason: "idx not in file" });
      }
    }
    return {
      fqn2wasmfunc: this.wasm_state.fqn2wasmfunc,
      fqn2wasmfile: this.wasm_state.fqn2wasmfile,
      unresolved: unresolved,
      ambiguous: ambiguous
    };
  }

  resolveWasmAddresses() {
    const res = this.resolve_wasm();
    for (const fqn of Object.keys(res.fqn2wasmfunc)) {
      const lib = res.fqn2wasmfile[fqn];
      this.addBridge(fqn, res.fqn2wasmfile[fqn], lib, BridgeType.WASM);
    }
    this.stats['ambiguous'] = res.ambiguous;
    this.stats['unresolved'] = res.unresolved;
  }

  resolveNativeAddresses() {
    const cbs = Array.from(this.state.cbs_set);
    const resolve_addresses = new Set(cbs)

    for (const key in this.state.fqn2overloadsaddr) {
      this.state.fqn2overloadsaddr[key].forEach(
        item => resolve_addresses.add(item));
    }

    if (resolve_addresses.size > 0) {
      const res1 = utils.resolveGDB(Array.from(resolve_addresses))
      for (let addr in res1) {
        this.state.addr2sym[addr] = res1[addr];
      }
    }

    for (const fqn in this.state.fqn2overloadsaddr) {
      for (const addr of this.state.fqn2overloadsaddr[fqn]) {
        let lib;
        try {
          lib = this.state.addr2sym[addr].library;
        } catch (error){
          console.log(`Error: ${error}`)
          this.state.fqn2failed[fqn] = 'OVERLOAD_RESOLUTION';
          continue;
        }
        const fn = this.state.addr2sym[addr].cfunc;
        this.addBridge(fqn, fn, lib, BridgeType.NATIVE);
      }
    }

    for (const fqn in this.state.fqn2cbaddr) {
      const addr = this.state.fqn2cbaddr[fqn];
      const cb = this.state.addr2sym[addr].cfunc;
      this.state.fqn2cb[fqn] = cb;
    }

    for (const fqn in this.state.fqn2cbaddr) {
      this.extract_cfunc(fqn);
    }

    resolve_addresses.clear()
    for (const fqn in this.state.fqn2cbaddr2) {
      const addr = this.state.fqn2cbaddr2[fqn];
      resolve_addresses.add(addr);
    }


    if (resolve_addresses.size > 0) {
      const res2 = utils.resolveGDB(Array.from(resolve_addresses))
      for (const addr in res2) {
        const addr_dec = String(Number(addr));
        this.state.addr2sym[addr_dec] = res2[addr];
      }
    }

    for (const fqn in this.state.fqn2cbaddr2) {
      const addr = this.state.fqn2cbaddr2[fqn]
      try {
        const cb = this.state.addr2sym[addr].cfunc
        this.state.fqn2cb2[fqn] = cb;
      } catch (error) {
        console.log(`fqn = ${fqn}, fqn2cbaddr2 resolve ${error}`)
      }
    }

    for (const fqn in this.state.fqn2cb2) {
      this.extract_cfunc_2(fqn);
    }

    resolve_addresses.clear()
    for (const fqn in this.state.fqn2cfuncaddr) {
      const addr_dec = String(Number(this.state.fqn2cfuncaddr[fqn]))
      this.state.fqn2cfuncaddr[fqn] = addr_dec
      resolve_addresses.add(addr_dec)
    }

    if (resolve_addresses.size > 0) {
      const res3 = utils.resolveGDB(Array.from(resolve_addresses))
      for (let addr in res3) {
        const addr_dec = String(Number(addr))
        this.state.addr2sym[addr_dec] = res3[addr]
      }
    }

    for (const fqn in this.state.fqn2cfuncaddr) {
      const addr = this.state.fqn2cfuncaddr[fqn]
      let lib;
      try {
        lib = this.state.addr2sym[addr].library;
      } catch (error) {
        console.log(`Key = ${addr} not found`);
        this.state.fqn2failed[fqn] = 'CFUNC_ADDRESS_RESOLUTION';
        continue;
      }
      const fn = this.state.addr2sym[addr].cfunc;
      this.addBridge(fqn, fn, lib, BridgeType.NATIVE);
    }
  }

  resolveAddresses() {
    if (!this.args.wasmOnly) {
      this.resolveNativeAddresses();
    }
    if (!this.args.nativeOnly) {
      this.resolveWasmAddresses();
    }
  }

  loadModule(module) {
    try {
      if (this.args.internal) {
        return process.binding(module);
      } else {
        return require(module);
      }
    } catch (error) {
      console.log(error);
      return undefined;
    }
  }

  analyzeSingle(moduleFile, pkgRoot) {
    this.state.reset();
    this.wasm_state.reset();
    this.currentFile = moduleFile;
    const obj = this.loadModule(moduleFile);
    const jsname = utils.getModuleFQN(moduleFile, pkgRoot);
    console.log(`${moduleFile}: jsname = ${jsname}`);
    this.introspect(obj, jsname);
    this.resolveAddresses();
  }

  getModules() {
    if (this.args.module) {
      return [this.args.module];
    }
    const modules = [];
    if (!this.args.wasmOnly) {
      modules.push(...utils.locateNativeModules(this.args.root));
    }
    if (!this.args.nativeOnly) {
      modules.push(...utils.locateJSModules(this.args.root));
    }
    return modules;
  }

  analyzeModules() {
    const modules = this.getModules();
    console.log(`List of analyzed modules :\n${modules.join('\n')}`);
    for (const mod of modules) {
      this.analyzeSingle(mod, this.args.root);
      this.stats.modules.push(mod);
    }
    if (this.args.profileHeap) {
      console.log('In this.args.AnalyzeHeap')
      this.state.reset();
      this.wasm_state.reset();
      this.analyzeHeapAfter();
      this.resolveAddresses();
    }

  }

  isNewHeapAddr(addr) {
    return (!this.heap_jsfuncs_after_addresses.includes(addr));
  }

  extractWasmFunctions(input) {
    const regex = /#([^\s:]+):\s*(0x[0-9a-fA-F]+)\s*<JSFunction\s+js-to-wasm\b[^>]*/g;
    let match;
    let addr;
    let ob;

    while ((match = regex.exec(input)) !== null) {
      this.stats.callable_objects += 1;
      this.stats.objects_examined += 1;

      addr = parseInt(match[2]).toString()
      ob = {address: addr, name: match[1]}

      if (this.isNewHeapAddr(addr)) {
        this.heap_jsfuncs_after.push(ob);
        this.heap_jsfuncs_after_addresses.push(addr);
      }
    }
  }

  extractJSFunctions(input) {
    const regexAddrFirst = /(0x[0-9a-fA-F]+)\s*<JSFunction\s+([^\s<(]+)/g;
    const regexNameFirst = /([a-zA-Z0-9_]+):\s*(0x[0-9a-fA-F]+)\s*<JSFunction/g;

    let match;
    let addr;
    let ob;

    // Address-first pattern
    while ((match = regexAddrFirst.exec(input)) !== null) {
      this.stats.callable_objects += 1;
      this.stats.objects_examined += 1;

      addr = parseInt(match[1]).toString();
      ob = { address: addr, name: match[2] };

      if (this.isNewHeapAddr(addr)) {
        this.heap_jsfuncs_after.push(ob);
        this.heap_jsfuncs_after_addresses.push(addr);
      }
    }

    // Name-first pattern
    while ((match = regexNameFirst.exec(input)) !== null) {
      this.stats.callable_objects += 1;
      this.stats.objects_examined += 1;

      addr = parseInt(match[2]).toString();
      ob = { address: addr, name: match[1] };

      if (this.isNewHeapAddr(addr)) {
        this.heap_jsfuncs_after.push(ob);
        this.heap_jsfuncs_after_addresses.push(addr);
      }
    }
  }

  extractGetSetters(input) {
    const regex = /(\w+):\s*(0x[0-9a-f]+)\s*<AccessorPair>/g;
    let match;
    let addr;
    let ob;
    let m;
    let name;
    let fqn;
    let cfunc_addr;
    let getter_jsfunc;
    let setter_jsfunc;
    let getter_cbdata;
    let setter_cbdata;
    let haps = [];

    while ((match = regex.exec(input)) !== null) {
      this.stats.objects_examined += 1;
      addr = parseInt(match[2]).toString();
      ob = {address: addr, name: match[1]};
      if (!(this.heap_AccessorPair_addresses.includes(addr))) {
        haps.push(ob);
        this.heap_AccessorPair_addresses.push(addr);
       }
    }

    for (const hap of haps) {
      addr = hap.address;
      name = hap.name;
      m = extract_ap(addr);
      if (m.type == 'JSFunction') {
        getter_jsfunc = m['getter'].address;
        if (!this.seenObjects.has(getter_jsfunc) && (getter_jsfunc != null)) {
          this.visitObjectNative(addr, name + '.' + 'GET');
        }
        setter_jsfunc = m['setter'].address;
        if (!this.seenObjects.has(getter_jsfunc) && (setter_jsfunc != null)) {
            this.visitObjectNative(addr, name + '.' + 'SET');
        }
      }

      if (m.type == 'CallbackData') {
        getter_cbdata = m['getter'].address;
        if (getter_cbdata != null) {
              cfunc_addr = mod.extract_cfunc_getset(parseInt(getter_cbdata));
              fqn = name + '.' + 'GET';
              if (cfunc_addr != 'NONE') {
                  this.stats.foreign_callable_objects += 1;
                  this.state.fqn2cfuncaddr[fqn] = cfunc_addr;
              }
          }
          setter_cbdata = m['setter'].address
          if (setter_cbdata != null) {
              cfunc_addr = mod.extract_cfunc_getset(parseInt(setter_cbdata));
              fqn = name + '.' + 'SET';
              if (cfunc_addr != 'NONE') {
                  this.stats.foreign_callable_objects += 1;
                  this.state.fqn2cfuncaddr[fqn] = cfunc_addr;
              }
          }
      }
    }
  }

  analyzeHeapBefore() {
    const object_addresses = JSON.parse(mod.get_objects())
    for (const addr of object_addresses) {
	  this.stats.objects_examined += 1
      if (!(this.heap_ids_before.includes(addr))) {
        this.heap_ids_before.push(addr)
      }
    }
  }

  analyzeHeapAfter() {
    const object_addresses = JSON.parse(mod.get_objects())
    for (const addr of object_addresses) {
      if (!(this.heap_ids_before.includes(addr))
          && !(this.heap_ids_after.includes(addr))) {
        this.heap_ids_after.push(addr);
      }
    }
    console.log('after heap snapshot, object addresses = ')
    console.log(object_addresses)
    for (const addr of this.heap_ids_after) {
      const raw = mod.job_addr(addr);
	  if (!this.args.nativeOnly) {
		this.extractWasmFunctions(raw);
	  }
	  if (!this.args.wasmOnly) {
		this.extractJSFunctions(raw);
		this.extractGetSetters(raw)
	  }
    }
    console.log(`HEAP FUNCS AFTER: ${this.heap_jsfuncs_after.length}`)
    console.log(JSON.stringify(this.heap_jsfuncs_after, null, 2))
    //
    // XXX: Visit the JSFunctions found
    const heap_jsfuncs = this.heap_jsfuncs_after
    for (const func of heap_jsfuncs) {
      const addr = func.address
      const name = func.name
      console.log(`HEAP FUNC: ${addr} NAME=${name}`)
      if (!this.seenObjects.has(addr)) {
        this.visitObject(addr, name)
      }
    }
  }

  analyze() {
    const start = Date.now();
    console.log(`Package root = ${this.args.root}`);
    this.prepare();
    this.analyzeModules();
    this.tearDown();
    const end = Date.now();
    const duration_sec = (end - start) / 1000;
    this.stats.duration_sec = duration_sec;
    this.stats['count'] = this.stats['bridges'].length;
  }

}


function parseWasmFuncExports(filePath) {
  const output = execSync(`wasm-objdump -xj Export ${filePath}`, {
    encoding: "utf8",
  });

    // 2) regex parse
  const re = /^\s*-\s*func\[(\d+)\]\s*<([^>]*)>\s*->\s*"([^"]*)"\s*$/;
  const idx2cfunc = {};
  const idx2jsnames = {};
	const allJsNames = [];

  for (const line of output.split(/\r?\n/)) {
    const m = re.exec(line);
    if (!m) continue;

    const index = Number(m[1]);
    const internalName = m[2];
    const exportName = m[3];

    if (!(index in idx2cfunc)) {
      idx2cfunc[index] = internalName;
    }
    (idx2jsnames[index] ??= []).push(exportName);
	  allJsNames.push(exportName);
  }
  return { idx2cfunc, idx2jsnames, allJsNames };
}


function extract_jsnames_from_export(text) {
  const out = [];
  const seen = new Set();
  const re = /#([^:\s]+)\s*:/; // captures the token after '#' up to ':' (name)

  for (const line of text.split(/\r?\n/)) {
    if (!line.includes("js-to-wasm")) continue;
    const m = re.exec(line);
    if (m) {
      const name = m[1];
      if (!seen.has(name)) {
        seen.add(name);
        out.push(name);
      }
    }
  }
  return out;
}


function extract_wasm_instance_address(text) {
  const re = /-\s*Wasm instance:\s*(0x[0-9a-fA-F]+)/;
  const m = re.exec(text);
  return m ? m[1] : null;
}


function extract_wasm_idx(text) {
  const re = /-\s*Wasm function index:\s*(\d+)/;
  const m = re.exec(text);
  return m ? parseInt(m[1], 10) : null;
}


function extract_exports_addr(text) {
  const re = /-\s*exports_object:\s*(0x[0-9a-fA-F]+)/;
  const m = re.exec(text);
  return m ? m[1] : null;
}

function extract_ap(addr) {
  let text;
  text = mod.job_addr(addr)
  const getterMatch =
    text.match(/getter:[\s\S]*?(?:___CALLBACK_DATA___(0x[0-9a-f]+)|\s*(0x[0-9a-f]+)\s*<JSFunction)/i);
  const setterMatch =
    text.match(/setter:[\s\S]*?(?:___CALLBACK_DATA___(0x[0-9a-f]+)|\s*(0x[0-9a-f]+)\s*<JSFunction)/i);

  const getter =
    getterMatch && (getterMatch[1] || getterMatch[2])
      ? {
          address: getterMatch[1] || getterMatch[2],
          type: getterMatch[1] ? "CallbackData" : "JSFunction",
        }
      : { address: null, type: null };

  const setter =
    setterMatch && (setterMatch[1] || setterMatch[2])
      ? {
          address: setterMatch[1] || setterMatch[2],
          type: setterMatch[1] ? "CallbackData" : "JSFunction",
        }
      : { address: null, type: null };

  // Attach summary type for the overall pair
  const type =
    getter.type && setter.type
      ? getter.type === setter.type
        ? getter.type
        : "Mixed"
      : getter.type || setter.type || null;

  return { getter, setter, type };
}


function main() {
  const args = parseArgs();
  const analysis = new OLAAnalysis(args);
  analysis.analyze();
  utils.storeBridges(args.output, analysis.stats);
}

main();
