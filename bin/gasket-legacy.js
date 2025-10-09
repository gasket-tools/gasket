#! /usr/bin/env node

const yargs = require('yargs');
const fs = require('fs');
const path = require('path');
const os = require('os');
const v8 = require('v8')
const { execSync, spawnSync } = require('child_process');
const { randomUUID } = require('crypto');

const {SimplePropertyRetriever} = require('gasket-tools/ffdir');

if (process.env.GASKET_ROOT) {
  RESOLVE_SCRIPT_PATH = path.join(process.env.GASKET_ROOT, 'scripts/resolve_syms.py')
} else {
  RESOLVE_SCRIPT_PATH = 'resolve-syms'
}

objects_examined = 0
callable_objects = 0
foreign_callable_objects = 0

cur_file = 'none'
use_heap = false

fqn2failed = {}
fqn2addr = {}
fqn2overloadsaddr = {}
fqn2overloads = {}
fqn2cbaddr = {}
fqn2cbaddr2 = {}
fqn2cb = {}
fqn2cb2 = {}
fqn2cfunc = {}
fqn2cfuncaddr = {}

fqn2type = {}

addr2sym = {}

cbs_set = new Set()
cbs = []

seen = new Set()
cfuncs_in_bridges = new Set()

heap_jsfuncs = []
heap_jsfuncs_before = []
heap_jsfuncs_before_addresses = []
heap_jsfuncs_after = []
heap_jsfuncs_after_addresses = []

heap_ids_before = []
heap_ids_after = []

final_result = {
    'objects_examined': 0,
    'callable_objects': 0,
    'foreign_callable_objects': 0,
    'duration_sec': 0,
    'count': 0,
    'modules': [],
    'jump_libs': [],
    'bridges': [],
}

function sleepSync(seconds) {
  const end = Date.now() + seconds * 1000;
  while (Date.now() < end);
}

function parse_args() {
    return yargs(process.argv.slice(2))
      .option('root', {
        alias: 'r',
        type: 'string',
        description: 'Package root',
        demandOption: true
      })
      .option('output', {
        alias: 'o',
        type: 'string',
        description: 'output file',
      })
      .option("heap_profiler", {
        alias: 'p',
        type: "boolean",
        describe: "Enable verbose mode",
        default: false
      })
      .help()
      .argv;
}

/*
 * Deduplicate file paths by basename,
 * prefer real files that do not contain 'build' or 'tmp'.
 */
function deduplicate_paths(paths) {
    const grouped = new Map(); // basename → list of paths

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
        p => !p.includes('darwin') && !p.includes('build') && !p.includes('tmp') && fs.existsSync(p)
      );

      // If not found, fallback to any existing file
      const fallback = pathList.find(p => fs.existsSync(p));

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
      const out = execSync(cmd, { encoding: 'utf-8', shell: true });
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

    pid = process.pid

	fs.writeFileSync(addr_file, JSON.stringify(addresses, null, 2));

	// var cmd = `bash -c 'python3 ${RESOLVE_SCRIPT_PATH} -p ${pid} -i ${addr_file} -o ${res_file}'`
    args = [RESOLVE_SCRIPT_PATH,
            '-p', String(pid),
            '-i', addr_file,
            '-o', res_file]
	// console.log(`CMD = python3 ${args}`)

	var result = spawnSync('python3', args, { encoding: 'utf-8' });
	const out = result.stdout
	console.log('OUT:')
	console.log(out)
	const err = result.stderr
	console.log('ERR:')
	console.log(err)

	const raw = fs.readFileSync(res_file, 'utf-8');
	result = JSON.parse(raw);
	// console.log('GDB RESULT:')
	// console.log(result)

	return result
}

function extract_fcb_invoke(fqn) {
    addr = fqn2addr[fqn]
	res = v8.extract_fcb_invoke(addr)
    if (res == 'NONE') {
        fqn2failed[fqn] = 'EXTRACT_FCB_INOKE'
    } else { /* res = address of cb2 */
        fqn2type[fqn] = 'fcb'
        fqn2cbaddr2[fqn] = res
	}
}

function extract_napi(fqn) {
    console.log(`Extract napi called: ${fqn}`)
    addr = fqn2addr[fqn]
	res = v8.extract_napi(addr)
    if (res == 'NONE') {
        fqn2failed[fqn] = 'EXTRACT_NAPI'
    } else {
        fqn2type[fqn] = 'napi'
        fqn2cfuncaddr[fqn] = res
	}
}

function extract_nan(fqn) {
    addr = fqn2addr[fqn]
	res = v8.extract_nan(addr)
    if (res == 'NONE') {
        fqn2failed[fqn] = 'EXTRACT_NAN'
    } else {
        fqn2type[fqn] = 'nan'
        fqn2cfuncaddr[fqn] = res
	}
}

function extract_cfunc(fqn) {
	cb = fqn2cb[fqn]

	if (cb.includes('v8impl')
            && cb.includes('FunctionCallbackWrapper6Invoke')) {
		extract_fcb_invoke(fqn)
	}
    else if (cb.includes('Nan') && cb.includes('imp')) {
        extract_nan(fqn)
    }
    else {
        fqn2cfuncaddr[fqn] = fqn2cbaddr[fqn]
    }
}

function extract_cfunc_2(fqn) {
	cb = fqn2cb2[fqn]

    // Napi::ObjectWrap::ConstructorCallbackWrapper
    if (cb.includes('Napi') && cb.includes('ObjectWrap') && cb.includes('ConstructorCallbackWrapper')) {
        var dem = demangle_cpp(cb)
        var cls = dem.match(/<([^>]*)>/)[1];
        var fn = cls + "::" + cls.split("::").pop();
        console.log(`fn = ${fn}`)
        // XXX: Spaghettoni
        var lib = addr2sym[fqn2cbaddr2[fqn]].library
        b = {
             'jsname': fqn,
             'cfunc': fn,
             'library': lib
             }

        console.log(b)
        final_result['bridges'].push(b)
        if (!(final_result['jump_libs'].includes(lib)))
            final_result['jump_libs'].push(lib)
    }

    // Generic Napi
	else if ((cb.includes('Napi') && cb.includes('CallbackData') && cb.includes('Wrapper'))
           || ((cb.includes('Napi') && cb.includes('InstanceWrap')))
           || ((cb.includes('Napi') && cb.includes('ObjectWrap')))) {

		extract_napi(fqn)
	}

    else if (cb.includes('neon') && cb.includes('sys')) {
		addr = fqn2addr[fqn]
        var name = v8.extract_neon(addr)
        if (name !== 'NONE') {
            const match = name.match(/#([^>]+)>/);
            if (match) {
                fn = match[1];
            } else { /* failed regex */
                fqn2failed[fqn] = 'NEON_FAIL'
                return;
            }
            lib = cur_file
            b = {
                 'jsname': fqn,
                 'cfunc': fn,
                 'library': lib
                 }
            final_result['bridges'].push(b)
            if (!(final_result['jump_libs'].includes(lib)))
                final_result['jump_libs'].push(lib)
        }
    }
    // napi-rs
    else if (cb.includes('_napi_internal_register')) {
        var fn = demangle_cpp(cb)
        console.log(`fn = ${fn}`)
        var lib = addr2sym[fqn2cbaddr2[fqn]].library
        b = {
             'jsname': fqn,
             'cfunc': fn,
             'library': lib
             }

        console.log(b)
        final_result['bridges'].push(b)
        if (!(final_result['jump_libs'].includes(lib)))
            final_result['jump_libs'].push(lib)
    }

    // node-bindgen
    else if (cb.includes('napi_')) {
        var fn = demangle_cpp(cb)
        console.log(`fn = ${fn}`)
        var lib = addr2sym[fqn2cbaddr2[fqn]].library
        b = {
             'jsname': fqn,
             'cfunc': fn,
             'library': lib
             }

        console.log(b)
        final_result['bridges'].push(b)
        if (!(final_result['jump_libs'].includes(lib)))
            final_result['jump_libs'].push(lib)
    }

    else {
        fqn2cfuncaddr[fqn] = fqn2cbaddr2[fqn]
    }
}

function clear_dicts() {
    fqn2addr = {}
    fqn2overloadsaddr = {}
    fqn2overloads = {}
    fqn2cbaddr = {}
    fqn2cbaddr2 = {}
    fqn2cb = {}
    fqn2cb2 = {}
    fqn2cfunc = {}
    fqn2cfuncaddr = {}

    fqn2type = {}

    addr2sym = {}

    cbs_set = new Set()
    cbs = []
}

function analyze_single(mod_file, pkg_root) {
	clear_dicts()
    cur_file = mod_file
    try {
        obj = require(mod_file)
    } catch(error) {
        console.log(error)
        return
    }
    jsname = get_mod_fqn(mod_file, pkg_root)
    console.log(`${mod_file}: jsname = ${jsname}`)
    recursive_inspect(obj, jsname)

	if (use_heap) {
		analyze_heap()
	}

	cbs = Array.from(cbs_set)
    // XXX: Initialize Set with CBS!
    var resolve_addresses = new Set(cbs)

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
        fqn2overloadsaddr[key].forEach(item => resolve_addresses.add(item))
    }

    // console.log(`FQN2OVERLOADSADDR = ${JSON.stringify(fqn2overloadsaddr, null, 2)}`)
	if (resolve_addresses.size > 0) {
		var res1 = gdb_resolve(Array.from(resolve_addresses))
		for (let addr in res1) {
		  addr2sym[addr] = res1[addr]
		}
	}

    for (let fqn in fqn2overloadsaddr) {
        for (let addr of fqn2overloadsaddr[fqn]) {
            try {
                lib = addr2sym[addr].library
            } catch (error){
                console.log(`Error: ${error}`)
                fqn2failed[fqn] = 'OVERLOAD_RESOLUTION'
                continue
            }
            b = {
                 'jsname': fqn,
                 'cfunc': addr2sym[addr].cfunc,
                 'library': lib
                 }
            final_result['bridges'].push(b)
            if (!(final_result['jump_libs'].includes(lib)))
                final_result['jump_libs'].push(lib)
        }
    }

    for (let fqn in fqn2cbaddr) {
        addr = fqn2cbaddr[fqn]
        cb = addr2sym[addr].cfunc
        fqn2cb[fqn] = cb
    }

    // console.log(`FQN2CB = ${JSON.stringify(fqn2cb, null, 2)}`)
    // console.log(`FQN2OVERLOADS = ${JSON.stringify(fqn2overloads, null, 2)}`)
    // console.log('fqn2addr: (next line)')
    // console.log(fqn2addr)

    for (let fqn in fqn2cbaddr) {
        extract_cfunc(fqn)
    }

    // console.log(`FQN2CBADDR2 = ${JSON.stringify(fqn2cbaddr2, null, 2)}`)

    // sleepSync(1000)

    resolve_addresses.clear()
    for (let fqn in fqn2cbaddr2) {
        addr = fqn2cbaddr2[fqn]
        resolve_addresses.add(addr)
    }


	if (resolve_addresses.size > 0) {
		var res2 = gdb_resolve(Array.from(resolve_addresses))
		// console.log('RES2:')
		// console.log(res2)
		for (let addr in res2) {
			addr_dec = String(Number(addr))
			addr2sym[addr_dec] = res2[addr]
		}
	}
    // console.log(addr2sym)

    for (let fqn in fqn2cbaddr2) {
        addr = fqn2cbaddr2[fqn]
        try {
            cb = addr2sym[addr].cfunc
        } catch (error) {
            // console.log(`fqn = ${fqn}, fqn2cbaddr2 resolve ${error}`)
        }
            fqn2cb2[fqn] = cb
    }

    for (let fqn in fqn2cb2) {
        extract_cfunc_2(fqn)
    }

    // console.log('FQN2CFUNCADDR')
    // console.log(fqn2cfuncaddr)

    resolve_addresses.clear()
    for (let fqn in fqn2cfuncaddr) {
        addr_dec = String(Number(fqn2cfuncaddr[fqn]))
        fqn2cfuncaddr[fqn] = addr_dec
        resolve_addresses.add(addr_dec)
    }
    // console.log('RESOLVE_ADDRESSES FOR FINAL CFUNCS')
    // console.log(resolve_addresses)

	if (resolve_addresses.size > 0) {
		var res3 = gdb_resolve(Array.from(resolve_addresses))
		for (let addr in res3) {
		  addr_dec = String(Number(addr))
		  addr2sym[addr_dec] = res3[addr]
		}
	}

	// console.log('ADDR2SYM')
    // console.log(addr2sym)

    // console.log('FQN2CFUNCADDR')
    // console.log(fqn2cfuncaddr)


    for (let fqn in fqn2cfuncaddr) {
        addr = fqn2cfuncaddr[fqn]
        try {
            lib = addr2sym[addr].library
        } catch (error) {
            console.log(`Key = ${addr} not found`)
            fqn2failed[fqn] = 'CFUNC_ADDRESS_RESOLUTION'
            continue
        }
        b = {
             'jsname': fqn,
             'cfunc': demangle_cpp(addr2sym[addr].cfunc),
             'library': lib
             }
        final_result['bridges'].push(b)
        if (!(final_result['jump_libs'].includes(lib)))
            final_result['jump_libs'].push(lib)
    }
}

function locate_so_modules(packagePath) {
    const soFiles = [];

    function walkDir(dir) {
        const files = fs.readdirSync(dir);
        files.forEach(file => {
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);

            if (stat.isDirectory()) {
                walkDir(fullPath); // Recursive call for directories
            } else if (file.endsWith('.node')) {
                soFiles.push(path.resolve(fullPath)); // Add .so files to the list
            }
        });
    }

    walkDir(packagePath);
    return soFiles;
}

function get_mod_fqn(fullPath, packageRoot) {
    const packageName = path.basename(packageRoot);
    const relativePath = path.relative(packageRoot, fullPath);
    const noExt = relativePath.replace(/\.[^/.]+$/, ''); // strip extension
    // const dottedPath = noExt.split(path.sep).join('.');
    // return `${packageName}.${dottedPath}`;
    return `${packageName}/${noExt}`;
    // const relativePath = path.relative(packageRoot, fullPath);
    // const noExt = relativePath.replace(/\.node$/, ''); // remove .node
}

function check_bingo(addr, jsname) {
    res = v8.getcb(addr)
    if (res == 'NONE') {
        // fqn2failed[jsname] = 'FAILED_GETCB'
        return
    } else {
        foreign_callable_objects += 1
        jres = JSON.parse(res)
        cb = jres['callback']
        overloads = jres['overloads']
        console.log(`FQN = ${jsname}`)
        console.log(`cb = ${cb}`)
        if (cb == '0') {
            fqn2failed[jsname] = 'NULL_CB'
            return
        }
        cbs_set.add(cb)
        // console.log('CBS = (next line)')
        // console.log(cbs_set)
        fqn2cbaddr[jsname] = cb
        fqn2overloadsaddr[jsname] = overloads
        fqn2addr[jsname] = addr
    }
}

function recursive_inspect(obj, jsname) {
    pending = [[obj, jsname]]
    // console.log(`pending = ${pending}`)
    seen = new Set()

    // XXX: BFS. Use queue: insert using .push(),
    //      get head using .shift
    while (pending.length > 0) {
        [obj, jsname] = pending.shift()
        // console.log(`jsname = ${jsname}`)

        if (!(obj instanceof(Object))) {
            continue
        }
        desc_names = Object.getOwnPropertyNames(obj)
        // console.log(`NAMES: ${desc_names}`)
        for (const name of Object.getOwnPropertyNames(obj)) {
          desc = Object.getOwnPropertyDescriptor(obj, name);
          descname = jsname + '.' + name
          // console.log(`DESC: ${descname}`)
          getter = desc['get']
          setter = desc['set']
          if (typeof(getter) == 'function') {
              check_bingo(v8.jid(getter), descname + '.' + 'GET')
          }
          if (typeof(setter) == 'function') {
              check_bingo(v8.jid(setter), descname + '.' + 'SET')
          }
        }
        if (typeof(obj) == 'function') {
            check_bingo(v8.jid(obj), jsname)
        }

        for (const k of dir(obj)) {
            // console.log(`getattr(${jsname}, ${k})`)
            try {
              v = obj[k]
            } catch(error) {
              // console.log(error)
              continue
            }
            objects_examined += 1
            if (typeof v == 'undefined' || !(v instanceof(Object))) {
                continue
            }

            if (typeof(obj) == 'function')
                callable_objects += 1

            ident = v8.jid(v)
            if (seen.has(ident)) {
                // console.log('ALREADY SEEN')
                continue
            } else {
                seen.add(ident)
            }

            pending.push([v, jsname + '.' + k])
        }
        seen.add(v8.jid(obj))
    }
}
function extractJSFunctions_before(input) {
    const regex = /(0x[0-9a-fA-F]+)\s*<JSFunction\s+([^\s<(]+)/g;
    let match;
	let addr;

    while ((match = regex.exec(input)) !== null) {
	    addr = parseInt(match[1]).toString()
        let ob = {address: addr, name: match[2]}
        if (!(heap_jsfuncs_before_addresses.includes(addr))){
            heap_jsfuncs_before.push(ob);
            heap_jsfuncs_before_addresses.push(addr);
        }
	    // if (!(seen.has(addr))) {
		//     heap_jsfuncs_before.push({ address: addr, name: match[2] });
		// 	// seen.add(addr)
		// }
    }
}

function extractJSFunctions(input) {
    const regex = /(0x[0-9a-fA-F]+)\s*<JSFunction\s+([^\s<(]+)/g;
    let match;
	let addr;

    while ((match = regex.exec(input)) !== null) {
	    addr = parseInt(match[1]).toString()
        let ob = {address: addr, name: match[2]}
        if (!(heap_jsfuncs_after_addresses.includes(addr))) {
            if (!(heap_jsfuncs_before_addresses.includes(addr))) {
                heap_jsfuncs_after.push(ob);
                heap_jsfuncs_after_addresses.push(addr);
            }
        }
    }
}

function analyze_heap_before() {
	var object_addresses = JSON.parse(v8.get_objects())
    var addr
    var raw
	for (const addr of object_addresses) {
		if (!(heap_ids_before.includes(addr))) {
			heap_ids_before.push(addr)
		}
	}
}

function analyze_heap() {
	var object_addresses = JSON.parse(v8.get_objects())
    var raw
	for (const addr of object_addresses) {
		if (!(heap_ids_before.includes(addr)) && !(heap_ids_after.includes(addr))) {
			heap_ids_after.push(addr)
		}
	}
	for (const addr of heap_ids_after) {
		raw = v8.job_addr(addr)
		extractJSFunctions(raw)
	}
    // console.log(`HEAP FUNCS BEFORE: ${heap_jsfuncs_before.length}`)
    // console.log(JSON.stringify(heap_jsfuncs_before, null, 2))
    console.log(`HEAP FUNCS AFTER: ${heap_jsfuncs_after.length}`)
    console.log(JSON.stringify(heap_jsfuncs_after, null, 2))

    heap_jsfuncs = heap_jsfuncs_after
	for (const func of heap_jsfuncs) {
		addr = func.address
		name = func.name
        console.log(`HEAP FUNC: ${addr} NAME=${name}`)
        // check_bingo(addr, name)
        if (!seen.has(addr)) {
            check_bingo(addr, name)
        }
	}
}

function main() {
    var start = Date.now()
    const args = parse_args();
    var output_file = args.output
	if (args.heap_profiler) {
		use_heap = true
	}
	if (use_heap) {
		analyze_heap_before()
	}


    console.log(`Package root = ${args.root}`)

    so_files = locate_so_modules(args.root)
    // so_files = deduplicate_paths(so_files)
    console.log(`Native extension files :\n${so_files.join('\n')}`)


    for (const so_file of so_files) {
      analyze_single(so_file, args.root);
      final_result['modules'].push(so_file)
    }

    var end = Date.now()

    var duration_sec = Math.round((end - start) / 1000)
    final_result['duration_sec'] = duration_sec
    final_result['objects_examined'] = objects_examined
    final_result['callable_objects'] = callable_objects
    final_result['foreign_callable_objects'] = foreign_callable_objects
    final_result['count'] = final_result['bridges'].length

    final_result['failed'] = fqn2failed
    if (output_file !== undefined) {
	    fs.writeFileSync(output_file, JSON.stringify(final_result, null, 2));
        console.log(`Wrote bridges to ${output_file}`)
    }
    else {
        console.log(JSON.stringify(final_result, null, 2))
    }
}

main()
