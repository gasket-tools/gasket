import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

let RESOLVE_SCRIPT_PATH;
if (process.env.GASKET_ROOT) {
  RESOLVE_SCRIPT_PATH = path.join(
    process.env.GASKET_ROOT,
    "scripts/resolve_syms.py",
  );
} else {
  RESOLVE_SCRIPT_PATH = 'resolve-syms'
}

export function demangleCpp(mangled) {
  const cmd = `c++filt '${mangled}'`;
  try {
    const out = execSync(cmd, { encoding: "utf-8", shell: true });
    return out.trim();
  } catch (err) {
    console.error(err);
    throw err;
  }
}

export function resolveGDB(addresses) {
  const tmpDir = os.tmpdir();
  const addrFile = path.join(tmpDir, `addr_${randomUUID()}.json`);
  const resFile = path.join(tmpDir, `res_${randomUUID()}.json`);

  const pid = process.pid;

  fs.writeFileSync(addrFile, JSON.stringify(addresses, null, 2));

  // var cmd = `bash -c 'python3 ${RESOLVE_SCRIPT_PATH} -p ${pid} \
  //   -i ${addrFile} -o ${resFile}'`
  const args = [
    "-p",
    String(pid),
    "-i",
    addrFile,
    "-o",
    resFile,
  ];

  var result = spawnSync(RESOLVE_SCRIPT_PATH, args, { encoding: "utf-8" });
  const out = result.stdout;
  console.log("OUT:");
  console.log(out);
  const err = result.stderr;
  console.log("ERR:");
  console.log(err);

  const raw = fs.readFileSync(resFile, "utf-8");
  return JSON.parse(raw);
}

export function getModuleFQN(fullPath, packageRoot) {
  const root = packageRoot == undefined ? "" : packageRoot;
  const packageName = path.basename(root);
  const relativePath = path.relative(root, fullPath);
  const noExt = relativePath.replace(/\.[^/.]+$/, ""); // strip extension
  return `${packageName}/${noExt}`;
}

function locateModules(packagePath, filter) {
  const chosenFiles = [];

  function walkDir(dir) {
    const files = fs.readdirSync(dir);
    files.forEach((file) => {
      const fullPath = path.join(dir, file);
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        walkDir(fullPath); // Recursive call for directories
      } else if (filter(file)) {
        chosenFiles.push(path.resolve(fullPath));
      }
    });
  }
  walkDir(packagePath);
  return chosenFiles;
}

export function locateNativeModules(packagePath) {
  return locateModules(packagePath, (x) => x.endsWith(".node"));
}

export function locateWasmModules(packagePath) {
  return locateModules(packagePath, (x) => x.endsWith(".wasm"));
}

export function locateJSModules(packagePath) {
  return locateModules(packagePath, (x) => x.endsWith(".js"));
}

export function storeBridges(outputFile, bridges) {
  if (outputFile !== undefined) {
    fs.writeFileSync(outputFile, JSON.stringify(bridges, null, 2));
    console.log(`Wrote bridges to ${outputFile}`);
  } else {
    console.log(JSON.stringify(bridges, null, 2));
  }
}
