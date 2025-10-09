let mod;
if (typeof Deno !== "undefined") {
  mod = await import("./exporter/deno.js");
} else {
  mod = await import("./exporter/node.js");
}

const t = mod.t;
const fs = mod.fs;
const parser = mod.parser;
const traverse = mod.traverseMod.default;
const generate = mod.generateMod.default;


const ModuleType = Object.freeze({
  MIXED: "mixed",
  CJS: "cjs",
  ESM: "esm",
  UNKNOWN: "uknown"
});


function parse(code) {
  return parser.parse(code, {
    sourceType: "unambiguous",
    allowImportExportEverywhere: true,
    plugins: [
      "jsx",
      "typescript",
      "classProperties",
      "classPrivateProperties",
      "classPrivateMethods",
      "topLevelAwait",
      "importMeta",
    ],
  });
}

function saveChanges(originalFilePath, originalCode, transformedCode) {
  const backupPath = originalFilePath + ".backup";
  fs.writeFileSync(backupPath, originalCode, "utf8");
  fs.writeFileSync(originalFilePath, transformedCode, "utf8")
}


function getModuleType(ast) {
  let hasESM = false;
  let hasCJS = false;

  traverse(ast, {
    enter(p) {
      const n = p.node;
      // ESM signals
      if (
        n.type === "ImportDeclaration" ||
        n.type === "ExportNamedDeclaration" ||
        n.type === "ExportDefaultDeclaration" ||
        n.type === "ExportAllDeclaration"
      ) {
        hasESM = true;
      }
      // top-level await implies ESM (by spec)
      if (n.type === "AwaitExpression" && p.getFunctionParent() == null) {
        hasESM = true;
      }

      // CommonJS signals
      if (
        n.type === "CallExpression" &&
        n.callee.type === "Identifier" &&
        n.callee.name === "require"
      ) {
        hasCJS = true;
      }
      if (
        n.type === "AssignmentExpression" &&
        n.left.type === "MemberExpression"
      ) {
        const obj = n.left.object;
        const prop = n.left.property;
        if (
          obj?.type === "Identifier" &&
          obj.name === "module" &&
          prop?.type === "Identifier" &&
          prop.name === "exports"
        ) {
          hasCJS = true;
        }
        if (obj?.type === "Identifier" && obj.name === "exports") {
          hasCJS = true;
        }
      }
    },
  });

  if (hasESM && hasCJS) return ModuleType.MIXED;
  if (hasESM) return ModuleType.ESM;
  if (hasCJS) return ModuleType.CJS;
  return ModuleType.UNKNOWN;
}


function isRequireCall(n) {
  return (
    n &&
    t.isCallExpression(n) &&
    t.isIdentifier(n.callee, { name: "require" })
  );
}

function recordExportedObjects(ast) {
  const imported = new Set();
  const alreadyExported = new Set();

  // Pass 1: record imported names and already-exported locals
  traverse(ast, {
    ImportDeclaration(p) {
      for (const s of p.node.specifiers) {
        imported.add(s.local.name);
      }
    },
    ExportNamedDeclaration(p) {
      const d = p.node.declaration;
      if (d) {
        if (t.isVariableDeclaration(d)) {
          for (const decl of d.declarations) {
            if (t.isIdentifier(decl.id)) {
              alreadyExported.add(decl.id.name);
            }
          }
        } else if (
          (t.isFunctionDeclaration(d) || t.isClassDeclaration(d)) &&
          d.id
        ) {
          alreadyExported.add(d.id.name);
        }
      }
      for (const s of p.node.specifiers || []) {
        if (t.isExportSpecifier(s) && t.isIdentifier(s.local)) {
          alreadyExported.add(s.local.name);
        }
      }
    },
    ExportDefaultDeclaration(p) {
      const d = p.node.declaration;
      if ((t.isFunctionDeclaration(d) || t.isClassDeclaration(d)) && d.id) {
        alreadyExported.add(d.id.name);
      }
    },
    AssignmentExpression(p) {
      const L = p.node.left;
      // exports.foo = ...
      if (
        t.isMemberExpression(L) &&
        t.isIdentifier(L.object, { name: "exports" }) &&
        t.isIdentifier(L.property)
      ) {
        alreadyExported.add(L.property.name);
      }
      // module.exports = { a: ..., b: ... }
      if (
        t.isMemberExpression(L) &&
        t.isIdentifier(L.object, { name: "module" }) &&
        t.isIdentifier(L.property, { name: "exports" })
      ) {
        const R = p.node.right;
        if (t.isObjectExpression(R)) {
          for (const prop of R.properties) {
            if (t.isObjectProperty(prop) && t.isIdentifier(prop.key)) {
              alreadyExported.add(prop.key.name);
            }
          }
        }
      }
    },
  });
  return {
    exported: alreadyExported,
    imported: imported
  };
}


function cjsTransform(filePath, code, ast) {

  // Pass 1: record imported names and already-exported locals
  const {exported, imported} = recordExportedObjects(ast);
  const unexportedObjects = new Set();
  // Pass 2: in-place export of eligible top-level variable declarations
  traverse(ast, {
    VariableDeclaration(path) {
      if (path.parent.type !== "Program") return;

      const node = path.node;

      if (
        node.declarations.length !== 1 ||
        !t.isIdentifier(node.declarations[0].id)
      ) {
        return;
      }

      const id = node.declarations[0].id;
      const init = node.declarations[0].init;
      const name = id.name;
      if (isRequireCall(init) || imported.has(name) || exported.has(name)) {
        return;
      }
      unexportedObjects.add(name);
    },
  });

  // Add exports to the end of the file.
  let transformedCode = code;
  let transformed = false;
  for (const unexportedObj of unexportedObjects) {
    transformedCode = `${transformedCode}\nmodule.exports.${unexportedObj} = ${unexportedObj};`
    transformed = true;
  }
  if (transformed) {
    saveChanges(filePath, code, transformedCode);
  }
  return transformed;
}


function esmTransform(filePath, code, ast) {
  const {exported, imported} = recordExportedObjects(ast);
  let transformed = false;
  traverse(ast, {
    VariableDeclaration(path) {
      if (path.parent.type !== "Program") return; // top-level only

      const node = path.node;

      // Only transform *single* declarator with identifier id
      if (
        node.declarations.length !== 1 ||
        !t.isIdentifier(node.declarations[0].id)
      ) {
        return;
      }

      const id = node.declarations[0].id;        // Identifier
      const init = node.declarations[0].init;     // RHS (may be null)
      const name = id.name;

      // Skip: require(...) initializers, imported names, or already exported
      if (isRequireCall(init) || imported.has(name) || exported.has(name)) {
        return;
      }

      // Build a fresh export-wrapped declaration with deep clones
      transformed = true;
      const clonedId = t.identifier(name);
      const clonedInit = init ? t.cloneNode(init, /* deep */ true) : null;
      const newVarDecl = t.variableDeclaration(node.kind, [
        t.variableDeclarator(clonedId, clonedInit),
      ]);
      const exportDecl = t.exportNamedDeclaration(newVarDecl, []);

      path.replaceWith(exportDecl);
      path.skip();
    },
  });

  const transformedCode = generate(ast, {
    retainLines: false,
    compact: false,
    concise: false,
    comments: true,
  }).code;
  if (transformed) {
    saveChanges(filePath, code, transformedCode);
  }
  return transformed;

}


export default function transform(filePath) {
  const code = fs.readFileSync(filePath, "utf8");
  let ast;
  try {
    ast = parse(code);
  } catch {
    return false;
  }
  const moduleType = getModuleType(ast);
  if (moduleType == ModuleType.UNKNOWN || moduleType.MIXED) {
    return false;
  }
  if (moduleType == ModuleType.CJS) {
    return cjsTransform(filePath, code, ast);
  } else {
    return esmTransform(filePath, code, ast);
  }
}

export function revertChanges(filePath) {
  const backupPath = filePath + ".backup";
  if (fs.existsSync(backupPath)) {
    fs.renameSync(backupPath, filePath);
  }
}


if (process.argv[1] === mod.__filename) {
  const file = process.argv[2];
  if (!file) {
    console.error("Usage: node transformer.js <path/to/file.js>");
    process.exit(1);
  }
  transform(file);
}
