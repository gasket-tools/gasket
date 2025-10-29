![Node.js Version](docs/nodejs-version-badge.svg)
![Deno Version](docs/deno-version-badge.svg)

# Gasket

Gasket is a command-line tool for uncovering bridges between JavaScript and
low-level native code such as C, Rust, or WebAssembly.
It performs a dynamic analysis that systematically inspects
the in-memory layout of JavaScript function objects to identify
functions that cross the language boundary.

Detecting these cross-language links, Gasket enables
powerful cross-language analyses, including:

* Vulnerability detection in native bindings

* Cross-language call graph construction

* Supply-chain and dependency security auditing through reachability analysis


## Table of Contents
- [Requirements](#requirements)
- [Build/Install from Source](#install-gasket-from-source)
  - [Gasket](#install-gasket-from-source)
  - [Deno (w/ Gasket patch)](#install-gasket-from-source)
- [Use a Prebuilt Docker Image](#use-a-prebuilt-docker-image)
- [Build Docker Image From Source](#build-docker-image-from-source)
- [Usage](#usage)
  - [Node.js](#nodejs)
  - [Deno](#deno)
- [Optional Arguments](#optional-arguments)
- [Related Publications](#related-publications)

## Requirements
- Node.js >= 21.x, Deno >=1.46.x (with Gasket patch, see below)
- wget, unzip (for installing precompiled deno)
- git, sudo, make, g++, c++filt, GNU Debugger (GDB)
- wasm-objdump (offered by the wabt package on Debian)

## Install Gasket From Source
> These instructions assume building on Debian-based system.
1. Clone this repository:
```
git clone https://github.com/gasket-tools/gasket.git
```

2. Build and install Gasket:
> Gasket's source code is organized as an npm package, and running `npm install` will also
> trigger compilation of Gasket's C++ backend.
```
cd gasket && npm install && npm install -g
```

3. (Recommended: Option A) Download and Install a Precompiled Deno Binary (w/ Gasket patch):
```
wget https://github.com/gasket-tools/gasket/releases/download/0.1.0/deno-gasket-x86_64-unknown-linux-gnu.zip && \
unzip deno-gasket-x86_64-unknown-linux-gnu.zip && \
sudo mv deno /usr/local/bin/deno && \
rm deno-gasket-x86_64-unknown-linux-gnu.zip
```

3. (Option B) Build and Install Deno (w/ Gasket patch) from Source:

See [docs/deno-build.md](docs/deno-build.md) for instructions.

## Use a Prebuilt Docker Image
1. Download the prebuilt Docker image with Gasket installed:
```
docker pull grgalex/gasket:0.1.0
```

2. Run a container using Gasket's Docker image:
> The `cap-add=SYS_PTRACE` is necessary to allow Gasket to use GDB inside the container.
```
docker run -ti --cap-add=SYS_PTRACE grgalex/gasket:0.1.0
```

## Build Docker Image From Source
1. Clone the Gasket source code repository:
```
git clone https://github.com/gasket-tools/gasket.git
```

2. Build the Docker image:
```
docker build -t gasket-wip -f docker/Dockerfile .
```

3. Run a container using the image:
> The `cap-add=SYS_PTRACE` is necessary to allow Gasket to use GDB inside the container.
```
docker run -ti --cap-add=SYS_PTRACE gasket-wip
```

# Usage

## Node.js
The `gasket` executable provides a command-line interface that allows you
to analyze a given *installed* `npm` package
and identify its bridges:
```
$ gasket -h
Options:
      --version       Show version number                            [boolean]
  -r, --root          Package root                                    [string]
  -m, --module        Module to analyze                               [string]
      --internal      Whether the analyzed module is an internal binding (to
                      be used with -m)              [boolean] [default: false]
  -o, --output        output file                                     [string]
  -p, --profile-heap  Profile the V8 Heap for unexported objects
                                                    [boolean] [default: false]
      --native-only   Detect only JS-to-Native bridges               [boolean]
      --wasm-only     Detect only JS-to-Wasm bridges                 [boolean]
      --force-export  Force export top-level declarations in analyzed modules
                                                                     [boolean]
      --help          Show help                                      [boolean]

```

### Analyze a Node.js Package
1. (Optional) Install the target package from npm into a temporary directory:
> Replace \<dir> and \<pkg> with your desired directory and package name.
```
npm install --prefix <dir> <pkg>
```

For example, to install the `sqlite3` package in `/tmp`, run:
```
npm install --prefix /tmp sqlite3
```
2. Run Gasket:
> In default mode, this will search for both Native and WASM bridges.
```
gasket -r <dir>/node_modules/<package> -o bridges.json
```

For example, to analyze the installed `sqlite3` package, run:
```
gasket -r /tmp/node_modules/sqlite3 -o bridges.json
```

3. Examine Gasket's output:
Gasket stores its results in a JSON file that includes the following information:

* `objects_examined`: Number of objects examined by `Gasket`.
* `callable_objects`: Number of callable callable objects examined by `Gasket`.
* `foreign_callbable_objects`: Number of callable objects.
with a foreign implementation (e.g., an implementation in C++).
* `duration`: Time in seconds spent analyzing the given package.
* `count`: Number of identified bridges.
* `modules`: Analyzed modules. These include both native extension binaries (`.node`)
as well as JavaScript files.
* `jump_libs`: ELF binary and WASM files that identified bridges lead to.
This is a set containing all distinct `library` fields identified in the bridges.
* `bridges`: A detailed list of identified bridges. Every bridge is a triple
containing the following information:
  - `type`: Either `js-to-native` or `js-to-wasm`.
  - `jsname`: Name of the foreign callbable object on the JavaScript side.
  - `cfunc`: Name of the low-level function (binary/WASM) that implements the logic
   of the object exposed in JavaScript.
  - `library`: The library where this low-level function is found.

4. Sample output for the `sqlite3` package (Native extension bridges):
> In default mode, Gasket analyzes both native addon binaries and JavaScript source files.
> As such, it may output multiple JavaScript fully-qualified-names (FQNs) pointing to the
> same binary function.
> For example, `sqlite3/build/Release/node_sqlite3.Database` and `sqlite3/lib/sqlite3.Database`
> both correspond to the `node_sqlite3::Database::Database` binary function.
```
{
  "objects_examined": 5974,
  "callable_objects": 4534,
  "foreign_callable_objects": 84,
  "duration_sec": 4.988,
  "count": 84, 
  "modules": [
    "/tmp/packages/node_modules/sqlite3/build/Release/node_sqlite3.node",
    "/tmp/packages/node_modules/sqlite3/deps/extract.js",
    "/tmp/packages/node_modules/sqlite3/lib/sqlite3-binding.js",
    "/tmp/packages/node_modules/sqlite3/lib/sqlite3.js",
    "/tmp/packages/node_modules/sqlite3/lib/trace.js"
  ],
  "jump_libs": [
    "/tmp/packages/node_modules/sqlite3/build/Release/node_sqlite3.node"
  ],
  "bridges": [ 
    {
      "type": "js-to-native",
      "jsname": "sqlite3/build/Release/node_sqlite3.Database",
      "cfunc": "node_sqlite3::Database::Database",
      "library": "/tmp/packages/node_modules/sqlite3/build/Release/node_sqlite3.node"
    },
    {
      "type": "js-to-native",
      "jsname": "sqlite3/build/Release/node_sqlite3.Statement",
      "cfunc": "node_sqlite3::Statement::Statement",
      "library": "/tmp/packages/node_modules/sqlite3/build/Release/node_sqlite3.node"
    },
... (more bridges)
    {
      "type": "js-to-native",
      "jsname": "sqlite3/lib/sqlite3.Database",
      "cfunc": "node_sqlite3::Database::Database",
      "library": "/tmp/t88/node_modules/sqlite3/build/Release/node_sqlite3.node"
    },
... (more bridges)
```

5. Sample output for the `tiny-secp256k1` package (WASM bridges):
```
{
  "objects_examined": 7609,
  "callable_objects": 6683,
  "foreign_callable_objects": 7,
  "duration_sec": 0.249,
  "count": 22,
  "modules": [
    "/tmp/t88/node_modules/tiny-secp256k1/lib/index.js",
    "/tmp/t88/node_modules/tiny-secp256k1/lib/rand.browser.js",
    "/tmp/t88/node_modules/tiny-secp256k1/lib/rand.js",
    "/tmp/t88/node_modules/tiny-secp256k1/lib/validate.js",
    "/tmp/t88/node_modules/tiny-secp256k1/lib/validate_error.js",
    "/tmp/t88/node_modules/tiny-secp256k1/lib/wasm_loader.browser.js",
    "/tmp/t88/node_modules/tiny-secp256k1/lib/wasm_loader.js",
    "/tmp/t88/node_modules/tiny-secp256k1/lib/wasm_path.js"
  ],
  "jump_libs": [
    "/tmp/t88/node_modules/tiny-secp256k1/lib/secp256k1.wasm"
  ],
  "bridges": [
    {
      "type": "js-to-wasm",
      "jsname": "tiny-secp256k1/lib/wasm_loader.default.initializeContext",
      "cfunc": "initializeContext",
      "library": "/tmp/t88/node_modules/tiny-secp256k1/lib/secp256k1.wasm"
    },
...
```

## Deno
> `gasket-deno` requires a `deno` binary with Gasket's patches available in $PATH.

1. Fetch the source code of the package you want to analyze (e.g., `@db/sqlite`):
> Packages on deno.land/jsr.io contain links to the corresponding source code repositories.
```
git clone https://github.com/denodrivers/sqlite3 deno-sqlite3
```

3. Enter the source code directory:
```
cd deno-sqlite3
```

3. Analyze the package using `gasket-deno`:
```
gasket-deno -r . -o deno-bridges.json
```

## Optional Arguments
### 1. Native-only Analysis (`--native-only`):

Only analyze `.node` native extension modules
for `js-to-native` bridges.

### 2. WASM-only Analysis (`--wasm-only`):

Only analyze JavaScript source files for `js-to-wasm` bridges.

### 3. Force Export of JavaScript Variables (`--force-export`):

Before analysis,
create modified copies of JavaScript source files with all variables explicitly exported.
This exposes more objects to Gasket for introspection
and may uncover otherwise missed bridges.

### 4. Use the V8 Heap Profiler (`-p/--profile-heap`):
> Setting this option significantly increases Gasket's execution time
to ~10 minutes.

Take a snapshot of the V8 heap after importing the modules
under analysis. This ensures that *all* objects are available
to Gasket for introspection, whether they stem from
native extension modules or JavaScript source files.

### 5. Analyze a single {JS, extension} module (`-m/--module`):

Only load and analyze a single module located at the provided path.

### 5. Analyze an internal Node.js module (`--internal` + `-m/--module` combination):

Load and analyze an internal Node.js module.
For example, to analyze the `fs` module,
you can run:
```bash
gasket -m fs --internal -o fs_bridges.json
```

## Related Publications

* Georgios Alexopoulos, Thodoris Sotiropoulos, Zhendong Su, and Dimitris Mitropoulos.
[Best of Both Worlds: Effective Foreign Bridge Identification in V8 Embedders for Security Analysis](https://grgalex.gr/assets/pdf/gasket_sp26.pdf).
In Proceedings of the 2026 IEEE Symposium on Security and Privacy (S&P'26). IEEE, 2026.
To appear.
