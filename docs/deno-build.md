# Build and Install Deno From Source
### 1. Select the Deno version you want from its repository tags:
> You can view all available Deno tags at https://github.com/denoland/deno/tags
```
export DENO_TAG=v2.5.4
```
### 2. Clone Deno's source code repository:
> This will create a directory named `deno`.
```
git clone --branch ${DENO_TAG?} --depth 1 https://github.com/denoland/deno.git
```

### 3. Find the `deno_core` tag corresponding to the selected Deno tag:
```
export DENO_CORE_TAG=$(grep -A1 'name = "deno_core"' deno/Cargo.lock | grep version | sed -E 's/.*"([^"]+)".*/\1/')
```
### 4. Clone `deno_core`'s source code repository:
```
git clone --branch ${DENO_CORE_TAG?} --depth 1 https://github.com/denoland/deno_core.git
```

### 5. Find the `rusty_v8` tag corresponding to the selected Deno tag:
```
export RUSTY_V8_TAG=$(grep -A1 'name = "v8"' deno/Cargo.lock | grep version | sed -E 's/.*"([^"]+)".*/v\1/')
```

### 6. Clone the `rusty_v8` source code repository, including its Git submodules:
```
git clone --branch ${RUSTY_V8_TAG} --depth 1 --recurse-submodules https://github.com/denoland/rusty_v8.git
```

### 7. Ensure that `gasket`, `deno`, `deno_core`, and `rusty_v8` reside in the same parent directory:
```
|-- deno
|-- deno_core
|-- gasket 
`-- rusty_v8
```

### 8. Locate the root of the `gasket` source code repository:
```
export GASKET_ROOT=$(readlink -f gasket)
```

### 9. Apply Gasket's patch to `deno`:
```
git -C deno/ am -3 ${GASKET_ROOT?}/deno-patches/deno/0001-Export-symbols-needed-for-Gasket.patch
```

### 10. Apply Gasket's patch to `rusty_v8/v8`:
```
git -C rusty_v8/v8 am -3 ${GASKET_ROOT?}/deno-patches/rusty_v8/0001-visibility-patch.patch
```

### 11. Install Deno's build dependencies:
> Adapted from: https://github.com/denoland/deno/blob/main/.github/CONTRIBUTING.md#building-from-source
```
curl https://sh.rustup.rs -sSf | sh -s -- -y && \
source ${HOME}/.cargo/env && \
sudo apt install protobuf-compire cmake clang pkg-config libglib2.0-dev libgtk-3-dev -y
```

### 12. Build Deno from source:
```
export V8_FROM_SOURCE=1 && \
cd deno && \
cargo --config .cargo/local-build.toml build && \
cd ..
```

### 13. Install the built `deno` binary to a directory in `$PATH`:
```
export PATH="$(pwd)/deno/target/debug:$PATH"
```

### 14. Ensure our custom version of Deno has priority in `$PATH`:
```
which deno
```
