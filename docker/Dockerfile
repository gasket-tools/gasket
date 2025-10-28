# =========================
# Stage 1: Build Deno
# =========================
FROM ubuntu:24.04 AS deno-builder
SHELL ["/bin/bash", "-c"]

ENV DENO_TAG=v2.5.4
ENV DENO_CORE_TAG=0.362.0
ENV RUSTY_V8_TAG=v140.2.0

RUN apt update -yq && apt install -yq \
    git curl build-essential python3 python3-pip \
    protobuf-compiler cmake clang pkg-config libglib2.0-dev libgtk-3-dev

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:$PATH"

# Clone sources
WORKDIR /tmp
RUN git clone --branch ${DENO_TAG?} --depth 1 https://github.com/denoland/deno.git && \
    git clone --branch ${DENO_CORE_TAG?} --depth 1 https://github.com/denoland/deno_core.git && \
    git clone --branch ${RUSTY_V8_TAG?} --depth 1 --recurse-submodules https://github.com/denoland/rusty_v8.git

# Copy patches (will come from build context)
ARG GASKET_PATCH_DIR=/gasket-patches
COPY deno-patches ${GASKET_PATCH_DIR}

# Apply patches
RUN git config --global user.email "builder@localhost" && \
    git config --global user.name "Docker Builder" && \
    git -C deno/ am -3 ${GASKET_PATCH_DIR}/deno/0001-Export-symbols-needed-for-Gasket.patch && \
    git -C rusty_v8/v8 am -3 ${GASKET_PATCH_DIR}/rusty_v8/0001-visibility-patch.patch

# Build Deno
RUN source $HOME/.cargo/env && export V8_FROM_SOURCE=1 && \
    cd deno && cargo --config .cargo/local-build.toml build && cd ..

# =========================
# Stage 2: Final runtime
# =========================
FROM ubuntu:24.04
SHELL ["/bin/bash", "-c"]

ENV NODE_VERSION=22.21.0
ENV TZ=Europe/Athens
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# --- Base system ---
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt update -yq && apt upgrade -yq && \
    apt install -yq git sudo wget curl locales build-essential python3 python3-pip gdb wabt && \
    locale-gen en_US.UTF-8 && rm -rf /var/lib/apt/lists/*

# --- Create non-root user ---
RUN useradd -ms /bin/bash gasket && echo gasket:gasket | chpasswd && \
    echo 'gasket ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers
USER gasket
ENV HOME=/home/gasket
WORKDIR $HOME

# --- Install Node.js manually ---
USER root
RUN ARCH= && dpkgArch="$(dpkg --print-architecture)" \
  && case "${dpkgArch##*-}" in \
    amd64) ARCH='x64';; arm64) ARCH='arm64';; armhf) ARCH='armv7l';; i386) ARCH='x86';; *) echo "unsupported architecture"; exit 1;; \
  esac \
  && curl -fsSLO --compressed "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$ARCH.tar.xz" \
  && tar -xJf "node-v$NODE_VERSION-linux-$ARCH.tar.xz" -C /usr/local --strip-components=1 --no-same-owner \
  && rm "node-v$NODE_VERSION-linux-$ARCH.tar.xz" \
  && node --version && npm --version

# --- Switch to gasket for user-level installs ---
USER gasket
RUN mkdir -p "$HOME/.npm-global" && npm config set prefix "$HOME/.npm-global"
ENV PATH="$HOME/.npm-global/bin:$PATH"

# --- Install Gasket ---
RUN git clone --single-branch https://github.com/gasket-tools/gasket.git "$HOME/gasket"
WORKDIR $HOME/gasket
RUN npm install -g node-gyp node-addon-api && npm install && npm install -g

# --- Copy Deno binary from builder ---
USER root
COPY --from=deno-builder /tmp/deno/target/debug/deno /usr/local/bin/deno

# --- Final user ---
USER gasket
ENV PATH="$HOME/.npm-global/bin:$HOME/.cargo/bin:$PATH"
WORKDIR $HOME
