# syntax=docker/dockerfile:1.6
# Dockerfile pour update-rs : environnement de développement et CI
#
# Le build est NATIF (architecture du conteneur). La cross-compilation ARMv7
# est optionnelle : stage `cross`, documentée dans docs/cross-compilation.md.
#
# Stages :
#   base     : paquets communs
#   build    : toolchains Rust (stable + nightly), outils (fuzz, audit, couverture)
#   cross    : (optionnel) build + toolchain de cross-compilation ARMv7 et qemu-user
#   release  : compile les binaires (natif)
#   runtime  : image minimale d'exécution (natif)
#   dev      : build + outils de debug (dernier stage = cible par défaut)

# ============================================================================
# Stage 1 : Base commune
# ============================================================================
FROM debian:bookworm-slim AS base

ENV DEBIAN_FRONTEND=noninteractive

# bash + pipefail : un `curl | sh` qui échoue doit faire échouer le build
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# Stage 2 : Build natif (Rust stable + nightly, TPM2-TSS)
# ============================================================================
FROM base AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libtss2-dev \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:${PATH}

# Rust stable puis nightly (cargo-fuzz).
# Les options courtes -c sont répétables : plus robuste que "--component a b".
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
      --default-toolchain stable \
      --profile minimal \
      -c rustfmt -c clippy \
    && rustup toolchain install nightly --profile minimal -c rust-src

# Outils cargo (un layer chacun : un échec n'invalide pas les autres).
# Versions épinglées pour éviter les ruptures de build lors de mises à jour
# incompatibles.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo +nightly install cargo-fuzz --locked

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-tarpaulin --locked

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo install cargo-audit --locked

WORKDIR /workspace

# --- Cache des dépendances -------------------------------------------------
# On ne copie que les manifestes, avec des sources factices : sans cibles
# (src/lib.rs ou src/main.rs), `cargo fetch` échoue ("no targets specified").
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/update-bundle/Cargo.toml crates/update-bundle/
COPY crates/update-tpm/Cargo.toml crates/update-tpm/
COPY crates/update-slot/Cargo.toml crates/update-slot/
COPY crates/updated/Cargo.toml crates/updated/
COPY crates/updatectl/Cargo.toml crates/updatectl/
COPY crates/bundle-tool/Cargo.toml crates/bundle-tool/

RUN for c in update-bundle update-tpm update-slot; do \
        mkdir -p "crates/$c/src" && : > "crates/$c/src/lib.rs"; \
    done \
    && for c in updated updatectl bundle-tool; do \
        mkdir -p "crates/$c/src" && echo 'fn main() {}' > "crates/$c/src/main.rs"; \
    done \
    && (test -s Cargo.lock || cargo generate-lockfile) \
    && cargo fetch \
    && rm -rf crates/*/src

# --- Code source -----------------------------------------------------------
# (voir .dockerignore)
COPY . .

ENV CARGO_TARGET_DIR=/workspace/target \
    FUZZ_CORPUS_DIR=/workspace/fuzz/corpus \
    FUZZ_ARTIFACTS_DIR=/workspace/fuzz/artifacts

# ============================================================================
# Stage 3 (optionnel) : Cross-compilation ARMv7 — voir docs/cross-compilation.md
# ============================================================================
FROM build AS cross

# qemu-user fournit qemu-arm (runner des tests ARMv7, cf. .cargo/config.toml).
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-arm-linux-gnueabihf \
    libc6-dev-armhf-cross \
    qemu-user \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add armv7-unknown-linux-gnueabihf

# Pas de PKG_CONFIG_ALLOW_CROSS : il ferait lier des bibliothèques de l'hôte
# dans les binaires ARMv7. Quand tss-esapi sera ajouté, utiliser un sysroot
# ARMv7 (PKG_CONFIG_SYSROOT_DIR / PKG_CONFIG_PATH, cf. .cargo/config.toml).
ENV CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    UPDATE_RS_TARGET=armv7-unknown-linux-gnueabihf

# ============================================================================
# Stage 4 : Release (compilation native)
# ============================================================================
FROM build AS release

RUN cargo build --release --locked --workspace

# ============================================================================
# Stage 5 : Runtime (natif, minimal)
# ============================================================================
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Quand le backend TPM (tss-esapi) sera ajouté, installer ici les bibliothèques
# d'exécution libtss2-* correspondantes.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=release /workspace/target/release/updated /usr/local/bin/updated
COPY --from=release /workspace/target/release/updatectl /usr/local/bin/updatectl
# Note : bundle-tool est un utilitaire hôte (création de bundles),
# il ne doit PAS être dans l'image runtime embarquée.

RUN mkdir -p /run/update-rs /var/log/update-rs

CMD ["updated"]

# ============================================================================
# Stage 6 : Dev (environnement de développement complet, natif)
# ============================================================================
FROM build AS dev

RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    less \
    htop \
    strace \
    gdb \
    && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
