# syntax=docker/dockerfile:1.6
# Dockerfile pour update-rs : environnement de développement et CI
# Multi-stage : build (avec Rust nightly pour fuzzing) + runtime (minimal)

# ============================================================================
# Stage 1 : Base commune
# ============================================================================
FROM debian:bookworm-slim AS base

# Éviter les prompts interactifs
ENV DEBIAN_FRONTEND=noninteractive

# Installer les paquets de base
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# Stage 2 : Build (Rust stable + nightly, cross-compilation, TPM2-TSS)
# ============================================================================
FROM base AS build

# Installer les outils de build et cross-compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc-arm-linux-gnueabihf \
    libc6-dev-armhf-cross \
    libssl-dev \
    libtss2-dev \
    qemu-user \
    qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

# Installer Rust (stable + nightly pour fuzzing)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile minimal \
    --component rustfmt clippy

# Installer Rust nightly pour cargo-fuzz
RUN rustup install nightly \
    && rustup component add rust-src --toolchain nightly

# Installer les cibles cross-compilation
RUN rustup target add armv7-unknown-linux-gnueabihf

# Installer cargo-fuzz (nécessite nightly)
RUN cargo +nightly install cargo-fuzz

# Installer cargo-tarpaulin pour la couverture
RUN cargo install cargo-tarpaulin

# Installer cargo-audit pour la sécurité
RUN cargo install cargo-audit

# Configurer le linker pour cross-compilation
RUN mkdir -p /workspace/.cargo
COPY .cargo/config.toml /workspace/.cargo/config.toml

# Définir le répertoire de travail
WORKDIR /workspace

# Copier les fichiers de dépendances (pour le cache Docker)
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/update-bundle/Cargo.toml crates/update-bundle/
COPY crates/update-tpm/Cargo.toml crates/update-tpm/
COPY crates/update-slot/Cargo.toml crates/update-slot/
COPY crates/updated/Cargo.toml crates/updated/
COPY crates/updatectl/Cargo.toml crates/updatectl/
COPY crates/bundle-tool/Cargo.toml crates/bundle-tool/

# Pré-télécharger les dépendances (cache Docker)
RUN cargo fetch || true

# Copier le reste du code
COPY . .

# Variables d'environnement pour cross-compilation
ENV PKG_CONFIG_ALLOW_CROSS=1 \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    CARGO_TARGET_DIR=/workspace/target \
    UPDATE_RS_TARGET=armv7-unknown-linux-gnueabihf \
    FUZZ_CORPUS_DIR=/workspace/fuzz/corpus \
    FUZZ_ARTIFACTS_DIR=/workspace/fuzz/artifacts

# ============================================================================
# Stage 3 : Runtime (minimal, pour exécution des tests)
# ============================================================================
FROM debian:bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Installer uniquement les bibliothèques nécessaires à l'exécution
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libtss2-esys-3.0.2-0 \
    libtss2-mu0 \
    libtss2-rc0 \
    libtss2-sys0 \
    libtss2-tcti-device0 \
    qemu-user \
    && rm -rf /var/lib/apt/lists/*

# Copier les binaires depuis le stage build
COPY --from=build /workspace/target/armv7-unknown-linux-gnueabihf/release/updated /usr/local/bin/updated
COPY --from=build /workspace/target/armv7-unknown-linux-gnueabihf/release/updatectl /usr/local/bin/updatectl
COPY --from=build /workspace/target/release/bundle-tool /usr/local/bin/bundle-tool

# Créer les répertoires nécessaires
RUN mkdir -p /var/run /var/log/update-rs

# Exposer le socket Unix (pour updatectl)
VOLUME /var/run

# Par défaut, lancer le démon
CMD ["updated"]

# ============================================================================
# Stage 4 : Dev (environnement de développement complet)
# ============================================================================
FROM build AS dev

# Installer des outils supplémentaires pour le développement
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    less \
    htop \
    strace \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Shell par défaut
CMD ["/bin/bash"]
