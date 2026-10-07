# Cross-compilation ARMv7 (optionnelle)

Par défaut, `update-rs` se construit, se teste et se fuzze pour la **plateforme
native** (celle de la machine ou du conteneur Docker). La cross-compilation vers
la cible embarquée est **optionnelle** : elle sert à produire les binaires
`updated` et `updatectl` pour la carte, ou à vérifier que le code compile pour
cette cible.

| | |
|---|---|
| Carte cible | SolidRun Clearfog Pro (Marvell Armada 388, ARMv7-A, hard-float) |
| Triplet Rust | `armv7-unknown-linux-gnueabihf` |
| TPM | TPM 2.0, révision 1.39 |

`bundle-tool` est un outil **hôte** : il n'est jamais cross-compilé.

## 1. Via Docker (recommandé)

L'image dispose d'un stage optionnel `cross` (toolchain `arm-linux-gnueabihf`,
cible Rust, `qemu-user`). Il n'est pas construit par les commandes habituelles.

```bash
# Compiler updated et updatectl pour ARMv7 (release)
make docker-build-arm

# Tester sous émulation qemu-user
docker compose -f docker/docker-compose.yml --profile cross run --rm test-arm
```

Les binaires sont produits dans `target/armv7-unknown-linux-gnueabihf/release/`.

## 2. Sans Docker (hôte Debian/Ubuntu)

```bash
sudo apt-get install -y gcc-arm-linux-gnueabihf libc6-dev-armhf-cross qemu-user
rustup target add armv7-unknown-linux-gnueabihf

cargo build --release --target armv7-unknown-linux-gnueabihf -p updated -p updatectl
```

Le linker et le runner sont déjà déclarés dans `.cargo/config.toml` :

```toml
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
runner = "qemu-arm -L /usr/arm-linux-gnueabihf"
```

Le runner permet d'exécuter `cargo test --target armv7-unknown-linux-gnueabihf`
sous émulation. Ces réglages ne s'appliquent que lorsque `--target` est passé :
un `cargo build` ordinaire reste natif.

## 3. Vérification

```bash
file target/armv7-unknown-linux-gnueabihf/release/updated
# ELF 32-bit LSB pie executable, ARM, EABI5 ... interpreter /lib/ld-linux-armhf.so.3
```

## 4. Limites

- `qemu-user` émule le processeur et les appels système, pas le matériel :
  pas de vrai TPM (`/dev/tpmrm0`), et le comportement des namespaces, de
  seccomp et des capabilities n'est pas représentatif. Les tests de sécurité
  du jail et du TPM doivent tourner sur la carte (ou avec `swtpm`).
- Le fuzzing (`cargo-fuzz`) se fait toujours en natif.

## 5. Quand le backend TPM (`tss-esapi`) sera ajouté

La crate lie `libtss2` via `pkg-config` : pour la cible ARMv7, il faut des
bibliothèques **ARMv7**, pas celles de l'hôte.

- Ne **pas** définir `PKG_CONFIG_ALLOW_CROSS=1` : cela ferait lier des
  bibliothèques de l'hôte dans un binaire ARM.
- Pointer `pkg-config` vers un sysroot ARMv7 contenant `libtss2` :
  `PKG_CONFIG_SYSROOT_DIR=<sysroot>` et `PKG_CONFIG_PATH=<sysroot>/usr/lib/pkgconfig`.
- En production, privilégier le SDK Buildroot/Yocto de l'image de la carte
  (sysroot cohérent avec la libc et `tpm2-tss` réellement déployés).
