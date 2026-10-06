# update-rs

Système de mise à jour pour plateforme embarquée (type SolidRun Clearfog), écrit en Rust.

Objectifs :

- authenticité et confidentialité du payload, ancrées dans un TPM 2.0 (révision 1.59 de la spécification TCG) ;
- format d'archive de mise à jour **streamable** à la récupération (créée offline) ;
- cross-compilation vers la cible principale, la Clearfog Pro (ARMv7, `armv7-unknown-linux-gnueabihf`) ;
- primitives cryptographiques issues des mêmes bibliothèques que les projets GitHub de l'ANSSI.

> Statut : spécification en cours de rédaction. Voir [`docs/`](docs/README.md).

## Organisation du workspace

| Crate | Type | Rôle |
|---|---|---|
| `update-bundle` | lib | format d'archive de mise à jour (lecture en streaming, vérification, déchiffrement) |
| `update-tpm` | lib | abstraction du TPM 2.0 (scellement, NV, compteur, PCR) |
| `update-slot` | lib | gestion des slots A/B et du bootloader |
| `updated` | bin | démon de mise à jour (machine à états) |
| `updatectl` | bin | CLI de pilotage du démon |
| `bundle-tool` | bin | outil hôte : création, signature et chiffrement des bundles |

## Développement

```sh
cargo build --workspace
cargo clippy --workspace --all-targets
cargo test --workspace

# Cross-compilation (gcc-arm-linux-gnueabihf requis ; les binaires ARMv7 s'exécutent via
# qemu-arm, voir .cargo/config.toml)
cargo build --workspace --target armv7-unknown-linux-gnueabihf
```

Règles : aucun `unsafe` (`forbid` au niveau workspace), pas de `unwrap`/`expect`/`panic!`
dans le code non-test. Toute exception doit faire l'objet d'un ADR (`docs/adr/`).
