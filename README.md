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

> **Important** : Tout build, test, lint et fuzzing doit s'effectuer dans le conteneur Docker.
> Voir [`AGENTS.md`](AGENTS.md) pour les détails complets.

### Démarrage rapide (Docker)

```sh
# Construire l'image Docker
make docker-build

# Lancer un shell interactif dans le conteneur
make docker-shell

# Dans le conteneur :
cargo build --workspace
cargo clippy --workspace --all-targets
cargo test --workspace

# Cross-compilation ARMv7 (dans le conteneur)
cargo build --workspace --target armv7-unknown-linux-gnueabihf --release
```

### Fuzzing

Le fuzzing est **obligatoire** pour toute fonction qui parse des données externes.

```sh
# Lancer 5 minutes de fuzzing sur une cible
make docker-fuzz TARGET=bundle_header DURATION=300

# Fuzzing de toutes les cibles (10 min chacune)
make docker-fuzz-all

# Vérifier les crashes
./scripts/fuzz-run.sh --check-crashes --target bundle_header
```

Voir [`fuzz/README.md`](fuzz/README.md) pour les détails.

### Build natif (déconseillé)

```sh
cargo build --workspace
cargo clippy --workspace --all-targets
cargo test --workspace

# Cross-compilation (gcc-arm-linux-gnueabihf requis ; les binaires ARMv7 s'exécutent via
# qemu-arm, voir .cargo/config.toml)
cargo build --workspace --target armv7-unknown-linux-gnueabihf
```

## Règles de développement

- **Aucun `unsafe`** (`forbid` au niveau workspace)
- **Pas de `unwrap`/`expect`/`panic!`** dans le code non-test
- Toute exception doit faire l'objet d'un ADR (`docs/adr/`)
- **Fuzzing obligatoire** pour tout parsing de données externes
- **Couverture ≥ 80 %** sur `update-bundle` et `update-tpm`

Voir [`AGENTS.md`](AGENTS.md) pour les conventions complètes et [`ROADMAP.md`](ROADMAP.md) pour le plan de développement.

## Documentation

| Document | Description |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Guide pour les agents (conventions, outils, contraintes) |
| [`ROADMAP.md`](ROADMAP.md) | Plan de développement détaillé avec checklist |
| [`docs/spec/`](docs/spec/) | Spécifications techniques |
| [`docs/adr/`](docs/adr/) | Architecture Decision Records |
| [`docs/EBIOS-RM-analysis.md`](docs/EBIOS-RM-analysis.md) | Analyse de risque |
| [`fuzz/README.md`](fuzz/README.md) | Guide de fuzzing |
