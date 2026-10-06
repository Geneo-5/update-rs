# Fuzzing pour update-rs

Ce répertoire contient les cibles de fuzzing pour le projet `update-rs`.

## Philosophie

**Toute fonction qui parse des données externes** (bundle, header, manifest CBOR, commandes TPM) **doit avoir une cible de fuzzing**. Le fuzzing n'est pas optionnel — c'est une exigence de sécurité.

## Cibles de fuzzing

| Cible | Description | Corpus initial |
|---|---|---|
| `bundle_header` | Parsing du header de bundle (1024 octets) | Bundles valides générés par `bundle-tool` |
| `bundle_chunk` | Décryptage et validation d'un chunk | Chunks extraits de bundles valides |
| `jail_manifest` | Parsing CBOR du manifeste de jail | Manifestes valides |
| `tpm_command` | Parsing des commandes/réponses TPM | Traces de commandes TPM légitimes |
| `state_machine` | Séquences d'états du démon | Séquences d'états valides |

## Prérequis

Le fuzzing nécessite **Rust nightly** et `cargo-fuzz` :

```bash
# Dans le conteneur Docker (recommandé)
make docker-shell
cargo +nightly fuzz --version

# Ou installation manuelle
rustup install nightly
cargo +nightly install cargo-fuzz
```

## Utilisation

### Lancer le fuzzing

```bash
# Fuzzing continu (jusqu'à Ctrl-C)
make docker-fuzz TARGET=bundle_header

# Fuzzing avec timeout (5 minutes)
make docker-fuzz TARGET=bundle_header DURATION=300

# Fuzzing de toutes les cibles (10 min chacune)
make docker-fuzz-all

# Ou directement avec cargo-fuzz
cargo +nightly fuzz run bundle_header -- -max_total_time=300
```

### Lister les cibles

```bash
cargo +nightly fuzz list
```

### Gérer les crashes

Les crashes sont sauvegardés dans `fuzz/artifacts/<target>/`.

```bash
# Reproduire un crash
cargo +nightly fuzz run bundle_header fuzz/artifacts/bundle_header/crash-<hash>

# Minimiser un crash (réduire la taille de l'entrée)
cargo +nightly fuzz tmin bundle_header fuzz/artifacts/bundle_header/crash-<hash>

# Ou via le script
./scripts/fuzz-run.sh --minimize --target bundle_header --crash fuzz/artifacts/bundle_header/crash-<hash>
```

### Minimiser le corpus

```bash
# Réduire la taille du corpus tout en conservant la couverture
cargo +nightly fuzz cmin bundle_header
```

## Workflow de traitement d'un crash

Quand un crash est découvert :

1. **Reproduire** : `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`
2. **Minimiser** : `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>`
3. **Créer un test de non-régression** :
   ```bash
   mkdir -p tests/fixtures/regressions/<target>/
   cp fuzz/artifacts/<target>/crash-<hash>-minimized tests/fixtures/regressions/<target>/
   ```
4. **Corriger le bug** et vérifier que le test passe
5. **Ajouter le cas au corpus** :
   ```bash
   cp tests/fixtures/regressions/<target>/crash-<hash>-minimized fuzz/corpus/<target>/
   ```

## Génération de corpus initial

Pour chaque cible, générer un corpus initial avec des entrées valides :

### bundle_header

```bash
# Utiliser bundle-tool pour générer des bundles valides
cargo run --release --bin bundle-tool -- create --output test-bundle.bin

# Extraire le header (1024 premiers octets)
head -c 1024 test-bundle.bin > fuzz/corpus/bundle_header/valid-header-1.bin
```

### bundle_chunk

```bash
# Extraire un chunk d'un bundle valide
# (à implémenter avec bundle-tool extract-chunk)
```

### jail_manifest

```bash
# Créer des manifestes CBOR valides
python3 -c "import cbor2; print(cbor2.dumps({'entry_point': '/update.sh', 'root_tmpfs_size': 67108864}))" > fuzz/corpus/jail_manifest/valid-manifest-1.cbor
```

### tpm_command

```bash
# Capturer des commandes TPM légitimes depuis swtpm
# (à implémenter)
```

### state_machine

```bash
# Générer des séquences d'états valides
# (à implémenter)
```

## Couverture de code

Générer un rapport de couverture :

```bash
# Via le script
./scripts/fuzz-run.sh --coverage --target bundle_header

# Ou directement
cargo tarpaulin --workspace --out Html
```

Objectif : **≥ 90 %** de couverture sur les parsers après fuzzing.

## Intégration CI

Le fuzzing est intégré dans la CI (`.github/workflows/ci.yml`) :

- 5 minutes de fuzzing sur chaque cible
- Les crashes font échouer la CI
- Les artifacts sont uploadés en cas d'échec

## Ressources

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer tutorial](https://llvm.org/docs/LibFuzzerTutorial.html)
- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
