# AGENTS.md — Guide pour les agents de développement

Ce document décrit les conventions, outils et contraintes que tout agent (humain ou IA) doit respecter lorsqu'il contribue au projet `update-rs`.

## 1. Vue d'ensemble du projet

`update-rs` est un système de mise à jour sécurisé pour plateformes embarquées ARMv7 (SolidRun Clearfog Pro, Marvell Armada 388). Il repose sur :

- **TPM 2.0** (révision 1.59) pour l'ancrage de confiance et le scellement des clés
- **AES-GCM-SIV** pour le chiffrement authentifié du payload
- **ECDSA P-256** pour la signature des bundles (avec agilité cryptographique post-quantique prévue)
- **Jail** via namespaces Linux (sans CLONE_NEWUSER/CLONE_NEWPID)
- **Format de bundle streamable** avec hash global + AES-GCM par chunk

### Architecture du workspace

| Crate | Type | Rôle |
|---|---|---|
| `update-bundle` | lib | Format d'archive : parsing, vérification, déchiffrement streaming |
| `update-tpm` | lib | Abstraction TPM 2.0 : scellement, NV, PCR, compteur monotone |
| `update-slot` | lib | Gestion slots A/B et interface bootloader |
| `updated` | bin | Démon de mise à jour (machine à états) |
| `updatectl` | bin | CLI de pilotage (socket Unix + SO_PEERCRED) |
| `bundle-tool` | bin | Outil hôte : création, signature, chiffrement des bundles |

### Cible de déploiement

- **Architecture** : `armv7-unknown-linux-gnueabihf` (ARMv7-A, hard-float)
- **Kernel** : Linux (avec support namespaces, cgroups v2, seccomp)
- **TPM** : TPM 2.0 via `/dev/tpmrm0` (TPM2-TSS 3.x ou 4.x)

---

## 2. Environnement de build — Docker obligatoire

**Règle absolue** : tout build, test, lint et fuzzing doit s'effectuer dans le conteneur Docker. Aucun agent ne doit installer Rust ou les toolchains cross-compilation sur l'hôte.

### 2.1 Construction de l'image

```bash
# Construction initiale de l'image
docker build -t update-rs:dev -f docker/Dockerfile .

# Ou via make
make docker-build
```

### 2.2 Utilisation du conteneur

```bash
# Shell interactif
make docker-shell

# Build complet
make docker-build-release

# Tests
make docker-test

# Lint (clippy + rustfmt)
make docker-lint

# Fuzzing
make docker-fuzz TARGET=bundle_header
```

### 2.3 Variables d'environnement importantes

| Variable | Valeur par défaut | Description |
|---|---|---|
| `CARGO_TARGET_DIR` | `/workspace/target` | Répertoire des artefacts de build |
| `UPDATE_RS_TARGET` | `armv7-unknown-linux-gnueabihf` | Cible cross-compilation |
| `FUZZ_CORPUS_DIR` | `/workspace/fuzz/corpus` | Corpus de fuzzing |
| `FUZZ_ARTIFACTS_DIR` | `/workspace/fuzz/artifacts` | Crashes et timeouts |

---

## 3. Conventions de code

### 3.1 Règles strictes (enforced par le workspace)

Ces règles sont déclarées dans `Cargo.toml` au niveau workspace et **ne doivent jamais être contournées** :

```toml
[workspace.lints.rust]
unsafe_code = "forbid"        # Aucun unsafe autorisé
missing_docs = "warn"         # Documentation publique requise

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"          # Pas de .unwrap()
expect_used = "deny"          # Pas de .expect()
panic = "deny"                # Pas de panic!()
indexing_slicing = "warn"     # Accès par index à auditer
```

### 3.2 Gestion des erreurs

- **Toutes les erreurs** doivent utiliser le type `thiserror::Error` ou un enum custom dérivé de `std::error::Error`.
- **Aucun `unwrap()`/`expect()`/`panic!()`** dans le code de production. Les tests peuvent utiliser `.unwrap()` si c'est intentionnel pour l'assertion.
- **Propagation d'erreur** : utiliser l'opérateur `?` avec `map_err()` pour enrichir le contexte.

### 3.3 Documentation

- **Tout item public** (`pub`) doit avoir une docstring `///` expliquant son rôle, ses invariants, et ses cas d'erreur.
- **Les modules** doivent avoir un `//!` en en-tête décrivant leur responsabilité.
- **Les exemples** dans la doc (`# Examples`) sont encouragés pour les APIs publiques.

### 3.4 Conformité ANSSI

Suivre le [guide Rust de l'ANSSI](https://anssi-fr.github.io/rust-guide/) :

- **Règle 1** : Pas de `unsafe` (déjà `forbid`)
- **Règle 3** : Utiliser `Result` plutôt que `Option` pour les erreurs
- **Règle 5** : Pas de types mutables partagés sans synchronisation explicite
- **Règle 7** : Préférer les types à taille fixe (pas de `Vec` quand la taille est connue)
- **Règle 9** : Utiliser `zerocopy` ou `bytemuck` pour les conversions binaires sécurisées
- **Règle 11** : Logger les erreurs avec `tracing` ou `log`, pas `println!`

### 3.5 Cryptographie

- **Bibliothèques autorisées** : RustCrypto (auditées, utilisées par MLA de l'ANSSI)
  - `aes`, `aes-gcm`, `aes-gcm-siv`, `aes-kw` (RFC 5649)
  - `p256`, `ecdsa` pour ECDSA P-256
  - `sha2` pour SHA-256/384/512
  - `hkdf` pour dérivation de clés
  - `ml-kem`, `ml-dsa` pour post-quantique (en surveillance, versions 0.x)
- **Bibliothèques interdites** : toute bibliothèque non auditée ou non maintenue
- **Constantes temporelles** : toutes les opérations sur clés/secrets doivent être en temps constant (utiliser `subtle::ConstantTimeEq`)

---

## 4. Workflow de développement

### 4.1 Avant de coder

1. Lire la spécification concernée dans `docs/spec/`
2. Vérifier qu'il n'y a pas d'ADR (Architecture Decision Record) dans `docs/adr/` qui contredit l'approche
3. Vérifier l'analyse de risque dans `docs/EBIOS-RM-analysis.md` pour le scénario concerné

### 4.2 Pendant le développement

1. **Tests unitaires** : écrire les tests **en même temps** que le code, pas après
2. **Tests de non-régression** : tout bug découvert doit avoir un test de non-régression
3. **Fuzzing** : ajouter une cible de fuzzing pour tout parsing de données externes
4. **Pas de commits sans `cargo clippy --all-targets -- -D warnings`** qui passe

### 4.3 Avant de soumettre une PR

```bash
# Dans le conteneur Docker
make docker-lint          # clippy + rustfmt --check
make docker-test          # cargo test --all
make docker-fuzz-short    # 5 minutes de fuzzing sur les cibles principales
```

### 4.4 Checklist PR

- [ ] `cargo clippy --all-targets -- -D warnings` passe sans warning
- [ ] `cargo fmt --all --check` passe
- [ ] `cargo test --all` passe (tous les tests)
- [ ] `cargo test --all --release` passe (tests en mode release)
- [ ] Documentation des items publics ajoutée/mise à jour
- [ ] Si changement d'API publique : mise à jour de la doc dans `docs/spec/`
- [ ] Si changement cryptographique : revue contre le guide ANSSI v3.00
- [ ] Si nouveau parsing de données externes : cible de fuzzing ajoutée
- [ ] Si nouveau scénario de menace : mise à jour de `EBIOS-RM-analysis.md`
- [ ] Cross-compilation ARMv7 testée : `cargo build --target armv7-unknown-linux-gnueabihf --release`

---

## 5. Fuzzing

### 5.1 Philosophie

**Toute fonction qui parse des données externes** (bundle, header, manifest CBOR, commandes TPM) **doit avoir une cible de fuzzing**. Le fuzzing n'est pas optionnel — c'est une exigence de sécurité.

### 5.2 Cibles de fuzzing

| Cible | Fichier | Description | Corpus initial |
|---|---|---|---|
| `bundle_header` | `fuzz/fuzz_targets/bundle_header.rs` | Parsing du header de bundle | Bundles valides générés par `bundle-tool` |
| `bundle_chunk` | `fuzz/fuzz_targets/bundle_chunk.rs` | Décryptage et validation d'un chunk | Chunks extraits de bundles valides |
| `jail_manifest` | `fuzz/fuzz_targets/jail_manifest.rs` | Parsing CBOR du manifeste de jail | Manifestes valides |
| `tpm_command` | `fuzz/fuzz_targets/tpm_command.rs` | Parsing des commandes/réponses TPM | Traces de commandes TPM légitimes |
| `state_machine` | `fuzz/fuzz_targets/state_machine.rs` | Séquences d'états du démon | Séquences d'états valides |

### 5.3 Lancer le fuzzing

```bash
# Fuzzing continu (jusqu'à Ctrl-C)
make docker-fuzz TARGET=bundle_header

# Fuzzing avec timeout (5 minutes)
make docker-fuzz-short TARGET=bundle_header DURATION=300

# Fuzzing de toutes les cibles en parallèle
make docker-fuzz-all DURATION=600
```

### 5.4 Gestion des crashes

Les crashes sont sauvegardés dans `fuzz/artifacts/<target>/`. Quand un crash est découvert :

1. **Reproduire** : `cargo fuzz run <target> fuzz/artifacts/<target>/crash-<hash>`
2. **Minimiser** : `cargo fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>`
3. **Créer un test de non-régression** : copier le crash minimisé dans `tests/fixtures/regressions/`
4. **Corriger le bug** et vérifier que le test passe
5. **Ajouter le cas au corpus** : `cp crash-minimized fuzz/corpus/<target>/`

### 5.5 Connexion agent-fuzzer

Le script `scripts/fuzz-run.sh` fournit une interface CLI pour que les agents puissent :

```bash
# Lancer le fuzzer et attendre un résultat
./scripts/fuzz-run.sh --target bundle_header --duration 300 --report json

# Vérifier si des crashes existent
./scripts/fuzz-run.sh --check-crashes --target bundle_header

# Générer un rapport de couverture
./scripts/fuzz-run.sh --coverage --target bundle_header
```

Voir `scripts/fuzz-run.sh --help` pour toutes les options.

---

## 6. Tests

### 6.1 Types de tests requis

| Type | Emplacement | Fréquence | Obligatoire |
|---|---|---|---|
| Tests unitaires | `src/` (inline `#[cfg(test)]`) | Chaque commit | ✅ Oui |
| Tests d'intégration | `tests/` | Chaque PR | ✅ Oui |
| Tests de fuzzing | `fuzz/fuzz_targets/` | Chaque PR (5 min) | ✅ Oui |
| Tests de sécurité | `tests/security/` | Chaque release | ✅ Oui |
| Tests de performance | `benches/` | Chaque release | ⚠️ Recommandé |

### 6.2 Tests de sécurité spécifiques

Ces tests doivent exister et passer avant chaque release :

- **Anti-rollback** : un bundle avec version inférieure au compteur NV est rejeté
- **Signature invalide** : un bundle avec signature altérée est rejeté
- **Chiffrement invalide** : un chunk avec tag GCM invalide est rejeté
- **Replay** : un bundle déjà appliqué (même nonce) est rejeté
- **Overflow** : un header avec `chunk_count` > limite est rejeté
- **Time-of-check/time-of-use** : le header vérifié est le même que celui utilisé

### 6.3 Couverture de code

Objectif : **≥ 80 %** de couverture sur les crates `update-bundle` et `update-tpm`.

```bash
# Dans le conteneur Docker
make docker-coverage
```

---

## 7. Sécurité

### 7.1 Données sensibles

- **Jamais logger** de clés, nonces, ou matériel cryptographique
- **Zéroisation** : utiliser `zeroize::Zeroize` sur les clés en mémoire après usage
- **Pas de core dumps** : `core::hint::black_box()` sur les secrets, et `mlock()` si possible

### 7.2 Gestion du TPM

- **Sessions chiffrées** (parameter encryption) obligatoires pour toute communication avec le TPM
- **`TPMA_NV_COUNTER`** pour le compteur anti-rollback (incrément monotone garanti)
- **Policy de la KEK** : `PolicyCommandCode` + `PolicyCpHash` + `PolicyAuthorize`

### 7.3 Jail

- **Pas de `CLONE_NEWUSER`** ni **`CLONE_NEWPID`** (choix architectural assumé)
- **Seccomp** : filtre strict sur les syscalls autorisés
- **Capabilities** : drop toutes les capabilities sauf celles explicitement requises
- **Tmpfs** : taille configurable via le manifeste, jamais de persistance

---

## 8. Intégration continue (CI)

### 8.1 Pipeline CI (à implémenter dans `.github/workflows/`)

```yaml
jobs:
  lint:
    - cargo fmt --all --check
    - cargo clippy --all-targets -- -D warnings
  
  test:
    - cargo test --all
    - cargo test --all --release
  
  fuzz:
    - 5 minutes de fuzzing sur chaque cible
  
  cross-compile:
    - cargo build --target armv7-unknown-linux-gnueabihf --release
  
  coverage:
    - cargo tarpaulin --fail-under 80
```

### 8.2 Pré-merge gates

Aucune PR ne peut être mergée si :
- Un lint échoue
- Un test échoue
- Un crash de fuzzing est découvert (non corrigé)
- La couverture < 80 %

---

## 9. Documentation

### 9.1 Types de documentation

| Type | Emplacement | Public |
|---|---|---|
| Spécifications techniques | `docs/spec/` | Développeurs, architectes |
| ADRs | `docs/adr/` | Décisions architecturales |
| Analyse de risque | `docs/EBIOS-RM-analysis.md` | Sécurité, évaluateurs |
| Documentation utilisateur | `README.md`, `docs/README.md` | Intégrateurs |
| Documentation API | Docstrings Rust | Développeurs |

### 9.2 Mise à jour de la documentation

- **Tout changement d'API publique** → mise à jour de `docs/spec/`
- **Tout changement architectural** → nouvel ADR dans `docs/adr/`
- **Tout changement de sécurité** → mise à jour de `EBIOS-RM-analysis.md`

---

## 10. Glossaire

| Terme | Définition |
|---|---|
| **Bundle** | Archive de mise à jour chiffrée et signée |
| **KEK** | Key Encryption Key, scellée dans le TPM |
| **Chunk** | Bloc de données dans le bundle, chiffré en AES-GCM-SIV |
| **Jail** | Environnement isolé (namespaces + seccomp) pour exécuter le script de mise à jour |
| **Slot A/B** | Deux partitions de firmware, une active, une inactive pour mise à jour atomique |
| **CUP** | Phase Critique de Mise à Jour, moment où le payload est traité comme hostile |
| **Policy TPM** | Condition (PCR, commande, hash) qui doit être satisfaite pour utiliser une clé |
| **Mécanisme x3** | Alternative à AES Keywrap natif : 3 déchiffrements AES via policies TPM restreintes |

---

## 11. Contacts et escalade

- **Architecture** : voir `docs/spec/00-overview.md`
- **Sécurité** : voir `docs/EBIOS-RM-analysis.md` et `docs/spec/07-security-analysis.md`
- **Décisions passées** : voir `docs/adr/`
- **Questions ouvertes** : voir les sections « Questions ouvertes » de chaque spec

En cas de doute sur une décision architecturale, **ne pas deviner** — créer un nouvel ADR ou poser la question.

---

## 12. Attribution des commits

Seuls les **commits** créés par un agent s'attribuent — et *seulement dans le
message de commit*, **jamais** dans la documentation ni dans le code :

~~~
Agent: <nom de l'outil CLI de la session>
Model: <nom du modèle de la session>
~~~

`<nom de l'outil CLI de la session>` est l'agent (le hâble) qui opère :
`Claude Code`, `Codex`, `OpenHands`, … ; `<nom du modèle de la session>` est le
modèle indiqué dans le bloc d'environnement de la session en cours (par ex.
`ornith-ai/Ornith-1.5-…`).

Ces deux champs **reflètent** l'état de la session en cours : ils ne doivent
**jamais** être écrits en dur à « Claude Code ». Si la session tourne sur `Codex`
ou `OpenHands`, ils portent le nom de l'outil et du modèle réels. Ce n'est pas
un tag GPL ni une licence : c'est la signature de ce qui a exécuté
l'opération.