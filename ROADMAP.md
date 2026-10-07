# ROADMAP.md — Plan de développement détaillé

Ce document est la checklist de développement pour `update-rs`. Chaque tâche peut être cochée par un agent (humain ou IA) au fur et à mesure de son avancement.

**Légende** :
- ⬜ Non commencé
- 🔶 En cours
- ✅ Terminé
- ❌ Bloqué (raison dans la note)

---

## Phase 0 — Infrastructure de build

**Objectif** : Mettre en place l'environnement de développement Docker et la CI.

### 0.1 Docker

- [x] ✅ Créer `docker/Dockerfile` multi-stage (build + runtime)
- [x] ✅ Installer Rust stable + nightly (pour fuzzing)
- [x] ✅ Installer cross-compilation toolchain (`gcc-arm-linux-gnueabihf`)
- [x] ✅ Installer TPM2-TSS (libtss2-dev) et headers
- [x] ✅ Installer QEMU user-mode pour exécuter les binaires ARMv7
- [x] ✅ Installer `cargo-fuzz` (nightly)
- [x] ✅ Installer `cargo-tarpaulin` pour la couverture
- [x] ✅ Configurer le cache Docker (layer caching optimal)
- [ ] ⬜ Tester `docker build -t update-rs:dev .` (infrastructure prête, test à valider)
- [ ] ⬜ Tester cross-compilation ARMv7 dans le conteneur (infrastructure prête, test à valider)
- [x] ✅ Créer `docker/docker-compose.yml` pour faciliter l'usage
- [x] ✅ Documenter l'usage Docker dans `AGENTS.md` § 2

### 0.2 Scripts de build

- [x] ✅ Créer `Makefile` avec les targets : `build`, `test`, `lint`, `fuzz`, `coverage`, `docker-*`
- [x] ✅ Créer `scripts/build.sh` pour le build cross-compilation
- [x] ✅ Créer `scripts/fuzz-run.sh` pour le fuzzing avec reporting
- [x] ✅ Créer `scripts/check-pr.sh` qui vérifie tous les pre-merge gates

### 0.3 CI/CD

- [ ] ⬜ Créer `.github/workflows/ci.yml` (GitHub Actions)
- [ ] ⬜ Job `lint` : `cargo fmt --check` + `cargo clippy -- -D warnings`
- [ ] ⬜ Job `test` : `cargo test --all` + `cargo test --all --release`
- [ ] ⬜ Job `fuzz` : 5 minutes de fuzzing sur chaque cible
- [ ] ⬜ Job `cross-compile` : build ARMv7
- [ ] ⬜ Job `coverage` : `cargo tarpaulin --fail-under 80`
- [ ] ⬜ Job `security-audit` : `cargo audit` (vérifier les CVEs dans les dépendances)
- [ ] ⬜ Configurer les pre-merge gates (tous les jobs doivent passer)
- [ ] ⬜ Configurer les notifications (Slack, email, ou autre)

**Critère de succès** : Un agent peut cloner le repo, lancer `make docker-shell`, et avoir un environnement de développement complet en < 5 minutes.

---

## Phase 1 — Crate `update-bundle` (format de bundle)

**Spécification** : `docs/spec/02-bundle-format.md`

### 1.1 Structures de données

- [ ] ⬜ Définir `BundleHeader` (1024 octets, repr(C))
  - [ ] ⬜ Magic number (4 octets)
  - [ ] ⬜ Version (u16)
  - [ ] ⬜ Flags (u16)
  - [ ] ⬜ `bundle_hash` (SHA-256, 32 octets)
  - [ ] ⬜ `nonce` (16 octets)
  - [ ] ⬜ `kek_id` (16 octets)
  - [ ] ⬜ `wrapped_session_key` (40 octets, RFC 5649 ou mécanisme x3)
  - [ ] ⬜ `keywrap_alg` (u16 : 0x0001 = RFC 5649, 0x0002 = x3)
  - [ ] ⬜ `chunk_count` (u32)
  - [ ] ⬜ `chunk_size` (u32, défaut 64 KiB)
  - [ ] ⬜ `manifest_size` (u32)
  - [ ] ⬜ Signature Ed25519 (64 octets)
  - [ ] ⬜ Signature ML-DSA (2420 octets, post-quantique)
  - [ ] ⬜ Padding pour atteindre 1024 octets
- [ ] ⬜ Définir `BundleChunk` (header de chunk + données chiffrées)
  - [ ] ⬜ `chunk_index` (u32)
  - [ ] ⬜ `chunk_size` (u32)
  - [ ] ⬜ `tag` AES-GCM-SIV (16 octets)
  - [ ] ⬜ Données chiffrées (taille variable)
- [ ] ⬜ Définir `JailManifest` (CBOR)
  - [ ] ⬜ `entry_point` (chemin du script/binaire)
  - [ ] ⬜ `root_tmpfs_size` (u64, octets)
  - [ ] ⬜ `bind_mounts` (liste de chemins hôte → jail)
  - [ ] ⬜ `devices` (liste de dev nodes à créer)
  - [ ] ⬜ `capabilities` (liste de capabilities à conserver)
  - [ ] ⬜ `env_vars` (variables d'environnement)
  - [ ] ⬜ `timeout` (u32, secondes)
- [ ] ⬜ Définir les enums `BundleError`, `ParseError`, `CryptoError`

### 1.2 Parsing et validation

- [ ] ⬜ Implémenter `BundleReader` (lecture streaming depuis `Read`)
  - [ ] ⬜ `read_header()` : lire et parser le header (1024 octets)
  - [ ] ⬜ `validate_header()` : vérifier magic, version, bornes
  - [ ] ⬜ `verify_signature()` : vérifier Ed25519 + ML-DSA (optionnel)
  - [ ] ⬜ `decrypt_session_key()` : déchiffrer via RFC 5649 ou mécanisme x3
  - [ ] ⬜ `read_chunk()` : lire un chunk, vérifier tag GCM, déchiffrer
  - [ ] ⬜ `read_manifest()` : lire et parser le manifeste CBOR
- [ ] ⬜ Implémenter la validation des bornes
  - [ ] ⬜ `chunk_count` ≤ `MAX_CHUNKS` (configurable, défaut 1000)
  - [ ] ⬜ `chunk_size` ≤ `MAX_CHUNK_SIZE` (configurable, défaut 10 MiB)
  - [ ] ⬜ `manifest_size` ≤ `MAX_MANIFEST_SIZE` (configurable, défaut 1 MiB)
- [ ] ⬜ Implémenter le hash global du bundle (SHA-256)
  - [ ] ⬜ Hasher tout le bundle (header + chunks + manifest)
  - [ ] ⬜ Comparer avec `bundle_hash` du header avant l'exécution
- [ ] ⬜ Implémenter l'AEAD par chunk (AES-GCM-SIV)
  - [ ] ⬜ AAD structurée : `bundle_hash || chunk_index || chunk_size`
  - [ ] ⬜ Nonce dérivé : `nonce_bundle || chunk_index`
  - [ ] ⬜ Vérifier le tag avant de déchiffrer

### 1.3 Tests unitaires

- [ ] ⬜ Tests de parsing de header valide
- [ ] ⬜ Tests de parsing de header invalide (magic, version, bornes)
- [ ] ⬜ Tests de vérification de signature (valide, invalide, altérée)
- [ ] ⬜ Tests de déchiffrement de clé de session (RFC 5649, x3)
- [ ] ⬜ Tests de lecture de chunks (valide, invalide, altéré)
- [ ] ⬜ Tests de parsing de manifeste CBOR (valide, invalide)
- [ ] ⬜ Tests de validation des bornes (overflow, underflow)
- [ ] ⬜ Tests de hash global (valide, altéré)

### 1.4 Cibles de fuzzing

- [ ] ⬜ Créer `fuzz/fuzz_targets/bundle_header.rs`
- [ ] ⬜ Créer `fuzz/fuzz_targets/bundle_chunk.rs`
- [ ] ⬜ Créer `fuzz/fuzz_targets/jail_manifest.rs`
- [ ] ⬜ Générer un corpus initial (bundles valides, chunks valides, manifestes valides)
- [ ] ⬜ Lancer 1 heure de fuzzing sur chaque cible
- [ ] ⬜ Corriger les crashes découverts
- [ ] ⬜ Ajouter les crashes minimisés comme tests de non-régression

**Critère de succès** : `update-bundle` peut lire un bundle streamable, vérifier son intégrité, et déchiffrer les chunks sans exposition de la clé de session en mémoire non protégée.

---

## Phase 2 — Crate `update-tpm` (abstraction TPM)

**Spécification** : `docs/spec/03-tpm.md`

### 2.1 Abstraction de base

- [ ] ⬜ Définir `TpmContext` (wrapper autour de `tss-esapi::Context`)
  - [ ] ⬜ `connect()` : ouvrir `/dev/tpmrm0`
  - [ ] ⬜ `get_capability()` : interroger les capacités du TPM
  - [ ] ⬜ `self_test()` : lancer le self-test du TPM
- [ ] ⬜ Définir `TpmError` (erreurs TPM normalisées)
- [ ] ⬜ Implémenter les sessions chiffrées (parameter encryption)
  - [ ] ⬜ `start_auth_session()` : session ECDH avec salage (EK ou SRK)
  - [ ] ⬜ Chiffrer les paramètres sensibles (clés, mots de passe)
  - [ ] ⬜ Déchiffrer les réponses

### 2.2 Scellement et KEK

- [ ] ⬜ Implémenter `seal_key()` : sceller la KEK dans le TPM
  - [ ] ⬜ Policy : `PolicyCommandCode` + `PolicyCpHash` + `PolicyAuthorize`
  - [ ] ⬜ Lier la policy aux PCR (optionnel, configurable)
  - [ ] ⬜ Utiliser `TPM2_Create` avec `fixedTPM` + `fixedParent`
- [ ] ⬜ Implémenter `unseal_key()` : desceller la KEK
  - [ ] ⬜ Satisfaire la policy (signer le digest avec la clé éditeur)
  - [ ] ⬜ Récupérer la clé en mémoire protégée (`mlock` + `zeroize`)
- [ ] ⬜ Implémenter le **mécanisme x3** (3 déchiffrements AES)
  - [ ] ⬜ **Branche 1** : `PolicyCommandCode(TPM2_EncryptDecrypt2)` + `PolicyCpHash(args1)` + `PolicyAuthorize`
  - [ ] ⬜ **Branche 2** : `PolicyCommandCode(TPM2_EncryptDecrypt2)` + `PolicyCpHash(args2)` + `PolicyAuthorize`
  - [ ] ⬜ **Branche 3** : `PolicyCommandCode(TPM2_EncryptDecrypt2)` + `PolicyCpHash(args3)` + `PolicyAuthorize`
  - [ ] ⬜ `decrypt_x3()` : effectuer les 3 déchiffrements AES, combiner le résultat
  - [ ] ⬜ Zéroiser les clés intermédiaires après usage
- [ ] ⬜ Implémenter le support **AES Keywrap natif** (si supporté par le TPM)
  - [ ] ⬜ Détecter le support via `TPM2_GetCapability`
  - [ ] ⬜ Utiliser `TPM2_EncryptDecrypt2` avec mode AES-KW si disponible

### 2.3 NV et compteur anti-rollback

- [ ] ⬜ Implémenter `nv_write()` : écrire dans un index NV
- [ ] ⬜ Implémenter `nv_read()` : lire depuis un index NV
- [ ] ⬜ Implémenter `counter_increment()` : incrémenter un compteur monotone
  - [ ] ⬜ Utiliser `TPMA_NV_COUNTER` (incrément garanti par le TPM)
  - [ ] ⬜ Permissions : `TPMA_NV_AUTHWRITE` + `TPMA_NV_OWNERREAD`
- [ ] ⬜ Implémenter `counter_read()` : lire la valeur du compteur
- [ ] ⬜ Implémenter `check_version()` : vérifier que la version du bundle ≥ compteur

### 2.4 PCR

- [ ] ⬜ Implémenter `pcr_extend()` : étendre un PCR avec un hash
- [ ] ⬜ Implémenter `pcr_read()` : lire la valeur d'un PCR
- [ ] ⬜ Implémenter `pcr_policy()` : créer une policy liée à des PCR
- [ ] ⬜ Documenter quels PCR utiliser (configurable par l'intégrateur)

### 2.5 Tests unitaires

- [ ] ⬜ Tests avec `swtpm` (simulateur TPM)
- [ ] ⬜ Tests de scellement/descellement
- [ ] ⬜ Tests du mécanisme x3 (3 branches)
- [ ] ⬜ Tests de NV (write, read, counter)
- [ ] ⬜ Tests de PCR (extend, read, policy)
- [ ] ⬜ Tests de sessions chiffrées
- [ ] ⬜ Tests d'erreur (TPM busy, TPM error, permissions)

### 2.6 Cibles de fuzzing

- [ ] ⬜ Créer `fuzz/fuzz_targets/tpm_command.rs`
- [ ] ⬜ Fuzzer les commandes TPM envoyées au simulateur
- [ ] ⬜ Fuzzer les réponses TPM (parser des réponses malformées)

**Critère de succès** : `update-tpm` peut sceller une KEK, la desceller avec policy, incrémenter un compteur monotone, et fonctionner avec les deux modes (AES Keywrap natif et mécanisme x3).

---

## Phase 3 — Crate `update-slot` (gestion A/B)

**Spécification** : `docs/spec/04-update-flow.md`

### 3.1 Gestion des slots

- [ ] ⬜ Définir `SlotId` (A ou B)
- [ ] ⬜ Définir `SlotInfo` (version, hash, état)
- [ ] ⬜ Implémenter `get_active_slot()` : lire le slot actif depuis le bootloader
- [ ] ⬜ Implémenter `get_inactive_slot()` : déterminer le slot inactif
- [ ] ⬜ Implémenter `set_active_slot()` : basculer le slot actif (via bootloader)
- [ ] ⬜ Implémenter `get_slot_info()` : lire les infos d'un slot (version, hash)

### 3.2 Interface bootloader

- [ ] ⬜ Définir l'interface avec le bootloader (U-Boot env, `libubootenv`, ou autre)
- [ ] ⬜ Implémenter `read_boot_env()` : lire les variables d'environnement du bootloader
- [ ] ⬜ Implémenter `write_boot_env()` : écrire les variables d'environnement
- [ ] ⬜ Implémenter `commit_update()` : marquer la mise à jour comme réussie
- [ ] ⬜ Implémenter `rollback()` : revenir au slot précédent

### 3.3 Health-check et rollback

- [ ] ⬜ Implémenter `health_check()` : vérifier que le nouveau slot est bootable
  - [ ] ⬜ Vérifier la signature du kernel
  - [ ] ⬜ Vérifier l'intégrité du rootfs
  - [ ] ⬜ Vérifier les services critiques
- [ ] ⬜ Implémenter `rollback_on_failure()` : rollback automatique si health-check échoue
- [ ] ⬜ Implémenter `boot_count` : compter les tentatives de boot, rollback après N échecs

### 3.4 Tests unitaires

- [ ] ⬜ Tests de détection de slot actif/inactif
- [ ] ⬜ Tests de bascule de slot
- [ ] ⬜ Tests de health-check (succès, échec)
- [ ] ⬜ Tests de rollback
- [ ] ⬜ Tests avec bootloader simulé (mock)

**Critère de succès** : `update-slot` peut détecter le slot actif, basculer vers le slot inactif, et effectuer un rollback automatique en cas d'échec.

---

## Phase 4 — Démon `updated`

**Spécification** : `docs/spec/04-update-flow.md`

### 4.1 Machine à états

- [ ] ⬜ Définir les états : `Idle`, `AcquiringLock`, `Fetching`, `Verifying`, `PreparingJail`, `AssemblingJail`, `ExecutingJail`, `CleaningJail`, `LockHeld`, `Rejected`, `Error`
- [ ] ⬜ Définir les transitions entre états
- [ ] ⬜ Implémenter `StateMachine` avec pattern matching exhaustif
- [ ] ⬜ Logger chaque transition avec `tracing`

### 4.2 Verrouillage d'instance

- [ ] ⬜ Implémenter `acquire_lock()` : `flock(LOCK_EX | LOCK_NB)` sur `/var/run/update-rs.lock`
- [ ] ⬜ Implémenter `release_lock()` : libération explicite ou automatique
- [ ] ⬜ Gérer le cas où le verrou est déjà tenu (`LockHeld`)

### 4.3 Fetching (récupération du bundle)

- [ ] ⬜ Implémenter `fetch_bundle()` : lecture streaming depuis une source (fichier, socket)
- [ ] ⬜ Supporter la reprise de téléchargement (optionnel, côté client)
- [ ] ⬜ Calculer le hash global du bundle pendant la lecture

### 4.4 Verifying (vérification du header)

- [ ] ⬜ **Fork d'un processus fils** pour la vérification (isolation)
- [ ] ⬜ Le fils lit et parse le header
- [ ] ⬜ Le fils vérifie la signature (Ed25519 + ML-DSA)
- [ ] ⬜ Le fils vérifie l'anti-rollback (version ≥ compteur NV)
- [ ] ⬜ Le fils déchiffre la clé de session via le TPM
- [ ] ⬜ Le fils retourne la clé de session au père via **pipe Unix sécurisé**
- [ ] ⬜ Le père vérifie que le fils a terminé avec succès (`waitpid`)

### 4.5 Gestion des signaux

- [ ] ⬜ Installer les handlers pour `SIGTERM`, `SIGINT`, `SIGHUP`
- [ ] ⬜ Handlers async-signal-safe : flag atomique `CLEANUP_REQUESTED`
- [ ] ⬜ Cleanup hors du handler (démontage récursif, tmpfs, lock file)
- [ ] ⬜ Handler pour `SIGCHLD` (notification de fin du fils)
- [ ] ⬜ Handler pour `SIGALRM` (timeout du jail)

### 4.6 Cleanup garanti

- [ ] ⬜ Implémenter `cleanup()` : démontage récursif, libération tmpfs, lock file
- [ ] ⬜ `updated --cleanup` : lancé au boot pour nettoyer les mounts orphelins
- [ ] ⬜ Timer périodique pour détecter les artefacts orphelins

### 4.7 Socket Unix (canal de contrôle)

- [ ] ⬜ Créer le socket Unix `/var/run/updated.sock`
- [ ] ⬜ Authentification via `SO_PEERCRED` (UID/GID/PID du client)
- [ ] ⬜ Définir le protocole (commandes : `check`, `apply`, `status`, `rollback`)
- [ ] ⬜ Logger les commandes reçues avec le PID/UID du client

### 4.8 Tests unitaires

- [ ] ⬜ Tests de la machine à états (toutes les transitions)
- [ ] ⬜ Tests de verrouillage (instance unique, instance multiple)
- [ ] ⬜ Tests de gestion des signaux (SIGTERM, SIGINT, SIGALRM)
- [ ] ⬜ Tests de cleanup (normal, crash, mounts orphelins)
- [ ] ⬜ Tests du socket Unix (authentification, commandes)

### 4.9 Cible de fuzzing

- [ ] ⬜ Créer `fuzz/fuzz_targets/state_machine.rs`
- [ ] ⬜ Fuzzer les séquences d'états et de transitions

**Critère de succès** : `updated` peut acquérir un verrou, fetcher un bundle, le vérifier dans un processus fils, préparer et exécuter un jail, et nettoyer après exécution.

---

## Phase 5 — Jail (isolation)

**Spécification** : `docs/spec/06-jail.md`

### 5.1 Namespaces

- [ ] ⬜ Implémenter `unshare()` pour les namespaces : `CLONE_NEWNS`, `CLONE_NEWIPC`, `CLONE_NEWUTS`
- [ ] ⬜ **Pas de `CLONE_NEWUSER`** ni **`CLONE_NEWPID`** (choix assumé)
- [ ] ⬜ Monter un tmpfs comme racine (`root_tmpfs_size` configurable)
- [ ] ⬜ Appliquer les bind mounts du manifeste
- [ ] ⬜ Créer les dev nodes du manifeste

### 5.2 Pivot root et drop privileges

- [ ] ⬜ `pivot_root()` vers le tmpfs
- [ ] ⬜ Démonter l'ancienne racine
- [ ] ⬜ Drop toutes les capabilities sauf celles du manifeste
- [ ] ⬜ Appliquer `securebits` (no_new_privs, etc.)

### 5.3 Seccomp

- [ ] ⬜ Définir le filtre seccomp (whitelist de syscalls)
- [ ] ⬜ Appliquer le filtre avec `seccomp(SECCOMP_SET_MODE_FILTER, ...)`
- [ ] ⬜ Tester que les syscalls interdits sont bien bloqués

### 5.4 Cgroups

- [ ] ⬜ Limiter le nombre de processus (PID)
- [ ] ⬜ Limiter la mémoire (RSS + swap)
- [ ] ⬜ Limiter le CPU (quota)
- [ ] ⬜ Limiter les I/O (bandwidth)

### 5.5 Exécution du script

- [ ] ⬜ `execve()` du script/binaire d'entrée
- [ ] ⬜ Capturer stdout/stderr vers un log dédié
- [ ] ⬜ Appliquer le timeout du manifeste (`SIGALRM` → `SIGKILL`)
- [ ] ⬜ Récupérer le code de retour

### 5.6 Démontage et cleanup

- [ ] ⬜ Démonter récursivement le tmpfs
- [ ] ⬜ Libérer les namespaces
- [ ] ⬜ Supprimer le socket Unix (si créé)

### 5.7 Tests unitaires

- [ ] ⬜ Tests de création de namespaces
- [ ] ⬜ Tests de pivot root
- [ ] ⬜ Tests de drop privileges
- [ ] ⬜ Tests de seccomp (syscalls autorisés, interdits)
- [ ] ⬜ Tests de cgroups (limites atteintes)
- [ ] ⬜ Tests de timeout (script trop long)
- [ ] ⬜ Tests de cleanup (normal, crash)

**Critère de succès** : Le jail peut isoler un script, limiter ses ressources, et le nettoyer complètement après exécution.

---

## Phase 6 — Outil `bundle-tool` (création de bundles)

**Spécification** : `docs/spec/02-bundle-format.md`

### 6.1 Création de bundles

- [ ] ⬜ `bundle-tool create` : créer un bundle à partir d'un répertoire
  - [ ] ⬜ Générer la clé de session (AES-256, random)
  - [ ] ⬜ Chiffrer chaque chunk en AES-GCM-SIV
  - [ ] ⬜ Calculer le hash global du bundle
  - [ ] ⬜ Chiffrer la clé de session via RFC 5649 ou mécanisme x3
  - [ ] ⬜ Signer le header avec Ed25519 + ML-DSA
  - [ ] ⬜ Écrire le bundle streamable (header + chunks + manifest)

### 6.2 Signature

- [ ] ⬜ `bundle-tool sign` : signer un bundle existant
  - [ ] ⬜ Charger la clé privée (fichier, HSM, ou TPM)
  - [ ] ⬜ Calculer le hash du header
  - [ ] ⬜ Signer avec Ed25519 + ML-DSA
  - [ ] ⬜ Écrire les signatures dans le header

### 6.3 Chiffrement

- [ ] ⬜ `bundle-tool encrypt` : chiffrer un bundle existant
  - [ ] ⬜ Charger la KEK (fichier, TPM)
  - [ ] ⬜ Générer la clé de session
  - [ ] ⬜ Chiffrer les chunks
  - [ ] ⬜ Chiffrer la clé de session

### 6.4 Vérification

- [ ] ⬜ `bundle-tool verify` : vérifier un bundle
  - [ ] ⬜ Vérifier la signature
  - [ ] ⬜ Vérifier le hash global
  - [ ] ⬜ Vérifier l'intégrité des chunks

### 6.5 Extraction

- [ ] ⬜ `bundle-tool extract` : extraire le contenu d'un bundle
  - [ ] ⬜ Déchiffrer les chunks
  - [ ] ⬜ Écrire les fichiers extraits

### 6.6 Tests unitaires

- [ ] ⬜ Tests de création de bundle (valide, invalide)
- [ ] ⬜ Tests de signature (valide, invalide)
- [ ] ⬜ Tests de chiffrement (valide, invalide)
- [ ] ⬜ Tests de vérification (valide, invalide, altéré)
- [ ] ⬜ Tests d'extraction (valide, invalide)
- [ ] ⬜ Tests de round-trip (create → extract, vérification intégrité)

**Critère de succès** : `bundle-tool` peut créer, signer, chiffrer, vérifier et extraire des bundles conformes à la spécification.

---

## Phase 7 — CLI `updatectl`

**Spécification** : `docs/spec/04-update-flow.md`

### 7.1 Commandes

- [ ] ⬜ `updatectl check <URI>` : vérifier si une mise à jour est disponible
  - [ ] ⬜ Télécharger le manifeste (ou le bundle)
  - [ ] ⬜ Vérifier la signature
  - [ ] ⬜ Vérifier l'anti-rollback
  - [ ] ⬜ Afficher les infos de la mise à jour (version, taille, hash)
- [ ] ⬜ `updatectl apply` : appliquer la mise à jour
  - [ ] ⬜ Envoyer la commande au démon via le socket Unix
  - [ ] ⬜ Afficher la progression (fetching, verifying, executing)
  - [ ] ⬜ Afficher le résultat (succès, échec, rollback)
- [ ] ⬜ `updatectl status` : afficher l'état du démon
  - [ ] ⬜ État de la machine à états
  - [ ] ⬜ Slot actif/inactif
  - [ ] ⬜ Dernière mise à jour (succès, échec, date)
- [ ] ⬜ `updatectl rollback` : revenir au slot précédent
  - [ ] ⬜ Envoyer la commande au démon
  - [ ] ⬜ Confirmer le rollback

### 7.2 Authentification

- [ ] ⬜ Utiliser `SO_PEERCRED` pour authentifier le client
- [ ] ⬜ Vérifier que le client est root (ou dans un groupe autorisé)
- [ ] ⬜ Logger les commandes avec le PID/UID du client

### 7.3 Tests unitaires

- [ ] ⬜ Tests de chaque commande (check, apply, status, rollback)
- [ ] ⬜ Tests d'authentification (root, non-root)
- [ ] ⬜ Tests de communication avec le démon (socket Unix)

**Critère de succès** : `updatectl` peut vérifier, appliquer, et rollback une mise à jour via le démon.

---

## Phase 8 — Tests d'intégration

### 8.1 Tests end-to-end

- [ ] ⬜ Créer un bundle valide avec `bundle-tool`
- [ ] ⬜ Lancer `updated` dans un conteneur Docker (avec `swtpm`)
- [ ] ⬜ Utiliser `updatectl check` pour vérifier la disponibilité
- [ ] ⬜ Utiliser `updatectl apply` pour appliquer la mise à jour
- [ ] ⬜ Vérifier que le slot actif a basculé
- [ ] ⬜ Vérifier que le cleanup a été effectué

### 8.2 Tests de sécurité

- [ ] ⬜ Test d'anti-rollback : bundle avec version < compteur → rejeté
- [ ] ⬜ Test de signature invalide : bundle altéré → rejeté
- [ ] ⬜ Test de chiffrement invalide : chunk altéré → rejeté
- [ ] ⬜ Test de replay : bundle déjà appliqué → rejeté
- [ ] ⬜ Test d'overflow : header avec bornes invalides → rejeté
- [ ] ⬜ Test de TOCTOU : header modifié entre vérification et utilisation → détecté

### 8.3 Tests de performance

- [ ] ⬜ Mesurer le temps de vérification d'un bundle de 100 MiB
- [ ] ⬜ Mesurer le temps de déchiffrement d'un chunk de 64 KiB
- [ ] ⬜ Mesurer la latence du TPM (scellement, descellement, NV)
- [ ] ⬜ Mesurer l'empreinte mémoire du démon

### 8.4 Tests de résilience

- [ ] ⬜ Coupure d'alimentation pendant fetching → système bootable
- [ ] ⬜ Coupure d'alimentation pendant verifying → système bootable
- [ ] ⬜ Coupure d'alimentation pendant executing → système bootable
- [ ] ⬜ Crash du démon → cleanup automatique au reboot
- [ ] ⬜ Timeout du script → kill récursif, cleanup

**Critère de succès** : Tous les tests d'intégration passent, y compris les tests de sécurité et de résilience.

---

## Phase 9 — Fuzzing et durcissement

### 9.1 Fuzzing continu

- [ ] ⬜ Lancer 24h de fuzzing sur chaque cible
- [ ] ⬜ Corriger tous les crashes découverts
- [ ] ⬜ Ajouter les crashes minimisés comme tests de non-régression
- [ ] ⬜ Atteindre ≥ 90 % de couverture sur les parsers

### 9.2 Audit de sécurité

- [ ] ⬜ Audit du code cryptographique (guide ANSSI v3.00)
- [ ] ⬜ Audit du code TPM (spécification 1.59)
- [ ] ⬜ Audit du jail (namespaces, seccomp, cgroups)
- [ ] ⬜ Audit de la machine à états (transitions, cleanup)
- [ ] ⬜ Revue des dépendances (CVEs, licences)

### 9.3 Durcissement

- [ ] ⬜ Ajouter `mlock()` sur les clés en mémoire
- [ ] ⬜ Ajouter `zeroize` sur toutes les données sensibles
- [ ] ⬜ Ajouter `core::hint::black_box()` sur les secrets
- [ ] ⬜ Désactiver les core dumps (`prctl(PR_SET_DUMPABLE, 0)`)
- [ ] ⬜ Utiliser `seccomp` strict sur le démon (pas seulement le jail)

**Critère de succès** : Aucun crash de fuzzing non corrigé, audit de sécurité passé, durcissement complet.

---

## Phase 10 — Documentation et déploiement

### 10.1 Documentation

- [ ] ⬜ Mettre à jour `README.md` avec les instructions d'installation
- [ ] ⬜ Créer un guide d'intégration (`docs/integration-guide.md`)
- [ ] ⬜ Créer un guide de sécurité (`docs/security-guide.md`)
- [ ] ⬜ Documenter les prérequis d'intégration (`docs/prerequis-integration.md`)
- [ ] ⬜ Créer des exemples de configuration

### 10.2 Déploiement

- [ ] ⬜ Créer une image Docker de production (minimal, sécurisée)
- [ ] ⬜ Créer un package Debian/Ubuntu (`.deb`)
- [ ] ⬜ Créer un package Buildroot/Yocto
- [ ] ⬜ Tester le déploiement sur Clearfog Pro réelle
- [ ] ⬜ Documenter la procédure de mise en production

### 10.3 Release

- [ ] ⬜ Taguer la version 1.0.0
- [ ] ⬜ Publier les binaires signés
- [ ] ⬜ Publier la documentation
- [ ] ⬜ Annoncer la release (blog, mailing list, etc.)

**Critère de succès** : Documentation complète, packages disponibles, release 1.0.0 publiée.

---

## Résumé des phases

| Phase | Description | Tâches | Estimé |
|---|---|---|---|
| 0 | Infrastructure de build | ~25 tâches | 1-2 semaines |
| 1 | Crate `update-bundle` | ~40 tâches | 2-3 semaines |
| 2 | Crate `update-tpm` | ~35 tâches | 2-3 semaines |
| 3 | Crate `update-slot` | ~20 tâches | 1-2 semaines |
| 4 | Démon `updated` | ~35 tâches | 2-3 semaines |
| 5 | Jail | ~25 tâches | 1-2 semaines |
| 6 | Outil `bundle-tool` | ~25 tâches | 1-2 semaines |
| 7 | CLI `updatectl` | ~15 tâches | 1 semaine |
| 8 | Tests d'intégration | ~20 tâches | 1-2 semaines |
| 9 | Fuzzing et durcissement | ~15 tâches | 2-3 semaines |
| 10 | Documentation et déploiement | ~15 tâches | 1-2 semaines |

**Total estimé** : ~270 tâches, 14-24 semaines (3.5-6 mois) pour une équipe de 1-2 développeurs.
