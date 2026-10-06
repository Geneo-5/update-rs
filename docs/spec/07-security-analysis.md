# 07 — Analyse de sécurité approfondie

Statut : Brouillon (analyse critique à valider)

Ce document complète le modèle de menace (`01-threat-model.md`) en identifiant :
1. Les scénarios d'attaque non encore couverts
2. Les points de sécurité à clarifier ou à trancher
3. Les recommandations du guide Rust ANSSI applicables au projet

---

## 1. Scénarios d'attaque non encore couverts

### 1.1 Attaques sur le daemon de mise à jour

#### A9 — Compromission du daemon root
**Description** : Un attaquant ayant obtenu root (via une vulnérabilité kernel, un service exposé, ou un payload jail s'échappant) peut :
- Intercepter la clé de session en RAM avant qu'elle ne soit effacée
- Court-circuiter la vérification TPM en appelant directement le déchiffrement
- Installer un bundle malveillant sans vérification
- Corrompre l'index NV du TPM (anti-rollback counter)

**Mitigations proposées** :
- Fork du daemon en fils dédié à la vérification (déjà prévu dans `03-tpm.md`)
- **Architecture supervisor/worker** : le worker (sandboxé) parse et valide le bundle, le supervisor (privilégié) applique la policy et effectue les opérations critiques
- **Phase Critique de Mise à Jour (CUP)** : toute opération transformant des données du bundle en état persistant est traitée comme critique
- **NOUVEAU** : Utiliser `seccomp` sur le supervisor pour limiter les syscalls (uniquement `fork`, `waitpid`, `mount`, `umount2`, `pivot_root`, `execve`, `openat2`, `read`, `write`, `close`, `ioctl`, `flock`)
- **NOUVEAU** : `prctl(PR_SET_DUMPABLE, 0)` pour empêcher `ptrace` et core dumps
- **NOUVEAU** : `prctl(PR_SET_NO_NEW_PRIVS, 1)` même sur le supervisor (défense en profondeur)
- **NOUVEAU** : Verrouiller la mémoire avec `mlockall(MCL_CURRENT | MCL_FUTURE)` pour empêcher swap vers disque
- **NOUVEAU** : Utiliser `setrlimit(RLIMIT_CORE, 0)` pour désactiver les core dumps
- **NOUVEAU** : `prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NO_SETUID_FIXUP | SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_CAP_AMBIENT_RAISE)` comme dans le jail

#### A10 — Attaque temporelle (timing attack) sur la vérification
**Description** : Un attaquant local peut mesurer le temps de vérification du header pour détecter :
- Si la signature est valide (temps plus long si vérification réussie)
- Si le hash correspond (temps de hash variable selon la taille)
- Si le TPM accepte la policy (temps de déchiffrement vs rejet)

**Mitigations proposées** :
- **NOUVEAU** : Constant-time verification (impossible pour signature ECC, mais possible pour comparaison de hash)
- **NOUVEAU** : Ajouter un délai aléatoire (jitter) après chaque vérification pour masquer les timings
- **NOUVEAU** : Logger les temps de vérification pour détection d'anomalies

#### A11 — Attaque par exhaustion des ressources TPM
**Description** : Un attaquant peut envoyer de multiples requêtes de déchiffrement avec des headers invalides pour :
- Épuiser les ressources TPM (sessions, mémoire interne)
- Déclencher des lockout TPM (si trop d'échecs)
- Créer une DoS sur le service de mise à jour

**Mitigations proposées** :
- **NOUVEAU** : Rate limiting sur les tentatives de déchiffrement (max 10/min par IP si daemon réseau, max 3 tentatives consécutives sinon)
- **NOUVEAU** : Exponential backoff après chaque échec (1s, 2s, 4s, 8s, ...)
- **NOUVEAU** : Verrouillage temporaire du service après 5 échecs consécutifs (5 minutes)
- **NOUVEAU** : Monitoring des erreurs TPM et alertes

### 1.2 Attaques sur le jail et le payload

Identifiants `JE*` (jail, évasion), distincts des menaces J1 à J4 de [01-threat-model.md](01-threat-model.md) et de la surface d'attaque `JS1`–`JS11` de [06-jail.md](06-jail.md).

#### JE1 — Attaque par évasion via device nodes
**Description** : Le manifeste peut demander la création de device nodes dangereux :
- `/dev/mem`, `/dev/kmem` : accès mémoire physique
- `/dev/port` : accès ports I/O
- `/dev/nvram` : accès NVRAM
- `/dev/sda`, `/dev/mtd0` : accès stockage brut
- `/dev/cpu/0/msr` : accès Model-Specific Registers

**Mitigations proposées** :
- **NOUVEAU** : Whitelist explicite de device nodes autorisés (ex: `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/console`)
- **NOUVEAU** : Device cgroup avec whitelist stricte (major:minor autorisés)
- **NOUVEAU** : Refuser les device nodes avec major < 10 (réservés aux périphériques critiques)
- **NOUVEAU** : Logger tous les device nodes créés pour audit

#### JE2 — Attaque par évasion via bind mounts récursifs
**Description** : Un bind mount récursif (`MS_REC`) peut monter `/` entier dans le jail, exposant tout le système hôte.

**Mitigations proposées** :
- **NOUVEAU** : Interdire `MS_REC` sur les bind mounts host→jail
- **NOUVEAU** : Valider que la source du bind mount n'est pas `/`, `/etc`, `/root`, `/home`, `/var/log`
- **NOUVEAU** : Utiliser `MS_BIND | MS_NOSYMFOLLOW | MS_RDONLY` par défaut (read-only obligatoire)
- **NOUVEAU** : Si bind mount RW nécessaire, exiger justification explicite dans le manifeste et logger

#### JE3 — Attaque par évasion via `/proc` et `/sys`
**Description** : Même montés en RO, certains fichiers de `/proc` et `/sys` peuvent être dangereux :
- `/proc/sys/kernel/core_pattern` : peut être utilisé pour exécuter du code via core dump
- `/proc/sysrq-trigger` : reboot/halt immédiat
- `/sys/firmware/efi/vars` : modification UEFI variables
- `/sys/kernel/security` : accès LSM (SELinux, AppArmor)

**Mitigations proposées** :
- **NOUVEAU** : Monter `/proc` avec `hidepid=2` (masquer processus des autres users)
- **NOUVEAU** : Bind mount `/proc/sys` en `ro,nodev,noexec,nosuid`
- **NOUVEAU** : Utiliser `mount --bind /dev/null /proc/sysrq-trigger` pour masquer sysrq
- **NOUVEAU** : Ne pas monter `/sys` du tout si non nécessaire, sinon monter en `ro,nodev,noexec,nosuid` et masquer les sous-répertoires dangereux avec bind mounts sur `/dev/null`

#### JE4 — Attaque par évasion via pivot_root mal configuré
**Description** : Si `pivot_root` n'est pas fait correctement, l'ancien root peut rester accessible dans le jail.

**Mitigations proposées** :
- **NOUVEAU** : Après `pivot_root`, démonter l'ancien root avec `umount2(old_root, MNT_DETACH)` immédiatement
- **NOUVEAU** : Vérifier que `chdir("/")` a été fait avant `pivot_root`
- **NOUVEAU** : Logger le succès de `pivot_root` et vérifier que `/` est bien le nouveau root

#### JE5 — Attaque par évasion via environment variables
**Description** : Le processus jail peut hériter de variables d'environnement dangereuses :
- `LD_PRELOAD`, `LD_LIBRARY_PATH` : injection de bibliothèques
- `PATH` : exécution de binaires malveillants
- `HOME`, `USER` : confusion d'identité
- Variables custom contenant des secrets

**Mitigations proposées** :
- **NOUVEAU** : Vider complètement l'environnement avant `execve` (`envp = ["PATH=/usr/bin:/bin"]`)
- **NOUVEAU** : Si variables nécessaires, les passer via le manifeste et les définir explicitement
- **NOUVEAU** : Ne jamais hériter de l'environnement du daemon

#### JE6 — Attaque par évasion via file descriptors
**Description** : Le processus jail peut hériter de file descriptors ouverts :
- Sockets réseau (si daemon avait des connexions)
- Fichiers sensibles (`/etc/shadow`, `/etc/passwd`)
- Pipes vers d'autres processus
- TTY (accès au terminal)

**Mitigations proposées** :
- **NOUVEAU** : Fermer tous les FD > 2 avant `execve` (iter 0..1024, close si ouvert)
- **NOUVEAU** : Rediriger stdin/stdout/stderr vers `/dev/null` ou des pipes de logging
- **NOUVEAU** : Utiliser `O_CLOEXEC` sur tous les FD ouverts par le daemon

### 1.3 Attaques sur le bundle et le transport

#### A12 — Attaque par bundle corrompu partiellement
**Description** : Un attaquant peut corrompre un seul chunk du payload pour :
- Créer un fichier corrompu qui crash le processus jail
- Exploiter une vulnérabilité dans le parser du format de chunk (si non authentifié avant extraction)
- Déclencher un bug dans le format squashfs/erofs/cpio

**Mitigations proposées** :
- **NOUVEAU** : Vérifier l'authenticité de chaque chunk avant extraction (AES-GCM-SIV avec tag 128-bit)
- **NOUVEAU** : Ne jamais extraire un chunk corrompu, arrêter immédiatement et nettoyer
- **NOUVEAU** : Utiliser des parsers robustes pour squashfs/erofs (vérifier la structure avant écriture)

#### A13 — Attaque par bundle trop volumineux
**Description** : Un bundle de plusieurs Go peut :
- Épuiser le tmpfs (espace disque insuffisant)
- Épuiser la mémoire (extraction en RAM)
- Créer une DoS par exhaustion de ressources

**Mitigations proposées** :
- **NOUVEAU** : Limite stricte sur la taille du bundle (ex: 500 MB max)
- **NOUVEAU** : Limite sur le nombre de chunks (ex: 1000 max)
- **NOUVEAU** : Limite sur la taille d'un chunk (ex: 10 MB max)
- **NOUVEAU** : Vérifier que le tmpfs a assez d'espace (statfs) avant extraction
- **NOUVEAU** : Utiliser `RLIMIT_AS` pour limiter la mémoire du processus

#### A14 — Attaque par bundle avec nom de fichier malveillant
**Description** : Le manifeste peut contenir des noms de fichiers dangereux :
- Path traversal : `../../../etc/shadow`
- Noms spéciaux : `/dev/sda`, `../.ssh/authorized_keys`
- Symlinks : créer un lien vers `/etc/passwd`

**Mitigations proposées** :
- **NOUVEAU** : Valider tous les noms de fichiers (pas de `..`, pas de `/` absolu, pas de caractères spéciaux)
- **NOUVEAU** : Résoudre les chemins avec `openat2()` + `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` (pas de `realpath` suivi d'un `open`, sujet aux TOCTOU ; voir [06-jail.md](06-jail.md))
- **NOUVEAU** : Refuser les symlinks dans le payload (ou les résoudre et vérifier la cible)
- **NOUVEAU** : Limiter la longueur des noms (ex: 255 chars max)

### 1.4 Attaques sur le TPM

#### A15 — Attaque par réinitialisation TPM
**Description** : Un attaquant avec accès physique peut :
- Réinitialiser le TPM (effacer toutes les clés)
- Forcer un clear TPM via jumper ou commande
- Remplacer le TPM par un TPM différent

**Mitigations proposées** :
- **NOUVEAU** : Détecter la réinitialisation TPM (vérifier que la KEK existe toujours)
- **NOUVEAU** : Si TPM réinitialisé, invalider le device (bloquer les mises à jour)
- **NOUVEAU** : Utiliser un certificat d'attestation pour prouver l'identité du TPM
- **NOUVEAU** : Logger toute tentative de réinitialisation

#### A16 — Attaque par TPM non authentifié
**Description** : Un attaquant peut remplacer le TPM par un TPM malveillant qui :
- Accepte toutes les policies
- Déchiffre sans vérification
- Fournit des clés de session corrompues

**Mitigations proposées** :
- **NOUVEAU** : Utiliser `TPM2_Quote` pour attester l'identité du TPM (EK certificate)
- **NOUVEAU** : Vérifier le certificat EK contre une CA de confiance
- **NOUVEAU** : Utiliser une session chiffrée avec l'EK pour protéger les commandes

### 1.5 Attaques sur le processus de mise à jour

#### A17 — Attaque par interruption de mise à jour
**Description** : Un attaquant peut couper l'alimentation ou redémarrer le device pendant la mise à jour pour :
- Corrompre le stockage (écriture partielle)
- Laisser le device dans un état instable
- Forcer un rollback vers une version vulnérable

**Mitigations proposées** :
- **NOUVEAU** : Utiliser un système A/B de partitions (slot 0 / slot 1)
- **NOUVEAU** : Écrire le nouveau firmware dans le slot inactif
- **NOUVEAU** : Basculer vers le nouveau slot uniquement après vérification complète
- **NOUVEAU** : Si interruption, rollback automatique vers le slot actif
- **NOUVEAU** : Journaliser l'état de la mise à jour dans NV TPM pour reprise

#### A18 — Attaque par confusion de bundle (mix-and-match)
**Description** : Un attaquant peut combiner :
- Header d'un bundle valide
- Manifeste d'un autre bundle valide
- Chunks d'un troisième bundle valide

**Mitigations proposées** :
- **Traité** ([02-bundle-format.md](02-bundle-format.md)) : le header signé contient `manifest_hash` et `bundle_id` ; le lien manifeste → header est donc porté par la signature du header (un hash du header dans le manifeste serait circulaire)
- **Traité** : l'AAD de chaque chunk inclut `bundle_id` (signé dans le header), `chunk_index`, `chunk_count`, `is_last_chunk` et `chunk_data_length`
- **NOUVEAU** : Vérifier la chaîne de confiance : header → manifeste → chunks

---

## 2. Points de sécurité à clarifier

### 2.1 Architecture du daemon

**Question** : Comment structurer le daemon pour minimiser la surface d'attaque ?

**Options** :
1. **Daemon unique (root)** : tout le code dans un seul processus
   - ✓ Simple
   - ✗ Grande surface d'attaque, une vulnérabilité = compromission totale
   
2. **Daemon père (root) + fils (user)** : père fait fork d'un fils non-root pour la vérification
   - ✓ Isolation, si fils compromis le père reste root mais n'a pas accès au payload
   - ✗ Complexité, communication père-fils
   - **RECOMMANDÉ** (déjà prévu dans `03-tpm.md`)
   
3. **Daemon père (root) + fils (chroot)** : fils dans un chroot temporaire
   - ✓ Isolation renforcée
   - ✗ Complexité, chroot n'est pas une vraie isolation (évasion possible)
   
4. **Daemon père (root) + fils (namespace)** : fils dans un namespace user
   - ✓ Isolation forte (comme le jail)
   - ✗ Complexité, mais cohérent avec l'architecture jail

**Décision recommandée** : Option 2 (déjà prévue) avec ajout de seccomp sur le père et mlockall.

### 2.2 Gestion de la clé de session en mémoire

**Question** : Comment protéger la clé de session une fois déballée par le TPM ?

**Options** :
1. **Clé en clair dans une variable Rust** :
   - ✗ Peut être swappée sur disque
   - ✗ Peut être dumpée via core dump
   - ✗ Peut être lue via ptrace
   
2. **Clé dans un buffer mlock + zeroize** :
   - ✓ Pas de swap
   - ✓ Effacement explicite
   - ✗ Toujours vulnérable à ptrace
   
3. **Clé dans un buffer mlock + zeroize + prctl(PR_SET_DUMPABLE, 0)** :
   - ✓ Pas de swap
   - ✓ Effacement explicite
   - ✓ Pas de core dump
   - ✓ Pas de ptrace
   - **RECOMMANDÉ**

**Décision recommandée** : Option 3 avec wrapper type-safe en Rust.

### 2.3 Support TPM de AES Keywrap

**Question** : Que faire si le TPM ne supporte pas AES Keywrap nativement ?

**Analyse** :
- RFC 5649 (AES Key Wrap with Padding) n'est défini par aucune commande standard de TPM 2.0 : `TPM2_Unwrap` n'existe pas et `TPM2_Duplicate` n'est pas un AES-KW (voir l'avertissement de [03-tpm.md](03-tpm.md)) ; le support réel du TPM cible reste à établir
- Un fallback logiciel exposerait la KEK en RAM, ce qui est inacceptable
- La spécification actuelle exige que la KEK **ne quitte jamais le TPM**

**Options** :
1. **Exiger un TPM avec AES Keywrap natif** :
   - ✓ Simple, pas de fallback
   - ✓ KEK ne quitte jamais le TPM
   - ✗ Limite le choix des TPM
   
2. **Fallback logiciel avec déscellement de la KEK en RAM** :
   - ✗ Expose la KEK en RAM
   - ✗ Contredit REQ-THR-4
   - ✗ Surface d'attaque augmentée
   - **REJETÉ**
   
3. **Mécanisme x3 (3 déchiffrements AES via policies TPM restreintes)** :
   - ✓ La KEK ne quitte jamais le TPM (déchiffrements effectués par le TPM)
   - ✓ Permet de limiter les commandes et arguments autorisés via 3 branches de policy
   - ✗ Complexité additionnelle (3 branches à auditer)
   - **ALTERNATIVE ACCEPTABLE**

**Décision** : les **deux modes sont supportés** (natif et x3). Le choix dépend du TPM cible (vérifié au provisioning via `TPM2_GetCapability`). Si le TPM ne supporte ni l'un ni l'autre, il est rejeté lors du provisioning.

### 2.4 Anti-rollback : où stocker le compteur ?

**Question** : Où stocker le compteur anti-rollback ?

**Options** :
1. **Index NV TPM** :
   - ✓ Protégé par le TPM
   - ✓ Non modifiable sans policy
   - ✓ Persistant
   - **RECOMMANDÉ**
   
2. **Fichier sur le stockage** :
   - ✓ Simple
   - ✗ Modifiable si attaquant a accès au stockage
   - ✗ Vulnérable à A3
   
3. **Les deux (défense en profondeur)** :
   - ✓ Double vérification
   - ✗ Complexité
   - **RECOMMANDÉ**

**Décision recommandée** : Option 3 avec index NV TPM comme source principale et fichier comme backup.

### 2.5 Jail : faut-il utiliser `CLONE_NEWUSER` ?

~~**Question** : Faut-il ajouter `CLONE_NEWUSER` pour isoler les UID ?~~

**Décision** : **pas de `CLONE_NEWUSER`**. Le jail utilise `setresuid`/`setresgid` pour déprivilégier le processus fils avant `execve`, ce qui est suffisant pour un payload éphémère. Justification corrigée : root *peut* créer un user namespace ; ce qui l'exclut est l'impossibilité de `mknod` de vrais périphériques dans un user namespace non initial, alors que le script A/B doit écrire sur les block devices du slot inactif (à confirmer sur le noyau cible).

Voir [06-jail.md](06-jail.md) section « Choix de design » pour le détail.

### 2.6 Jail : faut-il utiliser `CLONE_NEWPID` ?

~~**Question** : Faut-il ajouter `CLONE_NEWPID` pour isoler les PID ?~~

**Décision** : **pas de `CLONE_NEWPID`**. Enbox n'utilise pas `CLONE_NEWPID` car il nécessite de gérer la logique `init` (processus PID 1 dans le namespace). Pour notre cas d'usage (payload éphémère exécutant un script), un simple `waitpid` suffit. Le timeout est géré par `timer_create` + `SIGALRM` qui envoie `SIGKILL` au processus jail. Contrepartie à assumer : sans PID namespace, les orphelins ne sont détruits que par `cgroup.kill` ; avec `CLONE_NEWPID`, la sortie du PID 1 du namespace tue tous les processus restants.

Voir [06-jail.md](06-jail.md) section « Choix de design » pour le détail.

### 2.7 Jail : faut-il utiliser `CLONE_NEWNET` ?

**Question** : Faut-il ajouter `CLONE_NEWNET` pour isoler le réseau ?

**Analyse** :
- `CLONE_NEWNET` crée un nouveau namespace réseau
- Le jail n'a pas d'interface réseau (sauf si veth pair créé)
- Empêche toute communication réseau

**Décision déjà prise** : `CLONE_NEWNET` obligatoire (voir `06-jail.md`).

### 2.8 Logging et audit

**Question** : Comment logger les événements de sécurité ?

**Options** :
1. **stdout/stderr uniquement** :
   - ✓ Simple
   - ✗ Perte de logs si daemon redémarré
   - ✗ Pas de persistance
   
2. **Fichier de log** :
   - ✓ Persistance
   - ✗ Peut être modifié par un attaquant
   - ✗ Peut être supprimé
   
3. **Syslog / journald** :
   - ✓ Persistance
   - ✓ Rotation automatique
   - ✓ Intégration système
   - **RECOMMANDÉ**
   
4. **TPM PCR extend** :
   - ✓ Non modifiable
   - ✓ Preuve cryptographique
   - ✗ Limité (peu de PCRs disponibles)
   - **RECOMMANDÉ pour événements critiques**

**Décision recommandée** : Option 3 + 4 avec logs dans journald et événements critiques (déchiffrement, installation) dans PCR TPM.

### 2.9 Mise à jour du firmware vs mise à jour du jail

**Question** : Le bundle met-il à jour le firmware (kernel, bootloader) ou juste le jail (application) ?

**Analyse** :
- Si firmware : nécessite un slot A/B, reboot après mise à jour
- Si jail : pas de reboot nécessaire, remplacement à chaud

**Options** :
1. **Firmware uniquement** :
   - ✓ Mise à jour complète du système
   - ✗ Nécessite reboot
   - ✗ Plus risqué (brick possible)
   
2. **Jail uniquement** :
   - ✓ Mise à jour rapide
   - ✓ Pas de reboot
   - ✓ Moins risqué
   - **RECOMMANDÉ pour mises à jour fréquentes**
   
3. **Les deux (selon le manifeste)** :
   - ✓ Flexibilité
   - ✗ Complexité
   - **RECOMMANDÉ**

**Décision recommandée** : Option 3 avec le manifeste spécifiant le type de mise à jour.

### 2.10 Rotation des clés

**Question** : Comment gérer la rotation de la KEK et de la clé de signature ?

**Options** :
1. **Clés statiques** :
   - ✓ Simple
   - ✗ Si compromise, tous les bundles sont compromis
   - ✗ Une compromission expose tous les bundles passés et futurs protégés par la même clé
   
2. **Rotation périodique** :
   - ✓ Limite la fenêtre d'exposition
   - ✓ Limite le nombre de bundles exposés par une compromission (si les anciennes KEK sont détruites)
   - ✗ Complexité (plusieurs KEK valides simultanément)
   - **RECOMMANDÉ**

**Décision recommandée** : Option 2 avec rotation annuelle de la KEK et de la clé de signature.

---

## 3. Recommandations du guide Rust ANSSI

Le guide Rust de l'ANSSI (https://anssi-fr.github.io/rust-guide/) contient des règles de sécurité spécifiques au développement Rust. Voici les règles les plus pertinentes pour ce projet, classées par catégorie.

### 3.1 Environnement de développement

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **DENV-STABLE** | Utiliser une toolchain stable | ✅ OUI | `rust-toolchain.toml` avec version stable |
| **DENV-TIERS** | Utiliser des cibles tier 1 pour le safety-critical | ⚠️ PARTIEL | La cible principale `armv7-unknown-linux-gnueabihf` est tier 2 : l'écart est à documenter et à compenser par des tests (QEMU, matériel) ; `x86_64-unknown-linux-gnu` (tier 1) reste la cible hôte |
| **DENV-CARGO-LOCK** | Tracker `Cargo.lock` dans le VCS | ✅ OUI | Commiter `Cargo.lock` |
| **DENV-CARGO-OPTS** | Ne pas override les variables critiques | ✅ OUI | Ne pas override `debug-assertions` et `overflow-checks` |
| **DENV-CARGO-ENVVARS** | Ne pas override `RUSTC`, `RUSTC_WRAPPER`, `RUSTFLAGS` | ✅ OUI | Utiliser `Cargo.toml` pour les options |
| **DENV-FORMAT** | Utiliser `rustfmt` | ✅ OUI | Configurer `rustfmt.toml` |
| **DENV-LINTER** | Utiliser `clippy` régulièrement | ✅ OUI | Intégrer `cargo clippy` dans la CI |
| **DENV-AUTOFIX** | Vérifier les fixes automatiques | ✅ OUI | Review manuelle des `cargo fix` |

**Actions concrètes** :
- `rust-toolchain.toml` est créé (canal `stable`, edition 2024 donc Rust ≥ 1.85) ; envisager d'épingler une version exacte pour la reproductibilité
- Créer `rustfmt.toml` avec configuration standard
- Ajouter `cargo clippy -- -D warnings` dans la CI
- Commiter `Cargo.lock`

### 3.2 Gestion des dépendances (supply chain)

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **LIBS-VETTING-DIRECT** | Valider les dépendances directes | ✅ OUI | Review de chaque dépendance |
| **LIBS-VETTING-TRANSITIVE** | Valider les dépendances transitives | ✅ OUI | Utiliser `cargo tree` pour auditer |
| **LIBS-OUTDATED** | Vérifier les dépendances obsolètes | ✅ OUI | Utiliser `cargo outdated` |
| **LIBS-AUDIT** | Vérifier les vulnérabilités connues | ✅ OUI | Utiliser `cargo audit` dans la CI |

**Actions concrètes** :
- Ajouter `cargo audit` dans la CI (fail si vulnérabilité critique)
- Utiliser `cargo-deny` pour auditer les licences et les dépendances
- Minimiser les dépendances (pas de `anyhow`, préférer `thiserror` pour les libs)
- Épingler les versions exactes dans `Cargo.toml` (ex: `aes-gcm-siv = "=0.11.1"`)
- Utiliser `cargo-vet` ou `cargo-crev` pour la validation communautaire

### 3.3 Utilisation de `unsafe`

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **UNSAFE-NOUB** | Pas de Undefined Behavior | ✅ OUI | Justifier chaque `unsafe` |
| **LANG-UNSAFE** | Éviter les blocs `unsafe` | ✅ OUI | Utiliser `#![forbid(unsafe_code)]` sauf dans les crates FFI |
| **LANG-UNSAFE-ENCP** | Encapsuler l'unsafe dans des APIs safe | ✅ OUI | Wrapper safe pour toutes les FFI |

**Actions concrètes** :
- Structure du workspace (proposition ; le workspace actuel, décrit dans le README, ne contient que `update-bundle`, `update-tpm`, `update-slot`, `updated`, `updatectl` et `bundle-tool`, avec `unsafe_code = "forbid"` au niveau workspace : toute exception requiert un ADR) :
  ```
  crates/
    update-daemon/       # #![forbid(unsafe_code)]
    update-jail/         # #![forbid(unsafe_code)]
    update-crypto/       # #![forbid(unsafe_code)]
    update-tpm/          # #![deny(unsafe_code)] (FFI libtss2)
    update-syscalls/     # #![deny(unsafe_code)] (FFI libc)
  ```
- Chaque bloc `unsafe` doit avoir un commentaire `// SAFETY: ...` expliquant pourquoi c'est safe
- Review obligatoire de chaque bloc `unsafe` en code review

### 3.4 Gestion de la mémoire

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **MEM-NO-LEAK** | Pas de memory leak | ✅ OUI | Zero memory leaks |
| **MEM-FORGET** | Ne pas utiliser `mem::forget` | ✅ OUI | `#![deny(clippy::mem_forget)]` |
| **MEM-LEAK** | Ne pas utiliser `Box::leak` | ✅ OUI | Éviter les leaks |
| **MEM-MANUALLYDROP** | Toujours libérer les `ManuallyDrop` | ✅ OUI | Utiliser avec précaution |
| **MEM-NORAWPOINTER** | Éviter les raw pointers | ✅ OUI | Préférer les références |
| **MEM-INTOFROMRAWALWAYS** | Toujours appeler `from_raw` après `into_raw` | ✅ OUI | Wrapper RAII |
| **MEM-INTOFROMRAWONLY** | Appeler `from_raw` uniquement sur des `into_raw` | ✅ OUI | Vérifier la provenance |
| **MEM-UNINIT** | Ne pas utiliser mémoire non initialisée | ✅ OUI | Utiliser `MaybeUninit` avec justification |

**Actions concrètes** :
- Créer un type `SecureBuffer<T>` qui :
  - `mlock` la mémoire à l'allocation
  - `zeroize` la mémoire à la libération
  - Empêche le swap
  - Empêche les core dumps
- Utiliser `zeroize` crate pour les types sensibles (clés, IV, etc.)
- Ne jamais utiliser `mem::forget` ou `Box::leak` sur des buffers contenant des secrets

### 3.5 FFI (Foreign Function Interface)

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **FFI-SAFEWRAPPING** | Wrapper safe pour les FFI | ✅ OUI | Créer des wrappers Rust safe |
| **FFI-CTYPE** | Utiliser des types C-compatibles | ✅ OUI | `#[repr(C)]` pour les structs FFI |
| **FFI-TCONS** | Types cohérents des deux côtés | ✅ OUI | Utiliser `bindgen` |
| **FFI-AUTOMATE** | Utiliser `bindgen` pour générer les bindings | ✅ OUI | `rust-bindgen` pour libtss2 |
| **FFI-PFTYPE** | Utiliser des types portables (`c_int`, `c_uint`) | ✅ OUI | `std::os::raw` |
| **FFI-CKNONROBUST** | Vérifier les valeurs non-robustes | ✅ OUI | Valider les enum, bool, etc. |
| **FFI-CKINRUST** | Vérifier les valeurs en Rust | ✅ OUI | Validation côté Rust |
| **FFI-CK-PTR-VALID** | Vérifier les pointeurs | ✅ OUI | Vérifier non-null |
| **FFI-INPUT-PTR** | Utiliser des raw pointers pour les entrées | ✅ OUI | `*const T` et `*mut T` |
| **FFI-CK-INPUT-REF-VALID** | Vérifier les références | ✅ OUI | Validation côté C si nécessaire |
| **FFI-MARKEDFUNPTR** | Marquer les function pointers comme `extern` et `unsafe` | ✅ OUI | `unsafe extern "C" fn` |
| **FFI-CKFUNPTR** | Vérifier les function pointers | ✅ OUI | Vérifier non-null |
| **FFI-NOENUM** | Ne pas utiliser d'enum Rust en FFI | ✅ OUI | Utiliser des `i32` ou `u32` |
| **FFI-R-OPAQUE** | Types opaques dédiés | ✅ OUI | `struct OpaqueTpm(*mut c_void)` |
| **FFI-C-OPAQUE** | Structs C incomplètes pour types opaques | ✅ OUI | `#[repr(C)] struct OpaqueTpm { _private: [u8; 0] }` |
| **FFI-CK-REF-MODEL** | Préserver le memory model Rust | ✅ OUI | Pas d'aliasing mutable |
| **FFI-MEM-NODROP** | Ne pas implémenter `Drop` pour les types FFI directs | ✅ OUI | Wrapper avec `Drop` |
| **FFI-MEM-OWNER** | Clarifier l'ownership | ✅ OUI | Documentation claire |
| **FFI-MEM-WRAPPING** | Wrapper avec `Drop` pour libération automatique | ✅ OUI | RAII |
| **FFI-NOPANIC** | Gérer les panics en FFI | ✅ OUI | `catch_unwind` ou `panic = 'abort'` |
| **FFI-CAPI** | Exposer uniquement une API C-compatible | ✅ OUI | API publique en `extern "C"` |

**Actions concrètes** :
- Utiliser `tss-esapi` (wrapper Rust de `tpm2-tss`) plutôt que de générer des bindings avec `rust-bindgen` : le code du projet reste sans `unsafe` (`forbid` au niveau workspace), l'`unsafe` étant confiné à la dépendance, à auditer (voir question ouverte 3 de [03-tpm.md](03-tpm.md))
- Les crates `update-tpm-sys` et `update-syscalls` de la structure proposée plus haut ne sont pas retenus tant qu'un ADR ne justifie pas une exception à `unsafe_code = "forbid"` ; privilégier des wrappers safe (`rustix`, `signal-hook`) pour `openat2`, `prctl`, `mount` et les signaux
- Chaque fonction FFI doit :
  - Vérifier les pointeurs (non-null)
  - Vérifier les valeurs (enum valides, bool ∈ {0, 1})
  - Cacher les panics avec `catch_unwind`
  - Retourner des codes d'erreur C (pas de `Result`)
  - Libérer la mémoire avec des fonctions dédiées (`tpm_free`)

### 3.6 Gestion des erreurs

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **LANG-ERRWRAP** | Type `Error` custom avec `Send + Sync + 'static` | ✅ OUI | `thiserror` pour les erreurs |
| **LANG-LIMIT-PANIC** | Limiter les panics | ✅ OUI | Utiliser `Result` partout |
| **LANG-LIMIT-PANIC-SRC** | Limiter `unwrap`, `expect`, `assert!` | ✅ OUI | Code review stricte |
| **LANG-ARRINDEXING** | Vérifier les index de tableaux | ✅ OUI | Utiliser `.get()` ou vérifier les bounds |

**Actions concrètes** :
- Utiliser `thiserror` pour définir les types d'erreur
- Ne jamais utiliser `unwrap()` ou `expect()` dans le code de production (sauf tests)
- Utiliser `?` pour la propagation d'erreurs
- Utiliser `.get()` pour les accès aux tableaux/slices
- Considérer `panic = 'abort'` dans `Cargo.toml` pour le profil release (fail-fast)

### 3.7 Entiers et arithmétique

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **LANG-ARITH** | Utiliser les opérations arithmétiques appropriées | ✅ OUI | `checked_add`, `checked_mul`, etc. |

**Actions concrètes** :
- Utiliser `checked_add`, `checked_sub`, `checked_mul`, `checked_div` pour les calculs de taille
- Ne pas désactiver `overflow-checks` dans le profil release
- Utiliser `saturating_add` si le wrapping est acceptable

### 3.8 Standard library

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **LANG-SYNC-TRAITS** | Justifier `Send` et `Sync` | ✅ OUI | Review des impls custom |
| **LANG-CMP-INV** | Respecter les invariants de comparaison | ✅ OUI | Utiliser les impls par défaut |
| **LANG-CMP-DEFAULTS** | Utiliser les impls par défaut | ✅ OUI | `#[derive(PartialEq, Eq, PartialOrd, Ord)]` |
| **LANG-CMP-DERIVE** | Dériver quand possible | ✅ OUI | Utiliser `derive` |
| **LANG-DROP** | Justifier les impls `Drop` | ✅ OUI | Review des impls custom |
| **LANG-DROP-NO-PANIC** | Ne pas panic dans `Drop` | ✅ OUI | Pas de `unwrap` dans `Drop` |
| **LANG-DROP-NO-CYCLE** | Pas de cycles de `Rc`/`Arc` | ✅ OUI | Éviter les cycles |
| **LANG-DROP-SEC** | Ne pas compter sur `Drop` pour la sécurité | ✅ OUI | Zeroize explicite |
| **MEM-MUT-REC-RC** | Éviter les références cycliques | ✅ OUI | Utiliser `Weak` si nécessaire |

**Actions concrètes** :
- Implémenter `Drop` pour `SecureBuffer` avec zeroize
- Ne jamais panic dans une impl `Drop` (utiliser `if let Ok(...) = ...` au lieu de `unwrap`)
- Utiliser `Arc` avec `Weak` pour éviter les cycles
- Ne pas compter sur `Drop` pour zeroize la mémoire (faire un zeroize explicite avant)

### 3.9 Conventions de nommage

| Règle ANSSI | Description | Applicable au projet ? | Action requise |
|---|---|---|---|
| **LANG-NAMING** | Respecter les conventions de nommage | ✅ OUI | `snake_case` pour les fonctions, `CamelCase` pour les types |

**Actions concrètes** :
- Suivre les conventions Rust standard
- Utiliser `cargo clippy -- -W clippy::pedantic` pour détecter les violations

---

## 4. Résumé des actions prioritaires

### 4.1 Actions critiques (à faire avant implémentation)

1. ~~Créer `rust-toolchain.toml`~~ (fait) ; reste à créer `rustfmt.toml`
2. **Structurer le workspace** avec des crates séparés (safe/unsafe)
3. **Créer `SecureBuffer<T>`** pour la gestion sécurisée de la mémoire
4. **Décider de l'architecture daemon** (option 2 : père root + fils user)
5. ~~Décider de l'utilisation de `CLONE_NEWUSER`~~ **Tranché** : non (voir § 2.5)
6. ~~Décider de l'utilisation de `CLONE_NEWPID`~~ **Tranché** : non (voir § 2.6)
7. **Décider du stockage anti-rollback** (option 3 : NV TPM + fichier)

### 4.2 Actions importantes (à faire pendant implémentation)

1. **Intégrer `cargo audit` et `cargo-deny`** dans la CI
2. **Utiliser `tss-esapi`** pour l'accès au TPM (pas de bindings `rust-bindgen` maison)
3. **Implémenter `seccomp`** sur le daemon père
4. **Implémenter `mlockall`** et `prctl(PR_SET_DUMPABLE, 0)`
5. **Créer une whitelist de device nodes** autorisés
6. **Valider tous les noms de fichiers** (pas de path traversal)
7. **Logger tous les événements critiques** dans journald + PCR TPM

### 4.3 Actions nice-to-have (à faire après MVP)

1. **Implémenter l'attestation distante** (TPM2_Quote)
2. **Implémenter la rotation des clés** (KEK et signature)
3. **Implémenter le rate limiting** sur les tentatives de déchiffrement
4. **Implémenter le système A/B** pour les mises à jour firmware
5. **Auditer le code avec des outils formels** (Prusti, Kani)

---

## 5. Questions ouvertes restantes

1. **Budget TPM** : Combien de PCRs sont disponibles pour le logging ? (typiquement 16-24, mais certains utilisés par le bootloader)
2. **Performance** : Quel est l'impact de `mlockall` sur un système embarqué avec peu de RAM ?
3. **Compatibilité** : Quels TPM 2.0 supportent réellement AES Keywrap (RFC 5649) ?
4. **Testing** : Comment tester les scénarios d'attaque sans TPM physique ? (simulateur TPM ?)
5. **Certification** : Faut-il viser une certification Common Criteria ou ANSSI CSPN ?
6. **Post-quantique** : Faut-il prévoir une migration vers des algorithmes post-quantiques (ML-KEM, ML-DSA) ?

---

## Références

- [Guide Rust ANSSI](https://anssi-fr.github.io/rust-guide/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [RFC 5649 - AES Key Wrap with Padding](https://www.rfc-editor.org/rfc/rfc5649)
- [RFC 8452 - AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452)
