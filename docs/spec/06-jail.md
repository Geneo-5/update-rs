# 06 — Environnement d'exécution « Jail »

Statut : Brouillon

Voir ADR : [ADR-0003](../adr/0003-jail-environment.md).

## Objet

Le payload contenu dans le bundle n'est pas installé sur un slot comme un rootfs
classique. Il s'exécute dans un **environnement sandboxé** (jail) construit dynamiquement
à partir d'un `tmpfs` racine, assemblé à la volée à partir de :

- répertoires créés dans le jail,
- bind mounts depuis le système hôte,
- fichiers chargés depuis le payload chiffré,
- nœuds de périphériques créés dans `/dev`,
- pseudo-systèmes (`proc`, `sysfs`, `devtmpfs`).

Une fois l'environnement monté, le root du jail est **verrouillé en lecture seule**, les
privilèges sont réduits (capabilities, seccomp, UID/GID), et un script d'entrée est
exécuté.

Ce modèle s'inspire fortement de [enbox](https://github.com/grgbr/enbox) (sandboxing
embarqué en C), adapté à notre cas d'usage : exécuter un payload **éphémère** dont
l'intégrité et la confidentialité sont garanties par le bundle lui-même.

## Exigences globales

- **REQ-JAIL-1** — Le jail NE DOIT pas écrire sur le système hôte hors zones explicitement
  autorisées par bind mount inversé (log, cache).
- **REQ-JAIL-2** — Le jail DOIT pouvoir être construit en flux tendu, au fur et à mesure
  du déchiffrement des chunks, sans avoir à les stocker intégralement.
- **REQ-JAIL-3** — L'environnement DOIT être démonté et libéré (tmpfs, namespaces) dès la
  fin de l'exécution, qu'elle soit normale ou en erreur.
- **REQ-JAIL-4** — Les capacités Linux accordées à l'entrée DOIVENT être le strict
  nécessaire ; toutes les autres DOIVENT être ôtées.
- **REQ-JAIL-5** — Un profil seccomp (`SECCOMP_MODE_FILTER`) DOIT être installé avant
  l'exécution du script d'entrée, et NE DOIT permettre aucun syscall non listé.
- **REQ-JAIL-6** — Le root du jail DOIT être remonté en lecture seule avant l'exécution.

## Principes de construction

Le lecteur de bundle (`updated`) est le **monteur** du jail. Il opère en tant que root
au début de la séquence, puis se déprivilégie avant d'exécuter le script d'entrée.

### Principes fondamentaux

1. **Base `tmpfs`** : la racine du jail est un `tmpfs` monté dans un nouveau namespace
   `mount`. Rien n'atteint le disque hôte sans bind mount explicite.
2. **Isolation par namespaces** : `mount`, `cgroup`, `uts`, `ipc`, **`net` (toujours isolé)**.
   `CLONE_NEWUSER` et `CLONE_NEWPID` ne sont PAS utilisés (voir section « Choix de design »).
3. **Bind mounts du host** : fichiers ou répertoires nécessaires au payload (ex:
   `/etc/resolv.conf`, `/run/dbus/system_bus_socket`, un socket UNIX) sont montés dans
   le jail en **`ro` par défaut** avec le flag **`MS_NOSYMFOLLOW`** pour empêcher les attaques
   par symlink.
4. **Chargement depuis le payload** : les fichiers extraits du bundle sont placés dans le
   jail au fil du déchiffrement (streaming).
5. **Nœuds de périphériques** : `/dev` est partiellement peuplé via création manuelle de
   `chrdev` / `blkdev` nécessaires au payload (pas de `devtmpfs` complet).
6. **Verrouillage final** : tous les points de montage internes sont remontés `ro,
   nodev, nosuid, noexec` ; les namespaces sont figés ; l'entrypoint est lancé avec un
   profil de sécurité minimal (capabilities + securebits + seccomp).
7. **Pas d'écriture sur l'hôte** : le jail NE PEUT PAS écrire sur l'hôte, sauf via des
   bind mounts inversés (`host_bind_back`) explicitement autorisés pour les logs uniquement.

## Phases d'exécution

```
┌────────────────────────────────────────────────────────────────┐
│ Phase 0 : Validation préliminaire                              │
│  - Bundle reçu, header validé, clé de session déballée (TPM)   │
│  - Manifeste déchiffré et authentifié                          │
│  - Extrait le JailManifest du manifeste                        │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ Phase 1 : Préparation (unshare)                                │
│  - unshare(CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS |         │
│            CLONE_NEWCGROUP | CLONE_NEWNET)                     │
│  - pivot_root() non fait ici (tmpfs d'abord)                   │
│  - montage tmpfs sur le répertoire de travail                  │
│  - **Pas de CLONE_NEWPID** (voir section « Choix de design »)  │
│  - **Pas de CLONE_NEWUSER** (daemon root nécessaire)           │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ Phase 2 : Assemblage (bind mounts + payload + dev nodes)       │
│  - création de l'arborescence (dirs, symlinks)                 │
│  - montage proc, sysfs, devtmpfs avec flags restrictifs        │
│  - bind mounts host→jail (selon JailManifest.fsset)            │
│  - streaming des chunks → fichiers dans le jail                │
│  - création de device nodes (mknod chrdev/blkdev)              │
│  - création de FIFO, sockets, symlinks                         │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ Phase 3 : Verrouillage                                         │
│  - remount ro,nosuid,nodev,noexec de tous les points           │
│  - pivot_root() dans le tmpfs (l'ancien root devient privé)    │
│  - déprivilégiation : setgroups, setresgid, setresuid          │
│  - **Securebits stricts** :                                    │
│    - SECBIT_NOROOT + SECBIT_NOROOT_LOCKED                     │
│    - SECBIT_NO_SETUID_FIXUP + SECBIT_NO_SETUID_FIXUP_LOCKED   │
│    - SECBIT_KEEP_CAPS_LOCKED                                   │
│    - SECBIT_NO_CAP_AMBIENT_RAISE + LOCKED                      │
│  - drop de toutes les capabilities non listées (keep_caps=0)   │
│  - **Clear ambient caps** : PR_CAP_AMBIENT_CLEAR_ALL           │
│  - application du filtre seccomp (BPF)                         │
│  - no_new_privs = 1                                            │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ Phase 4 : Entrée                                               │
│  - execve(script_entrypoint, argv, env)                        │
│  - cwd défini par le manifeste                                 │
│  - fds hérités selon JailManifest.keep_fds                     │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌────────────────────────────────────────────────────────────────┐
│ Phase 5 : Nettoyage (post-exécution, retour du fils)           │
│  - démontage récursif (MNT_DETACH)                             │
│  - libération du tmpfs                                         │
│  - sortie des namespaces (exit du processus monteur)           │
│  - retour à Idle (voir 04-update-flow.md)                      │
└────────────────────────────────────────────────────────────────┘

**Nettoyage sur signal** :
- Les signaux `SIGTERM`, `SIGINT`, `SIGHUP` déclenchent un cleanup immédiat.
- Le processus monteur installe un handler qui :
  1. Envoie `SIGKILL` au processus jail (via son PID).
  2. Attend la fin du fils (`waitpid`).
  3. Démonte récursivement tous les mounts.
  4. Libère le tmpfs.
  5. Termine avec un code d'erreur approprié.
- **Pas de dépendance à systemd** : le cleanup est géré par le daemon lui-même.
```

## Choix de design

### Pourquoi pas `CLONE_NEWUSER` ?

- Le daemon `updated` DOIT tourner en tant que **root** pour pouvoir :
  - Accéder au TPM (`/dev/tpm0`, `/dev/tpmrm0`)
  - Monter/démonter des filesystems
  - Écrire sur les devices MTD/block pour l'update
  - Créer des namespaces
- `CLONE_NEWUSER` nécessite que le daemon soit non-root pour mapper les UIDs, ce qui est incompatible avec notre architecture.
- Le jail utilise `setresuid`/`setresgid` pour déprivilégier le processus fils avant `execve`, ce qui est suffisant pour notre cas d'usage (payload éphémère).

### Pourquoi pas `CLONE_NEWPID` ?

- Enbox n'utilise pas `CLONE_NEWPID` car il nécessite de gérer la logique `init` (processus PID 1 dans le namespace).
- Pour notre cas d'usage (payload éphémère exécutant un script), un simple `waitpid` suffit pour attendre la fin du jail.
- Le timeout est géré par un `timer_create` + `SIGALRM` qui envoie `SIGKILL` au processus jail.
- Si le processus jail fork des enfants, ils sont tués automatiquement quand le père (monteur) termine (process group leader).

### Pourquoi `CLONE_NEWNET` (réseau isolé) ?

- Le payload d'update n'a **jamais** besoin d'accès réseau : tout est déjà téléchargé dans le bundle.
- Isoler le réseau empêche toute exfiltration de données ou attaque sur des services internes.
- Si un futur cas d'usage nécessite le réseau, il faudra ajouter un firewalling dédié (nftables) et une policy TPM spécifique.

### Pourquoi `MS_NOSYMFOLLOW` sur les bind mounts ?

- Empêche les attaques par symlink : un attaquant ne peut pas créer un symlink `/jail/etc/passwd -> /etc/shadow` pour exposer des fichiers sensibles de l'hôte.
- Tous les bind mounts host→jail DOIVENT utiliser ce flag.
- Disponible depuis Linux 5.10 (flag `MS_NOSYMFOLLOW` = `1 << 8`).

### Pourquoi les securebits stricts ?

Inspiré d'enbox, les securebits suivants sont verrouillés :

| Securebit | Effet |
|---|---|
| `SECBIT_NOROOT` | Empêche le kernel d'accorder les capacités root lors d'un `execve` de binaire setuid root |
| `SECBIT_NO_SETUID_FIXUP` | Empêche le kernel d'ajuster les capacités lors d'un changement d'UID effectif |
| `SECBIT_KEEP_CAPS_LOCKED` | Empêche de conserver les capacités lors d'un changement d'UID (sauf si explicitement demandé) |
| `SECBIT_NO_CAP_AMBIENT_RAISE` | Empêche de lever des capacités ambient (qui survivent à `execve`) |

Ces bits sont **verrouillés** (suffix `_LOCKED`) pour empêcher le processus jail de les désactiver.

## Manifeste du jail (JailManifest)

Le manifeste du bundle (voir [02-bundle-format.md](02-bundle-format.md)) contient un
objet `jail` qui décrit l'environnement à construire.

### Schéma (esquisse, TOML-like)

```toml
[jail]
# Namespace policy
namespaces = ["mount", "pid", "ipc", "uts", "cgroup"]  # "net" optionnel
root_tmpfs_size = "64M"        # limite tmpfs (0 = pas de limite)
hostname = "update-payload"

# Script d'entrée
entrypoint = "/bin/entry.sh"
cwd = "/"
argv = ["/bin/entry.sh", "--apply"]

# Identité
user = "payload"               # utilisateur dans le jail
group = "payload"
auid = "update-payload"        # audit UID

# Environnement (liste blanche)
env_pass = ["PATH", "HOME", "LANG"]
env_set = { "BUNDLE_VERSION" = "${bundle_version}" }

# Capabilities accordées (tout le reste est drop)
caps_keep = ["net_bind_service", "dac_override"]

# Seccomp : profil BPF ou liste blanche de syscalls
seccomp_profile = "strict"     # "strict" | "default" | "custom"
seccomp_allow_extra = []       # syscalls supplémentaires si custom

# Fds hérités
keep_fds = [0, 1, 2]

# --- fsset : liste ordonnée de règles de montage ---
[[jail.fsset]]
type = "proc"
path = "/proc"
flags = ["ro", "nosuid", "nodev", "noexec", "noatime"]
opts = "hidepid=invisible,subset=pid"

[[jail.fsset]]
type = "sysfs"
path = "/sys"
flags = ["ro", "nosuid", "nodev", "noexec", "noatime"]

[[jail.fsset]]
type = "devtmpfs"
path = "/dev"
flags = ["nosuid", "noexec", "mode=0755"]

[[jail.fsset]]
type = "dir"
path = "/etc"
mode = 0o755
user = 0
group = 0

[[jail.fsset]]
type = "host_bind"             # bind mount depuis l'hôte
path = "/etc/resolv.conf"
orig = "/etc/resolv.conf"
flags = ["ro", "nodev", "nosuid", "noexec", "nosymfollow"]

[[jail.fsset]]
type = "host_bind"
path = "/run/dbus/system_bus_socket"
orig = "/run/dbus/system_bus_socket"
flags = ["ro", "nodev", "nosuid", "noexec", "nosymfollow"]

[[jail.fsset]]
type = "payload_file"          # fichier extrait du bundle
path = "/bin/entry.sh"
source_ref = "rootfs/bin/entry.sh"   # référence dans le payload
flags = ["ro", "nodev", "nosuid", "noexec"]
mode = 0o755

[[jail.fsset]]
type = "chrdev"
path = "/dev/urandom"
major = 1
minor = 9
mode = 0o444
user = 0
group = 0

[[jail.fsset]]
type = "chrdev"
path = "/dev/null"
major = 1
minor = 3
mode = 0o666

[[jail.fsset]]
type = "blkdev"
path = "/dev/mmcblk0"
major = 179
minor = 0
mode = 0o660
user = 0
group = "disk"

[[jail.fsset]]
type = "slink"
path = "/dev/fd"
target = "/proc/self/fd"

[[jail.fsset]]
type = "fifo"
path = "/run/log.fifo"
mode = 0o600

[[jail.fsset]]
type = "dir"
path = "/var/log/payload"
mode = 0o755
# bind mount inversé : le jail écrit ici, visible sur l'hôte
host_bind_back = "/var/log/update-payload"
```

### Types de `fsset` supportés

| Type | Description |
|---|---|
| `dir` | Crée un répertoire dans le jail (mode/uid/gid optionnels). Peut être bindé vers l'hôte via `host_bind_back`. |
| `file` | Crée un fichier vide (mode/uid/gid). |
| `host_bind` | Bind mount d'un chemin hôte vers le jail (lecture seule par défaut). |
| `payload_file` | Fichier extrait depuis le payload chiffré. Référence par `source_ref` (chemin relatif dans le payload). |
| `payload_dir` | Arborescence complète extraite depuis le payload (équivalent à plusieurs `payload_file`). |
| `chrdev` | Nœud de périphérique caractère (`mknod S_IFCHR`). |
| `blkdev` | Nœud de périphérique bloc (`mknod S_IFBLK`). |
| `slink` | Lien symbolique. |
| `fifo` | FIFO nommée (`mkfifo`). |
| `proc` | Montage du pseudo-système `procfs` avec options restrictives. |
| `sysfs` | Montage de `sysfs` avec options restrictives. |
| `devtmpfs` | Montage d'un `devtmpfs` peuplé automatiquement par le noyau. |
| `tmpfs` | Montage tmpfs supplémentaire à l'intérieur du jail (quota, flags). |

### Règles d'application

- **Ordre d'application** : les règles `fsset` sont appliquées dans l'ordre du manifeste.
  Le parent d'un chemin DOIT exister avant (via une règle `dir` précédente).
- **Redondance interdite** : un même chemin DOIT apparaître une seule fois.
- **Validation à la construction** : tout chemin non listé dans `fsset` ne doit **pas**
  être monté (le lecteur ne doit pas interpréter de champs inconnus).

## Modèle de sécurité du jail

### Surface d'attaque spécifique

Le jail ajoute aux menaces globales (voir [01-threat-model.md](01-threat-model.md)) les
menaces locales suivantes :

| Id | Menace | Atténuation |
|---|---|---|
| J1 | Payload échappant le jail via un bind mount mal configuré | Liste blanche `fsset` stricte, validation côté monteur, aucun `orig` en écriture sans `host_bind_back` explicite |
| J2 | Device node malicieux donnant accès à un device sensible | Nœuds créés uniquement via `fsset` validé par signature du manifeste ; `major`/`minor` validés contre liste blanche |
| J3 | `proc`/`sys` en écriture permettant escalade | Options `ro,nosuid,nodev,noexec` obligatoires ; `hidepid=invisible` pour `proc` |
| J4 | Seccomp contourné par un binaire du payload | Filtre installé **après** pivot_root, `no_new_privs=1` empêchant tout `setuid` ou `execve` vers des binaires privilégiés |
| J5 | Capabilities conservées après execve | `SECBIT_KEEP_CAPS=0`, `keep_caps=0` sur execve, `PR_CAP_AMBIENT_CLEAR_ALL` |
| J6 | Fuite de données du payload via bind mount inversé | `host_bind_back` limité à des zones spécifiques (logs) ; contenu validé après exécution |
| J7 | Processus orphelin gardant des ressources | Pas de PID namespace ; le processus monteur attend le jail via `waitpid` et envoie `SIGKILL` sur timeout |
| J8 | Race condition entre démontage et sortie | `MNT_DETACH` suivi de la sortie du monteur ; le tmpfs disparaît au dernier close |
| J9 | Attaque par symlink sur bind mount | Flag `MS_NOSYMFOLLOW` obligatoire sur tous les bind mounts host→jail |

### Posture par défaut

La posture par défaut est **deny-all, allow-list** :

- Rien n'est monté sans règle `fsset` explicite.
- Aucune capability n'est accordée sans être dans `caps_keep`.
- Aucun syscall n'est autorisé hors profil seccomp.
- Aucun fichier du payload n'est accessible sans être dans `payload_file`/`payload_dir`.

## Profil seccomp

Trois profils sont prévus :

| Profil | Description | Cas d'usage |
|---|---|---|
| `strict` | Lecture, écriture, `exit`, `sigreturn`, `brk`, `mmap` (anonymes) uniquement | Payload ne faisant que lire ses entrées et écrire une sortie |
| `default` | Strict + `openat`, `close`, `stat`, `lseek`, `read`, `write`, `mmap`/`munmap` sur fichiers existants, `futex`, `clock_gettime` | Payload applicatif standard |
| `custom` | Liste blanche définie dans `seccomp_allow_extra` | Payload nécessitant des syscalls spécifiques |

Les filtres BPF sont installés via `seccomp(SECCOMP_SET_MODE_FILTER, …)` après `pivot_root`
et avant `execve` du script d'entrée.

## Exigences

- **REQ-JAIL-7** — Le lecteur DOIT valider le `JailManifest` **avant** tout `unshare`,
  et rejeter les règles incohérentes (chemins relatifs sortant du jail, major/minor
  hors liste blanche, bind mount hôte inexistant).
- **REQ-JAIL-8** — Toutes les opérations de montage DOIVENT être journalisées avec un
  niveau de sévérité adapté (info, warn, error).
- **REQ-JAIL-9** — Le script d'entrée DOIT disposer d'un timeout configurable ; son
  expiration entraîne un `SIGKILL` récursif via le PID namespace.
- **REQ-JAIL-10** — Les sorties stdout/stderr du script d'entrée DOIVENT être capturées
  et journalisées dans la zone `host_bind_back` de logs si configurée.
- **REQ-JAIL-11** — En cas d'échec de n'importe quelle phase, le lecteur DOIT démonter
  intégralement (y compris en cas de panic — via guard Rust ou `Drop` dédié).
- **REQ-JAIL-12** — Le lecteur NE DOIT PAS exécuter directement de binaire issu du
  payload ; SEUL le script d'entrée déclaré est autorisé.

## Questions ouvertes

1. **Net namespace** : isolation totale (pas d'accès réseau), ou partage avec l'hôte ?
   Si partage, faut-il un firewalling dédié via nftables ?
2. **User namespace** : à utiliser systématiquement (meilleur isolement) ou seulement si
   l'host kernel le permet proprement (certaines distributions embarquées ont des
   restrictions) ?
3. **Poids** : taille mémoire acceptable du tmpfs sur cible (64M ? 128M ? 256M ?) ?
4. **Payload multi-images** : un bundle peut-il contenir plusieurs jails à exécuter
   séquentiellement ou en parallèle ?
5. **Persistance post-jail** : le payload peut-il laisser des artefacts sur l'hôte
   (fichiers de config, clés) ? Si oui, dans quelle zone et avec quelle politique ?
6. **Mise à jour du payload lui-même** : le jail est-il utilisé pour installer un
   nouveau rootfs (cas A/B), ou seulement pour exécuter un script d'application ?
7. **Compatibilité avec enbox** : doit-on reprendre sa config syntaxique (libconfig) ou
   opter pour TOML/JSON/CBOR ? (CBOR aligne avec le format de manifeste — à privilégier).
8. **Rollback** : si l'exécution du jail échoue, faut-il pouvoir relancer un jail
   précédent, ou retourner à Idle ?
9. **Observation** : faut-il un canal de sortie structuré (JSON lines) pour le script
   d'entrée, au-delà du simple stdout ?
