# ADR-0003 — Payload exécuté dans un environnement jail (tmpfs + bind mounts + seccomp)

**Statut** : Accepté (brouillon)

## Contexte

Le bundle ne contient pas un rootfs à installer sur un slot A/B, mais un **payload** qui
doit être **exécuté** sur le device cible pour réaliser une opération (application d'un
patch, reconfiguration, installation ciblée, migration, etc.).

Ce payload est sensible : il contient du code, des données propriétaires, et potentiellement
des informations confidentielles. Son exécution doit donc :

1. être **isolée** du système hôte,
2. ne pas pouvoir **écrire** sur le système hôte sans autorisation explicite,
3. ne pas disposer de **privilèges** au-delà du strict nécessaire,
4. ne pas pouvoir être **observée** par un processus voisin,
5. être **nettoyée** intégralement après exécution.

L'approche classique (extraire vers un répertoire temporaire puis `chroot`) est insuffisante :
un `chroot` n'est pas un isolement de sécurité, et un simple `unshare` sans tmpfs laisse
des traces sur le système de fichiers hôte.

## Décision

Le payload s'exécutera dans un **environnement jail** construit dynamiquement par le
lecteur de bundle (`updated`), en suivant le modèle suivant :

### Architecture en 5 phases

1. **Préparation** : `unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS |
   CLONE_NEWCGROUP)` + montage d'un `tmpfs` comme racine du jail.
2. **Assemblage** : application ordonnée d'un `JailManifest` (contenu dans le manifeste
   du bundle, authentifié par AEAD) : création de répertoires, bind mounts depuis l'hôte,
   extraction de fichiers du payload, création de device nodes, montage de `proc`/`sysfs`/
   `devtmpfs`.
3. **Verrouillage** : `pivot_root`, remount `ro,nosuid,nodev,noexec`, déprivilégiation
   (setresuid/setresgid, drop caps), installation du filtre seccomp, `no_new_privs=1`.
4. **Entrée** : `execve(script_entrypoint, argv, env)` avec cwd et fds définis par le
   manifeste.
5. **Nettoyage** : démontage récursif, libération du tmpfs, sortie des namespaces.

### Manifeste déclaratif

L'environnement est **entièrement décrit** dans un `JailManifest` contenu dans le manifeste
du bundle (format CBOR aligné avec le reste du format). Les règles de type `fsset` sont
appliquées dans l'ordre, sans interprétation de champs inconnus.

### Référence externe

L'architecture s'inspire fortement de [enbox](https://github.com/grgbr/enbox) (framework
de sandboxing embarqué en C, maintenu par grgbr), dont on reprend la taxonomie des types
de `fsset` : `dir`, `file`, `host_bind`, `chrdev`, `blkdev`, `slink`, `fifo`, `proc`,
`sysfs`, `devtmpfs`, `tmpfs`.

On y ajoute :
- `payload_file` / `payload_dir` : fichiers extraits depuis le payload chiffré,
- `host_bind_back` : bind mount inversé (jail → hôte) pour les zones de logs.

### Posture de sécurité

- **Deny-all, allow-list** : rien n'est monté/autorisé sans règle explicite.
- **Seccomp** : trois profils (`strict`, `default`, `custom`) installés avant `execve`.
- **Capabilities** : `caps_keep` liste blanche, toutes les autres sont drop.
- **RO final** : tous les points de montage internes sont remontés `ro,nosuid,nodev,noexec`.
- **PID namespace** : tue les orphelins à la sortie.

## Conséquences

### Positives

- Le payload ne laisse **aucune trace** sur le système hôte (hors bind mounts inversés
  explicitement autorisés).
- Le lecteur de bundle reste **maître** des opérations : il n'exécute que le script
  d'entrée déclaré, pas des binaires arbitraires du payload.
- Le `JailManifest` étant dans le manifeste signé/chiffré, il bénéficie des mêmes
  garanties d'intégrité et de confidentialité que le reste du bundle.
- Le modèle est **généralisable** : le même mécanisme peut servir à exécuter un script
  de migration, un diagnostic, ou même installer un nouveau rootfs (cas A/B).

### Négatives

- **Complexité accrue** du lecteur : il faut implémenter correctement l'ensemble
  `unshare`/`pivot_root`/`mount`/`mknod`/`seccomp`/`execve` en Rust, avec gestion robuste
  des erreurs (cleanup via `Drop`).
- **Dépendance noyau** : toutes les cibles doivent supporter les namespaces (c'est le cas
  depuis Linux 3.x, donc acquis sur Clearfog).
- **Surcoût mémoire** : le `tmpfs` consomme de la RAM pendant l'exécution (limité par
  `root_tmpfs_size`).
- **Limitations** : certaines opérations nécessitent un accès privilégié au noyau hôte
  (ex: chargement de module, mise à jour du bootloader). Ce modèle n'est alors pas adapté.

### Neutres

- La décision n'exclut **pas** le modèle A/B classique : le jail peut contenir un script
  qui écrit dans un slot inactif (via bind mount explicite de `/dev/mmcblk0pN`).
- La compatibilité avec la configuration d'enbox (syntaxe libconfig) n'est **pas**
  recherchée ; on préfère CBOR pour homogénéité avec le reste du format de bundle.

## Alternatives considérées

| Alternative | Description | Pourquoi rejetée |
|---|---|---|
| **Simple `chroot`** | Extraire le payload, puis `chroot` dedans | Pas d'isolation de sécurité (partage mount namespace, pas de seccomp par défaut) |
| **Conteneur (LXC/podman)** | Utiliser un runtime conteneur standard | Trop lourd, dépendances systemd/cgroups complexes, inadapté embarqué |
| **MicroVM (Firecracker/QEMU)** | Isoler dans une microVM | Surcoût CPU/mémoire prohibitif sur cible embarquée |
| **Installation A/B classique** | Installer le payload comme rootfs | Ne permet pas d'exécuter des scripts de migration, ne convient pas aux petits bundles |

## Points à revoir

1. **Validation formelle du profil seccomp** : s'assurer que les profils `strict` et
   `default` couvrent les cas d'usage réels sans bloquer légitimement le payload.
2. **Gestion du timeout** : politique de kill récursif (PID namespace + `SIGKILL` + wait).
3. **Observation** : format de sortie structuré (JSON lines) à définir.
4. **Persistance post-jail** : politique des artefacts (fichiers, clés) écrits via
   `host_bind_back`.
5. **Tests** : émuler les namespaces sous QEMU/swtpm ; définir des tests d'intégration
   pour chaque type de `fsset`.

## Documents liés

- [spec/06-jail.md](../spec/06-jail.md) — spécification détaillée
- [spec/02-bundle-format.md](../spec/02-bundle-format.md) — le `JailManifest` fait partie du manifeste
- [spec/01-threat-model.md](../spec/01-threat-model.md) — menaces J1-J8
- [enbox (GitHub)](https://github.com/grgbr/enbox) — référence externe
