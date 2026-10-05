# 04 — Flux de mise à jour

Statut : Brouillon

## Machine à états (esquisse)

```
Idle → AcquiringLock → Fetching → Verifying → PreparingJail → AssemblingJail → ExecutingJail → CleaningJail → Idle
         │                   │              │                 │                │              │
         └── LockHeld ───────┴─ Rejected ───┴─ Error ──────────┴────────────────┴──────────────┘
```

### États détaillés

- **AcquiringLock** : tentative d'acquisition du verrou (file lock ou lock file) pour éviter les instances multiples.
- **LockHeld** : verrou acquis, prêt à démarrer une mise à jour.
- **Fetching** : récupération du bundle (réseau, stockage local) en streaming.
- **Verifying** : **fork d'un processus fils** pour validation du header (magic, version, anti-rollback, hash TPM, signature ECC, déchiffrement clé de session via TPM). Le fils retourne la clé de session au père via pipe sécurisé, puis se termine.
- **PreparingJail** : `unshare` des namespaces, montage du tmpfs racine.
- **AssemblingJail** : application du `JailManifest` (dirs, bind mounts, extraction payload, dev nodes), streaming des chunks.
- **ExecutingJail** : pivot_root, verrouillage RO, drop privileges, securebits, seccomp, execve du script d'entrée.
- **CleaningJail** : démontage récursif, libération tmpfs, sortie namespaces.
- **Rejected** : bundle invalide, retour à Idle.
- **Error** : erreur pendant préparation/assemblage/exécution, nettoyage forcé, retour à Idle.

## Verrouillage d'instance

**Objectif** : empêcher l'exécution simultanée de plusieurs instances du daemon `updated`, qui pourraient se marcher dessus (corruption de MTD, double montage, etc.).

**Mécanisme** :
- **Lock file** : `/var/run/update-rs.lock` (ou chemin configurable).
- **Type de verrou** : `flock(LOCK_EX | LOCK_NB)` (verrou exclusif non-bloquant).
- **Si le verrou est déjà tenu** : le daemon log un message d'erreur et termine immédiatement avec code de sortie spécifique.
- **Libération du verrou** : automatique à la fermeture du fd (fin du processus), ou explicite avant retour à Idle.

**Alternative** : si le système n'a pas de `/var/run` monté, utiliser un socket Unix avec `SO_REUSEADDR=0` et tentative de `bind()`.

## Gestion des signaux et cleanup

**Signaux gérés** :
- `SIGTERM`, `SIGINT`, `SIGHUP` : déclenchent un cleanup immédiat.
- `SIGCHLD` : notification de fin du processus fils (jail ou vérification).
- `SIGALRM` : timeout du script d'entrée du jail.

**Handler de signal** :
```rust
// Pseudo-code
fn handle_signal(sig: Signal) {
    match sig {
        SIGTERM | SIGINT | SIGHUP => {
            // 1. Envoyer SIGKILL au processus jail (si en cours)
            // 2. Démonter récursivement tous les mounts
            // 3. Libérer le tmpfs
            // 4. Libérer le lock file
            // 5. Terminer avec code d'erreur
        }
        SIGCHLD => {
            // Récupérer le statut du fils (waitpid)
        }
        SIGALRM => {
            // Timeout du jail : envoyer SIGKILL
        }
        _ => {}
    }
}
```

**Cleanup garanti** :
- Le handler de signal est installé dès l'acquisition du verrou.
- En cas de crash (SIGSEGV, SIGABRT), le lock file est libéré automatiquement par le kernel.
- Les mounts orphelins (tmpfs, bind mounts) sont nettoyés au prochain boot par `systemd-tmpfiles --remove` (si systemd présent) ou par un script de boot dédié.

## Exigences

- **REQ-FLW-1** — Le slot actif ne DOIT jamais être modifié pendant une mise à jour.
- **REQ-FLW-2** — Une coupure d'alimentation à n'importe quel point DOIT laisser un système bootable.
- **REQ-FLW-3** — Un échec de health-check ou un nombre de tentatives dépassé DOIT déclencher un rollback automatique.
- **REQ-FLW-4** — L'état de la machine à états DOIT être persistant et reprenable après reboot.
- **REQ-FLW-5** — L'environnement jail DOIT être intégralement démonté (tmpfs, namespaces, bind mounts) avant retour à Idle, qu'il s'agisse d'une fin normale ou d'une erreur.
- **REQ-FLW-6** — Le script d'entrée du jail DOIT disposer d'un timeout configurable ; son expiration entraîne un kill récursif via `SIGKILL`.
- **REQ-FLW-7** — Les sorties du script d'entrée (stdout/stderr/code retour) DOIVENT être capturées et journalisées dans une zone dédiée sur l'hôte.
- **REQ-FLW-8** — Le daemon DOIT acquérir un verrou exclusif (file lock ou socket) avant toute opération, pour empêcher les instances multiples.
- **REQ-FLW-9** — Les signaux `SIGTERM`, `SIGINT`, `SIGHUP` DOIVENT déclencher un cleanup immédiat et garanti.
- **REQ-FLW-10** — La vérification du header DOIT être effectuée par un processus fils forké par le daemon, pour isolation.

## Questions ouvertes

1. Quel health-check, et qui le définit (service, script, watchdog) ?
2. Stratégie de staging : espace temporaire nécessaire, ou écriture directe dans le slot inactif ?
3. Interface avec le bootloader (U-Boot env, `libubootenv`, autre) ?
4. Mises à jour partielles/delta : hors périmètre v1 ?
5. Déclenchement : pull périodique, push, commande manuelle (`updatectl`) ?
6. Persistance de l'état du jail entre exécutions : le jail peut-il laisser des artefacts sur l'hôte (fichiers de config, clés) ? Si oui, dans quelle zone ?
7. Rollback après échec du jail : faut-il pouvoir relancer un jail précédent, ou retourner à Idle ?
