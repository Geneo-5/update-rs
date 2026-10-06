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
- **LockHeld** : verrou déjà détenu par une autre instance ; le daemon journalise l'erreur et termine (voir « Verrouillage d'instance »). Si le verrou est obtenu, l'état suivant est **Fetching**.
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
            // Opérations async-signal-safe uniquement :
            // 1. Positionner le flag atomique CLEANUP_REQUESTED
            // 2. Envoyer SIGKILL au processus jail (si en cours)
            // Le cleanup (démontage récursif, tmpfs, lock file, code de sortie)
            // est effectué par le thread principal, hors du handler (voir 06-jail.md).
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
- Les mounts orphelins (tmpfs, bind mounts) sont nettoyés au démarrage suivant par `updated --cleanup`, lancé par le système d'init (service systemd si présent, sinon script de boot dédié) ; voir [06-jail.md](06-jail.md), « Cleanup garanti après crash ».

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

1. Quel health-check, et qui le définit (service, script, watchdog) ? **Hors scope** : le health-check est géré par le script A/B dans le jail (voir [06-jail.md](06-jail.md) section « Modèle A/B et rollback »).
2. Stratégie de staging : espace temporaire nécessaire, ou écriture directe dans le slot inactif ? **Hors scope** : géré par le script A/B dans le jail.
3. Interface avec le bootloader (U-Boot env, `libubootenv`, autre) ? **Hors scope** : chaîne de boot imposée comme prérequis d'intégration (voir `prerequis-integration.md`).
4. Mises à jour partielles/delta : hors périmètre v1 ? **Hors scope** : pas de delta updates en v1.
5. ~~Déclenchement : pull périodique, push, commande manuelle (`updatectl`) ?~~ **Résolu** : **client compatible cron** qui check une URI. Le daemon `updated` ne fait pas de pull automatique. Un client externe (script cron, service systemd timer) appelle `updatectl check <URI>` pour vérifier les mises à jour disponibles, puis `updatectl apply` pour les appliquer.
6. ~~Persistance de l'état du jail entre exécutions : le jail peut-il laisser des artefacts sur l'hôte ?~~ **Résolu** : pas de persistance du jail (éphémère, tmpfs). Reboot si update réussie.
7. ~~Rollback après échec du jail : faut-il pouvoir relancer un jail précédent, ou retourner à Idle ?~~ **Résolu** : si le jail échoue, rien n'a été modifié (tmpfs éphémère), le daemon retourne à Idle. Si on rentre dans le jail, c'est au script de gérer le rollback (voir [06-jail.md](06-jail.md) section « Modèle A/B et rollback »).
8. ~~La machine à états décrit l'exécution d'un payload dans un jail, alors que REQ-FLW-1 à 3 supposent un modèle A/B (slot inactif, health-check, rollback) absent des états ci-dessus.~~ **Résolu** : le modèle A/B est géré par le script dans le jail, pas par le daemon. Le daemon charge le payload et exécute le script ; le script gère l'écriture dans le slot inactif, le commit, et le rollback si échec.

## Client compatible cron

**Architecture** : le daemon `updated` ne fait **pas** de pull automatique. Un client externe (script cron, service systemd timer, ou commande manuelle) est responsable de vérifier les mises à jour disponibles.

**Client `updatectl`** :
- `updatectl check <URI>` : vérifie si une mise à jour est disponible à l'URI donnée (télécharge uniquement le header, vérifie la signature, compare les versions).
- `updatectl apply` : applique la mise à jour (télécharge le bundle complet, le passe au daemon `updated`).
- `updatectl status` : affiche l'état du daemon et la version installée.

**Canal de communication** : socket Unix stream avec `SO_PEERCRED` pour l'authentification du client (vérification de l'UID/GID du processus client).

**Exemple de configuration cron** :
```bash
# /etc/cron.d/update-rs
# Vérifier les mises à jour toutes les heures
0 * * * * root /usr/bin/updatectl check https://updates.example.com/bundle.bin && /usr/bin/updatectl apply
```
