# 04 — Flux de mise à jour

Statut : Brouillon

## Machine à états (esquisse)

```
Idle → Fetching → Verifying → PreparingJail → AssemblingJail → ExecutingJail → CleaningJail → Idle
                      │              │                 │                │              │
                      └─ Rejected ───┴─ Error ──────────┴────────────────┴──────────────┘
```

### États détaillés

- **Fetching** : récupération du bundle (réseau, stockage local) en streaming.
- **Verifying** : validation du header (magic, version, anti-rollback, signature ECC, déchiffrement clé de session via TPM).
- **PreparingJail** : `unshare` des namespaces, montage du tmpfs racine.
- **AssemblingJail** : application du `JailManifest` (dirs, bind mounts, extraction payload, dev nodes), streaming des chunks.
- **ExecutingJail** : pivot_root, verrouillage RO, drop privileges, seccomp, execve du script d'entrée.
- **CleaningJail** : démontage récursif, libération tmpfs, sortie namespaces.
- **Rejected** : bundle invalide, retour à Idle.
- **Error** : erreur pendant préparation/assemblage/exécution, nettoyage forcé, retour à Idle.

## Exigences

- **REQ-FLW-1** — Le slot actif ne DOIT jamais être modifié pendant une mise à jour.
- **REQ-FLW-2** — Une coupure d'alimentation à n'importe quel point DOIT laisser un système bootable.
- **REQ-FLW-3** — Un échec de health-check ou un nombre de tentatives dépassé DOIT déclencher un rollback automatique.
- **REQ-FLW-4** — L'état de la machine à états DOIT être persistant et reprenable après reboot.
- **REQ-FLW-5** — L'environnement jail DOIT être intégralement démonté (tmpfs, namespaces, bind mounts) avant retour à Idle, qu'il s'agisse d'une fin normale ou d'une erreur.
- **REQ-FLW-6** — Le script d'entrée du jail DOIT disposer d'un timeout configurable ; son expiration entraîne un kill récursif via PID namespace.
- **REQ-FLW-7** — Les sorties du script d'entrée (stdout/stderr/code retour) DOIVENT être capturées et journalisées dans une zone dédiée sur l'hôte.

## Questions ouvertes

1. Quel health-check, et qui le définit (service, script, watchdog) ?
2. Stratégie de staging : espace temporaire nécessaire, ou écriture directe dans le slot inactif ?
3. Interface avec le bootloader (U-Boot env, `libubootenv`, autre) ?
4. Mises à jour partielles/delta : hors périmètre v1 ?
5. Déclenchement : pull périodique, push, commande manuelle (`updatectl`) ?
6. Persistance de l'état du jail entre exécutions : le jail peut-il laisser des artefacts sur l'hôte (fichiers de config, clés) ? Si oui, dans quelle zone ?
7. Rollback après échec du jail : faut-il pouvoir relancer un jail précédent, ou retourner à Idle ?
