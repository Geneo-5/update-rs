# Documentation update-rs

Ce dossier contient la spécification du projet. Elle est rédigée en commun ; chaque
document a un **statut** en tête de fichier (`Brouillon` → `En revue` → `Stable`).

## Index

| Doc | Sujet | Statut |
|---|---|---|
| [spec/00-overview.md](spec/00-overview.md) | Périmètre, cibles, exigences globales, glossaire | Brouillon |
| [spec/01-threat-model.md](spec/01-threat-model.md) | Acteurs, actifs, menaces, hors périmètre | Brouillon |
| [spec/02-bundle-format.md](spec/02-bundle-format.md) | Format d'archive streamable, header binaire, clé de session | Brouillon |
| [spec/03-tpm.md](spec/03-tpm.md) | Rôle du TPM 2.0, hiérarchie de clés (KEK, ECC), policies, sessions chiffrées | Brouillon |
| [spec/04-update-flow.md](spec/04-update-flow.md) | Machine à états, A/B, rollback | Brouillon |
| [spec/05-crypto.md](spec/05-crypto.md) | Primitives et bibliothèques (AES-GCM, AES Keywrap, ECDSA P-256 via TPM, Ed25519/ML-DSA) | Brouillon |
| [spec/06-jail.md](spec/06-jail.md) | Environnement d'exécution sandboxé du payload (tmpfs, namespaces, fsset, seccomp) | Brouillon |
| [adr/](adr/) | Décisions d'architecture (une par fichier) | — |

## Conventions

- Mots-clés **DOIT / NE DOIT PAS / DEVRAIT / PEUT** au sens de la RFC 2119.
- Chaque exigence porte un identifiant stable (`REQ-<domaine>-<n>`) pour pouvoir
  être référencée dans le code, les tests et les ADR.
- Les points non tranchés sont listés en **Questions ouvertes** à la fin de chaque
  document ; une question résolue donne lieu à un ADR puis disparaît de la liste.
- Les décisions structurantes vont dans `adr/` (modèle : [adr/0000-template.md](adr/0000-template.md)).
