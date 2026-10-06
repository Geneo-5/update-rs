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
| [spec/07-security-analysis.md](spec/07-security-analysis.md) | Analyse de sécurité approfondie : scénarios d'attaque, points à clarifier, guide Rust ANSSI | Brouillon |
| [state-of-the-art.md](state-of-the-art.md) | État de l'art des systèmes de mise à jour sécurisés (recherche, normes, implémentations, limites) | Brouillon |
| [tpm-revisions-comparison.md](tpm-revisions-comparison.md) | Comparaison des révisions de la bibliothèque TPM 2.0 (1.59 → 1.84+, composants certifiés, impact projet) | Brouillon |
| [key-management.md](key-management.md) | Cycle de vie complet des clés cryptographiques (`K-SIGN-REL`, `K-KEK-DEVICE`, `K-TPM-EK/AK`, Secure Boot, provisioning, rotation, révocation, destruction) — conforme ANSSI RGS B2 et NIST SP 800-57 | Brouillon |
| [prerequis-integration.md](prerequis-integration.md) | Prérequis d'intégration et éléments hors scope `update-rs` (Secure Boot, provisioning TPM, MTD, supply chain, configuration Linux, CUP) — matrice de responsabilités (4 acteurs) | Brouillon |
| [adr/](adr/) | Décisions d'architecture (une par fichier) : [0001 format dédié](adr/0001-custom-bundle-format.md), [0002 profil TPM](adr/0002-tpm-kek-policy-signature.md), [0003 jail](adr/0003-jail-environment.md) | — |
| [EBIOS-RM-analysis.md](EBIOS-RM-analysis.md) | Analyse de risque EBIOS Risk Manager (ateliers 1 à 5, plan de traitement) | Brouillon |
| [CHANGES-security-review.md](CHANGES-security-review.md) | Journal des modifications issues de la revue de sécurité du 2026-10-06 | — |

## Conventions

- Mots-clés **DOIT / NE DOIT PAS / DEVRAIT / PEUT** au sens de la RFC 2119.
- Chaque exigence porte un identifiant stable (`REQ-<domaine>-<n>`) pour pouvoir
  être référencée dans le code, les tests et les ADR.
- Les points non tranchés sont listés en **Questions ouvertes** à la fin de chaque
  document ; une question résolue donne lieu à un ADR puis disparaît de la liste.
- Une question ouverte transverse (bootloader, PCR, anti-rollback…) n'est détaillée qu'à **un seul endroit** ; les autres documents y renvoient au lieu de la recopier.
- Les décisions structurantes vont dans `adr/` (modèle : [adr/0000-template.md](adr/0000-template.md)).
