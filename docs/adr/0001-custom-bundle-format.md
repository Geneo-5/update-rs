# ADR-0001 — Format d'archive dédié (MLA écarté)

- Statut : Accepté
- Date : 2026-10-05

## Contexte

L'archive de mise à jour est créée offline mais doit être **streamable** à la récupération
sur le device (REQ-BUN-2, REQ-BUN-3, REQ-BUN-5).

## Options considérées

1. Utiliser MLA (ANSSI-FR/MLA) comme conteneur.
2. Définir un format dédié, en réutilisant les bibliothèques cryptographiques de MLA.

## Décision

Option 2 : format dédié, spécifié dans [02-bundle-format.md](../spec/02-bundle-format.md).
MLA n'est pas retenu comme format d'archive.

## Conséquences

- Le format, son parseur et sa robustesse face aux entrées hostiles sont à notre charge
  (spécification précise, fuzzing, vecteurs de test).
- Les primitives restent celles des projets ANSSI (REQ-CRY-1) ; seul le format est propre au projet.
- À compléter : les raisons techniques précises de l'incompatibilité de MLA avec le besoin de streaming.
