# ADR-0002 — Profil TPM : KEK AES avec policy liée à la signature ECC du header

- Statut : Proposé
- Date : 2026-10-06

## Contexte

Le système doit garantir que :

1. **Confidentialité** : le payload des bundles n'est déchiffrable que sur un device disposant du TPM cible (REQ-THR-2).
2. **Authenticité** : seuls les bundles signés par l'éditeur peuvent être déchiffrés (REQ-THR-1).
3. **Non-exportabilité** : la clé de déchiffrement ne quitte jamais le TPM.
4. **Résistance à l'écoute bus** : un attaquant écoutant SPI/I2C ne doit pas obtenir les secrets (REQ-THR-5).

Les options A (clé scellée en RAM) et B (ECDH via TPM) discutées précédemment présentaient chacune des inconvénients :
- Profil A : la clé transite en RAM, exposée à un attaquant A6 (compromission logicielle partielle).
- Profil B : pas d'ECDH P-256 + KEM hybride dans les listes ANSSI, glue à écrire, pas de composante PQ.

## Options considérées

1. **Profil A** (clé privée scellée déballée en RAM) : primitives libres mais exposition RAM.
2. **Profil B** (ECDH résident via `TPM2_ECDH_ZGen`) : pas d'exposition, mais glue, pas PQ, pas de KEM standard.
3. **Profil C (retenu)** : KEK AES-256 scellée + policy `PolicyAuthorize` conditionnée à la vérification ECC du header par le TPM. Fallback logiciel x3 si AES Keywrap non supporté par le TPM. Sessions chiffrées via EK/AK ECC pour protéger le bus.

## Décision

**Option C retenue**, combinant les avantages des deux autres :

- **KEK AES-256 non exportable** dans le TPM, avec `sign=0, decrypt=1, restricted=0`.
- **Policy `PolicyAuthorize`** : la KEK ne peut être utilisée pour déchiffrer la clé de session (AES Keywrap) que si le TPM a préalablement validé la signature ECDSA P-256 du header (via `TPM2_VerifySignature` + `TPM2_PolicyAuthorize`).
- **Clé de vérification ECC P-256** stockée dans le TPM (publique uniquement, privée côté éditeur).
- **Fallback x3** : si le TPM ne supporte pas AES Keywrap, la KEK est déscellée en RAM temporaire, mais le mécanisme de vérification de signature est répété 3 fois (hash du header recalculé 3 fois, 3 `TPM2_VerifySignature` distincts) pour compenser la fenêtre d'exposition RAM.
- **Sessions chiffrées** : toutes les commandes TPM sensibles sont exécutées sous session chiffrée/authentifiée dérivée de l'EK/AK ECC (protège contre A4).

### Justification

- La KEK ne quitte jamais le TPM dans le cas idéal (AES Keywrap supporté).
- Dans le cas fallback, la répétition x3 du mécanisme de vérification est une **compensation probabiliste** : un attaquant A6 qui aurait compromis le logiciel entre deux vérifications aurait une fenêtre d'exploitation réduite, et devrait contourner 3 vérifications successives.
- L'utilisation d'ECDSA P-256 (courbe NIST) est acceptable car exécutée **via TPM** (pas de code sensible en clair côté logiciel), et la clé privée n'est jamais exposée (côté éditeur uniquement).
- Les sessions chiffrées via EK/AK ECC protègent le bus contre A4 (écoute SPI/I2C).

## Conséquences

### Positives

- La clé de session AES-GCM (Key + IV) peut être générée côté éditeur de manière standard (CSPRNG), puis encapsulée via AES Keywrap (RFC 3394).
- Le format de bundle est simple : un header de 512 octets avec `wrapped_session_key` (40 octets) et signature ECC (128 octets).
- Le TPM joue son rôle d'ancre de confiance sans devoir faire de chiffrement de masse.
- L'alignement avec ANSSI est maintenu pour les primitives côté éditeur (Ed25519 + ML-DSA pour les signatures "long-terme" ; ECDSA P-256 via TPM uniquement pour le header, acceptable).
- Résistance à l'écoute du bus TPM (sessions chiffrées).

### Négatives / risques

- **Dépendance au support AES Keywrap du TPM** : certains TPM bon marché ne supportent pas `TPM2_Duplicate` AES ou `TPM2_Unwrap`. Le fallback x3 introduit une fenêtre d'exposition RAM de la KEK.
- **Complexité du fallback** : 3 vérifications de signature successives coûtent 3 appels TPM + 3 calculs SHA-256 du header.
- **ECDSA P-256** : courbe NIST, hors liste ANSSI préférée, mais acceptable car exécutée via TPM.
- **TOCTOU** : entre `TPM2_VerifySignature` et le déchiffrement AES Keywrap, un attaquant A6 pourrait tenter de modifier le header. Atténuation : la policy `PolicyAuthorize` lie la signature à l'usage de la KEK, donc toute modification du header invaliderait la policy.

### À revoir

- Valider le fallback x3 par analyse formelle (probabiliste vs déterministe).
- Décider si la KEK doit être renouvelable en field (pour compromis) ou fixe à vie.
- Choisir la bibliothèque Rust pour AES Keywrap (`aes-kw` ou implémentation sur `aes`).
- Valider que `swtpm` supporte les sessions chiffrées ECDH pour les tests.

## Références

- Spécification : [`docs/spec/03-tpm.md`](../spec/03-tpm.md), [`docs/spec/02-bundle-format.md`](../spec/02-bundle-format.md).
- RFC 3394 : AES Key Wrap Algorithm.
- TPM 2.0 Library Specification, Part 2 (Structures), Part 3 (Commands) : `TPM2_PolicyAuthorize`, `TPM2_VerifySignature`, `TPM2_Duplicate`, sessions chiffrées.
- RFC 6979 : Deterministic Usage of ECDSA and DSA.
