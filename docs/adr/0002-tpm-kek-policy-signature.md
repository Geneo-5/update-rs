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
3. **Profil C (retenu)** : KEK AES-256 scellée + policy `PolicyAuthorize` conditionnée à la vérification ECC du header par le TPM. **Pas de fallback logiciel** : le TPM DOIT supporter AES Keywrap nativement. Sessions chiffrées via EK/AK ECC pour protéger le bus.

## Décision

**Option C retenue**, combinant les avantages des deux autres :

- **KEK AES-256 non exportable** dans le TPM, avec `sign=0, decrypt=1, restricted=0`.
- **Policy `PolicyAuthorize`** : la KEK ne peut être utilisée pour déchiffrer la clé de session (AES Keywrap) que si le TPM a préalablement validé la signature ECDSA P-256 du header (via `TPM2_VerifySignature` + `TPM2_PolicyAuthorize`).
- **Clé de vérification ECC P-256** stockée dans le TPM (publique uniquement, privée côté éditeur).
- **Pas de fallback logiciel** : le TPM cible DOIT supporter le déchiffrement AES Keywrap (RFC 5649) en interne. Si le TPM ne le supporte pas, il est rejeté lors du provisioning. La KEK **ne quitte jamais le TPM**.
- **Sessions chiffrées** : toutes les commandes TPM sensibles sont exécutées sous session chiffrée/authentifiée dérivée de l'EK/AK ECC (protège contre A4).

### Justification

- La KEK **ne quitte jamais le TPM**, ce qui élimine la surface d'attaque d'exposition en RAM.
- L'utilisation d'ECDSA P-256 (courbe NIST) est acceptable car exécutée **via TPM** (pas de code sensible en clair côté logiciel), et la clé privée n'est jamais exposée (côté éditeur uniquement).
- Les sessions chiffrées via EK/AK ECC protègent le bus contre A4 (écoute SPI/I2C).

## Conséquences

### Positives

- La clé de session AES-GCM (Key + IV) peut être générée côté éditeur de manière standard (CSPRNG), puis encapsulée via AES Keywrap (RFC 5649).
- Le format de bundle est simple : un header de 512 octets avec `wrapped_session_key` (56 octets) et signature ECC (64 octets).
- Le TPM joue son rôle d'ancre de confiance sans devoir faire de chiffrement de masse.
- L'alignement avec ANSSI est maintenu pour les primitives côté éditeur (Ed25519 + ML-DSA pour les signatures "long-terme" ; ECDSA P-256 via TPM uniquement pour le header, acceptable).
- Résistance à l'écoute du bus TPM (sessions chiffrées).
- **La KEK ne quitte jamais le TPM**, ce qui élimine la surface d'attaque d'exposition en RAM.

### Négatives / risques

- **Dépendance au support AES Keywrap du TPM** : certains TPM bon marché ne supportent pas `TPM2_Duplicate` AES ou `TPM2_Unwrap`. Ces TPM sont rejetés lors du provisioning.
- **ECDSA P-256** : courbe NIST, hors liste ANSSI préférée, mais acceptable car exécutée via TPM.
- **TOCTOU** : entre `TPM2_VerifySignature` et le déchiffrement AES Keywrap, un attaquant A6 pourrait tenter de modifier le header. Atténuation : la policy `PolicyAuthorize` lie la signature à l'usage de la KEK, donc toute modification du header invaliderait la policy.

### À revoir

- Décider si la KEK doit être renouvelable en field (pour compromis) ou fixe à vie.
- Choisir la bibliothèque Rust pour AES Keywrap (`aes-kw` ou implémentation sur `aes`).
- Valider que `swtpm` supporte les sessions chiffrées ECDH pour les tests.
- Spécifier précisément la chaîne de boot pour ancrer le TPM dans une chaîne de confiance vérifiée (secure boot → bootloader → kernel → rootfs → `updated`).

### Alternative : mécanisme x3

Si le TPM ne supporte pas AES Keywrap (RFC 5649) nativement, un mécanisme alternatif x3 est acceptable :

- Le TPM effectue 3 déchiffrements AES séparés via des policies restreintes
- Chaque policy limite strictement la commande (AES decrypt) et les arguments
- La KEK reste toujours dans le TPM (non exportable)
- Les arguments sont contraints via `PolicyCpHash` ou mécanisme équivalent

Voir `docs/spec/03-tpm.md` section "Mécanisme alternatif x3" pour les détails.

## Conformité au guide ANSSI 3.00 (2026)

**Référence** : [Guide ANSSI — Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques, version 3.00 (2026-03-20)](https://cyber.gouv.fr/publications/regles-et-recommandations-concernant-le-choix-et-le-dimensionnement-des-mecanismes-cryptographiques)

### Analyse de conformité

#### AES-256 (KEK et AES Key Wrap)

**Conformité** : ✅ **CONFORME** aux règles ET recommandations post-quantiques

- **Règle `RègleTailleCléSym`** : taille minimale 128 bits → AES-256 utilise 256 bits ✅
- **Recommandation `RecoPQTailleCléSym`** : sécurité post-quantique nécessite au moins 192 bits → AES-256 utilise 256 bits ✅
- **Règle `RègleTailleBlocSym`** : blocs d'au moins 128 bits → AES utilise des blocs de 128 bits ✅
- **Règle `RèglePrimChiffBloc`** : pas d'attaque classique < 2^128 opérations → AES-256 conforme ✅
- **Règle `RèglePQPrimChiffBloc`** : pas d'attaque quantique < 2^80 opérations et profondeur < 2^48 → AES-256 conforme ✅
- **Recommandation `RecoPQPrimChiffBloc`** : pas d'attaque quantique < 2^128 opérations et profondeur < 2^64 → AES-256 conforme ✅

**Verdict** : AES-256 est explicitement listé comme conforme aux règles ET recommandations post-quantiques dans le guide ANSSI 3.00.

#### ECDSA P-256 (signature du header)

**Conformité** : ⚠️ **ACCEPTABLE** (avec justification)

- **Non post-quantique** : ECDSA P-256 est vulnérable à l'algorithme de Shor sur un ordinateur quantique suffisamment puissant.
- **Guide ANSSI 3.00** : pour une sécurité post-quantique, il faudrait utiliser des algorithmes post-quantiques (ML-DSA, Dilithium, etc.).
- **Atténuation** : ECDSA P-256 est utilisé **uniquement via TPM** pour la vérification de la signature du header. La clé privée n'est jamais exposée (côté éditeur uniquement), et l'opération de vérification est effectuée par le TPM lui-même.
- **Justification** : l'utilisation via TPM élimine la surface d'attaque logicielle. Le risque post-quantique est limité car :
  1. L'attaquant quantique devrait cibler le TPM (matériel sécurisé)
  2. La signature protège uniquement le header, pas le payload (qui est chiffré avec AES-256, post-quantique)
  3. Un compromis post-quantique permettrait de forger des headers, mais pas de déchiffrer les payloads (protégés par AES-256 + clé encapsulée par TPM)

**Recommandation** : pour une future version, envisager une transition vers des algorithmes post-quantiques (ML-DSA-65 ou ML-DSA-87) lorsque les TPM les supporteront nativement.

### Synthèse de conformité

| Primitive | Conformité | Justification |
|---|---|---|
| AES-256 (KEK) | ✅ Conforme | Taille de clé 256 bits, blocs 128 bits, résistant aux attaques classiques et quantiques |
| AES Key Wrap (RFC 5649) | ✅ Conforme | Utilise AES-256, mécanisme standardisé |
| ECDSA P-256 | ⚠️ Acceptable | Non post-quantique, mais utilisé via TPM uniquement |
| ECDH P-256 (sessions TPM) | ⚠️ Acceptable | Non post-quantique, mais utilisé via TPM uniquement |

**Verdict global** : ✅ **CONFORME** (avec atténuation pour ECDSA P-256). L'architecture est conforme au guide ANSSI 3.00, avec une exception acceptable pour ECDSA P-256 qui est atténuée par l'utilisation via TPM.

Voir [05-crypto.md](../spec/05-crypto.md) pour l'analyse détaillée de conformité.

## Références

- Spécification : [`docs/spec/03-tpm.md`](../spec/03-tpm.md), [`docs/spec/02-bundle-format.md`](../spec/02-bundle-format.md).
- RFC 5649 : AES Key Wrap with Padding Algorithm.
- TPM 2.0 Library Specification, Part 2 (Structures), Part 3 (Commands) : `TPM2_PolicyAuthorize`, `TPM2_VerifySignature`, `TPM2_Duplicate`, sessions chiffrées.
- RFC 6979 : Deterministic Usage of ECDSA and DSA.
- [Guide ANSSI 3.00 (2026)](https://cyber.gouv.fr/publications/regles-et-recommandations-concernant-le-choix-et-le-dimensionnement-des-mecanismes-cryptographiques) : Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques.
