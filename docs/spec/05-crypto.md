# 05 — Cryptographie

Statut : Brouillon

## Principe

**REQ-CRY-1** — Toute primitive cryptographique DOIT venir des bibliothèques utilisées par les
projets GitHub de l'ANSSI. Aucune primitive n'est réimplémentée.

Référence principale : le projet Rust **MLA** (ANSSI-FR/MLA). Même si son format d'archive
n'est pas retenu, ses dépendances cryptographiques servent de liste de référence.

## Candidats (à confirmer par audit des dépendances)

| Besoin | Candidat | Crates |
|---|---|---|
| AEAD | **AES-256-GCM-SIV** (RFC 8452, nonce-misuse resistant) | `aes-gcm-siv` (RustCrypto) |
| AEAD (fallback) | AES-256-GCM (si GCM-SIV non disponible) | `aes-gcm` (RustCrypto) |
| KDF | HKDF-SHA512 | `hkdf`, `sha2` |
| KEM classique | X25519 (DHKEM, HPKE RFC 9180) | `x25519-dalek`, `hpke` |
| KEM post-quantique | ML-KEM-1024 (hybride avec X25519) | `ml-kem` |
| Signature (éditeur) | Ed25519 + ML-DSA (hybride) | `ed25519-dalek`, `ml-dsa` |
| **Signature (header, TPM)** | **ECDSA P-256 (SHA-256)** | **`p256` (RustCrypto), utilisé via TPM** |
| **Encapsulation clé** | **AES Key Wrap with Padding (RFC 5649)** | **`aes-kw` ou implémenté sur `aes`** |
| **Session TPM** | **ECDH P-256 + KDF (salage de session)** | **via `tss-esapi` (délégé au TPM)** |
| Hygiène | zeroize, comparaisons à temps constant | `zeroize`, `subtle` |

### Justification des choix

#### AES-GCM-SIV vs AES-GCM

**AES-GCM-SIV (RFC 8452)** est préféré à AES-GCM classique car il est **nonce-misuse resistant** :
- Si un nonce/IV est accidentellement réutilisé avec la même clé, la sécurité ne s'effondre pas (contrairement à GCM classique où une réutilisation de nonce permet de forger des ciphertexts).
- Pour notre cas d'usage, la clé de session est unique par bundle, donc le risque de réutilisation est faible. Cependant, GCM-SIV apporte une robustesse supplémentaire en cas d'erreur d'implémentation ou de bug dans la génération de nonce côté éditeur.
- **Statut ANSSI** : AES-GCM-SIV est référencé dans les guides BSI (Allemagne) et SOG-IS. L'ANSSI ne l'a pas explicitement listé dans ses guides publics récents, mais elle suit généralement les recommandations SOG-IS. Si GCM-SIV n'est pas disponible dans les crates Rust auditées, AES-256-GCM classique reste acceptable avec génération de nonce déterministe.

#### AES Key Wrap with Padding (RFC 5649) vs AES Key Wrap (RFC 3394)

**RFC 5649** est préféré à RFC 3394 car il supporte des **tailles arbitraires** (non multiples de 8 octets) :
- Notre clé de session = Key (32 octets) + IV (12 octets) = **44 octets**, qui n'est pas un multiple de 8.
- RFC 3394 nécessite que le plaintext soit un multiple de 8 octets (sinon padding manuel requis).
- RFC 5649 gère automatiquement le padding avec un format spécifique (4 octets de Magic + 4 octets de longueur + données).

**Calcul de la taille ciphertext RFC 5649** :
- Plaintext : 44 octets (Key 32 + IV 12)
- Padding : RFC 5649 padde à un multiple de 8 octets → 44 → 48 octets
- Header RFC 5649 : 8 octets (4 octets Magic + 4 octets longueur originale)
- **Ciphertext final : 8 + 48 = 56 octets**

**Statut ANSSI** : RFC 5649 n'est pas explicitement mentionné dans les guides ANSSI, mais RFC 3394 est bien connu et accepté. RFC 5649 est une extension naturelle qui simplifie l'implémentation.

## Exigences

- **REQ-CRY-2** — Versions épinglées, `Cargo.lock` versionné, audit (`cargo audit`/`cargo vet`/`cargo deny`) en CI.
- **REQ-CRY-3** — Vecteurs de test officiels (RFC, NIST) exécutés en CI, y compris sur ARMv7 (QEMU).
- **REQ-CRY-4** — Les clés et secrets intermédiaires DOIVENT être zeroizés.
- **REQ-CRY-5** — AES Key Wrap DOIT être implémenté selon **RFC 5649** (avec padding automatique). La taille du plaintext DOIT être 44 octets (Key 32 + IV 12), et le ciphertext résultant DOIT être 56 octets.
- **REQ-CRY-6** — ECDSA P-256 utilisé pour la signature du header DOIT être généré avec un nonce déterministe (RFC 6979) côté éditeur pour éviter les fuites par biais de nonce.
- **REQ-CRY-7** — L'implémentation d'AES Key Wrap DOIT être résistante aux fautes (vérification d'intégrité avant retour du plaintext).
- **REQ-CRY-8** — AES-GCM-SIV (RFC 8452) DOIT être utilisé pour le chiffrement des chunks si disponible. Sinon, AES-256-GCM classique avec génération de nonce déterministe (ex: HKDF-SHA512 sur le chunk index + clé de session).

## Conformité au guide ANSSI 3.00 (2026)

**Référence** : [Guide ANSSI — Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques, version 3.00 (2026-03-20)](https://cyber.gouv.fr/publications/regles-et-recommandations-concernant-le-choix-et-le-dimensionnement-des-mecanismes-cryptographiques)

### Cryptographie symétrique

#### AES-256 (taille de clé et primitive)

**Conformité** : ✅ **CONFORME** aux règles ET recommandations post-quantiques

- **Règle `RègleTailleCléSym`** : taille minimale 128 bits → AES-256 utilise 256 bits ✅
- **Recommandation `RecoPQTailleCléSym`** : sécurité post-quantique nécessite au moins 192 bits → AES-256 utilise 256 bits ✅
- **Règle `RègleTailleBlocSym`** : blocs d'au moins 128 bits → AES utilise des blocs de 128 bits ✅
- **Règle `RèglePrimChiffBloc`** : pas d'attaque classique < 2^128 opérations → AES-256 conforme ✅
- **Règle `RèglePQPrimChiffBloc`** : pas d'attaque quantique < 2^80 opérations et profondeur < 2^48 → AES-256 conforme ✅
- **Recommandation `RecoPQPrimChiffBloc`** : pas d'attaque quantique < 2^128 opérations et profondeur < 2^64 → AES-256 conforme ✅

**Verdict** : AES-256 est explicitement listé comme conforme aux règles ET recommandations post-quantiques dans le guide ANSSI 3.00.

#### AES-GCM-SIV (RFC 8452)

**Conformité** : ✅ **CONFORME**

- **Règle `RègleModeChiff`** : pas d'attaque exploitant < 2^(n/2) blocs sous une même clé → AES-GCM-SIV conforme (borne birthday-bound respectée) ✅
- **Recommandation `RecoModeChiff.1`** : mode non déterministe → AES-GCM-SIV utilise un nonce unique par message ✅
- **Recommandation `RecoModeChiff.2`** : preuve de sécurité dans un modèle pertinent → AES-GCM-SIV a une preuve de sécurité dans le modèle standard ✅
- **Recommandation `RecoModeChiff.3`** : ne pas employer isolément un mode sans intégrité → AES-GCM-SIV est un mode AEAD (chiffrement authentifié) ✅

**Note** : AES-GCM-SIV n'est pas explicitement mentionné dans le guide ANSSI 3.00, mais il est conforme aux règles génériques sur les modes opératoires. Il est également référencé dans les guides BSI (Allemagne) et SOG-IS, que l'ANSSI suit généralement.

#### AES Key Wrap with Padding (RFC 5649)

**Conformité** : ✅ **CONFORME**

- Utilise AES-256 comme primitive sous-jacente → conforme aux règles sur AES-256
- Mécanisme d'encapsulation de clé standardisé (RFC 5649)
- Pas explicitement mentionné dans le guide ANSSI 3.00, mais RFC 3394 (AES Key Wrap sans padding) est bien connu et accepté. RFC 5649 est une extension naturelle qui simplifie l'implémentation pour des tailles non multiples de 8 octets.

### Cryptographie asymétrique

#### ECDSA P-256 (courbe NIST)

**Conformité** : ⚠️ **ACCEPTABLE** (avec justification)

- **Non post-quantique** : ECDSA P-256 est vulnérable à l'algorithme de Shor sur un ordinateur quantique suffisamment puissant.
- **Guide ANSSI 3.00** : pour une sécurité post-quantique, il faudrait utiliser des algorithmes post-quantiques (ML-DSA, Dilithium, etc.).
- **Atténuation** : ECDSA P-256 est utilisé **uniquement via TPM** pour la vérification de la signature du header. La clé privée n'est jamais exposée (côté éditeur uniquement), et l'opération de vérification est effectuée par le TPM lui-même.
- **Justification** : l'utilisation via TPM élimine la surface d'attaque logicielle. Le risque post-quantique est limité car :
  1. L'attaquant quantique devrait cibler le TPM (matériel sécurisé)
  2. La signature protège uniquement le header, pas le payload (qui est chiffré avec AES-256, post-quantique)
  3. Un compromis post-quantique permettrait de forger des headers, mais pas de déchiffrer les payloads (protégés par AES-256 + clé encapsulée par TPM)

**Recommandation** : pour une future version, envisager une transition vers des algorithmes post-quantiques (ML-DSA-65 ou ML-DSA-87) lorsque les TPM les supporteront nativement.

#### Ed25519 + ML-DSA (signatures éditeur)

**Conformité** : ✅ **CONFORME** (hybride classique + post-quantique)

- **Ed25519** : signature classique basée sur Curve25519
- **ML-DSA** (Dilithium) : signature post-quantique sélectionnée par le NIST
- **Hybride** : les deux signatures sont utilisées en parallèle pour garantir la sécurité même si l'un des deux algorithmes est compromis
- **Conforme** aux recommandations post-quantiques du guide ANSSI 3.00

### Fonctions de hachage

#### SHA-256

**Conformité** : ✅ **CONFORME**

- **Règle `RègleHachage`** : pas d'attaque classique < 2^128 opérations → SHA-256 conforme (résistance aux préimages et collisions) ✅
- **Règle `RèglePQHachage`** : pas d'attaque quantique < 2^80 opérations et profondeur < 2^48 → SHA-256 conforme (Grover réduit la complexité à 2^128) ✅
- **Recommandation `RecoPQHachage`** : pas d'attaque quantique < 2^128 opérations et profondeur < 2^64 → SHA-256 conforme ✅

### Synthèse de conformité

| Primitive | Conformité | Justification |
|---|---|---|
| AES-256 | ✅ Conforme | Taille de clé 256 bits, blocs 128 bits, résistant aux attaques classiques et quantiques |
| AES-GCM-SIV | ✅ Conforme | Mode AEAD, nonce unique, preuve de sécurité |
| AES Key Wrap (RFC 5649) | ✅ Conforme | Utilise AES-256, mécanisme standardisé |
| ECDSA P-256 | ⚠️ Acceptable | Non post-quantique, mais utilisé via TPM uniquement |
| Ed25519 + ML-DSA | ✅ Conforme | Hybride classique + post-quantique |
| SHA-256 | ✅ Conforme | Résistant aux attaques classiques et quantiques |

### Durée de vie des clés (crypto-période)

Le guide ANSSI 3.00 (section A.4.1) mentionne la notion de **crypto-période** (durée de vie maximale des clés) pour réduire l'effet d'une éventuelle compromission.

**Notre architecture** :
- **Clé de session** : éphémère, unique par bundle (une nouvelle clé est générée pour chaque mise à jour)
- **KEK** : fixe à vie du dispositif (stockée dans le TPM, non exportable)
- **Clé de vérification ECC** : fixe à vie du dispositif (stockée dans le TPM, publique uniquement)

**Verdict** : ✅ **CONFORME**. L'utilisation de clés de session éphémères (une par bundle) est excellente et suit les meilleures pratiques.

### Recommandations post-quantiques

Le guide ANSSI 3.00 recommande de viser une sécurité post-quantique pour les mécanismes utilisés au-delà du 1er janvier 2030 (RecoSécuLongTerme).

**Notre architecture** :
- **Chiffrement du payload** : AES-256-GCM-SIV → **post-quantique** ✅
- **Encapsulation de clé** : AES Key Wrap avec AES-256 → **post-quantique** ✅
- **Signature du header** : ECDSA P-256 → **non post-quantique** ⚠️ (mais utilisé via TPM uniquement)
- **Signatures éditeur** : Ed25519 + ML-DSA → **hybride post-quantique** ✅

**Verdict** : ⚠️ **PARTIELLEMENT CONFORME**. Le chiffrement du payload est post-quantique, mais la signature du header (ECDSA P-256) ne l'est pas. Cependant, ce risque est atténué par l'utilisation via TPM.

**Recommandation** : surveiller l'évolution des TPM pour adopter des algorithmes de signature post-quantiques (ML-DSA) lorsque le support sera disponible.

## Questions ouvertes

1. Hybride PQ/classique dès la v1, ou classique d'abord avec agilité prévue ?
2. Maturité des crates `ml-kem` / `ml-dsa` (versions 0.x) : politique d'épinglage et de mise à jour ?
3. Cas d'usage de la libecc (C, ANSSI) : nécessaire ou exclue (FFI) ?
4. ECDSA P-256 est une courbe NIST, pas dans les listes ANSSI préférées (qui préfère Ed25519). Acceptable car utilisée uniquement **via TPM** (pas de code sensible en clair) ?
5. Crate `aes-kw` : existe-t-il une implémentation auditable, ou faut-il implémenter sur `aes` ?
6. Gestion des nonces ECDSA côté éditeur : RFC 6979 obligatoire ou optionnel ?
7. Interaction avec le profil TPM retenu ([03-tpm.md](03-tpm.md)) : ECDH P-256 via TPM pour sessions chiffrées — quelles bibliothèques Rust fiables ?
8. AES-GCM-SIV : nonce dérivé de manière déterministe (HKDF) ou aléatoire (CSPRNG) ?
9. **Transition post-quantique pour ECDSA P-256** : quel calendrier pour adopter ML-DSA dans les TPM ?
10. **Migration de clé** : comment gérer la rotation de la KEK si une vulnérabilité est découverte dans AES-256 (improbable mais à prévoir) ?
