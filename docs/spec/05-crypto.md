# 05 — Cryptographie

Statut : Brouillon

## Principe

**REQ-CRY-1** — Toute primitive cryptographique DOIT venir des bibliothèques utilisées par les
projets GitHub de l'ANSSI. Aucune primitive n'est réimplémentée.

Référence principale : le projet Rust **MLA** (ANSSI-FR/MLA). Même si son format d'archive
n'est pas retenu, ses dépendances cryptographiques servent de liste de référence.

## Candidats (à confirmer par audit des dépendances)

> **Écart avec REQ-CRY-1** : les dépendances cryptographiques de MLA 2.1 (vérifiées dans son `Cargo.toml`) sont `aes`, `ctr`, `ghash`, `hkdf`, `sha2`, `subtle`, `zeroize`, `x25519-dalek`, `hpke`, `ml-kem`, `ed25519-dalek` et `ml-dsa`. Ni `aes-gcm-siv`, ni `aes-kw`, ni `p256` n'en font partie (`aes-gcm` n'y figure qu'en dev-dependency). Les choix GCM-SIV et RFC 5649 ne respectent donc pas littéralement REQ-CRY-1 : soit la règle est assouplie en « crates RustCrypto auditées », soit on se rapproche des briques MLA (AES-GCM construit sur `aes` + `ghash`).

**Principe** : utiliser les bibliothèques **validées par l'ANSSI** ou **auditées** (RustCrypto, ANSSI MLA, projets GitHub ANSSI). Aucune primitive n'est réimplémentée.

| Besoin | Candidat | Crates | Statut ANSSI/audit |
|---|---|---|---|
| AEAD | **AES-256-GCM-SIV** (RFC 8452, nonce-misuse resistant) | `aes-gcm-siv` (RustCrypto) | ✅ Audité (RustCrypto) |
| AEAD (fallback) | AES-256-GCM (si GCM-SIV non disponible) | `aes-gcm` (RustCrypto) | Audit à confirmer |
| KDF | HKDF-SHA256 (dérivation de la clé et du nonce de chaque chunk depuis la clé de session, voir [02-bundle-format.md](02-bundle-format.md)) | `hkdf`, `sha2` | `hkdf`, `sha2` sont des dépendances de MLA |
| KEM classique | X25519 (DHKEM, HPKE RFC 9180) | `x25519-dalek`, `hpke` | Non utilisé en v1 (profil KEK/TPM, pas de KEM) |
| KEM post-quantique | ML-KEM-1024 (hybride avec X25519) | `ml-kem` | Non utilisé en v1 |
| Signature (éditeur) | Ed25519 + ML-DSA (hybride) | `ed25519-dalek`, `ml-dsa` |
| **Signature (header, TPM)** | **ECDSA P-256 (SHA-256)** | **`p256` (RustCrypto), utilisé via TPM** |
| **Encapsulation clé** | **AES Key Wrap with Padding (RFC 5649)** | **`aes-kw` ou implémenté sur `aes`** |
| **Session TPM** | **ECDH P-256 + KDF (salage de session)** | **via `tss-esapi` (délégé au TPM)** |
| Hygiène | zeroize, comparaisons à temps constant | `zeroize`, `subtle` |

### Justification des choix

#### AES-GCM-SIV vs AES-GCM

**AES-GCM-SIV (RFC 8452)** est préféré à AES-GCM classique car il est **nonce-misuse resistant** :
- Si un nonce/IV est accidentellement réutilisé avec la même clé, la sécurité ne s'effondre pas (contrairement à GCM classique où une réutilisation de nonce permet de forger des ciphertexts).
- Chaque chunk est chiffré sous une clé dérivée distincte (voir [02-bundle-format.md](02-bundle-format.md)) : aucun couple (clé, nonce) n'est réutilisé par construction. GCM-SIV reste une défense en profondeur contre une erreur d'implémentation de la dérivation.
- **Statut ANSSI** : AES-GCM-SIV serait référencé dans les guides BSI (Allemagne) et SOG-IS (à vérifier). L'ANSSI ne l'a pas explicitement listé dans ses guides publics récents, mais elle suit généralement les recommandations SOG-IS. Si GCM-SIV n'est pas disponible dans les crates Rust auditées, AES-256-GCM classique reste acceptable (clé de chunk unique par message, voir [02-bundle-format.md](02-bundle-format.md)).

#### AES Key Wrap with Padding (RFC 5649) vs AES Key Wrap (RFC 3394)

**RFC 5649** est retenu pour supporter des **tailles arbitraires** (non multiples de 8 octets). Avec une clé de session de 32 octets (multiple de 8), RFC 3394 donnerait la même taille de ciphertext (voir question ouverte 9) :
- Notre clé de session = **32 octets** (master key), multiple de 8 : aucun padding n'est nécessaire.
- RFC 3394 nécessite que le plaintext soit un multiple de 8 octets (sinon padding manuel requis).
- RFC 5649 gère automatiquement le padding avec un format spécifique (4 octets de Magic + 4 octets de longueur + données).

**Calcul de la taille ciphertext RFC 5649** :
- Plaintext : 32 octets (clé de session)
- Padding : aucun (déjà multiple de 8)
- Header RFC 5649 : 8 octets (4 octets Magic + 4 octets longueur originale)
- **Ciphertext final : 8 + 32 = 40 octets**

**Statut ANSSI** : RFC 5649 n'est pas explicitement mentionné dans les guides ANSSI, mais RFC 3394 est bien connu et accepté. RFC 5649 est une extension naturelle qui simplifie l'implémentation.

## Exigences

- **REQ-CRY-2** — Versions épinglées, `Cargo.lock` versionné, audit (`cargo audit`/`cargo vet`/`cargo deny`) en CI.
- **REQ-CRY-3** — Vecteurs de test officiels (RFC, NIST) exécutés en CI, y compris sur ARMv7 (QEMU).
- **REQ-CRY-4** — Les clés et secrets intermédiaires DOIVENT être zeroizés.
- **REQ-CRY-5** — AES Key Wrap DOIT être implémenté selon **RFC 5649**. La taille du plaintext DOIT être 32 octets (clé de session) et le ciphertext résultant DOIT être 40 octets.
- **REQ-CRY-6** — ECDSA P-256 utilisé pour la signature du header DOIT être généré avec un nonce déterministe (RFC 6979) côté éditeur pour éviter les fuites par biais de nonce.
- **REQ-CRY-7** — L'implémentation d'AES Key Wrap DOIT être résistante aux fautes (vérification d'intégrité avant retour du plaintext).
- **REQ-CRY-8** — AES-GCM-SIV (RFC 8452) DOIT être utilisé pour le chiffrement des chunks si disponible, sous une clé et un nonce dérivés par chunk (REQ-CRY-9). Sinon, AES-256-GCM classique, avec la même dérivation.
- **REQ-CRY-9** — La clé et le nonce de chaque chunk (et du manifeste) DOIVENT être dérivés de la clé de session par `HKDF-Expand-SHA256` avec les `info` définis dans [02-bundle-format.md](02-bundle-format.md) ; la clé de session NE DOIT jamais chiffrer directement, et les clés dérivées DOIVENT être zeroizées après usage.

## Conformité au guide ANSSI 3.00 (2026)

**Référence** : [Guide ANSSI — Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques, version 3.00 (2026-03-20)](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf)

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
- **Recommandation `RecoModeChiff.1`** : mode non déterministe → ✅ chaque message est chiffré sous une clé dérivée unique ; le caractère déterministe pour une clé de session donnée est sans effet puisque celle-ci est unique par bundle
- **Recommandation `RecoModeChiff.2`** : preuve de sécurité dans un modèle pertinent → AES-GCM-SIV a une preuve de sécurité dans le modèle standard ✅
- **Recommandation `RecoModeChiff.3`** : ne pas employer isolément un mode sans intégrité → AES-GCM-SIV est un mode AEAD (chiffrement authentifié) ✅

**Note** : AES-GCM-SIV n'est pas explicitement mentionné dans le guide ANSSI 3.00, mais il est conforme aux règles génériques sur les modes opératoires. Il est également référencé dans les guides BSI (Allemagne) et SOG-IS (à vérifier), que l'ANSSI suit généralement.

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
- **Clé de session** : éphémère, unique par bundle (une nouvelle clé est générée pour chaque mise à jour) ; les clés de chunk en sont dérivées, une par chunk
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
4. ECDSA P-256 est une courbe NIST, pas dans les listes ANSSI préférées (préférence pour Ed25519 : **à sourcer**, non vérifiée). Acceptable car utilisée uniquement **via TPM** (pas de code sensible en clair) ?
5. Crate `aes-kw` : existe-t-il une implémentation auditable, ou faut-il implémenter sur `aes` ?
6. Interaction avec le profil TPM retenu ([03-tpm.md](03-tpm.md)) : ECDH P-256 via TPM pour sessions chiffrées — quelles bibliothèques Rust fiables ?
7. **Transition post-quantique pour ECDSA P-256** : quel calendrier pour adopter ML-DSA dans les TPM ?
8. **Migration de clé** : comment gérer la rotation de la KEK si une vulnérabilité est découverte dans AES-256 (improbable mais à prévoir) ?
9. Clé de session de 32 octets : conserver RFC 5649 (padding non exercé) ou revenir à RFC 3394 (même taille de ciphertext, plus simple, mieux connu) ? Impact sur `keywrap_alg`, REQ-CRY-5, REQ-TPM-6 et le mécanisme x3.
   > **État actuel** : RFC 5649 est retenu dans `02-bundle-format.md`, `03-tpm.md`, `ADR-0002` et `CHANGES-security-review.md`. L'historique des décisions est documenté dans `CHANGES-security-review.md` (section « Dérivation de clés par chunk »). Cette question peut être résolue par un ADR formel si un retour à RFC 3394 est envisagé.
10. HKDF-SHA256 : conformité au guide ANSSI 3.00 (fonctions de dérivation de clés) à confirmer, et crate `hkdf` à auditer.
11. `state-of-the-art.md` cite le chiffrement de clé « SIV » du guide de sélection ANSSI : il s'agit d'AES-SIV (RFC 5297), distinct d'AES-GCM-SIV (RFC 8452) retenu ici. La conformité d'AES-GCM-SIV reste donc une extrapolation des règles génériques.
12. Les verdicts « conforme » du guide 3.00 ci-dessus n'ont pas été recoupés avec le texte du guide lors de la relecture du 2026-10-07 : à vérifier avant toute communication externe.
