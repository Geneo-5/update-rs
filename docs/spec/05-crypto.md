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
- **Statut ANSSI** : RFC 5649 n'est pas explicitement mentionné dans les guides ANSSI, mais RFC 3394 est bien connu et accepté. RFC 5649 est une extension naturelle qui simplifie l'implémentation. Si RFC 5649 n'est pas disponible, utiliser RFC 3394 avec padding manuel (ajouter 4 octets de zéros pour atteindre 48 octets, puis troncature après unwrap).

## Exigences

- **REQ-CRY-2** — Versions épinglées, `Cargo.lock` versionné, audit (`cargo audit`/`cargo vet`/`cargo deny`) en CI.
- **REQ-CRY-3** — Vecteurs de test officiels (RFC, NIST) exécutés en CI, y compris sur ARMv7 (QEMU).
- **REQ-CRY-4** — Les clés et secrets intermédiaires DOIVENT être zeroizés.
- **REQ-CRY-5** — AES Key Wrap DOIT être implémenté selon **RFC 5649** (avec padding automatique). Si RFC 5649 n'est pas disponible, utiliser RFC 3394 avec padding manuel (ajouter 4 octets de zéros pour atteindre un multiple de 8 octets).
- **REQ-CRY-6** — ECDSA P-256 utilisé pour la signature du header DOIT être généré avec un nonce déterministe (RFC 6979) côté éditeur pour éviter les fuites par biais de nonce.
- **REQ-CRY-7** — L'implémentation d'AES Key Wrap DOIT être résistante aux fautes (vérification d'intégrité avant retour du plaintext).
- **REQ-CRY-8** — AES-GCM-SIV (RFC 8452) DOIT être utilisé pour le chiffrement des chunks si disponible. Sinon, AES-256-GCM classique avec génération de nonce déterministe (ex: HKDF-SHA512 sur le chunk index + clé de session).

## Questions ouvertes

1. Hybride PQ/classique dès la v1, ou classique d'abord avec agilité prévue ?
2. Maturité des crates `ml-kem` / `ml-dsa` (versions 0.x) : politique d'épinglage et de mise à jour ?
3. Cas d'usage de la libecc (C, ANSSI) : nécessaire ou exclue (FFI) ?
4. ECDSA P-256 est une courbe NIST, pas dans les listes ANSSI préférées (qui préfère Ed25519). Acceptable car utilisée uniquement **via TPM** (pas de code sensible en clair) ?
5. Crate `aes-kw` : existe-t-il une implémentation auditable, ou faut-il implémenter sur `aes` ?
6. Gestion des nonces ECDSA côté éditeur : RFC 6979 obligatoire ou optionnel ?
7. Interaction avec le profil TPM retenu ([03-tpm.md](03-tpm.md)) : ECDH P-256 via TPM pour sessions chiffrées — quelles bibliothèques Rust fiables ?
