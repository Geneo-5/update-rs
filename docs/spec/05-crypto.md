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
| AEAD | AES-256-GCM | RustCrypto (`aes`, `ghash`, ou `aes-gcm`) |
| KDF | HKDF-SHA512 | `hkdf`, `sha2` |
| KEM classique | X25519 (DHKEM, HPKE RFC 9180) | `x25519-dalek`, `hpke` |
| KEM post-quantique | ML-KEM-1024 (hybride avec X25519) | `ml-kem` |
| Signature (éditeur) | Ed25519 + ML-DSA (hybride) | `ed25519-dalek`, `ml-dsa` |
| **Signature (header, TPM)** | **ECDSA P-256 (SHA-256)** | **`p256` (RustCrypto), utilisé via TPM** |
| **Encapsulation clé** | **AES Keywrap (RFC 3394)** | **`aes-kw` ou implémenté sur `aes`** |
| **Session TPM** | **ECDH P-256 + KDF (salage de session)** | **via `tss-esapi` (délégé au TPM)** |
| Hygiène | zeroize, comparaisons à temps constant | `zeroize`, `subtle` |

## Exigences

- **REQ-CRY-2** — Versions épinglées, `Cargo.lock` versionné, audit (`cargo audit`/`cargo vet`/`cargo deny`) en CI.
- **REQ-CRY-3** — Vecteurs de test officiels (RFC, NIST) exécutés en CI, y compris sur ARMv7 (QEMU).
- **REQ-CRY-4** — Les clés et secrets intermédiaires DOIVENT être zeroizés.
- **REQ-CRY-5** — AES Keywrap DOIT être implémenté selon RFC 3394 avec authentification intégrée (IV par défaut `0xA6A6A6A6A6A6A6A6`).
- **REQ-CRY-6** — ECDSA P-256 utilisé pour la signature du header DOIT être généré avec un nonce déterministe (RFC 6979) côté éditeur pour éviter les fuites par biais de nonce.
- **REQ-CRY-7** — L'implémentation d'AES Keywrap DOIT être résistante aux fautes (vérification d'intégrité avant retour du plaintext).

## Questions ouvertes

1. Hybride PQ/classique dès la v1, ou classique d'abord avec agilité prévue ?
2. Maturité des crates `ml-kem` / `ml-dsa` (versions 0.x) : politique d'épinglage et de mise à jour ?
3. Cas d'usage de la libecc (C, ANSSI) : nécessaire ou exclue (FFI) ?
4. ECDSA P-256 est une courbe NIST, pas dans les listes ANSSI préférées (qui préfère Ed25519). Acceptable car utilisée uniquement **via TPM** (pas de code sensible en clair) ?
5. Crate `aes-kw` : existe-t-il une implémentation auditable, ou faut-il implémenter sur `aes` ?
6. Gestion des nonces ECDSA côté éditeur : RFC 6979 obligatoire ou optionnel ?
7. Interaction avec le profil TPM retenu ([03-tpm.md](03-tpm.md)) : ECDH P-256 via TPM pour sessions chiffrées — quelles bibliothèques Rust fiables ?
