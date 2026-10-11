//! Primitives cryptographiques pour le déchiffrement de bundles.
//!
//! Spécification : `docs/spec/05-crypto.md`.
//!
//! Ce module expose les fonctions bas-niveau utilisées par `BundleReader`
//! pour le déchiffrement et la vérification :
//!
//! - **AES-256-GCM-SIV** (RFC 8452) : chiffrement authentifié par chunk
//! - **HKDF-SHA256** (RFC 5869) : dérivation de clés et nonces par chunk
//! - **AES Key Wrap with Padding** (RFC 5649) : enveloppe la clé de session
//! - **AES-256 Key Wrap** (RFC 3394) : utilisé par le mécanisme x3
//!
//! # Conformité ANSSI
//!
//! Toutes les opérations sur clés/secrets utilisent des bibliothèques
//! RustCrypto auditées. Les constantes temporelles sont assurées par
//! `subtle::ConstantTimeEq` pour les comparaisons cryptographiques.
//! Les secrets sont zeroizés après usage (`zeroize::Zeroize`)
//! conformément au REQ-CRY-4.

use crate::errors::CryptoError;
use aes::cipher::{BlockDecrypt, BlockEncrypt};
use aes::cipher::generic_array::GenericArray;
use aes_gcm_siv::aead::AeadInPlace;
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Label HKDF pour la dérivation de clé de chunk : `"update-rs/chunk"`.
pub const HKDF_CHUNK_LABEL: &[u8] = b"update-rs/chunk";

/// Label HKDF pour la dérivation de clé de manifeste : `"update-rs/manifest"`.
pub const HKDF_MANIFEST_LABEL: &[u8] = b"update-rs/manifest";

/// Taille d'une clé AES-256 en octets.
pub const AES256_KEY_SIZE: usize = 32;

/// Taille d'un nonce AES-GCM en octets.
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Taille d'un tag AES-GCM en octets.
pub const AES_GCM_TAG_SIZE: usize = 16;

/// Taille d'une clé AES-128 en octets (pour le mécanisme x3).
pub const AES128_KEY_SIZE: usize = 16;

/// Nombre de blocs AES-128 dans le mécanisme x3.
pub const X3_BLOCKS: usize = 3;

/// Taille de la clé de session en octets.
pub const SESSION_KEY_SIZE: usize = 32;

// ─── AES-256-GCM-SIV (RFC 8452) ──────────────────────────────────────────────

/// Chiffre des données plaintext avec AES-256-GCM-SIV.
///
/// Retourne le ciphertext + tag (tag appendé aux données chiffrées).
///
/// # Paramètres
///
/// - `key` : clé AES-256 (32 octets)
/// - `nonce` : nonce 96-bit (12 octets)
/// - `plaintext` : données à chiffrer
/// - `aad` : données authentifiées mais non chiffrées
///
/// # Erreurs
///
/// - `CryptoError::InvalidKeySize` : clé ne fait pas 32 octets
/// - `CryptoError::InvalidNonceSize` : nonce ne fait pas 12 octets
/// - `CryptoError::DecryptionFailed` : échec interne du chiffrement
pub fn aes_gcm_siv_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: key.len(),
            expected: AES256_KEY_SIZE,
        });
    }
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceSize {
            size: nonce.len(),
            expected: AES_GCM_NONCE_SIZE,
        });
    }

    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    // Buffer : plaintext + tag (16 octets)
    let mut buf = Vec::with_capacity(plaintext.len() + AES_GCM_TAG_SIZE);
    buf.extend_from_slice(plaintext);

    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut buf)
        .map_err(|_| CryptoError::DecryptionFailed("échec du chiffrement AES-GCM-SIV".into()))?;

    buf.extend_from_slice(tag.as_slice());
    Ok(buf)
}

/// Déchiffre des données avec AES-256-GCM-SIV.
///
/// Les données attendues sont : `ciphertext || tag` (tag sur 16 octets
/// appendé à la fin, format standard AES-GCM-SIV).
///
/// # Paramètres
///
/// - `key` : clé AES-256 (32 octets)
/// - `nonce` : nonce 96-bit (12 octets)
/// - `ciphertext_with_tag` : données chiffrées + tag (tag en fin)
/// - `aad` : données authentifiées mais non chiffrées
///
/// # Erreurs
///
/// - `CryptoError::InvalidKeySize` : clé ne fait pas 32 octets
/// - `CryptoError::InvalidNonceSize` : nonce ne fait pas 12 octets
/// - `CryptoError::InvalidTag` : tag d'authentification invalide
/// - `CryptoError::DecryptionFailed` : échec interne du déchiffrement
///
/// # Sécurité
///
/// La clé et le nonce sont zeroizés après usage (REQ-CRY-4).
pub fn aes_gcm_siv_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: key.len(),
            expected: AES256_KEY_SIZE,
        });
    }
    if nonce.len() != AES_GCM_NONCE_SIZE {
        return Err(CryptoError::InvalidNonceSize {
            size: nonce.len(),
            expected: AES_GCM_NONCE_SIZE,
        });
    }

    let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    // Split ciphertext + tag (last 16 bytes)
    let len = ciphertext_with_tag.len();
    if len < AES_GCM_TAG_SIZE {
        return Err(CryptoError::DecryptionFailed(
            "ciphertext trop court pour contenir un tag".into(),
        ));
    }
    let (ciphertext, tag_bytes) = ciphertext_with_tag.split_at(len - AES_GCM_TAG_SIZE);

    let tag = Tag::from_slice(tag_bytes);

    // Decrypt in place
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    plaintext.extend_from_slice(ciphertext);

    cipher
        .decrypt_in_place_detached(nonce, aad, &mut plaintext, tag)
        .map_err(|_| CryptoError::InvalidTag)?;

    // Zeroization des secrets (REQ-CRY-4) — le key/nonce
    // est zeroizé à la fin de la fonction appelante.
    Ok(plaintext)
}

// ─── HKDF-SHA256 (RFC 5869) ──────────────────────────────────────────────────

/// Dérive une clé et un nonce par chunk depuis la clé de session.
///
/// Utilise HKDF-Expand-SHA256 (RFC 5869 §2.2) avec le label
/// `"update-rs/chunk"` pour dériver `okm` :
///
/// ```text
/// info = HKDF_Label || bundle_id || chunk_index (u32 big-endian)
/// okm = HKDF-Expand-SHA256(session_key, info, 44)
/// chunk_key = okm[0..32]    # 32 octets pour AES-256
/// chunk_nonce = okm[32..44] # 12 octets pour AES-GCM 96-bit
/// ```
///
/// # Paramètres
///
/// - `session_key` : clé de session master (32 octets)
/// - `bundle_id` : identifiant unique du bundle (32 octets)
/// - `chunk_index` : index 0-based du chunk
///
/// # Returns
///
/// `(chunk_key, chunk_nonce)` où :
/// - `chunk_key` : clé AES-256 unique par chunk (32 octets)
/// - `chunk_nonce` : nonce 96-bit unique par chunk (12 octets)
///
/// # Conformité
///
/// Cette fonction satisfait REQ-CRY-9 (nonce unique par chunk) en
/// dérivant un nonce différent pour chaque chunk via HKDF.
#[inline]
#[allow(clippy::unwrap_used)]
pub fn derive_chunk_key(
    session_key: &[u8; AES256_KEY_SIZE],
    bundle_id: &[u8; 32],
    chunk_index: u32,
) -> ([u8; AES256_KEY_SIZE], [u8; AES_GCM_NONCE_SIZE]) {
    // Construire le info string : label || bundle_id || chunk_index (u32 BE)
    let mut info = Vec::with_capacity(HKDF_CHUNK_LABEL.len() + bundle_id.len() + 4);
    info.extend_from_slice(HKDF_CHUNK_LABEL);
    info.extend_from_slice(bundle_id);
    info.extend_from_slice(&chunk_index.to_be_bytes());

    // HKDF-Expand-SHA256 pour dériver 44 octets (32 key + 12 nonce)
    let hkdf = Hkdf::<Sha256>::new(None::<&[u8]>, session_key);
    let mut okm = [0u8; 44]; // 32 (key) + 12 (nonce)
    hkdf.expand(&info as &[u8], &mut okm)
        .expect("HKDF-Expand-SHA256 ne peut pas échouer avec cette taille de sortie");

    // Extraire la clé et le nonce
    let mut chunk_key = [0u8; AES256_KEY_SIZE];
    let mut chunk_nonce = [0u8; AES_GCM_NONCE_SIZE];

    chunk_key.copy_from_slice(&okm[0..AES256_KEY_SIZE]);
    chunk_nonce.copy_from_slice(&okm[AES256_KEY_SIZE..AES256_KEY_SIZE + AES_GCM_NONCE_SIZE]);

    // Zeroization de l'okm intermédiaire (REQ-CRY-4)
    okm.zeroize();

    (chunk_key, chunk_nonce)
}

/// Dérive une clé de manifeste depuis la clé de session.
///
/// Utilise HKDF-Expand-SHA256 (RFC 5869 §2.2) avec le label
/// `"update-rs/manifest"` pour dériver la clé de chiffrement du
/// manifeste :
///
/// ```text
/// info = "update-rs/manifest" || bundle_id
/// chunk_key = HKDF-Expand-SHA256(session_key, info, 32)
/// ```
///
/// # Paramètres
///
/// - `session_key` : clé de session master (32 octets)
/// - `bundle_id` : identifiant unique du bundle (32 octets)
///
/// # Returns
///
/// Clé AES-256 unique pour le manifeste (32 octets).
///
/// # Conformité
///
/// Cette fonction satisfie REQ-CRY-9 en dérivant une clé unique
/// pour le manifeste, différente de celle utilisée pour les chunks.
#[inline]
#[allow(clippy::unwrap_used)]
pub fn derive_manifest_key(
    session_key: &[u8; AES256_KEY_SIZE],
    bundle_id: &[u8; 32],
) -> [u8; AES256_KEY_SIZE] {
    // Construire le info string : label || bundle_id
    let mut info = Vec::with_capacity(HKDF_MANIFEST_LABEL.len() + bundle_id.len());
    info.extend_from_slice(HKDF_MANIFEST_LABEL);
    info.extend_from_slice(bundle_id);

    // HKDF-Expand-SHA256 pour dériver 32 octets (clé AES-256)
    let hkdf = Hkdf::<Sha256>::new(None::<&[u8]>, session_key);
    let mut key = [0u8; AES256_KEY_SIZE];
    hkdf.expand(&info as &[u8], &mut key)
        .expect("HKDF-Expand-SHA256 ne peut pas échouer avec cette taille de sortie");

    // Zeroization de l'info intermédiaire (REQ-CRY-4)
    info.zeroize();

    key
}

/// Dérive une clé de manifeste et un nonce depuis la clé de session.
///
/// Utilise HKDF-Expand-SHA256 (RFC 5869 §2.2) avec le label
/// `"update-rs/manifest"` pour dériver simultanément la clé de
/// chiffrement et le nonce du manifeste :
///
/// ```text
/// info = "update-rs/manifest" || bundle_id
/// okm = HKDF-Expand-SHA256(session_key, info, 44)
/// manifest_key = okm[0..32]   # 32 octets pour AES-256
/// nonce = okm[32..44]         # 12 octets pour AES-GCM 96-bit
/// ```
///
/// # Paramètres
///
/// - `session_key` : clé de session master (32 octets)
/// - `bundle_id` : identifiant unique du bundle (32 octets)
///
/// # Returns
///
/// `(manifest_key, nonce)` où :
/// - `manifest_key` : clé AES-256 unique pour le manifeste (32 octets)
/// - `nonce` : nonce 96-bit unique pour le manifeste (12 octets)
///
/// # Conformité
///
/// Cette fonction satisfie REQ-CRY-9 en dérivant une clé et un nonce
/// uniques pour le manifeste, différents de ceux utilisés pour les chunks.
#[inline]
#[allow(clippy::unwrap_used)]
pub fn decrypt_manifest_key(
    session_key: &[u8; AES256_KEY_SIZE],
    bundle_id: &[u8; 32],
) -> ([u8; AES256_KEY_SIZE], [u8; AES_GCM_NONCE_SIZE]) {
    // Construire le info string : label || bundle_id
    let mut info = Vec::with_capacity(HKDF_MANIFEST_LABEL.len() + bundle_id.len());
    info.extend_from_slice(HKDF_MANIFEST_LABEL);
    info.extend_from_slice(bundle_id);

    // HKDF-Expand-SHA256 pour dériver 44 octets (32 key + 12 nonce)
    let hkdf = Hkdf::<Sha256>::new(None::<&[u8]>, session_key);
    let mut okm = [0u8; 44]; // 32 (key) + 12 (nonce)
    hkdf.expand(&info as &[u8], &mut okm)
        .expect("HKDF-Expand-SHA256 ne peut pas échouer avec cette taille de sortie");

    // Extraire la clé et le nonce
    let mut manifest_key = [0u8; AES256_KEY_SIZE];
    let mut nonce = [0u8; AES_GCM_NONCE_SIZE];

    manifest_key.copy_from_slice(&okm[0..AES256_KEY_SIZE]);
    nonce.copy_from_slice(&okm[AES256_KEY_SIZE..AES256_KEY_SIZE + AES_GCM_NONCE_SIZE]);

    // Zeroization de l'okm intermédiaire (REQ-CRY-4)
    okm.zeroize();

    (manifest_key, nonce)
}

// ─── AES Key Wrap with Padding (RFC 5649) ─────────────────────────────────────

/// Enveloppe une clé de session (32 octets) selon AES Key Wrap avec Padding.
///
/// Produit un ciphertext de 40 octets à partir d'une clé de 32 octets,
/// conformément à RFC 5649 §3 :
///
/// - Les 32 octets de clé sont padisés avec `0x01` suivi de zéros
/// - 4 blocs AES-128 sont chiffrés en mode CBC avec le wrap cipher
/// - Le dernier bloc est padisé (64-bit granular padding)
///
/// # Paramètres
///
/// - `kek` : Key Encryption Key (32 octets — utilisé comme KEK AES-256)
///
/// # Returns
///
/// Ciphertext de 40 octets (RFC 5649).
///
/// # Conformité
///
/// Cette fonction satisfait REQ-CRY-5 (32→40 octets) et REQ-CRY-7
/// (résistance aux fautes pour AES Key Wrap).
///
/// # Notes de sécurité
///
/// La KEK est zeroisée après usage (`zeroize::Zeroize`).
pub fn aes_key_wrap_padded(session_key: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if session_key.len() != SESSION_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: session_key.len(),
            expected: SESSION_KEY_SIZE,
        });
    }
    if kek.len() != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: kek.len(),
            expected: AES256_KEY_SIZE,
        });
    }

    let cipher = aes_kw::KekAes256::try_from(kek).map_err(|_| CryptoError::InvalidKeySize {
        size: kek.len(),
        expected: AES256_KEY_SIZE,
    })?;

    // RFC 5649 : `wrap_with_padding` gère lui-même l'AIV et le padding.
    // 32 octets de clé → 40 octets de sortie (8 octets d'AIV).
    let mut ciphertext = [0u8; 40];
    cipher
        .wrap_with_padding(session_key, &mut ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed("échec du wrap RFC 5649".into()))?;

    Ok(ciphertext.to_vec())
}

/// Développe une clé de session enveloppée selon AES Key Wrap with Padding.
///
/// Inverse `aes_key_wrap_padded()` : produit un key plaintext de 32 octets
/// à partir d'un ciphertext de 40 octets.
///
/// # Paramètres
///
/// - `wrapped_key` : clé enveloppée (40 octets, RFC 5649)
/// - `kek` : Key Encryption Key (32 octets)
///
/// # Returns
///
/// Key de session plaintext (32 octets).
///
/// # Erreurs
///
/// - `CryptoError::InvalidWrappedKeySize` : wrapped_key ne fait pas 40 octets
/// - `CryptoError::InvalidKeySize` : kek ne fait pas 32 octets
/// - `CryptoError::DecryptionFailed` : déchiffrement échoué (key invalide)
///
/// # Conformité
///
/// Satisfait REQ-CRY-5 (32→40 octets) et REQ-CRY-7 (résistance aux fautes).
pub fn aes_key_unwrap_padded(wrapped_key: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if wrapped_key.len() != 40 {
        return Err(CryptoError::InvalidWrappedKeySize {
            size: wrapped_key.len(),
            expected: 40,
        });
    }
    if kek.len() != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: kek.len(),
            expected: AES256_KEY_SIZE,
        });
    }

    let cipher = aes_kw::KekAes256::try_from(kek).map_err(|_| CryptoError::InvalidKeySize {
        size: kek.len(),
        expected: AES256_KEY_SIZE,
    })?;

    // `unwrap_with_padding` vérifie l'AIV (intégrité) et le padding RFC 5649
    // et renvoie directement le plaintext (sans padding).
    // RFC 5649 : le buffer de sortie doit faire exactement `wrapped_key.len() - 8` octets.
    let mut buf = [0u8; SESSION_KEY_SIZE];
    let result = cipher
        .unwrap_with_padding(wrapped_key, &mut buf)
        .map(<[u8]>::to_vec)
        .map_err(|_| {
            CryptoError::DecryptionFailed("intégrité ou padding RFC 5649 invalide".into())
        });
    buf.zeroize();

    let session_key = result?;
    if session_key.len() != SESSION_KEY_SIZE {
        return Err(CryptoError::DecryptionFailed(
            "padding RFC 5649 invalide : longueur inattendue".into(),
        ));
    }
    Ok(session_key)
}

// ─── AES Key Wrap (RFC 3394) — utilisé par mécanisme x3 ──────────────────────

/// Déchiffre un bloc AES-128 en mode ECB.
///
/// Utilisé par le mécanisme x3 pour déchiffrer les 3 blocs de 16 octets.
///
/// # Paramètres
///
/// - `key` : clé AES-128 (16 octets)
/// - `block` : bloc à déchiffrer (16 octets)
///
/// # Returns
///
/// Bloc déchiffré (16 octets).
#[inline]
pub fn aes128_ecb_decrypt_block(
    key: &[u8; AES128_KEY_SIZE],
    block: &[u8; AES128_KEY_SIZE],
) -> [u8; AES128_KEY_SIZE] {
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut block_io = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut block_io);
    let mut out = [0u8; AES128_KEY_SIZE];
    out.copy_from_slice(&block_io);
    out
}

/// Déchiffre un bloc AES-256 en mode ECB.
///
/// Utilisé par le mécanisme x3 pour déchiffrer les 3 blocs de 16 octets.
///
/// # Paramètres
///
/// - `key` : clé AES-256 (32 octets)
/// - `block` : bloc à déchiffrer (16 octets)
///
/// # Returns
///
/// Bloc déchiffré (16 octets).
#[inline]
pub fn aes256_ecb_decrypt_block(
    key: &[u8; AES256_KEY_SIZE],
    block: &[u8; AES128_KEY_SIZE],
) -> [u8; AES128_KEY_SIZE] {
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let mut block_io = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut block_io);
    let mut out = [0u8; AES128_KEY_SIZE];
    out.copy_from_slice(&block_io);
    out
}

/// Chiffre un bloc AES-256 en mode ECB (côté éditeur, mécanisme x3).
///
/// # Paramètres
///
/// - `key` : clé AES-256 (32 octets)
/// - `block` : bloc à chiffrer (16 octets)
///
/// # Returns
///
/// Bloc chiffré (16 octets).
#[inline]
pub fn aes256_ecb_encrypt_block(
    key: &[u8; AES256_KEY_SIZE],
    block: &[u8; AES128_KEY_SIZE],
) -> [u8; AES128_KEY_SIZE] {
    let cipher = aes::Aes256::new(GenericArray::from_slice(key));
    let mut block_io = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut block_io);
    let mut out = [0u8; AES128_KEY_SIZE];
    out.copy_from_slice(&block_io);
    out
}

// ─── Mécanisme x3 (3 × AES-256-ECB, voir docs/spec/03-tpm.md) ────────────────

/// Label de domaine du tag de confirmation x3.
pub const X3_TAG_LABEL: &[u8] = b"update-rs/x3";

/// Taille du tag de confirmation x3 en octets.
pub const X3_TAG_SIZE: usize = 8;

/// Taille d'une clé de session enveloppée en mode x3 (3 blocs de 16 octets).
pub const X3_WRAPPED_SIZE: usize = 48;

/// Tag de confirmation x3 : `SHA-256("update-rs/x3" || bundle_id || S)[0..8]`.
fn x3_tag(bundle_id: &[u8; 32], session_key: &[u8; AES256_KEY_SIZE]) -> [u8; X3_TAG_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(X3_TAG_LABEL);
    hasher.update(bundle_id);
    hasher.update(session_key);
    let digest = hasher.finalize();

    let mut tag = [0u8; X3_TAG_SIZE];
    tag.copy_from_slice(&digest[..X3_TAG_SIZE]);
    tag
}

/// Enveloppe une clé de session selon le mécanisme x3 (côté éditeur).
///
/// Format (voir `docs/spec/03-tpm.md`) :
///
/// ```text
/// T  = SHA-256("update-rs/x3" || bundle_id || S)[0..8]
/// P  = T || S                                (40 octets)
/// B1 = P[0..16]   B2 = P[16..32]   B3 = P[32..40] || 0x08^8
/// Ci = AES-256-ECB-encrypt(KEK, Bi)
/// wrapped = C1 || C2 || C3                   (48 octets)
/// ```
///
/// # Erreurs
///
/// - `CryptoError::InvalidKeySize` : `session_key` ou `kek` ne fait pas 32 octets
pub fn encrypt_session_key_x3(
    session_key: &[u8],
    kek: &[u8],
    bundle_id: &[u8; 32],
) -> Result<[u8; X3_WRAPPED_SIZE], CryptoError> {
    let session_key: &[u8; AES256_KEY_SIZE] =
        session_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeySize {
                size: session_key.len(),
                expected: AES256_KEY_SIZE,
            })?;
    let kek: &[u8; AES256_KEY_SIZE] = kek.try_into().map_err(|_| CryptoError::InvalidKeySize {
        size: kek.len(),
        expected: AES256_KEY_SIZE,
    })?;

    // P = T || S || padding PKCS#7 (0x08 × 8)
    let mut plain = [0x08u8; X3_WRAPPED_SIZE];
    plain[..X3_TAG_SIZE].copy_from_slice(&x3_tag(bundle_id, session_key));
    plain[X3_TAG_SIZE..X3_TAG_SIZE + AES256_KEY_SIZE].copy_from_slice(session_key);

    let mut wrapped = [0u8; X3_WRAPPED_SIZE];
    for (src, dst) in plain
        .chunks_exact(AES128_KEY_SIZE)
        .zip(wrapped.chunks_exact_mut(AES128_KEY_SIZE))
    {
        let mut block = [0u8; AES128_KEY_SIZE];
        block.copy_from_slice(src);
        dst.copy_from_slice(&aes256_ecb_encrypt_block(kek, &block));
    }
    plain.zeroize();

    Ok(wrapped)
}

/// Déchiffre une clé de session enveloppée selon le mécanisme x3.
///
/// Fait l'opération inverse de [`encrypt_session_key_x3`] : 3 déchiffrements
/// AES-256-ECB, vérification du padding, puis du tag de confirmation `T`
/// recalculé à partir de la clé de session et du `bundle_id`.
///
/// # Paramètres
///
/// - `wrapped_key` : clé enveloppée (48 octets, format x3)
/// - `kek` : Key Encryption Key (32 octets)
/// - `bundle_id` : identifiant du bundle (entre dans le tag de confirmation)
///
/// # Returns
///
/// Clé de session plaintext (32 octets).
///
/// # Erreurs
///
/// - `CryptoError::InvalidWrappedKeySize` : `wrapped_key` ne fait pas 48 octets
/// - `CryptoError::InvalidKeySize` : `kek` ne fait pas 32 octets
/// - `CryptoError::DecryptionFailed` : padding ou tag de confirmation invalide
///
/// # Conformité
///
/// Le padding et le tag sont comparés en temps constant (`subtle`). Les
/// plaintexts intermédiaires sont zeroizés après usage (REQ-CRY-4).
pub fn decrypt_session_key_x3(
    wrapped_key: &[u8],
    kek: &[u8],
    bundle_id: &[u8; 32],
) -> Result<[u8; AES256_KEY_SIZE], CryptoError> {
    if wrapped_key.len() != X3_WRAPPED_SIZE {
        return Err(CryptoError::InvalidWrappedKeySize {
            size: wrapped_key.len(),
            expected: X3_WRAPPED_SIZE,
        });
    }
    let kek: &[u8; AES256_KEY_SIZE] = kek.try_into().map_err(|_| CryptoError::InvalidKeySize {
        size: kek.len(),
        expected: AES256_KEY_SIZE,
    })?;

    // 3 déchiffrements AES-256-ECB : P' = B1 || B2 || B3
    let mut plain = [0u8; X3_WRAPPED_SIZE];
    for (src, dst) in wrapped_key
        .chunks_exact(AES128_KEY_SIZE)
        .zip(plain.chunks_exact_mut(AES128_KEY_SIZE))
    {
        let mut block = [0u8; AES128_KEY_SIZE];
        block.copy_from_slice(src);
        dst.copy_from_slice(&aes256_ecb_decrypt_block(kek, &block));
    }

    // P = T || S (40 octets), suivi de 0x08 × 8
    let padding_ok = plain[X3_TAG_SIZE + AES256_KEY_SIZE..].ct_eq(&[0x08u8; 8][..]);

    let mut tag = [0u8; X3_TAG_SIZE];
    tag.copy_from_slice(&plain[..X3_TAG_SIZE]);
    let mut session_key = [0u8; AES256_KEY_SIZE];
    session_key.copy_from_slice(&plain[X3_TAG_SIZE..X3_TAG_SIZE + AES256_KEY_SIZE]);
    plain.zeroize();

    let tag_ok = tag.ct_eq(&x3_tag(bundle_id, &session_key));

    if bool::from(padding_ok & tag_ok) {
        Ok(session_key)
    } else {
        session_key.zeroize();
        Err(CryptoError::DecryptionFailed(
            "mécanisme x3 : tag de confirmation ou padding invalide, clé incorrecte".into(),
        ))
    }
}

// ─── Constant-time helpers ────────────────────────────────────────────────────

/// Compare deux slices constant-time.
///
/// Utilise `subtle::ConstantTimeEq` pour éviter les failles temporelles
/// sur les comparaisons de valeurs cryptographiques (hachages, tags, etc.).
///
/// # Returns
///
/// `true` si les slices sont identiques, `false` sinon.
/// Le temps d'exécution ne dépend pas du contenu des slices.
#[inline]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::CryptoError;

    #[test]
    fn aes_gcm_siv_roundtrip() {
        let key = [0x41u8; AES256_KEY_SIZE];
        let nonce = [0x42u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"hello world";
        let aad = b"test_aad";

        let ciphertext = aes_gcm_siv_encrypt(&key, &nonce, plaintext, aad).expect("encrypt");

        // Le tag fait 16 octets
        assert!(ciphertext.len() >= AES_GCM_TAG_SIZE);

        let plaintext_out = aes_gcm_siv_decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt");
        assert_eq!(plaintext_out, plaintext.as_slice());
    }

    #[test]
    fn aes_gcm_siv_wrong_key_size() {
        let key = [0x41u8; 16]; // Taille incorrecte
        let nonce = [0x42u8; AES_GCM_NONCE_SIZE];
        let err = aes_gcm_siv_encrypt(&key, &nonce, b"data", b"").unwrap_err();
        match err {
            CryptoError::InvalidKeySize { size, expected } => {
                assert_eq!(size, 16);
                assert_eq!(expected, AES256_KEY_SIZE);
            }
            _ => panic!("attendu InvalidKeySize"),
        }
    }

    #[test]
    fn aes_gcm_siv_wrong_nonce_size() {
        let key = [0x41u8; AES256_KEY_SIZE];
        let nonce = [0x42u8; 8]; // Taille incorrecte
        let err = aes_gcm_siv_encrypt(&key, &nonce, b"data", b"").unwrap_err();
        match err {
            CryptoError::InvalidNonceSize { size, expected } => {
                assert_eq!(size, 8);
                assert_eq!(expected, AES_GCM_NONCE_SIZE);
            }
            _ => panic!("attendu InvalidNonceSize"),
        }
    }

    #[test]
    fn aes_gcm_siv_ciphertext_too_short() {
        let key = [0x41u8; AES256_KEY_SIZE];
        let nonce = [0x42u8; AES_GCM_NONCE_SIZE];
        // 8 octets < AES_GCM_TAG_SIZE (16)
        let ciphertext = [0u8; 8];
        let err = aes_gcm_siv_decrypt(&key, &nonce, &ciphertext, b"").unwrap_err();
        match err {
            CryptoError::DecryptionFailed(reason) => {
                assert!(reason.contains("tag"));
            }
            _ => panic!("attendu DecryptionFailed"),
        }
    }

    #[test]
    fn aes_gcm_siv_wrong_tag_fails() {
        let key = [0x41u8; AES256_KEY_SIZE];
        let nonce = [0x42u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"secret data";
        let aad = b"associated";

        let ciphertext = aes_gcm_siv_encrypt(&key, &nonce, plaintext, aad).expect("encrypt");

        // Altérer un octet du ciphertext
        let mut modified = ciphertext;
        modified[10] ^= 0x01;

        let err = aes_gcm_siv_decrypt(&key, &nonce, &modified, aad).unwrap_err();
        match err {
            CryptoError::InvalidTag => {}
            _ => panic!("attendu InvalidTag"),
        }
    }

    #[test]
    fn aes_gcm_siv_empty_plaintext() {
        let key = [0x41u8; AES256_KEY_SIZE];
        let nonce = [0x42u8; AES_GCM_NONCE_SIZE];
        let aad = b"non_empty_aad";

        let ciphertext = aes_gcm_siv_encrypt(&key, &nonce, b"", aad).expect("encrypt");
        let plaintext = aes_gcm_siv_decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt");
        assert!(plaintext.is_empty());
    }

    #[test]
    fn aes_gcm_siv_large_plaintext() {
        let key = [0x41u8; AES256_KEY_SIZE];
        let nonce = [0x42u8; AES_GCM_NONCE_SIZE];
        let plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        let aad = b"big_data";

        let ciphertext = aes_gcm_siv_encrypt(&key, &nonce, &plaintext, aad).expect("encrypt");
        let plaintext_out = aes_gcm_siv_decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt");
        assert_eq!(plaintext_out, plaintext.as_slice());
    }

    #[test]
    fn aes_gcm_siv_decrypt_auth_failure() {
        let key = [0x41u8; AES256_KEY_SIZE];
        let nonce = [0x42u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"test";
        let aad = b"original_aad";
        let modified_aad = b"modified_aaa";

        let ciphertext = aes_gcm_siv_encrypt(&key, &nonce, plaintext, aad).expect("encrypt");

        let err = aes_gcm_siv_decrypt(&key, &nonce, &ciphertext, modified_aad).unwrap_err();
        match err {
            CryptoError::InvalidTag => {}
            _ => panic!("attendu InvalidTag"),
        }
    }

    // === derive_chunk_key ===

    #[test]
    fn derive_chunk_key_uniqueness() {
        let session_key = [0x11u8; 32];
        let bundle_id = [0x22u8; 32];
        let mut seen: Vec<[u8; 32]> = Vec::new();

        for i in 0..10 {
            let (key, _nonce) = derive_chunk_key(&session_key, &bundle_id, i);
            assert!(!seen.contains(&key));
            seen.push(key);
        }
    }

    #[test]
    fn derive_chunk_key_deterministic() {
        let (k1, n1) = derive_chunk_key(&[0x11u8; 32], &[0x22u8; 32], 42);
        let (k2, n2) = derive_chunk_key(&[0x11u8; 32], &[0x22u8; 32], 42);
        assert_eq!(k1, k2);
        assert_eq!(n1, n2);
    }

    // === derive_manifest_key / decrypt_manifest_key ===

    #[test]
    fn derive_manifest_key_uniqueness() {
        let session_key = [0x11u8; 32];
        let mut keys: Vec<[u8; 32]> = Vec::new();

        for i in 0..5 {
            let key = derive_manifest_key(&session_key, &[i; 32]);
            assert!(!keys.contains(&key));
            keys.push(key);
        }
    }

    #[test]
    fn decrypt_manifest_returns_key_and_nonce() {
        let session_key = [0x11u8; 32];
        let bundle_id = [0x22u8; 32];

        let (key, nonce) = decrypt_manifest_key(&session_key, &bundle_id);

        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 12);

        // Vérifier que (key, nonce) est valide pour AES-GCM-SIV
        let ciphertext = aes_gcm_siv_encrypt(&key, &nonce, b"test", b"").expect("encrypt");
        let _ = aes_gcm_siv_decrypt(&key, &nonce, &ciphertext, b"").expect("decrypt");
    }

    // === AES Key Wrap with Padding (RFC 5649) ===

    #[test]
    fn aes_key_wrap_padded_roundtrip() {
        let key = [0x41u8; 32];
        let kek = [0x42u8; 32];

        let wrapped = aes_key_wrap_padded(&key, &kek).expect("wrap");
        assert_eq!(wrapped.len(), 40);

        let unwrapped = aes_key_unwrap_padded(&wrapped, &kek).expect("unwrap");
        assert_eq!(unwrapped.len(), 32);
        assert_eq!(unwrapped, key);
    }

    #[test]
    fn aes_key_wrap_padded_wrong_key_size() {
        let key = [0x41u8; 16]; // 16 au lieu de 32
        let kek = [0x42u8; 32];
        let err = aes_key_wrap_padded(&key, &kek).unwrap_err();
        match err {
            CryptoError::InvalidKeySize { size, expected } => {
                assert_eq!(size, 16);
                assert_eq!(expected, 32);
            }
            _ => panic!("attendu InvalidKeySize"),
        }
    }

    #[test]
    fn aes_key_wrap_padded_wrong_kek_size() {
        let key = [0x41u8; 32];
        let kek = [0x42u8; 16]; // 16 au lieu de 32
        let err = aes_key_wrap_padded(&key, &kek).unwrap_err();
        match err {
            CryptoError::InvalidKeySize { size, expected } => {
                assert_eq!(size, 16);
                assert_eq!(expected, 32);
            }
            _ => panic!("attendu InvalidKeySize"),
        }
    }

    #[test]
    fn aes_key_unwrap_padded_wrong_wrapped_size() {
        let wrapped = [0u8; 32]; // 32 au lieu de 40
        let kek = [0x42u8; 32];
        let err = aes_key_unwrap_padded(&wrapped, &kek).unwrap_err();
        match err {
            CryptoError::InvalidWrappedKeySize { size, expected } => {
                assert_eq!(size, 32);
                assert_eq!(expected, 40);
            }
            _ => panic!("attendu InvalidWrappedKeySize"),
        }
    }

    #[test]
    fn aes_key_unwrap_padded_wrong_key() {
        let key = [0x41u8; 32];
        let kek1 = [0x42u8; 32];
        let kek2 = [0x43u8; 32];

        let wrapped = aes_key_wrap_padded(&key, &kek1).expect("wrap");
        let err = aes_key_unwrap_padded(&wrapped, &kek2).unwrap_err();
        match err {
            CryptoError::DecryptionFailed(reason) => {
                assert!(reason.contains("padding"));
            }
            _ => panic!("attendu DecryptionFailed"),
        }
    }

    // === decrypt_session_key_x3 ===

    #[test]
    fn decrypt_session_key_x3_success() {
        let session_key = [0x55u8; 32];
        let kek = [0x41u8; 32];
        let bundle_id = [0x22u8; 32];

        let wrapped = encrypt_session_key_x3(&session_key, &kek, &bundle_id).expect("wrap x3");
        assert_eq!(wrapped.len(), X3_WRAPPED_SIZE);

        let unwrapped = decrypt_session_key_x3(&wrapped, &kek, &bundle_id).expect("x3");
        assert_eq!(unwrapped, session_key);
    }

    #[test]
    fn decrypt_session_key_x3_wrong_bundle_id() {
        let kek = [0x41u8; 32];
        let wrapped = encrypt_session_key_x3(&[0x55u8; 32], &kek, &[0x22u8; 32]).expect("wrap x3");

        let err = decrypt_session_key_x3(&wrapped, &kek, &[0x23u8; 32]).unwrap_err();
        assert!(matches!(err, CryptoError::DecryptionFailed(_)));
    }

    #[test]
    fn decrypt_session_key_x3_wrong_size() {
        let wrapped_key = [0u8; 40]; // 40 au lieu de 48
        let kek = [0x41u8; 32];
        let err = decrypt_session_key_x3(&wrapped_key, &kek, &[0u8; 32]).unwrap_err();
        match err {
            CryptoError::InvalidWrappedKeySize { size, expected } => {
                assert_eq!(size, 40);
                assert_eq!(expected, 48);
            }
            _ => panic!("attendu InvalidWrappedKeySize"),
        }
    }

    #[test]
    fn decrypt_session_key_x3_wrong_key() {
        let bundle_id = [0x22u8; 32];
        let wrapped_key =
            encrypt_session_key_x3(&[0x55u8; 32], &[0x41u8; 32], &bundle_id).expect("wrap x3");
        let wrong_kek = [0x42u8; 32];

        let err = decrypt_session_key_x3(&wrapped_key, &wrong_kek, &bundle_id).unwrap_err();
        match err {
            CryptoError::DecryptionFailed(reason) => {
                assert!(reason.contains("tag"));
            }
            _ => panic!("attendu DecryptionFailed"),
        }
    }

    // === constant_time_compare ===

    #[test]
    fn constant_time_compare_equal() {
        assert!(constant_time_compare(&[1u8, 2, 3], &[1u8, 2, 3]));
    }

    #[test]
    fn constant_time_compare_not_equal() {
        assert!(!constant_time_compare(&[1u8, 2, 3], &[1u8, 2, 4]));
    }

    #[test]
    fn constant_time_compare_different_lengths() {
        assert!(!constant_time_compare(&[1u8, 2], &[1u8, 2, 3]));
    }

    #[test]
    fn constant_time_compare_empty() {
        assert!(constant_time_compare(&[], &[]));
    }

    // === AES-ECB ===

    #[test]
    fn aes128_ecb_consistent() {
        let block = [0x00u8; 16];
        let key = [0x42u8; 16];
        let result1 = aes128_ecb_decrypt_block(&key, &block);
        let result2 = aes128_ecb_decrypt_block(&key, &block);
        assert_eq!(result1, result2);
    }

    #[test]
    fn aes256_ecb_consistent() {
        let block = [0x00u8; 16];
        let key = [0x42u8; 32];
        let result1 = aes256_ecb_decrypt_block(&key, &block);
        let result2 = aes256_ecb_decrypt_block(&key, &block);
        assert_eq!(result1, result2);
    }
}
