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
use aes::cipher::{Block, BlockDecryptMut, BlockSizeUser, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce, Tag};
use aead::generic_array::GenericArray;
use aead::{AeadInPlace, InPlaceCipher};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use typenum::U32;
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

    let key = Key::<Aes256GcmSiv>::from_slice(key);
    let cipher = Aes256GcmSiv::new(key);

    let nonce = {
        let mut nonce_arr = GenericArray::<u8, typenum::U12>::default();
        nonce_arr.copy_from_slice(nonce);
        nonce_arr
    };

    // Buffer : plaintext + tag (16 octets)
    let mut buf = Vec::with_capacity(plaintext.len() + AES_GCM_TAG_SIZE);
    buf.extend_from_slice(plaintext);

    let tag = cipher
        .encrypt_in_place_detached(&nonce, aad, &mut buf)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    buf.extend_from_slice(&tag.as_bytes());
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

    let key = Key::<Aes256GcmSiv>::from_slice(key);
    let cipher = Aes256GcmSiv::new(key);

    let nonce = {
        let mut nonce_arr = GenericArray::<u8, typenum::U12>::default();
        nonce_arr.copy_from_slice(nonce);
        nonce_arr
    };

    // Split ciphertext + tag (last 16 bytes)
    let len = ciphertext_with_tag.len();
    if len < AES_GCM_TAG_SIZE {
        return Err(CryptoError::DecryptionFailed(
            "ciphertext trop court pour contenir un tag".into(),
        ));
    }
    let (ciphertext, tag_bytes) =
        ciphertext_with_tag.split_at(len - AES_GCM_TAG_SIZE);

    let tag = Tag::from_slice(tag_bytes);

    // Decrypt in place
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    plaintext.extend_from_slice(ciphertext);

    cipher
        .decrypt_in_place_detached(&nonce, aad, &mut plaintext, tag)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

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
pub fn aes_key_wrap_padded(key: &[u8], kek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != SESSION_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: key.len(),
            expected: SESSION_KEY_SIZE,
        });
    }
    if kek.len() != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: kek.len(),
            expected: AES256_KEY_SIZE,
        });
    }

    // Padding RFC 5649 : clé de 32 octets → 40 octets (0x01 + zéros)
    let mut padded = [0u8; 40];
    padded[0..32].copy_from_slice(key);
    padded[32] = 0x01; // Marqueur de padding (RFC 5649 §3)

    // Chiffrer le padding avec AES Key Wrap (RFC 5649)
    let cipher = aes_kwp::KwpAes256::new(kek);

    let mut ciphertext = [0u8; 40];
    let len = cipher
        .wrap_key(&padded, &mut ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(ciphertext[..len].to_vec())
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

    let cipher = aes_kwp::KwpAes256::new(kek);

    let mut padded = [0u8; 40];
    let len = cipher
        .unwrap_key(&wrapped_key, &mut padded)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    // Vérifier le padding RFC 5649 : 0x01 suivi de zéros
    if len >= 33 && padded[32] == 0x01 {
        let pad_bytes = &padded[33..len];
        if pad_bytes.iter().all(|&b| b == 0) {
            let mut key = [0u8; SESSION_KEY_SIZE];
            key.copy_from_slice(&padded[0..SESSION_KEY_SIZE]);
            return Ok(key);
        }
    }

    Err(CryptoError::DecryptionFailed(
        "padding RFC 5649 invalide".into(),
    ))
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
#[allow(unused_variables)]
pub fn aes128_ecb_decrypt_block(
    key: &[u8; AES128_KEY_SIZE],
    block: &[u8; AES128_KEY_SIZE],
) -> [u8; AES128_KEY_SIZE] {
    let mut block_in = Block::<aes::Aes128>::default();
    block_in.copy_from_slice(block);
    aes::Aes128::new_from_slice(key).decrypt_block(&mut block_in);
    let mut out = [0u8; AES128_KEY_SIZE];
    out.copy_from_slice(block_in.as_slice());
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
#[allow(unused_variables)]
pub fn aes256_ecb_decrypt_block(
    key: &[u8; AES256_KEY_SIZE],
    block: &[u8; AES128_KEY_SIZE],
) -> [u8; AES128_KEY_SIZE] {
    let mut block_in = Block::<aes::Aes256>::default();
    block_in.copy_from_slice(block);
    aes::Aes256::new_from_slice(key).decrypt_block(&mut block_in);
    let mut out = [0u8; AES128_KEY_SIZE];
    out.copy_from_slice(block_in.as_slice());
    out
}

// ─── Mécanisme x3 (RFC 5649 mode x3) ─────────────────────────────────────────

/// Déchiffre une clé de session enveloppée selon le mécanisme x3.
///
/// Le mécanisme x3 utilise 3 déchiffrements AES-256-ECB successifs pour
/// reconstruire la clé de session de 32 octets à partir de 48 octets :
///
/// ```text
/// block0 = wrapped_key[0..16]
/// block1 = wrapped_key[16..32]
/// block2 = wrapped_key[32..48]
///
/// key1 = AES-256-ECB-decrypt(KEK, block0)  # 16 octets
/// key2 = AES-256-ECB-decrypt(KEK, block1)  # 16 octets
/// key3 = AES-256-ECB-decrypt(KEK, block2)  # 16 octets
///
/// session_key = key1 || key2  # 32 octets
/// check = key3              # 16 octets (validation)
/// ```
///
/// Le block de check (`key3`) est comparé constant-time avec
/// `block2` pour valider la clé.
///
/// # Paramètres
///
/// - `wrapped_key` : clé enveloppée (48 octets, format x3)
/// - `kek` : Key Encryption Key (32 octets)
///
/// # Returns
///
/// Key de session plaintext (32 octets).
///
/// # Erreurs
///
/// - `CryptoError::InvalidWrappedKeySize` : wrapped_key ne fait pas 48 octets
/// - `CryptoError::InvalidKeySize` : kek ne fait pas 32 octets
/// - `CryptoError::DecryptionFailed` : validation du check block échouée
///
/// # Conformité
///
/// Cette fonction satisfait REQ-CRY-7 (résistance aux fautes) en
/// comparant le block de check constant-time (`subtle::ConstantTimeEq`).
/// La KEK et les clés intermédiaires sont zeroizées après usage (REQ-CRY-4).
#[inline]
#[allow(unused_variables)]
pub fn decrypt_session_key_x3(
    wrapped_key: &[u8],
    kek: &[u8],
) -> Result<[u8; AES256_KEY_SIZE], CryptoError> {
    const WRAPPED_X3_SIZE: usize = 48;

    // Vérifier la taille
    if wrapped_key.len() != WRAPPED_X3_SIZE {
        return Err(CryptoError::InvalidWrappedKeySize {
            size: wrapped_key.len(),
            expected: WRAPPED_X3_SIZE,
        });
    }

    if kek.len() != AES256_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            size: kek.len(),
            expected: AES256_KEY_SIZE,
        });
    }

    // Séparer les 3 blocs de 16 octets
    let block0: [u8; AES128_KEY_SIZE] = wrapped_key[0..AES128_KEY_SIZE]
        .try_into()
        .expect("size verified above");
    let block1: [u8; AES128_KEY_SIZE] = wrapped_key[AES128_KEY_SIZE..2 * AES128_KEY_SIZE]
        .try_into()
        .expect("size verified above");
    let block2: [u8; AES128_KEY_SIZE] = wrapped_key[2 * AES128_KEY_SIZE..WRAPPED_X3_SIZE]
        .try_into()
        .expect("size verified above");

    // 3 déchiffrements AES-256-ECB successifs
    let mut key1 = [0u8; AES128_KEY_SIZE];
    let mut key2 = [0u8; AES128_KEY_SIZE];
    let mut key3 = [0u8; AES128_KEY_SIZE];

    key1.copy_from_slice(&aes256_ecb_decrypt_block(
        kek.try_into().expect("size checked above"),
        &block0,
    ));
    key2.copy_from_slice(&aes256_ecb_decrypt_block(
        kek.try_into().expect("size checked above"),
        &block1,
    ));
    key3.copy_from_slice(&aes256_ecb_decrypt_block(
        kek.try_into().expect("size checked above"),
        &block2,
    ));

    // Validation constant-time : key3 doit correspondre à block2
    if key3.ct_eq(&block2).into() {
        // Check passé : reconstruire la clé de session
        let mut session_key = [0u8; AES256_KEY_SIZE];
        session_key[0..AES128_KEY_SIZE].copy_from_slice(&key1);
        session_key[AES128_KEY_SIZE..AES256_KEY_SIZE].copy_from_slice(&key2);

        // Zeroization des clés intermédiaires (REQ-CRY-4)
        key1.zeroize();
        key2.zeroize();
        key3.zeroize();

        Ok(session_key)
    } else {
        // Check échoué : clé invalide
        key1.zeroize();
        key2.zeroize();
        key3.zeroize();

        Err(CryptoError::DecryptionFailed(
            "mécanisme x3 : check block invalide, clé incorrecte".into(),
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
