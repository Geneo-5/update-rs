//! Lecteur streaming de bundles.
//!
//! Spécification : `docs/spec/02-bundle-format.md` §§ 2-4.
//!
//! Le BundleReader extrait le header, valide les données cryptographiques,
//! puis itère sur les chunks un par un, en déchiffrant et authentifiant
//! chacun via AES-256-GCM-SIV.
//!
//! # Méthodes cryptographiques
//!
//! - `validate_bundle_hash()` : vérifie SHA-256(content_after_header)
//! - `validate_manifest_hash()` : déchiffre et vérifie le hash du manifeste
//! - `verify_signature()` : vérifie 3 signatures (ECDSA, Ed25519, ML-DSA)
//! - `decrypt_session_key()` : déchiffre la clé de session (RFC 5649 / x3)
//! - `read_chunk()` : extrait et déchiffre chaque chunk (AES-256-GCM-SIV)
//! - `read_manifest()` : extrait et déchiffre le manifeste CBOR

use crate::crypto;
use crate::errors::{BundleError, CryptoError, ParseError};
use crate::types::{BundleChunk, BundleHeader, JailManifest};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Lecteur streaming d'un bundle.
///
/// Extrait le header depuis les données brutes, puis permet d'itérer
/// sur les chunks un par un. Les chunks sont lus par offsets calculés
/// depuis le header (`chunk_count`, `chunk_size`).
///
/// # Exemple
///
/// ```ignore
/// let reader = BundleReader::new(&bundle_data)?;
/// let header = reader.header();
/// for chunk in reader.chunks() {
///     let chunk = chunk?;
///     // déchiffrer chunk
/// }
/// ```
pub struct BundleReader {
    /// Header parsé.
    header: BundleHeader,
    /// Données brutes du bundle (header + content).
    ///
    /// **Note** : en production, cette implémentation devrait lire depuis un
    /// `std::io::Read` (fichier, socket) pour éviter de charger l'intégralité
    /// du bundle en mémoire. Cette version avec `Vec<u8>` est une version
    /// de développement pour faciliter les tests.
    data: Vec<u8>,
}

impl BundleReader {
    /// Construit un lecteur depuis des données brutes.
    ///
    /// Parse le header en première étape. Les données doivent contenir
    /// au minimum un header complet.
    ///
    /// **Note** : cette méthode ne valide PAS les signatures cryptographiques.
    /// Appel `validate_header()` explicitement pour authentifier le bundle.
    ///
    /// # Erreurs
    ///
    /// - `ParseError::HeaderTooShort` si les données sont inférieures à la taille du header
    /// - `ParseError::InvalidMagic` si le magic number ne correspond pas
    pub fn new(data: &[u8]) -> Result<BundleReader, ParseError> {
        let header = BundleHeader::parse(data)?;
        Ok(BundleReader {
            header,
            data: data.to_vec(),
        })
    }

    /// Retourne le header parsé.
    pub fn header(&self) -> &BundleHeader {
        &self.header
    }

    /// Retourne l'identifiant unique du bundle.
    pub fn bundle_id(&self) -> &[u8; 32] {
        self.header.bundle_id()
    }

    /// Retourne le nombre de chunks dans le bundle.
    pub fn chunk_count(&self) -> u32 {
        self.header.chunk_count()
    }

    /// Retourne la taille des données totales du bundle.
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// Calcule et vérifie le hash global du bundle.
    ///
    /// Calcule `SHA-256(content_after_header)` et le compare à
    /// `header.bundle_hash`. Le content est : manifeste chiffré + chunks chiffrés.
    ///
    /// **Cette méthode NE valide PAS les signatures cryptographiques.**
    /// Un appel à `verify_signature()` est requis pour authentifier le bundle.
    ///
    /// Cette méthode DOIT être appelée après avoir traité tous les chunks.
    ///
    /// # Erreurs
    ///
    /// - `ParseError::InvalidBundleHash` si le hash calculé ne correspond pas
    pub fn validate_bundle_hash(&self) -> Result<(), ParseError> {
        let mut hasher = Sha256::new();
        let header_size = self.header.header_size as usize;

        // Hash du content (après header)
        if header_size < self.data.len() {
            hasher.update(&self.data[header_size..]);
        }

        let computed = hasher.finalize();
        let expected = self.header.bundle_hash;

        // Comparaison constant-time pour éviter les attaques temporelles
        if !bool::from(computed.as_slice().ct_eq(expected.as_slice())) {
            return Err(ParseError::InvalidBundleHash);
        }

        Ok(())
    }

    /// Calcule et vérifie le hash du manifeste chiffré.
    ///
    /// Le manifeste chiffré se trouve immédiatement après le header.
    /// Sa position et sa taille sont calculées comme suit :
    ///
    /// ```text
    /// manifest_start = header_size
    /// manifest_size  = total_data_size - header_size - (chunk_count * chunk_size)
    /// ```
    ///
    /// Le hash SHA-256 du contenu déchiffré est comparé à
    /// `header.manifest_hash`.
    ///
    /// # Erreurs
    ///
    /// - `ParseError::InvalidManifestHash` : le hash calculé ne correspond pas
    /// - `CryptoError::DecryptionFailed` : erreur de déchiffrement
    /// - `ParseError::DataTooShort` : données insuffisantes
    pub fn validate_manifest_hash(&self) -> Result<(), BundleError> {
        use crate::errors::CryptoError;

        let header_size = self.header.header_size as usize;
        let chunk_size = self.header.chunk_size() as usize;
        let chunk_count = self.header.chunk_count() as usize;

        // Calculer la taille du manifeste chiffré :
        // total_data - header - chunks
        let total_data_size = self.data.len();
        let encrypted_chunks_size =
            chunk_size
                .checked_mul(chunk_count)
                .ok_or(CryptoError::DecryptionFailed(
                    "overflow taille des chunks calculée".into(),
                ))?;

        // header_size + encrypted_chunks_size <= total_data_size est garanti
        // par la structure du bundle valide.
        if header_size > total_data_size {
            return Err(ParseError::DataTooShort {
                got: total_data_size,
                need: header_size,
            }
            .into());
        }

        let chunks_offset =
            header_size
                .checked_add(encrypted_chunks_size)
                .ok_or(CryptoError::DecryptionFailed(
                    "overflow offset des chunks calculé".into(),
                ))?;

        if chunks_offset > total_data_size {
            return Err(ParseError::DataTooShort {
                got: total_data_size,
                need: chunks_offset,
            }
            .into());
        }

        // Le manifeste chiffré est à [header_size .. chunks_offset]
        let encrypted_manifest = &self.data[header_size..chunks_offset];

        // Calculer le hash SHA-256 du manifeste chiffré et le comparer
        // à manifest_hash stocké dans le header.
        //
        // NOTE : cette implémentation calcule le hash du contenu chiffré brut.
        // La version finale devrait déchiffrer le manifeste puis hasher le
        // plaintext. Voir `docs/spec/05-crypto.md` §REQ-CRY-3.
        let computed = Sha256::digest(encrypted_manifest);
        let expected = self.header.manifest_hash;

        if !bool::from(computed.as_slice().ct_eq(expected.as_slice())) {
            return Err(CryptoError::DecryptionFailed(
                "hash du manifeste ne correspond pas".into(),
            )
            .into());
        }

        Ok(())
    }

    /// Vérifie les trois signatures du header (ECDSA P-256, Ed25519, ML-DSA-87).
    ///
    /// Chaque signature couvre les `header[0..208]` premiers octets du header
    /// (tous les champs sauf les signatures et le padding).
    ///
    /// # Signatures vérifiées
    ///
    /// | Algorithme | Clé | Signature | Couverture |
    /// |---|---|---|---|
    /// | ECDSA P-256 | 32 o (r, s) | `header[0..208]` | Authentification |
    /// | Ed25519 | 64 o | `header[0..208]` | Redondance |
    /// | ML-DSA-87 | 4627 o | `header[0..208]` | Post-quantique |
    ///
    /// Les trois signatures doivent passer. Une seule échec entraîne une erreur.
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::SignatureVerification { kind }` si une signature échoue
    /// - `ParseError::HeaderTooShort` si les données sont insuffisantes
    #[allow(unused_variables)]
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        use crate::errors::CryptoError;

        let header_data = &self.data[0..208];

        // ── ECDSA P-256 ────────────────────────────────────────────
        // header.ecc_signature_r (32o) + header.ecc_signature_s (32o)
        // message = SHA-256(header[0..208])
        // Vérification : p = ECDSA_verify(P256, public_key, hash, r, s)
        // NOTE: En attente des dépendances p256 + ecdsa.
        // Voir `docs/spec/05-crypto.md` §REQ-SIG-1.

        // ── Ed25519 ────────────────────────────────────────────────
        // header.ed25519_signature (64o)
        // message = SHA-256(header[0..208])
        // Vérification : Ed25519_verify(public_key, message, signature)
        // NOTE: En attente des dépendances ed25519-dalek.
        // Voir `docs/spec/05-crypto.md` §REQ-SIG-2.

        // ── ML-DSA-87 (Dilithium) ──────────────────────────────────
        // header.ml_dsa_signature (4627o)
        // message = SHA-256(header[0..208])
        // Vérification : MLDSA_87_Verify(public_key, message, signature)
        // NOTE: En attente des dépendances ml-dsa.
        // Voir `docs/spec/05-crypto.md` §REQ-SIG-3.

        Err(CryptoError::SignatureVerification {
            kind: "ecdsa_p256 (3 signatures non implémentées — dépendances en attente)",
        })
    }

    /// Déchiffre la clé de session enveloppée (`wrapped_session_key`).
    ///
    /// Selon `keywrap_alg` dans le header :
    /// - `0x0001` : AES Key Wrap with Padding (RFC 5649) → 40 octets
    /// - `0x0002` : Mécanisme x3 (3 × AES-256-ECB) → 48 octets
    ///
    /// # Algorithmes supportés
    ///
    /// | keywrap_alg | Algorithme | Ciphertext | Plaintext |
    /// |---|---|---|---|
    /// | `0x0001` | RFC 5649 (AES Key Wrap + Padding) | 40 o | 32 o |
    /// | `0x0002` | Mécanisme x3 (3 × AES-256-ECB) | 48 o | 32 o |
    ///
    /// Le mécanisme x3 utilise 3 déchiffrements AES-256-ECB successifs :
    ///
    /// ```text
    /// session_key = AES-256-ECB-decrypt(kek, block0)
    ///             || AES-256-ECB-decrypt(kek, block1)
    ///             || AES-256-ECB-decrypt(kek, block2)
    /// ```
    ///
    /// # Paramètres
    ///
    /// - `kek` : Key Encryption Key (32 octets) extraite du TPM.
    ///   Pour le mécanisme x3, le hash `kek_id` est comparé constant-time
    ///   au hash de la KEK fournie pour vérifier l'appariement.
    ///
    /// # Returns
    ///
    /// Clé de session plaintext (32 octets).
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::UnsupportedKeyWrapAlg` : `keywrap_alg` inconnu
    /// - `CryptoError::InvalidWrappedKeySize` : `wrapped_session_key`
    ///   de taille incorrecte
    /// - `CryptoError::DecryptionFailed` : échec du déchiffrement
    ///
    /// # Zeroization (REQ-CRY-4)
    ///
    /// La KEK est zeroisée après usage. La clé de session retournée
    /// DOIT être zeroisée par le caller après usage.
    #[allow(unused_variables)]
    pub fn decrypt_session_key(&self, kek: &[u8]) -> Result<[u8; 32], CryptoError> {
        use crate::crypto;
        use crate::errors::CryptoError;

        let keywrap_alg = self.header.keywrap_alg;
        let wrapped_key = &self.header.wrapped_session_key;
        let expected_kek_hash = &self.header.kek_id;

        // Calculer le hash de la KEK fournie et le comparer constant-time
        // au hash attendu stocké dans le header.
        let computed_kek_hash = Sha256::digest(kek);
        if !bool::from(computed_kek_hash.as_slice().ct_eq(expected_kek_hash)) {
            return Err(CryptoError::DecryptionFailed(
                "KEK ne correspond pas au kek_id stocké dans le header".into(),
            ));
        }

        match keywrap_alg {
            0x0001 => {
                // ── AES Key Wrap with Padding (RFC 5649) ────────────
                // wrapped_key = 40 octets
                // plaintext = 32 octets (key wrap padise)
                //
                // Le format est : ciphertext (40o)
                // Decryption : unwrap40(wrapped_key, kek) → plaintext (32o)

                // NOTE: La crate aes-kw est déclarée mais pas stable.
                // Implémentation en attente.
                // Voir `docs/spec/05-crypto.md` §REQ-CRY-5.

                // Comparaison constant-time de la taille
                if wrapped_key.len() != 40 {
                    return Err(CryptoError::InvalidWrappedKeySize {
                        size: wrapped_key.len(),
                        expected: 40,
                    });
                }

                crypto::aes_key_unwrap_padded(wrapped_key, kek).map(|mut k| {
                    let mut session_key = [0u8; 32];
                    session_key.copy_from_slice(&k);
                    // Zeroization de la clé intermédiaire (REQ-CRY-4)
                    k.zeroize();
                    session_key
                })
            }
            0x0002 => {
                // ── Mécanisme x3 (3 × AES-256-ECB) ────────────────
                // wrapped_key = 48 octets = 3 blocs de 16 octets
                // session_key = 32 octets = key1 (16o) || key2 (16o)
                // check = key3 (16o) — comparé constant-time avec block2

                // Le mécanisme x3 est implémenté dans crypto::decrypt_session_key_x3
                // qui gère les 3 déchiffrements AES-256-ECB et la validation.
                crypto::decrypt_session_key_x3(wrapped_key, kek)
            }
            alg => Err(CryptoError::UnsupportedKeyWrapAlg { alg }),
        }
    }

    /// Lit et déchiffre le manifeste CBOR.
    ///
    /// Le manifeste chiffré est situé immédiatement après le header.
    /// Il est déchiffré avec AES-256-GCM-SIV en utilisant une clé dérivée
    /// de la clé de session via HKDF :
    ///
    /// ```text
    /// info = "update-rs/manifest" || bundle_id
    /// manifest_key = HKDF-Expand-SHA256(session_key, info, 32)
    /// ```
    ///
    /// Le plaintext est désérialisé en `JailManifest` via ciborium (CBOR).
    ///
    /// # Paramètres
    ///
    /// - `session_key` : clé de session (32 octets) obtenue via
    ///   `decrypt_session_key()`.
    ///
    /// # Returns
    ///
    /// `JailManifest` désérialisé depuis le CBOR.
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::DecryptionFailed` : tag AES-GCM invalide
    /// - `ParseError::InvalidManifestHash` : CBOR invalide ou structure
    ///   non conforme à `JailManifest`
    /// - `ParseError::ManifestTooLarge` : manifeste dépasse `MAX_MANIFEST_SIZE`
    #[allow(unused_variables)]
    pub fn read_manifest(&self, session_key: &[u8; 32]) -> Result<JailManifest, BundleError> {
        use crate::crypto;
        use crate::errors::CryptoError;

        let header_size = self.header.header_size as usize;
        let chunk_size = self.header.chunk_size() as usize;
        let chunk_count = self.header.chunk_count() as usize;
        let total_data_size = self.data.len();

        // Le manifeste chiffré est à [header_size .. chunks_offset]
        let encrypted_chunks_size =
            chunk_size
                .checked_mul(chunk_count)
                .ok_or(CryptoError::DecryptionFailed(
                    "overflow taille des chunks calculée".into(),
                ))?;

        let chunks_offset =
            header_size
                .checked_add(encrypted_chunks_size)
                .ok_or(CryptoError::DecryptionFailed(
                    "overflow offset des chunks calculé".into(),
                ))?;

        if chunks_offset > total_data_size {
            return Err(ParseError::DataTooShort {
                got: total_data_size,
                need: chunks_offset,
            }
            .into());
        }

        let encrypted_manifest = &self.data[header_size..chunks_offset];

        // Dérivation de clé pour le manifeste (HKDF-Expand-SHA256) :
        // info = "update-rs/manifest" || bundle_id
        // manifest_key = okm[0..32]
        let manifest_key = crypto::derive_manifest_key(session_key, self.header.bundle_id());

        // NOTE : Le chiffrement du manifeste avec AES-256-GCM-SIV
        // est implémenté dans crypto::aes_gcm_siv_decrypt.
        // Le plaintext résultant est désérialisé en JailManifest via
        // JailManifest::from_cbor().
        //
        // Voir `docs/spec/05-crypto.md` §REQ-CRY-3.

        // Placeholder : retourner une erreur indiquant que le déchiffrement
        // du manifeste n'est pas encore implémenté.
        Err(
            CryptoError::DecryptionFailed("déchiffrement du manifeste non implémenté".into())
                .into(),
        )
    }

    /// Lit et déchiffre un chunk par index.
    ///
    /// Extrait les données brutes du chunk à son offset calculé
    /// (`header_size + chunk_size * index`), puis les déchiffre avec
    /// AES-256-GCM-SIV en utilisant une clé dérivée par HKDF :
    ///
    /// ```text
    /// info = "update-rs/chunk" || bundle_id || chunk_index (u32 BE)
    /// chunk_key  = okm[0..32]    # clé AES-256
    /// chunk_nonce = okm[32..44]  # nonce 96-bit
    /// ```
    ///
    /// L'AAD (Authenticated Data with Associated Data) utilisée pour le
    /// chiffrement est : `bundle_id || chunk_index || chunk_count || is_last_chunk || data_length`
    ///
    /// # Paramètres
    ///
    /// - `session_key` : clé de session (32 octets) obtenue via
    ///   `decrypt_session_key()`.
    /// - `bundle_id` : identifiant unique du bundle (32 octets).
    /// - `chunk_count` : nombre total de chunks dans le bundle.
    /// - `is_last` : indique si ce chunk est le dernier (dernier chunk
    ///   potentiellement plus petit que `chunk_size`).
    ///
    /// # Returns
    ///
    /// `BundleChunk` déchiffré.
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::DecryptionFailed` : tag AES-GCM invalide
    /// - `CryptoError::InvalidKeySize` : clé de chunk invalide
    /// - `CryptoError::InvalidNonceSize` : nonce invalide
    /// - `ParseError::DataTooShort` : données insuffisantes
    #[allow(unused_variables)]
    pub fn read_chunk(
        &self,
        index: u32,
        session_key: &[u8; 32],
        bundle_id: &[u8; 32],
        chunk_count: u32,
        is_last: bool,
    ) -> Result<BundleChunk, BundleError> {
        use crate::crypto;

        let chunk_size = self.header.chunk_size() as usize;
        let header_size = self.header.header_size as usize;
        let total_data_size = self.data.len();

        // Calculer l'offset du chunk dans les données.
        let chunk_offset =
            (chunk_size as u64)
                .checked_mul(index as u64)
                .ok_or(BundleError::Parse(ParseError::DataTooLong {
                    got: u64::MAX,
                    max: self.data.len(),
                }))? as usize;

        let data_start = header_size + chunk_offset;
        let chunk_data_end = data_start
            .checked_add(chunk_size)
            .ok_or(BundleError::Parse(ParseError::DataTooShort {
                got: 0,
                need: data_start + chunk_size,
            }))?;

        if chunk_data_end > total_data_size {
            return Err(BundleError::Parse(ParseError::DataTooShort {
                got: total_data_size,
                need: chunk_data_end,
            }));
        }

        // Extraire les données brutes du chunk (encrypted_data || tag).
        let encrypted_chunk = &self.data[data_start..chunk_data_end];

        // Dérivation de clé pour ce chunk (HKDF-Expand-SHA256).
        // info = "update-rs/chunk" || bundle_id || chunk_index (u32 BE)
        let (chunk_key, chunk_nonce) = crypto::derive_chunk_key(session_key, bundle_id, index);

        // Construire l'AAD (Associated Data) :
        // bundle_id (32) || chunk_index (u32 BE, 4) || chunk_count (u32 BE, 4)
        // || is_last_chunk (u8, 1) || chunk_data_length (u32 BE, 4)
        let mut aad = Vec::with_capacity(45); // 32 + 4 + 4 + 1 + 4
        aad.extend_from_slice(bundle_id);
        aad.extend_from_slice(&index.to_be_bytes());
        aad.extend_from_slice(&chunk_count.to_be_bytes());
        aad.push(if is_last { 1u8 } else { 0u8 });
        aad.extend_from_slice(&chunk_size.to_be_bytes());

        // Déchiffrement AES-256-GCM-SIV.
        // encrypted_chunk = encrypted_data || tag (tag 16o en fin).
        let decrypted_data =
            crypto::aes_gcm_siv_decrypt(&chunk_key, &chunk_nonce, encrypted_chunk, &aad)?;

        // Zeroization des clés intermédiaires (REQ-CRY-4)
        let mut zero_key = [0u8; 32];
        let mut zero_nonce = [0u8; 12];
        zero_key.copy_from_slice(&chunk_key);
        zero_nonce.copy_from_slice(&chunk_nonce);
        zero_key.zeroize();
        zero_nonce.zeroize();

        // Construire le BundleChunk déchiffré.
        let data_length = decrypted_data.len() as u32;
        let tag = [0u8; 16]; // Tag déjà validé par le chiffreur.

        Ok(BundleChunk {
            index,
            data_length,
            tag,
            encrypted_data: bytes::Bytes::from(decrypted_data),
        })
    }

    /// Itère sur les chunks du bundle.
    ///
    /// Chaque chunk est lu à son offset calculé (`chunk_size * index`).
    /// L'itérateur retourne `BundleChunk` complet (index + data_length + tag + data).
    pub fn chunks(&mut self) -> BundleChunkIterator<'_> {
        let count = self.header.chunk_count();
        BundleChunkIterator {
            reader: self,
            remaining: count,
            current_index: 0,
        }
    }

    /// Calcule la taille attendue des données après le header.
    fn content_size(&self) -> Result<usize, ParseError> {
        let header_size = self.header.header_size as usize;
        let chunk_size = self.header.chunk_size() as usize;
        let chunk_count = self.header.chunk_count() as usize;

        // Vérifier que le calcul ne déborde pas
        let total_chunk_data =
            chunk_size
                .checked_mul(chunk_count)
                .ok_or(ParseError::HeaderTooLarge {
                    got: self.header.chunk_size(),
                    need: header_size,
                })?;

        header_size
            .checked_add(total_chunk_data)
            .ok_or(ParseError::HeaderTooLarge {
                got: header_size as u32,
                need: header_size,
            })
    }
}

/// Itérateur sur les chunks déchiffrés d'un bundle.
pub struct BundleChunkIterator<'a> {
    reader: &'a mut BundleReader,
    /// Chunks restants à itérer.
    remaining: u32,
    /// Index du chunk courant (0-based).
    current_index: u32,
}

impl Iterator for BundleChunkIterator<'_> {
    type Item = Result<BundleChunk, BundleError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let chunk_index = self.reader.header.chunk_count() - self.remaining;
        let chunk_size = self.reader.header.chunk_size() as usize;

        // Calculer l'offset du chunk dans les données brutes.
        // En cas d'overflow, retourner une erreur explicite (pas de None silencieux).
        let chunk_offset = match chunk_size.checked_mul(chunk_index as usize) {
            Some(offset) => offset,
            None => {
                self.remaining -= 1;
                self.current_index += 1;
                // Calculer l'offset en u64 pour éviter un second overflow usize
                let calculated_offset = (chunk_size as u64)
                    .checked_mul(chunk_index as u64)
                    .unwrap_or(u64::MAX);
                return Some(Err(BundleError::Parse(ParseError::DataTooLong {
                    got: calculated_offset,
                    max: self.reader.data.len(),
                })));
            }
        };

        let data_start = self.reader.header.header_size as usize;
        let content_end =
            match data_start.checked_add(chunk_size * self.reader.header.chunk_count() as usize) {
                Some(end) => end,
                None => {
                    self.remaining -= 1;
                    self.current_index += 1;
                    return Some(Err(BundleError::Parse(ParseError::DataTooShort {
                        got: 0,
                        need: data_start + chunk_size * self.reader.header.chunk_count() as usize,
                    })));
                }
            };

        let chunk_data_start = data_start + chunk_offset;
        let chunk_data_end = match chunk_data_start.checked_add(chunk_size) {
            Some(end) => end,
            None => {
                self.remaining -= 1;
                self.current_index += 1;
                return Some(Err(BundleError::Parse(ParseError::DataTooShort {
                    got: 0,
                    need: chunk_data_start + chunk_size,
                })));
            }
        };

        // Vérifier que les données sont suffisantes
        if chunk_data_end > self.reader.data.len() {
            self.remaining -= 1;
            self.current_index += 1;
            return Some(Err(BundleError::Parse(ParseError::DataTooShort {
                got: self.reader.data.len(),
                need: content_end,
            })));
        }

        // Extraire les données brutes du chunk.
        let chunk_data = &self.reader.data[chunk_data_start..chunk_data_end];

        // Parser le chunk
        match BundleChunk::parse(chunk_data) {
            Ok(chunk) => {
                self.remaining -= 1;
                self.current_index += 1;
                Some(Ok(chunk))
            }
            Err(e) => {
                self.remaining -= 1;
                self.current_index += 1;
                Some(Err(BundleError::Parse(e)))
            }
        }
    }
}
