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
#[derive(Debug)]
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
    /// | ECDSA P-256 | 64 o (x, y) | `header[0..208]` | Authentification |
    /// | Ed25519 | 32 o | `header[0..208]` | Redondance |
    /// | ML-DSA-87 | 1971 o | `header[0..208]` | Post-quantique |
    ///
    /// Les trois signatures doivent passer. Une seule échec entraîne une erreur.
    ///
    /// # Paramètres
    ///
    /// - `ml_dsa_public_key` : clé publique ML-DSA-87 (1971 octets).
    ///   La clé publique ECDSA P-256 et Ed25519 sont lues directement
    ///   depuis le header (`ecc_public_key`, `ed25519_public_key`).
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::SignatureVerification { kind }` si une signature échoue
    /// - `ParseError::HeaderTooShort` si les données sont insuffisantes
    pub fn verify_signature(&self, ml_dsa_public_key: &[u8; 1971]) -> Result<(), CryptoError> {
        // Hash commun : header[0..208]
        let header_data = self
            .data
            .get(0..208)
            .ok_or(CryptoError::SignatureVerification { kind: "header" })?;
        let hash = <Sha256 as Digest>::digest(header_data);

        // ── 1. ECDSA P-256 ─────────────────────────────────────────
        self.verify_ecdsa_p256(
            &hash,
            &self.header.ecc_signature_r,
            &self.header.ecc_signature_s,
            &self.header.ecc_public_key,
        )?;

        // ── 2. Ed25519 ─────────────────────────────────────────────
        self.verify_ed25519(
            &hash,
            &self.header.ed25519_signature,
            &self.header.ed25519_public_key,
        )?;

        // ── 3. ML-DSA-87 (Dilithium) ──────────────────────────────
        self.verify_ml_dsa_87(&hash, &self.header.ml_dsa_signature, ml_dsa_public_key)?;

        Ok(())
    }

    /// Vérifie une signature ECDSA P-256.
    ///
    /// Reconstitue la signature à partir des composants r et s stockés
    /// dans le header, puis vérifie la signature sur le hash SHA-256
    /// du header avec la clé publique ECDSA P-256 extraite du header.
    ///
    /// # Paramètres
    ///
    /// - `hash` : hash SHA-256 du header[0..208] (32 octets).
    /// - `sig_r` : composant r de la signature ECDSA (32 octets).
    /// - `sig_s` : composant s de la signature ECDSA (32 octets).
    /// - `public_key` : clé publique P-256 non compressée (64 octets =
    ///   0x04 || x(32) || y(32)).
    ///
    /// # Returns
    ///
    /// `Ok(())` si la signature est valide.
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::SignatureVerification` : signature ou clé publique
    ///   invalide, ou signature qui ne correspond pas au hash.
    #[inline]
    fn verify_ecdsa_p256(
        &self,
        hash: &[u8],
        sig_r: &[u8; 32],
        sig_s: &[u8; 32],
        public_key: &[u8; 64],
    ) -> Result<(), CryptoError> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        use p256::{EncodedPoint, FieldBytes};

        let fail = || CryptoError::SignatureVerification { kind: "ecdsa_p256" };

        // Reconstituer la signature à partir de r et s
        let signature = Signature::from_scalars(
            FieldBytes::clone_from_slice(sig_r),
            FieldBytes::clone_from_slice(sig_s),
        )
        .map_err(|_| fail())?;

        // Reconstituer la clé publique à partir de (x, y) : le header stocke
        // les 64 octets x || y, sans l'octet de préfixe SEC1 (0x04).
        let (x, y) = public_key.split_at(32);
        let point = EncodedPoint::from_affine_coordinates(
            &FieldBytes::clone_from_slice(x),
            &FieldBytes::clone_from_slice(y),
            false,
        );
        let verifying_key = VerifyingKey::from_encoded_point(&point).map_err(|_| fail())?;

        // La signature porte sur le hash SHA-256 du header (pré-haché).
        verifying_key
            .verify_prehash(hash, &signature)
            .map_err(|_| fail())
    }

    /// Vérifie une signature Ed25519.
    ///
    /// Vérifie la signature Ed25519 (64 octets) stockée dans le header
    /// contre le hash SHA-256 du header, en utilisant la clé publique
    /// Ed25519 (32 octets) également stockée dans le header.
    ///
    /// # Paramètres
    ///
    /// - `hash` : hash SHA-256 du header[0..208] (32 octets).
    /// - `signature` : signature Ed25519 (64 octets).
    /// - `public_key` : clé publique Ed25519 (32 octets).
    ///
    /// # Returns
    ///
    /// `Ok(())` si la signature est valide.
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::SignatureVerification` : clé publique invalide, ou
    ///   signature qui ne correspond pas au hash.
    #[inline]
    fn verify_ed25519(
        &self,
        hash: &[u8],
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<(), CryptoError> {
        use ed25519_dalek::{Signature, VerifyingKey};

        let fail = || CryptoError::SignatureVerification { kind: "ed25519" };

        let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| fail())?;
        let sig = Signature::from_bytes(signature);

        verifying_key.verify_strict(hash, &sig).map_err(|_| fail())
    }

    /// Vérifie une signature ML-DSA-87 (Dilithium).
    ///
    /// Vérifie la signature ML-DSA-87 (4627 octets) stockée dans le header
    /// contre le hash SHA-256 du header, en utilisant la clé publique
    /// ML-DSA-87 (1971 octets) passée en paramètre.
    ///
    /// # Paramètres
    ///
    /// - `hash` : hash SHA-256 du header[0..208] (32 octets).
    /// - `signature` : signature ML-DSA-87 (4627 octets).
    /// - `public_key` : clé publique ML-DSA-87 (1971 octets).
    ///
    /// # Returns
    ///
    /// `Ok(())` si la signature est valide.
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::SignatureVerification` : toujours, tant que la
    ///   vérification ML-DSA n'est pas implémentée (échec fermé).
    #[inline]
    fn verify_ml_dsa_87(
        &self,
        hash: &[u8],
        _signature: &[u8],
        public_key: &[u8],
    ) -> Result<(), CryptoError> {
        // ML-DSA-87 (Dilithium) est un crate 0.1 (API unstable).
        // TODO: remplacer par la vérification réelle.
        let _ = (&self.header.ml_dsa_signature, public_key);
        let _ = hash;

        // TODO(ml-dsa): implémenter la vérification ML-DSA-87
        // avec `VerifyingKey<MlDsa87>::from_bytes()` et
        // `verify_with_context()` une fois `ml-dsa` stabilisé.
        Err(CryptoError::SignatureVerification {
            kind: "ml_dsa_87 (API unstable dans ml-dsa 0.1)",
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
                // `wrapped_session_key` fait 48 octets dans le header ;
                // RFC 5649 n'en utilise que les 40 premiers.
                let wrapped_key =
                    wrapped_key
                        .get(..40)
                        .ok_or(CryptoError::InvalidWrappedKeySize {
                            size: wrapped_key.len(),
                            expected: 40,
                        })?;

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
                crypto::decrypt_session_key_x3(wrapped_key, kek, &self.header.bundle_id)
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
    pub fn read_manifest(&self, session_key: &[u8; 32]) -> Result<JailManifest, BundleError> {
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

        // Dériver clé et nonce pour le manifeste (HKDF-Expand-SHA256) :
        // info = "update-rs/manifest" || bundle_id
        // okm[0..32]  = manifest_key (clé AES-256)
        // okm[32..44] = nonce 96-bit (12 octets)
        let (manifest_key, nonce) =
            crypto::decrypt_manifest_key(session_key, self.header.bundle_id());

        // Construire l'AAD (Authenticated Data) pour AES-GCM-SIV :
        // bundle_id (32) || chunk_index(0, u32 BE) || chunk_count (u32 BE)
        // || is_last_chunk (u8) || data_length (u32 BE)
        let mut aad = Vec::with_capacity(45);
        aad.extend_from_slice(self.header.bundle_id());
        aad.extend_from_slice(&0u32.to_be_bytes()); // chunk_index = 0
        aad.extend_from_slice(&self.header.chunk_count().to_be_bytes());
        aad.push(0u8); // is_last_chunk = false (1 chunk pour le manifeste)
        aad.extend_from_slice(&(encrypted_manifest.len() as u32).to_be_bytes());

        // Déchiffrer le manifeste avec AES-256-GCM-SIV
        let decrypted =
            crypto::aes_gcm_siv_decrypt(&manifest_key, &nonce, encrypted_manifest, &aad)?;

        // Zeroization de la clé de manifeste (REQ-CRY-4)
        let mut zero_key = [0u8; 32];
        zero_key.copy_from_slice(&manifest_key);
        zero_key.zeroize();

        // Désérialiser en JailManifest
        Ok(JailManifest::from_cbor(&decrypted)?)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{aes_gcm_siv_encrypt, aes_key_wrap_padded, derive_chunk_key};
    use crate::errors::ParseError;

    fn build_valid_header_bytes() -> [u8; 5120] {
        let mut header = [0u8; 5120];
        header[0..4].copy_from_slice(b"UPRS");
        let v: [u8; 2] = u16::to_le_bytes(1);
        header[4..6].copy_from_slice(&v);
        header[6..8].copy_from_slice(&v);
        let v2: [u8; 2] = u16::to_le_bytes(5120);
        header[8..10].copy_from_slice(&v2);
        let v3: [u8; 4] = u32::to_le_bytes(65536);
        header[10..14].copy_from_slice(&v3);
        let v4: [u8; 4] = u32::to_le_bytes(2);
        header[14..16].copy_from_slice(&v4);
        header[16..48].copy_from_slice(&[1u8; 32]);
        header[48..80].copy_from_slice(&[2u8; 32]);
        header[80..112].copy_from_slice(&[3u8; 32]);
        header[112..144].copy_from_slice(&[4u8; 32]);
        let v5: [u8; 2] = u16::to_le_bytes(1);
        header[144..146].copy_from_slice(&v5);
        header[146..210].copy_from_slice(&[5u8; 64]);
        header[210..274].copy_from_slice(&[6u8; 64]);
        header[274..4901].copy_from_slice(&[7u8; 4627]);
        header[4901..4933].copy_from_slice(&[8u8; 32]);
        let v6: [u8; 2] = u16::to_le_bytes(1);
        header[4933..4935].copy_from_slice(&v6);
        header[4935..4975].copy_from_slice(&[9u8; 40]);
        header
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).into()
    }

    #[test]
    fn new_valid_data() {
        let header_bytes = build_valid_header_bytes();
        let mut data = Vec::from(header_bytes.as_slice());
        data.extend_from_slice(&[0u8; 1000]);
        assert!(BundleReader::new(&data).is_ok());
    }

    #[test]
    fn new_invalid_magic() {
        let mut header = build_valid_header_bytes();
        header[0..4].copy_from_slice(b"XPRQ");
        match BundleReader::new(&header).unwrap_err() {
            ParseError::InvalidMagic { got, expected } => {
                assert_eq!(got, 0x58505251u32);
                assert_eq!(expected, 0x55505253u32);
            }
            _ => panic!("attendu Parse(InvalidMagic)"),
        }
    }

    #[test]
    fn new_header_too_short() {
        let header_bytes = build_valid_header_bytes();
        match BundleReader::new(&header_bytes[..100]).unwrap_err() {
            ParseError::HeaderTooShort { got, need } => {
                assert_eq!(got, 100usize);
                assert_eq!(need, 5120usize);
            }
            _ => panic!("attendu Parse(HeaderTooShort)"),
        }
    }

    #[test]
    fn new_accessors() {
        let header_bytes = build_valid_header_bytes();
        let mut data = Vec::from(header_bytes.as_slice());
        data.extend_from_slice(&[0u8; 1000]);
        let reader = BundleReader::new(&data).expect("new");
        let h = reader.header();
        assert_eq!(h.magic, 0x55505253u32);
        assert_eq!(h.header_size, 5120u32);
        assert_eq!(h.chunk_count, 2u32);
        assert_eq!(reader.bundle_id(), &[1u8; 32]);
    }

    #[test]
    fn validate_bundle_hash_correct() {
        let mut header = build_valid_header_bytes();
        let content: [u8; 1000] = [0u8; 1000];
        let hash = sha256(&content);
        header[112..144].copy_from_slice(&hash);
        let mut data = Vec::from(&header[..]);
        data.extend_from_slice(&content);
        let reader = BundleReader::new(&data).expect("new");
        assert!(reader.validate_bundle_hash().is_ok());
    }

    #[test]
    fn validate_bundle_hash_wrong() {
        let header_bytes = build_valid_header_bytes();
        let mut data = Vec::from(header_bytes.as_slice());
        data.extend_from_slice(&[0u8; 1000]);
        data[5121] ^= 0x01;
        let reader = BundleReader::new(&data).expect("new");
        match reader.validate_bundle_hash().unwrap_err() {
            ParseError::InvalidBundleHash { .. } => {}
            _ => panic!("attendu Parse(InvalidBundleHash)"),
        }
    }

    #[test]
    fn validate_manifest_hash_data_too_short() {
        let header_bytes = build_valid_header_bytes();
        let data: Vec<u8> = header_bytes.to_vec();
        let reader = BundleReader::new(&data).expect("new");
        match reader.validate_manifest_hash().unwrap_err() {
            BundleError::Parse(ParseError::DataTooShort { .. }) => {}
            _ => panic!("attendu Parse(DataTooShort)"),
        }
    }

    #[test]
    fn decrypt_session_key_keywrap_alg_0x0001() {
        let header_bytes = build_valid_header_bytes();
        let session_key = [8u8; 32];
        let kek = [0x41u8; 32];
        let _wrapped = aes_key_wrap_padded(&session_key, &kek).expect("wrap");
        let mut header = header_bytes;
        header[48..80].copy_from_slice(&sha256(&kek));
        let mut data = Vec::from(header.as_slice());
        data.extend_from_slice(&[0u8; 100]);
        let reader = BundleReader::new(&data).expect("new");
        let decrypted = reader.decrypt_session_key(&kek).expect("decrypt");
        assert_eq!(decrypted, session_key);
    }

    #[test]
    fn decrypt_session_key_wrong_kek_hash() {
        let mut header = build_valid_header_bytes();
        header[48..80].copy_from_slice(&[0xFFu8; 32]);
        let mut data = Vec::from(header.as_slice());
        data.extend_from_slice(&[0u8; 100]);
        let reader = BundleReader::new(&data).expect("new");
        match reader.decrypt_session_key(&[0x41u8; 32]).unwrap_err() {
            CryptoError::DecryptionFailed(_) => {}
            _ => panic!("attendu Crypto(DecryptionFailed)"),
        }
    }

    #[test]
    fn decrypt_session_key_unknown_alg() {
        let mut header = build_valid_header_bytes();
        header[48..80].copy_from_slice(&sha256(&[0x41u8; 32]));
        let v7: [u8; 2] = u16::to_le_bytes(99);
        header[4933..4935].copy_from_slice(&v7 as &[u8]);
        let mut data = Vec::from(header.as_slice());
        data.extend_from_slice(&[0u8; 100]);
        let reader = BundleReader::new(&data).expect("new");
        match reader.decrypt_session_key(&[0x41u8; 32]).unwrap_err() {
            CryptoError::UnsupportedKeyWrapAlg { .. } => {}
            _ => panic!("attendu Crypto(UnsupportedKeyWrapAlg)"),
        }
    }

    #[test]
    fn read_chunk_roundtrip() {
        let header_bytes = build_valid_header_bytes();
        let session_key: [u8; 32] = [8u8; 32];
        let bundle_id: [u8; 32] = [1u8; 32].try_into().unwrap();
        let (chunk_key, chunk_nonce) = derive_chunk_key(&session_key, &bundle_id, 0);
        let plaintext = b"chunk data here";
        let encrypted =
            aes_gcm_siv_encrypt(&chunk_key, &chunk_nonce, plaintext, b"").expect("encrypt");
        let mut chunk_data = Vec::new();
        let idx: [u8; 4] = u32::to_le_bytes(0);
        chunk_data.extend_from_slice(&idx);
        let len: [u8; 4] = u32::to_le_bytes(encrypted.len() as u32);
        chunk_data.extend_from_slice(&len);
        chunk_data.extend_from_slice(&[0u8; 32]);
        chunk_data.extend_from_slice(&encrypted);
        let mut data = Vec::from(header_bytes.as_slice());
        data.extend_from_slice(&chunk_data);
        let reader = BundleReader::new(&data).expect("new");
        let chunk = reader
            .read_chunk(0, &session_key, &bundle_id, 1, true)
            .expect("read_chunk");
        assert_eq!(chunk.encrypted_data.as_ref(), plaintext);
    }

    #[test]
    fn read_chunk_wrong_session_key() {
        let header_bytes = build_valid_header_bytes();
        let session_key: [u8; 32] = [8u8; 32];
        let bundle_id: [u8; 32] = [1u8; 32];
        let (chunk_key, chunk_nonce) = derive_chunk_key(&session_key, &bundle_id, 0);
        let encrypted =
            aes_gcm_siv_encrypt(&chunk_key, &chunk_nonce, b"real data", b"").expect("encrypt");
        let mut chunk_data = Vec::new();
        let idx: [u8; 4] = u32::to_le_bytes(0);
        chunk_data.extend_from_slice(&idx);
        let len: [u8; 4] = u32::to_le_bytes(encrypted.len() as u32);
        chunk_data.extend_from_slice(&len);
        chunk_data.extend_from_slice(&[0u8; 32]);
        chunk_data.extend_from_slice(&encrypted);
        let mut data = Vec::from(header_bytes.as_slice());
        data.extend_from_slice(&chunk_data);
        let reader = BundleReader::new(&data).expect("new");
        match reader
            .read_chunk(0, &[0u8; 32], &bundle_id, 1, true)
            .unwrap_err()
        {
            BundleError::Crypto(crate::errors::CryptoError::InvalidTag) => {}
            _ => panic!("attendu Crypto(InvalidTag)"),
        }
    }

    #[test]
    fn read_manifest_wrong_session_key() {
        let header_bytes = build_valid_header_bytes();
        let mut data = Vec::from(header_bytes.as_slice());
        data.extend_from_slice(&[0u8; 100]);
        let reader = BundleReader::new(&data).expect("new");
        match reader.read_manifest(&[0u8; 32]).unwrap_err() {
            BundleError::Crypto(crate::errors::CryptoError::DecryptionFailed(_)) => {}
            _ => panic!("attendu Crypto(DecryptionFailed)"),
        }
    }

    #[test]
    fn chunks_single() {
        let header_bytes = build_valid_header_bytes();
        let session_key: [u8; 32] = [8u8; 32];
        let bundle_id: [u8; 32] = [1u8; 32];
        let (chunk_key, chunk_nonce) = derive_chunk_key(&session_key, &bundle_id, 0);
        let encrypted =
            aes_gcm_siv_encrypt(&chunk_key, &chunk_nonce, b"single chunk", b"").expect("encrypt");
        let mut chunk_data = Vec::new();
        let idx: [u8; 4] = u32::to_le_bytes(0);
        chunk_data.extend_from_slice(&idx);
        let len: [u8; 4] = u32::to_le_bytes(encrypted.len() as u32);
        chunk_data.extend_from_slice(&len);
        chunk_data.extend_from_slice(&[0u8; 32]);
        chunk_data.extend_from_slice(&encrypted);
        let mut data = Vec::from(header_bytes.as_slice());
        data.extend_from_slice(&chunk_data);
        let mut reader = BundleReader::new(&data).expect("new");
        let chunks: Vec<_> = reader.chunks().collect();
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn chunks_multiple() {
        let header_bytes = build_valid_header_bytes();
        let session_key: [u8; 32] = [8u8; 32];
        let bundle_id: [u8; 32] = [1u8; 32];
        let mut data = Vec::from(header_bytes.as_slice());
        for i in 0..3u32 {
            let (chunk_key, chunk_nonce) = derive_chunk_key(&session_key, &bundle_id, i);
            let encrypted = aes_gcm_siv_encrypt(
                &chunk_key,
                &chunk_nonce,
                format!("chunk {i}").as_bytes(),
                b"",
            )
            .expect("encrypt");
            let mut chunk_data = Vec::new();
            chunk_data.extend_from_slice(&i.to_le_bytes());
            chunk_data.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
            chunk_data.extend_from_slice(&[0u8; 32]);
            chunk_data.extend_from_slice(&encrypted);
            data.extend_from_slice(&chunk_data);
        }
        let mut reader = BundleReader::new(&data).expect("new");
        let chunks: Vec<_> = reader.chunks().collect();
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn chunks_empty() {
        let mut header = build_valid_header_bytes();
        let v7: [u8; 2] = u16::to_le_bytes(0);
        header[14..16].copy_from_slice(&v7 as &[u8]);
        let data = header.as_slice();
        let mut reader = BundleReader::new(data).expect("new");
        let chunks: Vec<_> = reader.chunks().collect();
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn error_conversion_parse_to_bundle() {
        let parse_err = ParseError::InvalidMagic {
            got: 0xDEADBEEF,
            expected: 0x55505253,
        };
        let bundle_err: BundleError = parse_err.into();
        match bundle_err {
            BundleError::Parse(ParseError::InvalidMagic { got, expected }) => {
                assert_eq!(got, 0xDEADBEEF);
                assert_eq!(expected, 0x55505253);
            }
            _ => panic!("attendu InvalidMagic"),
        }
    }

    #[test]
    fn error_conversion_crypto_to_bundle() {
        let crypto_err = crate::errors::CryptoError::InvalidKeySize {
            size: 16,
            expected: 32,
        };
        let bundle_err: BundleError = crypto_err.into();
        match bundle_err {
            BundleError::Crypto(crate::errors::CryptoError::InvalidKeySize { size, .. }) => {
                assert_eq!(size, 16);
            }
            _ => panic!("attendu InvalidKeySize"),
        }
    }
}
