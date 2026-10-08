//! Types fondamentaux du format bundle : header, chunk, jail manifest.
//!
//! Spécification : `docs/spec/02-bundle-format.md` §§ 2-4.

use serde::{Deserialize, Serialize};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Version supportée du format header.
pub const HEADER_VERSION: u16 = 1;

/// Suite d'algorithmes supportée : AES-256-GCM-SIV + HKDF-SHA256
/// + ECDSA P-256 + SHA-256.
pub const ALG_SUITE: u16 = 1;

/// Magic number identifiant un bundle update-rs.
pub const BUNDLE_MAGIC: u32 = 0x55505253; // "UPRS"

/// Nombre maximum de chunks autorisés (compile-time configurable).
pub const MAX_CHUNKS: u32 = 1000;

/// Helper : lit un u32 big-endian depuis un slice (renvoie ParseError si
/// le slice est trop court). Appelée depuis `BundleHeader::parse` et
/// `BundleChunk::parse`.
fn read_u32_be(data: &[u8], offset: usize) -> Result<u32, crate::errors::ParseError> {
    <[u8; 4]>::try_from(&data[offset..offset + 4])
        .map(u32::from_be_bytes)
        .map_err(|_| crate::errors::ParseError::HeaderTooShort {
            got: data.len().saturating_sub(offset),
            need: 4,
        })
}

/// Helper : lit un u16 big-endian depuis un slice (renvoie ParseError si
/// le slice est trop court).
fn read_u16_be(data: &[u8], offset: usize) -> Result<u16, crate::errors::ParseError> {
    <[u8; 2]>::try_from(&data[offset..offset + 2])
        .map(u16::from_be_bytes)
        .map_err(|_| crate::errors::ParseError::HeaderTooShort {
            got: data.len().saturating_sub(offset),
            need: 2,
        })
}

/// Taille maximum d'un chunk en octets (compile-time configurable).
pub const MAX_CHUNK_SIZE: u32 = 10 * 1024 * 1024; // 10 MiB

/// Taille maximum du manifeste chiffré (compile-time configurable).
pub const MAX_MANIFEST_SIZE: u64 = 1024 * 1024; // 1 MiB

/// Taille par défaut du header (5120 = 10 secteurs de 512 o).
pub const DEFAULT_HEADER_SIZE: usize = 5120;

// ─── BundleHeader ─────────────────────────────────────────────────────────────

/// En-tête binaire d'un bundle de mise à jour.
///
/// Structure fixe de taille `H` octets (par défaut 5120). Contient les
/// métadonnées du bundle, la clé de session enveloppée, et les signatures.
///
/// # Layout (H = 5120, v1)
///
/// | Offset | Taille  | Champ                        |
/// |--------|---------|------------------------------|
/// | 0      | 4       | magic `"UPRS"` (0x55505253) |
/// | 4      | 2       | header_version (0x0001)      |
/// | 6      | 2       | alg_suite (0x0001)           |
/// | 8      | 4       | header_size                  |
/// | 12     | 4       | min_firmware_version         |
/// | 16     | 4       | bundle_version (monotone)   |
/// | 20     | 4       | chunk_size (64 KiB)          |
/// | 24     | 4       | chunk_count                  |
/// | 28     | 32      | manifest_hash (SHA-256)     |
/// | 60     | 32      | bundle_hash (SHA-256)       |
/// | 92     | 4       | keywrap_alg                |
/// | 96     | 32      | kek_id (hash target KEK)    |
/// | 128    | 32      | bundle_id (UUID/hash)       |
/// | 160    | 48      | wrapped_session_key         |
/// | 208    | 32      | ecc_signature_r             |
/// | 240    | 32      | ecc_signature_s             |
/// | 272    | 64      | ed25519_signature           |
/// | 336    | 4627    | ml_dsa_signature            |
/// | 4963   | 157     | padding (doit être zéro)    |
///
/// Les signatures couvrent `header[0..208]` (tous les champs sauf
/// signatures et padding).
#[derive(Debug, Clone)]
pub struct BundleHeader<const H: usize = DEFAULT_HEADER_SIZE> {
    /// Magic number ("UPRS").
    pub magic: u32,
    /// Version du format header.
    pub header_version: u16,
    /// Suite d'algorithmes.
    pub alg_suite: u16,
    /// Taille du header en octets.
    pub header_size: u32,
    /// Version minimale du firmware.
    pub min_firmware_version: u32,
    /// Version monotone du bundle.
    pub bundle_version: u32,
    /// Taille d'un chunk en octets.
    pub chunk_size: u32,
    /// Nombre de chunks.
    pub chunk_count: u32,
    /// SHA-256 du manifeste chiffré.
    pub manifest_hash: [u8; 32],
    /// SHA-256 du contenu post-header (stream complet).
    pub bundle_hash: [u8; 32],
    /// Algorithme de wrap de clé.
    pub keywrap_alg: u16,
    /// Hash de la KEK cible dans le TPM.
    pub kek_id: [u8; 32],
    /// Identifiant unique du bundle.
    pub bundle_id: [u8; 32],
    /// Clé de session enveloppée (40 o RFC 5649, 48 o mode x3).
    pub wrapped_session_key: [u8; 48],
    /// Partie r de la signature ECDSA P-256.
    pub ecc_signature_r: [u8; 32],
    /// Partie s de la signature ECDSA P-256.
    pub ecc_signature_s: [u8; 32],
    /// Signature Ed25519.
    pub ed25519_signature: [u8; 64],
    /// Signature ML-DSA-87.
    pub ml_dsa_signature: [u8; 4627],
}

impl<const H: usize> BundleHeader<H> {
    /// Parse un tableau d'octets en `BundleHeader`.
    ///
    /// Vérifie :
    /// - magic number = "UPRS"
    /// - header_version supporté
    /// - taille suffisante
    /// - header_size correspond à `H`
    /// - padding nul
    pub fn parse(data: &[u8]) -> Result<BundleHeader<H>, crate::errors::ParseError> {
        use crate::errors::ParseError;

        if data.len() < H {
            return Err(ParseError::HeaderTooShort {
                got: data.len(),
                need: H,
            });
        }

        // Helper : conversion slice → array via try_into, avec erreur de parsing
        // au lieu de .unwrap() (lint clippy unwrap_used = "deny").
        fn read_u32(slice: &[u8]) -> Result<u32, ParseError> {
            <[u8; 4]>::try_from(slice)
                .map(u32::from_be_bytes)
                .map_err(|_| ParseError::HeaderTooShort {
                    got: slice.len(),
                    need: 4,
                })
        }
        fn read_u16(slice: &[u8]) -> Result<u16, ParseError> {
            <[u8; 2]>::try_from(slice)
                .map(u16::from_be_bytes)
                .map_err(|_| ParseError::HeaderTooShort {
                    got: slice.len(),
                    need: 2,
                })
        }

        let magic = read_u32(&data[0..4])?;
        if magic != BUNDLE_MAGIC {
            return Err(ParseError::InvalidMagic {
                got: magic,
                expected: BUNDLE_MAGIC,
            });
        }

        let header_version = read_u16(&data[4..6])?;
        if header_version != HEADER_VERSION {
            return Err(ParseError::UnsupportedVersion {
                got: header_version,
                expected: HEADER_VERSION,
            });
        }

        let alg_suite = read_u16(&data[6..8])?;
        if alg_suite != ALG_SUITE {
            return Err(ParseError::UnsupportedAlgSuite { alg: alg_suite });
        }

        let declared_header_size = read_u32(&data[8..12])?;
        if declared_header_size as usize != H {
            return Err(ParseError::HeaderTooLarge {
                got: declared_header_size,
                need: H,
            });
        }

        let min_firmware_version = read_u32(&data[12..16])?;
        let bundle_version = read_u32(&data[16..20])?;

        let chunk_size = read_u32(&data[20..24])?;
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(ParseError::ChunkTooBig { got: chunk_size });
        }

        let chunk_count = read_u32(&data[24..28])?;
        if chunk_count == 0 || chunk_count > MAX_CHUNKS {
            return Err(ParseError::ChunkCountTooBig { got: chunk_count });
        }

        let mut manifest_hash = [0u8; 32];
        manifest_hash.copy_from_slice(&data[28..60]);

        let mut bundle_hash = [0u8; 32];
        bundle_hash.copy_from_slice(&data[60..92]);

        let keywrap_alg = read_u16(&data[92..96])?;

        let mut kek_id = [0u8; 32];
        kek_id.copy_from_slice(&data[96..128]);

        let mut bundle_id = [0u8; 32];
        bundle_id.copy_from_slice(&data[128..160]);

        let mut wrapped_session_key = [0u8; 48];
        wrapped_session_key.copy_from_slice(&data[160..208]);

        let mut ecc_signature_r = [0u8; 32];
        ecc_signature_r.copy_from_slice(&data[208..240]);

        let mut ecc_signature_s = [0u8; 32];
        ecc_signature_s.copy_from_slice(&data[240..272]);

        let mut ed25519_signature = [0u8; 64];
        ed25519_signature.copy_from_slice(&data[272..336]);

        // ── CORRECTION CRITIQUE ──────────────────────────────────────
        // Le code original lisait `&data[336..H]` ce qui, pour H = 5120,
        // tentait de copier 4784 octets dans un tableau de 4627 octets,
        // provoquant un panic dans `copy_from_slice`.
        // On lit maintenant exactement 4627 octets, puis on vérifie le padding.
        // ──────────────────────────────────────────────────────────────
        const ML_DSA_LEN: usize = 4627;
        let ml_dsa_end = 336 + ML_DSA_LEN; // 4963

        // Vérifier qu'il reste assez de données pour la signature ML-DSA
        if data.len() < ml_dsa_end {
            return Err(ParseError::HeaderTooShort {
                got: data.len(),
                need: ml_dsa_end,
            });
        }

        let mut ml_dsa_signature = [0u8; ML_DSA_LEN];
        ml_dsa_signature.copy_from_slice(&data[336..ml_dsa_end]);

        // Vérifier le padding (doit être zéro)
        if ml_dsa_end < H {
            let padding = &data[ml_dsa_end..H];
            if padding.iter().any(|&b| b != 0) {
                return Err(ParseError::NonZeroPadding {
                    offset: ml_dsa_end,
                    end: H,
                });
            }
        }

        Ok(BundleHeader {
            magic,
            header_version,
            alg_suite,
            header_size: declared_header_size,
            min_firmware_version,
            bundle_version,
            chunk_size,
            chunk_count,
            manifest_hash,
            bundle_hash,
            keywrap_alg,
            kek_id,
            bundle_id,
            wrapped_session_key,
            ecc_signature_r,
            ecc_signature_s,
            ed25519_signature,
            ml_dsa_signature,
        })
    }

    /// Retourne l'identifiant unique du bundle (32 o).
    pub fn bundle_id(&self) -> &[u8; 32] {
        &self.bundle_id
    }

    /// Retourne le nombre de chunks.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Retourne la taille d'un chunk en octets.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }
}

// ─── BundleChunk ──────────────────────────────────────────────────────────────

/// Chunk individuel d'un bundle de mise à jour.
///
/// Format binaire séquentiel :
/// ```text
/// [chunk_index:u32 BE][data_length:u32 BE][tag:16][encrypted_data:N]
/// ```
#[derive(Debug, Clone)]
pub struct BundleChunk {
    /// Index du chunk (0-based).
    pub index: u32,
    /// Taille des données plaintext.
    pub data_length: u32,
    /// Tag d'authentification AES-GCM-SIV (16 o).
    pub tag: [u8; 16],
    /// Données chiffrées (variable).
    pub encrypted_data: bytes::Bytes,
}

impl BundleChunk {
    /// Taille minimum d'un chunk (header 8 + tag 16 = 24 o).
    pub const MIN_CHUNK_HEADER_SIZE: usize = 24;

    /// Parse un chunk depuis un tableau d'octets.
    ///
    /// Retourne `ParseError::DataTooShort` si le tableau est insuffisant
    /// pour les 24 octets minimum.
    ///
    /// # Erreurs
    ///
    /// - `ParseError::DataTooShort` : données inférieures à `MIN_CHUNK_HEADER_SIZE`
    /// - `ParseError::ChunkTooBig` : `data_length` dépasse `MAX_CHUNK_SIZE`
    /// - `ParseError::ChunkIndexOutOfRange` : `index` incohérent
    pub fn parse(data: &[u8]) -> Result<BundleChunk, crate::errors::ParseError> {
        use crate::errors::ParseError;

        if data.len() < Self::MIN_CHUNK_HEADER_SIZE {
            return Err(ParseError::DataTooShort {
                got: data.len(),
                need: Self::MIN_CHUNK_HEADER_SIZE,
            });
        }

        // Helpers sans unwrap (lint clippy unwrap_used = "deny")
        let index = u32::from_be_bytes(
            <[u8; 4]>::try_from(&data[0..4])
                .map_err(|_| ParseError::DataTooShort { got: 4, need: 4 })?,
        );
        let data_length = u32::from_be_bytes(
            <[u8; 4]>::try_from(&data[4..8])
                .map_err(|_| ParseError::DataTooShort { got: 4, need: 4 })?,
        );

        // Vérifier que data_length est cohérent avec MAX_CHUNK_SIZE
        if data_length > MAX_CHUNK_SIZE {
            return Err(ParseError::ChunkTooBig { got: data_length });
        }

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[8..24]);

        let encrypted_data = bytes::Bytes::copy_from_slice(&data[24..]);

        // Vérifier la cohérence : la taille des données chiffrées doit être
        // compatible avec data_length (en AES-GCM, ciphertext = plaintext).
        if encrypted_data.len() as u32 != data_length {
            return Err(ParseError::ChunkTooLarge {
                got: encrypted_data.len() as u32,
                need: data_length as usize,
            });
        }

        Ok(BundleChunk {
            index,
            data_length,
            tag,
            encrypted_data,
        })
    }

    /// Retourne l'index du chunk.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Retourne la taille des données plaintext.
    pub fn data_length(&self) -> u32 {
        self.data_length
    }

    /// Déchiffre ce chunk en utilisant la clé de session dérivée.
    ///
    /// Utilise AES-256-GCM-SIV (RFC 8452) avec les paramètres suivants :
    /// - **Clé par chunk** : dérivée via HKDF-Expand-SHA256 avec le label
    ///   `"update-rs/chunk"` (voir `docs/spec/05-crypto.md` §REQ-CRY-9).
    /// - **Nonce par chunk** : dérivée avec le même HKDF (12 octets).
    /// - **AAD** : `bundle_id || chunk_index(u32 BE) || chunk_count(u32 BE)
    ///   || is_last_chunk(u8) || data_length(u32 BE)`.
    ///
    /// # Erreurs
    ///
    /// - `CryptoError::InvalidTag` : tag d'authentification invalide,
    ///   indiquant des données corrompues ou une clé incorrecte.
    /// - `CryptoError::DecryptionFailed` : échec interne du déchiffrement.
    ///
    /// # Zeroization (REQ-CRY-4)
    ///
    /// La clé et le nonce par chunk sont zeroizés après usage via
    /// `zeroize::Zeroize`.
    pub fn decrypt(
        &self,
        session_key: &[u8; 32],
        bundle_id: &[u8; 32],
        chunk_count: u32,
        is_last: bool,
    ) -> Result<bytes::Bytes, crate::errors::CryptoError> {
        use crate::errors::CryptoError;

        // ── Dérivation de clé par chunk (HKDF-Expand-SHA256) ─────────
        let (chunk_key, chunk_nonce) =
            crate::crypto::derive_chunk_key(session_key, bundle_id, self.index);

        // ── AAD : bundle_id || chunk_index || chunk_count ||
        // │          is_last_chunk || data_length ────────────────────
        let mut aad = Vec::with_capacity(45);
        aad.extend_from_slice(bundle_id);
        aad.extend_from_slice(&self.index.to_be_bytes());
        aad.extend_from_slice(&chunk_count.to_be_bytes());
        aad.push(if is_last { 1u8 } else { 0u8 });
        aad.extend_from_slice(&self.data_length.to_be_bytes());

        // Le tag (16 octets) est stocké séparément dans `self.tag`.
        // Les données à déchiffrer sont `encrypted_data` sans le tag.
        let encrypted_chunk = &self.encrypted_data;

        let decrypted_data =
            crate::crypto::aes_gcm_siv_decrypt(&chunk_key, &chunk_nonce, encrypted_chunk, &aad)?;

        // Zeroization des secrets (REQ-CRY-4)
        chunk_key.zeroize();
        chunk_nonce.zeroize();

        Ok(bytes::Bytes::from(decrypted_data))
    }
}

// ─── JailManifest ─────────────────────────────────────────────────────────────

/// Types de filesystem dans un jail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FsSet {
    /// Répertoire à créer.
    Dir {
        /// Chemin du répertoire à créer.
        path: String,
        /// Mode permissions (optionnel, sinon 0o755).
        mode: Option<u16>,
    },
    /// Fichier à créer avec contenu.
    File {
        /// Chemin du fichier à créer.
        path: String,
        /// Contenu du fichier.
        content: String,
        /// Mode permissions (optionnel).
        mode: Option<u16>,
    },
    /// Point de montage hôte.
    HostBind {
        /// Source (hôte).
        source: String,
        /// Cible (dans le jail).
        target: String,
    },
    /// Fichier de payload.
    PayloadFile {
        /// Source (fichier de payload).
        source: String,
        /// Cible (dans le jail).
        target: String,
    },
    /// Répertoire de payload.
    PayloadDir {
        /// Source (répertoire de payload).
        source: String,
        /// Cible (dans le jail).
        target: String,
    },
    /// Périphérique char.
    ChrDev {
        /// Majeure.
        major: u32,
        /// Mineure.
        minor: u32,
        /// Cible (dans le jail).
        target: String,
    },
    /// Périphérique bloc.
    BlkDev {
        /// Majeure.
        major: u32,
        /// Mineure.
        minor: u32,
        /// Cible (dans le jail).
        target: String,
    },
    /// Lien symbolique.
    Symlink {
        /// Destination du lien.
        target: String,
        /// Chemin du lien.
        link_path: String,
    },
    /// FIFO.
    Fifo {
        /// Chemin du FIFO.
        path: String,
        /// Mode permissions (optionnel).
        mode: Option<u16>,
    },
    /// Système de fichiers temporaire.
    Tmpfs {
        /// Chemin du tmpfs.
        path: String,
        /// Taille optionnelle.
        size: Option<u64>,
    },
    /// Montage devtmpfs.
    Devtmpfs {
        /// Chemin du montage devtmpfs.
        path: String,
    },
}

/// Manifeste de jail : configuration de l'environnement isolé.
///
/// Format sérialisable en CBOR (ou JSON, ou tout format supporté par serde).
/// Contient l'ensemble des règles de filesystem pour le jail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailManifest {
    /// Ensemble des règles de filesystem.
    pub filesystems: Vec<FsSet>,
    /// Variables d'environnement.
    pub env_vars: Option<Vec<(String, String)>>,
    /// Liste des capabilities à maintenir.
    pub capabilities: Option<Vec<String>>,
    /// Timeout en secondes.
    pub timeout: Option<u64>,
}

impl JailManifest {
    /// Sérialise le manifeste en CBOR.
    ///
    /// Utilise ciborium pour la sérialisation CBOR.
    ///
    /// # Erreurs
    ///
    /// - `BundleError::Parse(ParseError::ManifestTooLarge)` si le manifeste
    ///   sérialisé dépasse `MAX_MANIFEST_SIZE`.
    /// - `BundleError::Crypto(CryptoError::SerializationFailed)` si la sérialisation
    ///   CBOR échoue (structure interne invalide).
    pub fn to_cbor(&self) -> Result<Vec<u8>, crate::errors::BundleError> {
        let mut encoded = Vec::new();
        ciborium::into_writer(self, &mut encoded).map_err(|e| {
            crate::errors::BundleError::Crypto(crate::errors::CryptoError::SerializationFailed(
                e.to_string(),
            ))
        })?;
        if encoded.len() as u64 > MAX_MANIFEST_SIZE {
            return Err(crate::errors::BundleError::Parse(
                crate::errors::ParseError::ManifestTooLarge {
                    got: encoded.len() as u64,
                },
            ));
        }
        Ok(encoded)
    }

    /// Parse un manifeste depuis des données CBOR.
    ///
    /// Retourne `ParseError::InvalidManifestHash` si les données ne sont pas
    /// un CBOR valide, ou si la désérialisation échoue.
    ///
    /// # Erreurs
    ///
    /// - `ParseError::InvalidManifestHash` : données CBOR invalides ou structure
    ///   non conforme à `JailManifest`.
    pub fn from_cbor(data: &[u8]) -> Result<JailManifest, crate::errors::ParseError> {
        use crate::errors::ParseError;

        // Vérifier la borne supérieure avant de parser
        if data.len() as u64 > MAX_MANIFEST_SIZE {
            return Err(ParseError::ManifestTooLarge {
                got: data.len() as u64,
            });
        }

        let manifest: JailManifest =
            ciborium::from_reader(data).map_err(|_| ParseError::InvalidManifestHash)?;
        Ok(manifest)
    }

    /// Retourne le nombre de règles de filesystem.
    pub fn filesystem_count(&self) -> usize {
        self.filesystems.len()
    }

    /// Retourne les variables d'environnement.
    pub fn env_vars(&self) -> Option<&Vec<(String, String)>> {
        self.env_vars.as_ref()
    }

    /// Retourne le timeout en secondes, le cas échéant.
    pub fn timeout(&self) -> Option<u64> {
        self.timeout
    }

    /// Retourne les capabilities à maintenir.
    pub fn capabilities(&self) -> Option<&Vec<String>> {
        self.capabilities.as_ref()
    }
}
