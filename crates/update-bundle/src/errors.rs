//! Types d'erreur pour le parsing et le déchiffrement de bundles.
//!
//! Spécification : `docs/spec/02-bundle-format.md` §5.
//!
//! Toutes les erreurs remontent au caller via `Result<T, BundleError>`.
//! Aucun `unwrap()`, `expect()`, ou `panic!()` en production.

use std::fmt;

/// Erreur de parsing d'un en-tête ou d'un chunk.
///
/// Surviens lorsqu'un bundle ne respecte pas la structure binaire attendue :
/// magic number incorrect, taille insuffisante, valeurs hors bornes,
/// padding non nul, ou hash de vérification infructueux.
#[derive(Debug)]
pub enum ParseError {
    /// Magic number absent ou incorrect (attendu : "UPRS" / 0x55505253).
    InvalidMagic {
        /// Magic number trouvé dans les données.
        got: u32,
        /// Magic number attendu (0x55505253).
        expected: u32,
    },
    /// Version du header non supportée.
    UnsupportedVersion {
        /// Version trouvée dans le header.
        got: u16,
        /// Version attendue (HEADER_VERSION).
        expected: u16,
    },
    /// Données d'entrée trop courtes pour un header complet.
    HeaderTooShort {
        /// Nombre d'octets disponibles.
        got: usize,
        /// Nombre d'octets requis.
        need: usize,
    },
    /// Header dont la taille calculée dépasse les données disponibles.
    HeaderTooLarge {
        /// Taille du header déclarée dans les données.
        got: u32,
        /// Taille du header attendue (H).
        need: usize,
    },
    /// Champ `padding` du header contenant des octets non nuls.
    NonZeroPadding {
        /// Offset de début du padding.
        offset: usize,
        /// Offset de fin du padding.
        end: usize,
    },
    /// Hash du manifeste ne correspond pas au contenu.
    InvalidManifestHash,
    /// Hash du bundle complet ne correspond pas.
    InvalidBundleHash,
    /// Chunk dont la taille déclarée dépasse les données disponibles.
    ChunkTooLarge {
        /// Taille du chunk trouvée dans les données.
        got: u32,
        /// Taille de chunk attendue (chunk_size du header).
        need: usize,
    },
    /// Chunk indexé au-delà de `chunk_count`.
    ChunkIndexOutOfRange {
        /// Index du chunk trouvé dans les données.
        got: u32,
        /// Nombre de chunks attendu (chunk_count du header).
        expected: u32,
    },
    /// Taille de chunk dépassant la limite compilée.
    ChunkTooBig {
        /// Taille de chunk trouvée dans le header.
        got: u32,
    },
    /// Chunk count dépassant la limite compilée.
    ChunkCountTooBig {
        /// Nombre de chunks trouvé dans le header.
        got: u32,
    },
    /// Manifeste chiffré plus grand que la limite compilée.
    ManifestTooLarge {
        /// Taille du manifeste sérialisé.
        got: u64,
    },
    /// Données de bundle inférieures à la taille du header.
    DataTooShort {
        /// Nombre d'octets disponibles.
        got: usize,
        /// Nombre d'octets requis (header_size).
        need: usize,
    },
    /// Offset calculé pour un chunk dépasse la taille des données disponibles.
    ///
    /// Surviens lorsque le calcul `chunk_size × chunk_index` dépasse la taille
    /// des données disponibles, indiquant un header corrompu ou malveillant.
    DataTooLong {
        /// Offset calculé (peut être overflowé).
        got: u64,
        /// Taille des données disponibles.
        max: usize,
    },
    /// Algorithme de suite cryptographique non supporté (au parsing).
    UnsupportedAlgSuite {
        /// Algorithme trouvé dans le header.
        alg: u16,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidMagic { got, expected } => {
                write!(
                    f,
                    "magic number invalide : {got:#x} (attendu {expected:#x})"
                )
            }
            ParseError::UnsupportedVersion { got, expected } => {
                write!(
                    f,
                    "version du header {got} non supportée (attendu {expected})"
                )
            }
            ParseError::HeaderTooShort { got, need } => {
                write!(
                    f,
                    "données trop courtes pour un header : {got} < {need} octets"
                )
            }
            ParseError::HeaderTooLarge { got, need } => {
                write!(
                    f,
                    "header trop volumineux : header_size {got} > données disponibles {need}"
                )
            }
            ParseError::NonZeroPadding { offset, end } => {
                write!(f, "padding non nul aux offsets {offset}-{end}")
            }
            ParseError::InvalidManifestHash => {
                write!(f, "hash du manifeste invalide : vérification échouée")
            }
            ParseError::InvalidBundleHash => {
                write!(f, "hash du bundle invalide : vérification échouée")
            }
            ParseError::ChunkTooLarge { got, need } => {
                write!(
                    f,
                    "chunk trop volumineux : chunk_size {got} > données disponibles {need}"
                )
            }
            ParseError::ChunkIndexOutOfRange { got, expected } => {
                write!(f, "index de chunk {got} dépasse chunk_count {expected}")
            }
            ParseError::ChunkTooBig { got } => {
                write!(f, "chunk_size {got} dépasse MAX_CHUNK_SIZE compilé")
            }
            ParseError::ChunkCountTooBig { got } => {
                write!(f, "chunk_count {got} dépasse MAX_CHUNKS compilé")
            }
            ParseError::ManifestTooLarge { got } => {
                write!(
                    f,
                    "manifeste chiffré {got} dépasse MAX_MANIFEST_SIZE compilé"
                )
            }
            ParseError::DataTooShort { got, need } => {
                write!(
                    f,
                    "données trop courtes pour un header : {got} < {need} octets"
                )
            }
            ParseError::DataTooLong { got, max } => {
                write!(
                    f,
                    "offset de chunk {got:#x} dépasse données disponibles ({max} o)"
                )
            }
            ParseError::UnsupportedAlgSuite { alg } => {
                write!(f, "suite cryptographique non supportée : {alg:#x}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Erreur de couches cryptographiques.
///
/// Surviens lors d'opérations de chiffrement/déchiffrement, de dérivation
/// de clés, ou de vérification de signatures.
#[derive(Debug)]
pub enum CryptoError {
    /// Taille de clé incorrecte pour l'algorithme sélectionné.
    InvalidKeySize {
        /// Taille de clé trouvée.
        size: usize,
        /// Taille de clé attendue.
        expected: usize,
    },
    /// Nonce de taille incorrecte.
    InvalidNonceSize {
        /// Taille du nonce trouvé.
        size: usize,
        /// Taille de nonce attendue.
        expected: usize,
    },
    /// Échec de vérification du tag d'authentification GCM.
    InvalidTag,
    /// Taille de clé de wrap incorrecte pour AES Key Wrap.
    InvalidWrapKeySize {
        /// Taille de clé de wrap trouvée.
        size: usize,
        /// Taille de clé de wrap attendue.
        expected: usize,
    },
    /// Format de clé enveloppée invalide.
    InvalidWrappedKeySize {
        /// Taille de clé enveloppée trouvée.
        size: usize,
        /// Taille de clé enveloppée attendue.
        expected: usize,
    },
    /// Algorithme de wrap non supporté.
    UnsupportedKeyWrapAlg {
        /// Algorithme de wrap trouvé.
        alg: u16,
    },
    /// Algorithme de suite cryptographique non supporté.
    UnsupportedAlgSuite {
        /// Suite cryptographique trouvée.
        alg: u16,
    },
    /// Signature ne passe pas la vérification.
    SignatureVerification {
        /// Type de signature (ECDSA, Ed25519, ML-DSA).
        kind: &'static str,
    },
    /// Erreur générique de déchiffrement.
    DecryptionFailed(String),
    /// Erreur de sérialisation/désérialisation (CBOR, etc.).
    SerializationFailed(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeySize { size, expected } => {
                write!(
                    f,
                    "taille de clé invalide : {size} octets (attendu {expected})"
                )
            }
            CryptoError::InvalidNonceSize { size, expected } => {
                write!(
                    f,
                    "nonce de taille incorrecte : {size} octets (attendu {expected})"
                )
            }
            CryptoError::InvalidTag => {
                write!(
                    f,
                    "tag d'authentification invalide : données corrompues ou clé incorrecte"
                )
            }
            CryptoError::InvalidWrapKeySize { size, expected } => {
                write!(
                    f,
                    "taille de clé de wrap invalide : {size} octets (attendu {expected})"
                )
            }
            CryptoError::InvalidWrappedKeySize { size, expected } => {
                write!(
                    f,
                    "format de clé enveloppée invalide : {size} octets (attendu {expected})"
                )
            }
            CryptoError::UnsupportedKeyWrapAlg { alg } => {
                write!(f, "algorithme de wrap non supporté : {alg:#x}")
            }
            CryptoError::UnsupportedAlgSuite { alg } => {
                write!(f, "algorithme de suite non supporté : {alg:#x}")
            }
            CryptoError::SignatureVerification { kind } => {
                write!(
                    f,
                    "vérification de signature échouée : signature {kind} invalide"
                )
            }
            CryptoError::DecryptionFailed(reason) => {
                write!(f, "déchiffrement échoué : {reason}")
            }
            CryptoError::SerializationFailed(reason) => {
                write!(f, "sérialisation échouée : {reason}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Erreur unifiée de niveau bundle.
///
/// Aggregate toutes les erreurs possibles lors du traitement d'un bundle.
/// Le caller peut pattern-match sur `Kind` pour adapter la réponse.
#[derive(Debug)]
pub enum BundleError {
    /// Erreur de parsing structural.
    Parse(ParseError),
    /// Erreur de couches cryptographiques.
    Crypto(CryptoError),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::Parse(err) => write!(f, "{err}"),
            BundleError::Crypto(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BundleError::Parse(err) => Some(err),
            BundleError::Crypto(err) => Some(err),
        }
    }
}

impl From<ParseError> for BundleError {
    fn from(err: ParseError) -> Self {
        BundleError::Parse(err)
    }
}

impl From<CryptoError> for BundleError {
    fn from(err: CryptoError) -> Self {
        BundleError::Crypto(err)
    }
}
