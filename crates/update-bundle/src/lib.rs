//! Format d'archive de mise à jour.
//!
//! Spécification : `docs/spec/02-bundle-format.md` (en cours de rédaction).
//!
//! Contraintes structurantes :
//! - archive créée offline, mais **lue en streaming** sur le device ;
//! - aucune donnée non authentifiée ne doit être consommée (écrite, décompressée,
//!   interprétée) avant d'avoir été vérifiée.

pub mod errors;
pub mod reader;
pub mod types;

pub use errors::*;
pub use types::*;

/// Lecteur streaming de bundles.
pub use reader::BundleReader;

/// Chunk de bundle.
pub use types::BundleChunk;
