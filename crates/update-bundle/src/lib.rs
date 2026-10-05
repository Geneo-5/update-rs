//! Format d'archive de mise à jour.
//!
//! Spécification : `docs/spec/02-bundle-format.md` (en cours de rédaction).
//!
//! Contraintes structurantes :
//! - archive créée offline, mais **lue en streaming** sur le device ;
//! - aucune donnée non authentifiée ne doit être consommée (écrite, décompressée,
//!   interprétée) avant d'avoir été vérifiée.
