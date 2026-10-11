//! Abstraction du TPM 2.0.
//!
//! Spécification : `docs/spec/03-tpm.md`.

use thiserror::Error;

/// Erreur lors de l'interaction avec le TPM.
#[derive(Debug, Error)]
pub enum TpmError {
    /// Le TPM n'est pas disponible.
    #[error("TPM not available")]
    NotAvailable,
    /// La commande TPM a échoué avec le code d'erreur spécifié.
    #[error("TPM command failed: {0}")]
    CommandFailed(u32),
    /// L'index NV n'a pas été trouvé.
    #[error("NV index {0:x} not found")]
    NvIndexNotFound(u32),
}

/// Contexte TPM — placeholder.
/// TODO: implémenter avec `tss-esapi` une fois la spécification stabilisée.
pub struct TpmContext;

impl TpmContext {
    /// Ouvrir une connexion TPM.
    /// TODO: ouvrir `/dev/tpmrm0`.
    ///
    /// # Erreurs
    ///
    /// Retourne [`TpmError::NotAvailable`] si le TPM n'est pas accessible.
    pub fn open() -> Result<Self, TpmError> {
        Err(TpmError::NotAvailable)
    }
}
