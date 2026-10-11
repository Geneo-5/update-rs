//! Gestion des slots A/B et de l'interface bootloader.
//!
//! Spécification : `docs/spec/04-update-flow.md`.

use thiserror::Error;

/// Erreur lors de l'interaction avec un slot.
#[derive(Debug, Error)]
pub enum SlotError {
    /// Le slot spécifié n'existe pas.
    #[error("slot {0} not found")]
    SlotNotFound(u8),
    /// La communication avec le bootloader a échoué.
    #[error("bootloader communication failed: {0}")]
    BootloaderError(String),
}

/// État d'un slot de firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// Slot actuellement actif.
    Active,
    /// Slot inactif (prêt pour installation).
    Inactive,
    /// Slot en attente de confirmation.
    Pending,
    /// Slot ayant échoué lors d'une opération.
    Failed,
}

/// Gestionnaire de slots A/B — placeholder.
/// TODO: implémenter la logique A/B switch, bootloader interaction.
pub struct SlotManager;

impl SlotManager {
    /// Retourne l'état du slot spécifié.
    /// TODO: interroger le bootloader.
    ///
    /// # Erreurs
    ///
    /// Retourne [`SlotError::SlotNotFound`] si le slot n'existe pas.
    pub fn get_state(&self, slot: u8) -> Result<SlotState, SlotError> {
        Err(SlotError::SlotNotFound(slot))
    }
}
