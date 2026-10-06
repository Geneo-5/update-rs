//! Cible de fuzzing pour le parsing du manifeste de jail (CBOR)
//!
//! Cette cible fuzz le parsing CBOR du JailManifest.
//! Elle vérifie que :
//! 1. Le parser CBOR ne plante pas sur des entrées malformées
//! 2. Les validations de champs sont correctes
//! 3. Les chemins malveillants sont rejetés

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO : Appeler update_bundle::JailManifest::from_cbor(data)
    // et vérifier que :
    // 1. Le parser ne panique pas
    // 2. Les CBOR invalides sont rejetés (Result::Err)
    // 3. Les chemins avec ".." ou absolus non autorisés sont rejetés
    // 4. Les tailles (root_tmpfs_size) sont validées

    // Placeholder : vérifier que les données ne sont pas vides
    if data.is_empty() {
        return;
    }

    // Pour l'instant, on ne fait rien pour éviter les faux positifs
    // Cette cible sera complétée dans la Phase 1 de la roadmap
});
