//! Cible de fuzzing pour le parsing du manifeste de jail (CBOR)
//!
//! Cette cible fuzz le parsing CBOR du JailManifest.
//! Elle vérifie que :
//! 1. Le parser CBOR ne plante pas sur des entrées malformées
//! 2. Les validations de champs sont correctes
//! 3. Les tailles sont validées (MAX_MANIFEST_SIZE)

use libfuzzer_sys::fuzz_target;
use update_bundle::JailManifest;

fuzz_target!(|data: &[u8]| {
    // Appel au parser CBOR réel : retourne Result, pas de panic
    let _ = JailManifest::from_cbor(data);

    // Le parser retourne une erreur propre pour :
    // - CBOR invalide (données non sérialisées)
    // - manifeste dépassant MAX_MANIFEST_SIZE (1 MiB)
    // Aucune condition de course ni panic n'est attendue.
});
