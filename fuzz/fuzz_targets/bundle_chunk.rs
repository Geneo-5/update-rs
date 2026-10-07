//! Cible de fuzzing pour le décryptage et la validation des chunks
//!
//! Cette cible fuzz le parsing binaire des chunks du bundle.
//! Chaque chunk est structuré : index(4) + data_length(4) + tag(16) + data(variable).
//! Le parser vérifie les bornesMIN_CHUNK_HEADER_SIZE (24 o) et les limites
//! compilées (MAX_CHUNK_SIZE).

use libfuzzer_sys::fuzz_target;
use update_bundle::BundleChunk;

fuzz_target!(|data: &[u8]| {
    // Appel au parser réel : retourne Result, pas de panic
    let _ = BundleChunk::parse(data);

    // Le parser retourne une erreur propre pour :
    // - données trop courtes (< 24 o)
    // Aucune condition de course ni panic n'est attendue.
});
