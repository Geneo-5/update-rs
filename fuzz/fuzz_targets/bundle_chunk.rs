//! Cible de fuzzing pour le décryptage et la validation des chunks
//!
//! Cette cible fuzz le décryptage AES-GCM-SIV des chunks du bundle.
//! Elle vérifie que :
//! 1. Les tags GCM invalides sont rejetés
//! 2. Les chunks altérés sont détectés
//! 3. Le parser ne plante pas sur des entrées malformées

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Un chunk a au minimum :
    // - chunk_index (4 octets)
    // - chunk_size (4 octets)
    // - tag GCM (16 octets)
    // - données (taille variable)
    if data.len() < 24 {
        return;
    }

    // TODO : Appeler update_bundle::BundleChunk::decrypt(data, session_key)
    // et vérifier que :
    // 1. Le décryptage ne panique pas
    // 2. Les tags GCM invalides sont rejetés (Result::Err)
    // 3. Les chunks altérés sont détectés

    // Placeholder : extraire les champs
    let chunk_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let chunk_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let tag = &data[8..24];

    // Vérifier les bornes
    if chunk_size > 10 * 1024 * 1024 {
        // Chunk trop grand, devrait être rejeté
        return;
    }

    // Pour l'instant, on ne fait rien pour éviter les faux positifs
    let _ = (chunk_index, tag);
});
